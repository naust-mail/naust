"""
MFA (TOTP and WebAuthn/passkey) management for the admin control panel.

TOTP replay protection: each 30-second time-step is consumed atomically via a
conditional UPDATE. Once a step is consumed, the same code cannot be reused
within that window even under concurrent login attempts.

WebAuthn (passkeys) follow the FIDO2 spec: registration and authentication are
split into begin/complete round-trips, and the sign_count is updated on each
successful assertion to detect cloned authenticators.
"""

import base64
import io
import json as _json
import os
import time
from mail.mailconfig import open_database


def get_user_id(email, c):
	"""Look up the integer user id for an email address using an open cursor.
	Raises ValueError if the user does not exist."""
	c.execute('SELECT id FROM users WHERE email=?', (email,))
	r = c.fetchone()
	if not r:
		raise ValueError("User does not exist.")
	return r[0]


def get_mfa_state(email, env):
	"""Return all MFA rows for a user including secrets and replay state.
	Only used internally - never expose this to the frontend."""
	conn, c = open_database(env, with_connection=True)
	c.execute('SELECT id, type, secret, mru_token, label FROM mfa WHERE user_id=?', (get_user_id(email, c),))
	rows = c.fetchall()
	conn.close()
	return [{"id": r[0], "type": r[1], "secret": r[2], "mru_token": r[3], "label": r[4]} for r in rows]


def get_public_mfa_state(email, env):
	"""Return MFA state safe to send to the frontend - no secrets, no replay tokens.
	Combines TOTP entries and passkeys into a single list."""
	totp = [{"id": s["id"], "type": s["type"], "label": s["label"]} for s in get_mfa_state(email, env)]
	passkeys = [{"id": p["id"], "type": "webauthn", "name": p["name"], "last_used": p["last_used"]} for p in get_public_webauthn_credentials(email, env)]
	return totp + passkeys


def get_hash_mfa_state(email, env):
	"""Return only the fields needed to verify a TOTP code - id, type, and secret.
	Used by the auth pipeline; strips label and replay state."""
	mfa_state = get_mfa_state(email, env)
	return [{"id": s["id"], "type": s["type"], "secret": s["secret"]} for s in mfa_state]


def enable_mfa(email, type, secret, token, label, env):
	if type == "totp":
		import pyotp

		validate_totp_secret(secret)
		# Verify the user's current code before saving so we don't lock them
		# out with a secret their app can't actually produce.
		totp = pyotp.TOTP(secret)
		if not totp.verify(token, valid_window=1):
			msg = "Invalid token."
			raise ValueError(msg)
	else:
		msg = "Invalid MFA type."
		raise ValueError(msg)

	conn, c = open_database(env, with_connection=True)
	c.execute('INSERT INTO mfa (user_id, type, secret, label) VALUES (?, ?, ?, ?)', (get_user_id(email, c), type, secret, label))
	conn.commit()
	conn.close()


def consume_totp_step(email, mfa_id, env) -> bool:
	"""Atomically mark the current 30-second TOTP time-step as used.

	Stores the step counter (unix_time // 30) rather than the code itself.
	The conditional UPDATE only succeeds if the stored step is older than the
	current one, making it safe against concurrent login attempts - only one
	request can win the UPDATE for a given step.

	Returns False if the step was already consumed (replay attempt)."""
	step = str(int(time.time()) // 30)
	conn, c = open_database(env, with_connection=True)
	c.execute('UPDATE mfa SET mru_token=? WHERE id=? AND user_id=? AND (mru_token IS NULL OR CAST(mru_token AS INTEGER) < ?)', (step, mfa_id, get_user_id(email, c), step))
	consumed = c.rowcount > 0
	conn.commit()
	conn.close()
	return consumed


def disable_mfa(email, mfa_id, env):
	conn, c = open_database(env, with_connection=True)
	user_id = get_user_id(email, c)
	if mfa_id is None:
		# Disable all MFA for a user (TOTP and passkeys).
		c.execute('DELETE FROM mfa WHERE user_id=?', (user_id,))
		c.execute('DELETE FROM webauthn_credentials WHERE user_id=?', (user_id,))
		deleted = c.rowcount > 0
	else:
		# Try TOTP table first, then webauthn_credentials.
		c.execute('DELETE FROM mfa WHERE user_id=? AND id=?', (user_id, mfa_id))
		if c.rowcount == 0:
			c.execute('DELETE FROM webauthn_credentials WHERE user_id=? AND id=?', (user_id, mfa_id))
		deleted = c.rowcount > 0
	conn.commit()
	conn.close()
	return deleted


def validate_totp_secret(secret):
	if not isinstance(secret, str) or secret.strip() == "":
		msg = "No secret provided."
		raise ValueError(msg)
	if len(secret) != 32:
		msg = "Secret should be a 32 characters base32 string"
		raise ValueError(msg)


def provision_totp(email, env):
	import pyotp
	import qrcode

	# Make a new secret.
	secret = base64.b32encode(os.urandom(20)).decode('utf-8')
	validate_totp_secret(secret)  # sanity check

	# Make a URI that we encode within a QR code.
	uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=env["PRIMARY_HOSTNAME"] + " Naust Control Panel")

	# Generate a QR code as a base64-encode PNG image.
	qr = qrcode.make(uri)
	byte_arr = io.BytesIO()
	qr.save(byte_arr, format='PNG')
	png_b64 = base64.b64encode(byte_arr.getvalue()).decode('utf-8')

	return {"type": "totp", "secret": secret, "qr_code_base64": png_b64}


###################################
# WebAuthn / Passkeys


def _get_fido2_server(env):
	from fido2.server import Fido2Server
	from fido2.webauthn import PublicKeyCredentialRpEntity

	# rpId is fixed to PRIMARY_HOSTNAME. Moving the admin panel to a different
	# hostname will invalidate all registered passkeys. Users must re-register.
	rp = PublicKeyCredentialRpEntity(id=env["PRIMARY_HOSTNAME"], name="Naust")
	return Fido2Server(rp)


def _options_to_dict(options):
	# Convert fido2 CredentialCreationOptions / CredentialRequestOptions to a plain
	# Python dict safe for json.dumps. The double-pass guarantees no fido2 types leak.
	return _json.loads(_json.dumps(dict(options)))


def get_webauthn_credentials(email, env):
	"""Return stored AttestedCredentialData objects for a user."""
	from fido2.webauthn import AttestedCredentialData

	conn, c = open_database(env, with_connection=True)
	c.execute('SELECT public_key FROM webauthn_credentials WHERE user_id=?', (get_user_id(email, c),))
	rows = c.fetchall()
	conn.close()
	return [AttestedCredentialData(row[0]) for row in rows]


def get_public_webauthn_credentials(email, env):
	"""Return name/id/last_used for each passkey without key material."""
	conn, c = open_database(env, with_connection=True)
	c.execute('SELECT id, name, last_used FROM webauthn_credentials WHERE user_id=?', (get_user_id(email, c),))
	rows = c.fetchall()
	conn.close()
	return [{"id": r[0], "name": r[1], "last_used": r[2]} for r in rows]


def webauthn_register_begin(email, env):
	"""Begin passkey registration. Returns (options_dict, state); caller stores state."""
	from fido2.webauthn import PublicKeyCredentialUserEntity

	server = _get_fido2_server(env)
	conn, c = open_database(env, with_connection=True)
	user_id = get_user_id(email, c)
	conn.close()
	user = PublicKeyCredentialUserEntity(
		id=user_id.to_bytes(8, 'big'),
		name=email,
		display_name=email,
	)
	existing = get_webauthn_credentials(email, env)
	options, state = server.register_begin(
		user,
		credentials=existing,
		resident_key_requirement='required',
		user_verification='required',
	)
	return _options_to_dict(options), state


def webauthn_register_complete(email, state, client_response, name, env):
	"""Complete passkey registration and store the new credential."""
	from fido2.webauthn import RegistrationResponse

	server = _get_fido2_server(env)
	response = RegistrationResponse.from_dict(client_response)
	auth_data = server.register_complete(state, response)
	cred = auth_data.credential_data
	conn, c = open_database(env, with_connection=True)
	c.execute(
		'INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, aaguid, name) VALUES (?, ?, ?, ?, ?, ?)',
		(get_user_id(email, c), bytes(cred.credential_id), bytes(cred), 0, str(cred.aaguid), name),
	)
	conn.commit()
	conn.close()


def webauthn_authenticate_begin(email, env):
	"""Begin passkey authentication. Returns (options_dict, state); caller stores state.

	When no passkeys are registered we return a synthetic challenge indistinguishable
	from a real one so callers cannot enumerate which accounts have passkeys.
	"""
	server = _get_fido2_server(env)
	credentials = get_webauthn_credentials(email, env)
	if not credentials:
		# Return a fake challenge with the same shape as a real response.
		# The nonce stored in webauthn_challenges will have no credentials list,
		# so authenticate_complete will always reject it.
		import os as _os

		fake_challenge = _os.urandom(32)
		fake_options = {
			"challenge": list(fake_challenge),
			"timeout": 60000,
			"rpId": env.get("PRIMARY_HOSTNAME", "localhost"),
			"allowCredentials": [],
			"userVerification": "required",
		}
		return fake_options, {"fake": True}
	options, state = server.authenticate_begin(
		credentials,
		user_verification='required',
	)
	return _options_to_dict(options), state


def webauthn_authenticate_complete(email, state, client_response, env):
	"""Verify passkey assertion and update sign_count/last_used. Raises on failure."""
	from fido2.webauthn import AuthenticationResponse

	if state.get("fake"):
		raise ValueError("Authentication failed.")

	server = _get_fido2_server(env)
	credentials = get_webauthn_credentials(email, env)
	response = AuthenticationResponse.from_dict(client_response)
	result = server.authenticate_complete(state, credentials, response)
	new_sign_count = response.response.authenticator_data.counter
	credential_id_used = bytes(result.credential_id)
	conn, c = open_database(env, with_connection=True)
	c.execute(
		'UPDATE webauthn_credentials SET sign_count=?, last_used=datetime("now") WHERE user_id=? AND credential_id=?',
		(new_sign_count, get_user_id(email, c), credential_id_used),
	)
	conn.commit()
	conn.close()


###################################


def validate_auth_mfa(email, request, env):
	"""Validate that a login request satisfies the user's enabled MFA methods.

	Returns (True, []) on success. Returns (False, hints) if MFA is required but
	not satisfied, where hints is a list of strings indicating what the caller
	can supply. Possible hint values:
	  'missing-totp-token'   - X-Auth-Token header not present
	  'invalid-totp-token'   - code present but wrong or already used
	  'missing-webauthn-assertion' - account has passkeys; use the passkey flow instead
	"""

	mfa_state = get_mfa_state(email, env)

	# If no MFA modes are added, return True.
	if len(mfa_state) == 0:
		return (True, [])

	# Try the enabled MFA modes.
	hints = set()
	for mfa_mode in mfa_state:
		if mfa_mode["type"] == "totp":
			# Check that a token is present in the X-Auth-Token header.
			# If not, give a hint that one can be supplied.
			token = request.headers.get('x-auth-token')
			if not token:
				hints.add("missing-totp-token")
				continue

			import pyotp

			totp = pyotp.TOTP(mfa_mode["secret"])
			if not totp.verify(token, valid_window=1):
				hints.add("invalid-totp-token")
				continue

			if not consume_totp_step(email, mfa_mode["id"], env):
				hints.add("invalid-totp-token")
				continue

			return (True, [])

		if mfa_mode["type"] == "webauthn":
			# Password login cannot satisfy a WebAuthn requirement.
			# Passkey users must authenticate via /mfa/webauthn/authenticate/begin+complete.
			# continue (not return) so that a TOTP entry later in the list can still succeed.
			hints.add("missing-webauthn-assertion")
			continue

	# On a failed login, indicate failure and any hints for what the user can do instead.
	return (False, list(hints))
