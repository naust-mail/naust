import base64
import io
import json as _json
import os
import pyotp
import qrcode

from mailconfig import open_database

def get_user_id(email, c):
	c.execute('SELECT id FROM users WHERE email=?', (email,))
	r = c.fetchone()
	if not r: raise ValueError("User does not exist.")
	return r[0]

def get_mfa_state(email, env):
	conn, c = open_database(env, with_connection=True)
	c.execute('SELECT id, type, secret, mru_token, label FROM mfa WHERE user_id=?', (get_user_id(email, c),))
	rows = c.fetchall()
	conn.close()
	return [
		{ "id": r[0], "type": r[1], "secret": r[2], "mru_token": r[3], "label": r[4] }
		for r in rows
	]

def get_public_mfa_state(email, env):
	totp = [
		{ "id": s["id"], "type": s["type"], "label": s["label"] }
		for s in get_mfa_state(email, env)
	]
	passkeys = [
		{ "id": p["id"], "type": "webauthn", "name": p["name"], "last_used": p["last_used"] }
		for p in get_public_webauthn_credentials(email, env)
	]
	return totp + passkeys

def get_hash_mfa_state(email, env):
	mfa_state = get_mfa_state(email, env)
	return [
		{ "id": s["id"], "type": s["type"], "secret": s["secret"] }
		for s in mfa_state
	]

def enable_mfa(email, type, secret, token, label, env):
	if type == "totp":
		validate_totp_secret(secret)
		# Sanity check with the provide current token.
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

def set_mru_token(email, mfa_id, token, env):
	conn, c = open_database(env, with_connection=True)
	c.execute('UPDATE mfa SET mru_token=? WHERE user_id=? AND id=?', (token, get_user_id(email, c), mfa_id))
	conn.commit()
	conn.close()

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
	# Make a new secret.
	secret = base64.b32encode(os.urandom(20)).decode('utf-8')
	validate_totp_secret(secret) # sanity check

	# Make a URI that we encode within a QR code.
	uri = pyotp.TOTP(secret).provisioning_uri(
		name=email,
		issuer_name=env["PRIMARY_HOSTNAME"] + " Mail-in-a-Box Control Panel"
	)

	# Generate a QR code as a base64-encode PNG image.
	qr = qrcode.make(uri)
	byte_arr = io.BytesIO()
	qr.save(byte_arr, format='PNG')
	png_b64 = base64.b64encode(byte_arr.getvalue()).decode('utf-8')

	return {
		"type": "totp",
		"secret": secret,
		"qr_code_base64": png_b64
	}

###################################
# WebAuthn / Passkeys

def _get_fido2_server(env):
	from fido2.server import Fido2Server
	from fido2.webauthn import PublicKeyCredentialRpEntity
	# rpId is fixed to PRIMARY_HOSTNAME. Moving the admin panel to a different
	# hostname will invalidate all registered passkeys. Users must re-register.
	rp = PublicKeyCredentialRpEntity(id=env["PRIMARY_HOSTNAME"], name="Mail-in-a-Box")
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
	"""Begin passkey authentication. Returns (options_dict, state); caller stores state."""
	server = _get_fido2_server(env)
	credentials = get_webauthn_credentials(email, env)
	if not credentials:
		raise ValueError("No passkeys registered for this account.")
	options, state = server.authenticate_begin(
		credentials,
		user_verification='required',
	)
	return _options_to_dict(options), state

def webauthn_authenticate_complete(email, state, client_response, env):
	"""Verify passkey assertion and update sign_count/last_used. Raises on failure."""
	from fido2.webauthn import AuthenticationResponse
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
	# Validates that a login request satisfies any MFA modes
	# that have been enabled for the user's account. Returns
	# a tuple (status, [hints]). status is True for a successful
	# MFA login, False for a missing token. If status is False,
	# hints is an array of codes that indicate what the user
	# can try. Possible codes are:
	# "missing-totp-token"
	# "invalid-totp-token"

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

			# TOTP is intentionally stateless per RFC 6238 implementations;
			# replay protection is enforced at the session layer, not OTP level.
			totp = pyotp.TOTP(mfa_mode["secret"])
			if not totp.verify(token, valid_window=1):
				hints.add("invalid-totp-token")
				continue

			return (True, [])

		elif mfa_mode["type"] == "webauthn":
			# Password login cannot satisfy a WebAuthn requirement.
			# Passkey users must authenticate via /mfa/webauthn/authenticate/begin+complete.
			# continue (not return) so that a TOTP entry later in the list can still succeed.
			hints.add("missing-webauthn-assertion")
			continue

	# On a failed login, indicate failure and any hints for what the user can do instead.
	return (False, list(hints))
