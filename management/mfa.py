import base64
import hmac
import io
import os
import time
import pyotp
import qrcode

from mailconfig import open_database

def get_user_id(email, c):
	c.execute('SELECT id FROM users WHERE email=?', (email,))
	r = c.fetchone()
	if not r: raise ValueError("User does not exist.")
	return r[0]

def get_mfa_state(email, env):
	c = open_database(env)
	c.execute('SELECT id, type, secret, mru_token, label FROM mfa WHERE user_id=?', (get_user_id(email, c),))
	return [
		{ "id": r[0], "type": r[1], "secret": r[2], "mru_token": r[3], "label": r[4] }
		for r in c.fetchall()
	]

def get_public_mfa_state(email, env):
	mfa_state = get_mfa_state(email, env)
	return [
		{ "id": s["id"], "type": s["type"], "label": s["label"] }
		for s in mfa_state
	]

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

def set_mru_token(email, mfa_id, token, env):
	conn, c = open_database(env, with_connection=True)
	c.execute('UPDATE mfa SET mru_token=? WHERE user_id=? AND id=?', (token, get_user_id(email, c), mfa_id))
	conn.commit()

def disable_mfa(email, mfa_id, env):
	conn, c = open_database(env, with_connection=True)
	if mfa_id is None:
		# Disable all MFA for a user.
		c.execute('DELETE FROM mfa WHERE user_id=?', (get_user_id(email, c),))
	else:
		# Disable a particular MFA mode for a user.
		c.execute('DELETE FROM mfa WHERE user_id=? AND id=?', (get_user_id(email, c), mfa_id))
	conn.commit()
	return c.rowcount > 0

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

			# Replay protection: compare current time-step against the last
			# successfully consumed step. Storing the step index (not the token
			# string) blocks any token from a step that has already been used,
			# including valid-window tokens from adjacent steps.
			current_step = int(time.time()) // 30
			stored_raw = mfa_mode['mru_token']
			stored_step = int(stored_raw) if stored_raw and stored_raw.isdigit() and int(stored_raw) > 1000000 else -1
			if current_step <= stored_step:
				hints.add("invalid-totp-token")
				continue

			# Check the token. valid_window=0 accepts only the current 30s step.
			# Allowing adjacent steps would create a replay gap across step boundaries.
			totp = pyotp.TOTP(mfa_mode["secret"])
			if not totp.verify(token, valid_window=0):
				hints.add("invalid-totp-token")
				continue

			# Atomically consume this step. The UPDATE only succeeds when the stored
			# step is strictly less than current_step, so two concurrent requests with
			# the same token both verify but only one wins (rowcount > 0).
			conn, c = open_database(env, with_connection=True)
			user_id = get_user_id(email, c)
			c.execute(
				"""UPDATE mfa SET mru_token=? WHERE id=? AND user_id=?
				   AND (mru_token IS NULL OR CAST(mru_token AS INTEGER) < ?)""",
				(str(current_step), mfa_mode['id'], user_id, current_step)
			)
			conn.commit()
			if c.rowcount == 0:
				# Another concurrent request already consumed this step.
				hints.add("invalid-totp-token")
				continue

			return (True, [])

	# On a failed login, indicate failure and any hints for what the user can do instead.
	return (False, list(hints))
