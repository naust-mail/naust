"""
Encryption-at-rest setup ceremony (self-service).

Routes (proxied under /admin/):
  POST /user/encryption/setup      - generate MAIL_KEY + recovery codes, hold uncommitted
  POST /user/encryption/challenge  - prove a recovery code was saved, then commit slots
  GET  /user/encryption/status     - report whether encryption is enabled

The MAIL_KEY is never written to the database until the user proves, via the
challenge, that they copied at least one recovery code. Until then the prepared
(wrapped) slots live only in auth_service.encryption_setups (10 min TTL).

The passkey_prf slot is deferred (WebAuthn PRF is not wired into mfa.py yet), so
has_prf_slot is always false and no PRF slot is created here.
"""

import base64
import hmac
import time

from expiringdict import ExpiringDict

from flask import Blueprint, current_app, request

from core.app_context import env, auth_service
from core.auth_decorators import require_user_route
from core.web_helpers import json_response, sanitize_error_message, validate_email
from mail.mailconfig import open_database, get_mail_password
from mail.mailconfig.users import verify_password
from mail.mailconfig import mail_crypt

bp = Blueprint("encryption", __name__, url_prefix="/user/encryption")

_MAX_CHALLENGE_ATTEMPTS = 3

# Sliding-window rate limit for /relink. Keyed by email; value is a list of
# failure timestamps within the window. Cleared on success. Process-local and
# resets on service restart, which is acceptable given 75-bit code entropy.
# ExpiringDict auto-evicts stale entries so dead keys don't accumulate.
_RELINK_MAX_FAILURES = 5
_RELINK_WINDOW_SECS = 900  # 15 minutes
_relink_failures: ExpiringDict = ExpiringDict(max_len=1024, max_age_seconds=_RELINK_WINDOW_SECS)


def _log_enc_failure() -> None:
	"""Emit a syslog line that the fail2ban naust-encryption jail matches on."""
	ip = request.headers.getlist("X-Forwarded-For")[0] if request.headers.getlist("X-Forwarded-For") else request.remote_addr
	current_app.logger.warning(
		"Naust Management Daemon: Encryption auth failure from ip %s - timestamp %s",
		ip,
		time.time(),
	)


def _relink_rate_exceeded(email: str) -> bool:
	now = time.monotonic()
	window = [t for t in (_relink_failures.get(email) or []) if now - t < _RELINK_WINDOW_SECS]
	_relink_failures[email] = window
	return len(window) >= _RELINK_MAX_FAILURES


def _record_relink_failure(email: str) -> None:
	now = time.monotonic()
	window = [t for t in (_relink_failures.get(email) or []) if now - t < _RELINK_WINDOW_SECS]
	window.append(now)
	_relink_failures[email] = window


@bp.before_request
def _require_feature_enabled():
	"""Gate the whole ceremony on ENCRYPTION_AT_REST. When the box has the feature
	off, these routes behave as if they do not exist so nothing can create key
	slots that Dovecot is not configured to use."""
	if env.get("ENCRYPTION_AT_REST", "false") != "true":
		return ("Encryption at rest is not enabled on this server.", 404)
	return None


def _get_user_id(email):
	conn, c = open_database(env, with_connection=True)
	try:
		c.execute("SELECT id FROM users WHERE email=?", (email,))
		row = c.fetchone()
	finally:
		conn.close()
	if not row:
		raise ValueError("User does not exist.")
	return row[0]


def _slot_rows(user_id):
	"""Return the committed slot types for a user."""
	conn, c = open_database(env, with_connection=True)
	try:
		c.execute("SELECT slot_type FROM mail_keys WHERE user_id=?", (user_id,))
		return [r[0] for r in c.fetchall()]
	finally:
		conn.close()


@bp.route("/status", methods=["GET", "POST"])
@require_user_route
def encryption_status():
	try:
		user_id = _get_user_id(request.user_email)
	except ValueError as e:
		return (sanitize_error_message(str(e)), 400)
	slot_types = _slot_rows(user_id)
	return json_response({
		"enabled": "password" in slot_types,
		"slot_types": sorted(set(slot_types)),
		"has_prf_slot": False,  # passkey_prf deferred until WebAuthn PRF lands
	})


@bp.route("/setup", methods=["POST"])
@require_user_route
def encryption_setup():
	email = request.user_email
	password = request.form.get("password", "")
	if not password:
		return ("Your current password is required to enable encryption.", 400)

	try:
		user_id = _get_user_id(email)
	except ValueError as e:
		return (sanitize_error_message(str(e)), 400)

	# Refuse if a password slot already exists - encryption is already enabled.
	if "password" in _slot_rows(user_id):
		return ("Encryption at rest is already enabled for this account.", 400)

	# Re-authenticate: the password wraps the key slot, so a wrong password here
	# would silently create an unusable password slot.
	try:
		if not verify_password(get_mail_password(email, env), password):
			_log_enc_failure()
			return ("Password is incorrect.", 403)
	except ValueError as e:
		return (sanitize_error_message(str(e)), 400)

	# Build everything in memory. Nothing is persisted until the challenge passes.
	mail_key = mail_crypt.generate_mail_key()
	codes = mail_crypt.generate_recovery_codes()
	prepared = [mail_crypt.build_password_slot(password, mail_key)]
	prepared += mail_crypt.build_recovery_slots(codes, mail_key)

	auth_service.encryption_setups[email] = {"prepared": prepared, "attempts": 0}

	# Recovery codes are returned exactly once and never stored in plaintext.
	return json_response({"recovery_codes": codes})


@bp.route("/challenge", methods=["POST"])
@require_user_route
def encryption_challenge():
	email = request.user_email
	pending = auth_service.encryption_setups.get(email)
	if not pending or pending.get("mode") == "rotation":
		return ("No pending encryption setup. Start again.", 400)

	if pending["attempts"] >= _MAX_CHALLENGE_ATTEMPTS:
		del auth_service.encryption_setups[email]
		return ("Too many incorrect attempts. Start setup again.", 429)

	code = request.form.get("code", "")
	try:
		code_index = int(request.form.get("code_index", ""))
	except (TypeError, ValueError):
		return ("Invalid code index.", 400)

	# Fast client-side-style fail: bad CRC counts as an attempt but skips crypto.
	if not mail_crypt.validate_recovery_code_crc(code):
		_log_enc_failure()
		pending["attempts"] += 1
		auth_service.encryption_setups[email] = pending
		return ("That does not look like a valid recovery code.", 400)

	# Verify the code against the specific recovery slot the frontend asked for.
	recovery_slots = [s for s in pending["prepared"] if s[0] == "recovery_code"]
	target = next((s for s in recovery_slots if s[1] == str(code_index)), None)
	if target is None:
		return ("Invalid code index.", 400)

	# Unwrap MAIL_KEY from the verified slot - needed to generate the keypair.
	try:
		mail_key = mail_crypt.unwrap_prepared_slot(target, code)
	except Exception:
		_log_enc_failure()
		pending["attempts"] += 1
		auth_service.encryption_setups[email] = pending
		remaining = _MAX_CHALLENGE_ATTEMPTS - pending["attempts"]
		return (f"Incorrect recovery code. {max(remaining, 0)} attempt(s) left.", 400)

	# Generate the Dovecot keypair FIRST, password-protected by MAIL_KEY. Only if
	# that succeeds do we commit the slots, so a failure leaves the account in a
	# clean not-enabled state the user can retry (rather than "enabled" with no
	# keypair, which would silently not encrypt).
	try:
		_generate_user_keypair(email, mail_key.hex())
	except Exception as e:
		auth_service.encryption_setups.pop(email, None)
		current_app.logger.error("mailcrypt: keypair generation failed for %s: %s", email, e)
		return ("Could not initialise encryption keys. Please try again.", 500)

	# Commit all prepared slots, then discard the pending state.
	try:
		user_id = _get_user_id(email)
		conn, c = open_database(env, with_connection=True)
		try:
			mail_crypt.insert_prepared_slots(conn, user_id, pending["prepared"])
			conn.commit()
		finally:
			conn.close()
	except ValueError as e:
		return (sanitize_error_message(str(e)), 400)
	finally:
		auth_service.encryption_setups.pop(email, None)

	return json_response({"status": "ok", "enabled": True})


@bp.route("/relink", methods=["POST"])
@require_user_route
def encryption_relink():
	"""Re-establish the password slot from a recovery code.

	After a password change the system could not rotate (admin reset), the
	password slot is stale and login can no longer decrypt. The user supplies a
	recovery code and their current password; we unwrap MAIL_KEY via the code and
	re-wrap a fresh password slot under the current password. Recovery codes and
	the mail_crypt keypair are untouched (the keypair password IS the MAIL_KEY,
	which never changes)."""
	email = request.user_email

	if _relink_rate_exceeded(email):
		return ("Too many failed attempts. Try again later.", 429)

	code = request.form.get("code", "")
	password = request.form.get("password", "")
	if not code or not password:
		return ("Recovery code and current password are required.", 400)
	if not mail_crypt.validate_recovery_code_crc(code):
		_log_enc_failure()
		_record_relink_failure(email)
		return ("That does not look like a valid recovery code.", 400)

	# Verify the current password so the new slot is wrapped under the real login
	# password (otherwise future logins still would not decrypt).
	try:
		if not verify_password(get_mail_password(email, env), password):
			_log_enc_failure()
			_record_relink_failure(email)
			return ("Current password is incorrect.", 403)
	except ValueError as e:
		return (sanitize_error_message(str(e)), 400)

	try:
		user_id = _get_user_id(email)
	except ValueError as e:
		return (sanitize_error_message(str(e)), 400)
	if "recovery_code" not in _slot_rows(user_id):
		return ("Encryption is not enabled for this account.", 400)

	conn, c = open_database(env, with_connection=True)
	try:
		mail_crypt.relink_password_slot(conn, user_id, code, password)
		conn.commit()
	except ValueError:
		_log_enc_failure()
		_record_relink_failure(email)
		return ("Recovery code did not match. Check it and try again.", 400)
	finally:
		conn.close()

	_relink_failures.pop(email, None)
	current_app.logger.info("mailcrypt: password slot re-linked for %s", email)
	return json_response({"status": "ok"})


@bp.route("/rotate-recovery", methods=["POST"])
@require_user_route
def encryption_rotate_recovery():
	"""Start a recovery-code rotation ceremony.

	Unwraps MAIL_KEY with the current password, generates 4 new codes, and holds
	them pending until /rotate-recovery-confirm proves the user copied them.
	Old codes remain valid in the database until confirm succeeds."""
	email = request.user_email
	password = request.form.get("password", "")
	if not password:
		return ("Your current password is required.", 400)

	try:
		user_id = _get_user_id(email)
	except ValueError as e:
		return (sanitize_error_message(str(e)), 400)

	if "password" not in _slot_rows(user_id):
		return ("Encryption is not enabled for this account.", 400)

	try:
		if not verify_password(get_mail_password(email, env), password):
			_log_enc_failure()
			return ("Password is incorrect.", 403)
	except ValueError as e:
		return (sanitize_error_message(str(e)), 400)

	conn, c = open_database(env, with_connection=True)
	try:
		mail_key = mail_crypt.unwrap_via_password(conn, user_id, password)
	except ValueError:
		return ("Could not unlock your mail key. Try again.", 400)
	finally:
		conn.close()

	codes = mail_crypt.generate_recovery_codes()
	prepared = mail_crypt.build_recovery_slots(codes, mail_key)
	auth_service.encryption_setups[email] = {
		"prepared": prepared,
		"attempts": 0,
		"mode": "rotation",
	}

	return json_response({"recovery_codes": codes})


@bp.route("/rotate-recovery-confirm", methods=["POST"])
@require_user_route
def encryption_rotate_recovery_confirm():
	"""Complete the recovery-code rotation by verifying the user copied the new codes.

	Validates a challenge code against the pending rotation state, then atomically
	replaces old recovery_code slots in the database."""
	email = request.user_email
	pending = auth_service.encryption_setups.get(email)
	if not pending or pending.get("mode") != "rotation":
		return ("No pending code rotation. Start again.", 400)

	if pending["attempts"] >= _MAX_CHALLENGE_ATTEMPTS:
		del auth_service.encryption_setups[email]
		return ("Too many incorrect attempts. Start again.", 429)

	code = request.form.get("code", "")
	try:
		code_index = int(request.form.get("code_index", ""))
	except (TypeError, ValueError):
		return ("Invalid code index.", 400)

	if not mail_crypt.validate_recovery_code_crc(code):
		_log_enc_failure()
		pending["attempts"] += 1
		auth_service.encryption_setups[email] = pending
		return ("That does not look like a valid recovery code.", 400)

	recovery_slots = [s for s in pending["prepared"] if s[0] == "recovery_code"]
	target = next((s for s in recovery_slots if s[1] == str(code_index)), None)
	if target is None:
		return ("Invalid code index.", 400)

	try:
		mail_crypt.unwrap_prepared_slot(target, code)
	except Exception:
		_log_enc_failure()
		pending["attempts"] += 1
		auth_service.encryption_setups[email] = pending
		remaining = _MAX_CHALLENGE_ATTEMPTS - pending["attempts"]
		return (f"Incorrect recovery code. {max(remaining, 0)} attempt(s) left.", 400)

	try:
		user_id = _get_user_id(email)
		conn, c = open_database(env, with_connection=True)
		try:
			mail_crypt.replace_recovery_prepared(conn, user_id, pending["prepared"])
			conn.commit()
		finally:
			conn.close()
	except ValueError as e:
		return (sanitize_error_message(str(e)), 400)
	finally:
		auth_service.encryption_setups.pop(email, None)

	current_app.logger.info("mailcrypt: recovery slots rotated for %s", email)
	return json_response({"status": "ok"})


def _generate_user_keypair(email: str, mail_key_hex: str) -> None:
	"""Generate the user's mail_crypt EC keypair, password-protected by MAIL_KEY.

	Runs `doveadm mailbox cryptokey generate`. crypt_user_key_curve is set in the
	temp config (not globally) so mail_crypt never auto-generates keys for
	non-opted-in users. The MAIL_KEY is written to a mode-0600 temp config and
	passed via `doveadm -c` so it never appears in process argv.
	"""
	import os
	import subprocess
	import tempfile

	fd, tmppath = tempfile.mkstemp(suffix=".conf", prefix="naust-crypt-")
	try:
		with os.fdopen(fd, "w") as f:
			f.write("dovecot_config_version = 2.4.0\n")
			f.write("!include /etc/dovecot/dovecot.conf\n")
			f.write("crypt_user_key_curve = prime256v1\n")
			f.write(f"crypt_user_key_password = {mail_key_hex}\n")
		result = subprocess.run(
			["doveadm", "-c", tmppath, "mailbox", "cryptokey", "generate", "-u", email, "-U"],
			capture_output=True,
			text=True,
			check=False,
		)
	finally:
		os.unlink(tmppath)

	if result.returncode != 0:
		raise RuntimeError(f"doveadm cryptokey generate failed: {result.stderr.strip()}")


def _caller_has_master_key(req) -> bool:
	"""True only if the request carries the master api.key.

	Accepts the key via the X-Api-Key header (used by the Dovecot Lua passdb,
	which avoids needing base64 in Lua) or via Basic auth username. This gates the
	unwrap endpoint to on-box callers that can read /var/lib/naust/api.key.
	Combined with the requirement that the correct login password unwraps the
	slot, the key is double-gated."""
	header_key = req.headers.get("X-Api-Key", "")
	if header_key and hmac.compare_digest(header_key, auth_service.key):
		return True

	hdr = req.headers.get("Authorization", "")
	if not hdr.startswith("Basic "):
		return False
	try:
		decoded = base64.b64decode(hdr[6:]).decode("utf-8", "ignore")
	except Exception:
		return False
	username = decoded.split(":", 1)[0]
	return hmac.compare_digest(username, auth_service.key)


@bp.route("/unwrap", methods=["POST"])
def encryption_unwrap():
	"""Return the unwrapped MAIL_KEY (hex) for a user, given their login password.

	Called by the Dovecot Lua passdb on 127.0.0.1 during authentication. The
	returned value becomes crypt_user_key_password for the session. Requires the
	master api.key. The password is validated implicitly: a wrong password fails
	the AES-GCM unwrap, so only the correct password yields a key.

	Always returns 200 with mail_key=null for unknown users, users without
	encryption, or a wrong password, so a non-encryption login is unaffected and
	the endpoint is not a user-enumeration oracle. Every call is logged."""
	if not _caller_has_master_key(request):
		return ("Forbidden.", 403)

	user = request.form.get("user", "")
	password = request.form.get("password", "")
	if not user or not password:
		return ("Missing parameters.", 400)

	remote = request.remote_addr
	try:
		email = validate_email(user)
		user_id = _get_user_id(email)
	except ValueError:
		current_app.logger.info("mailcrypt unwrap: unknown user (from %s)", remote)
		return json_response({"status": "ok", "mail_key": None})

	if "password" not in _slot_rows(user_id):
		return json_response({"status": "ok", "mail_key": None})

	conn, c = open_database(env, with_connection=True)
	try:
		mail_key = mail_crypt.unwrap_via_password(conn, user_id, password)
	except ValueError:
		current_app.logger.warning("mailcrypt unwrap: password did not unlock key for %s (from %s)", email, remote)
		return json_response({"status": "ok", "mail_key": None})
	finally:
		conn.close()

	current_app.logger.info("mailcrypt unwrap: key delivered for %s (from %s)", email, remote)
	return json_response({"status": "ok", "mail_key": mail_key.hex()})
