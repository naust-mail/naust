"""Integration tests for auth/auth.py - AuthService class.

AuthService.init_system_api_key() reads a key file from disk. We patch that
out with a temporary file so tests don't need /var/lib/naust to exist.
"""

import sqlite3
from unittest.mock import patch, MagicMock

import pytest
import pathlib

_KICK_USERS = "mail.mailconfig.sync.kick"
_DOVEADM = "mail.mailconfig.users.dovecot_quota_recalc"


def _make_auth_service(tmp_path):
	"""Build an AuthService whose API key lives in tmp_path."""
	key_file = str(tmp_path / "api.key")
	import secrets as _secrets

	api_key = _secrets.token_hex(32)
	pathlib.Path(key_file).write_text(api_key)
	from auth.auth import AuthService

	svc = AuthService.__new__(AuthService)
	# Manually init so we can point key_path at tmp_path.
	svc.key_path = key_file
	from datetime import timedelta
	from expiringdict import ExpiringDict

	svc.auth_realm = "Test"
	svc.max_session_duration = timedelta(hours=1)
	svc.init_system_api_key()
	duration = svc.max_session_duration.total_seconds()
	svc.login_sessions = ExpiringDict(max_len=1024, max_age_seconds=duration)
	svc.cookie_sessions = ExpiringDict(max_len=1024, max_age_seconds=60 * 30)
	svc.webauthn_challenges = ExpiringDict(max_len=512, max_age_seconds=300)
	return svc


def _add_user(email, env, pw="Password123!"):
	with patch(_KICK_USERS, return_value="ok"), patch(_DOVEADM):
		from mail.mailconfig.users import add_mail_user

		return add_mail_user(email, pw, "", "0", env)


# ---------------------------------------------------------------------------
# check_user_auth / authenticate helpers
# ---------------------------------------------------------------------------


def _make_request_no_mfa():
	"""Return a fake request object that has no X-Auth-Token header."""
	req = MagicMock()
	req.headers = {}
	return req


def test_check_user_auth_correct_password_does_not_raise(test_db, tmp_path):
	_add_user("authuser@example.com", test_db)
	svc = _make_auth_service(tmp_path)
	req = _make_request_no_mfa()
	# Should not raise.
	svc.check_user_auth("authuser@example.com", "Password123!", req, test_db)


def test_check_user_auth_wrong_password_raises(test_db, tmp_path):
	_add_user("authwrong@example.com", test_db)
	svc = _make_auth_service(tmp_path)
	req = _make_request_no_mfa()
	with pytest.raises(ValueError, match="Incorrect email"):
		svc.check_user_auth("authwrong@example.com", "WrongPassword!", req, test_db)


def test_check_user_auth_nonexistent_user_raises(test_db, tmp_path):
	svc = _make_auth_service(tmp_path)
	req = _make_request_no_mfa()
	with pytest.raises(ValueError, match="Incorrect email"):
		svc.check_user_auth("nobody@example.com", "anything", req, test_db)


def test_auth_wrong_and_nonexistent_both_complete_in_under_five_seconds(test_db, tmp_path):
	"""Both wrong-password and nonexistent-user paths should complete quickly."""
	import time

	_add_user("timeduser@example.com", test_db)
	svc = _make_auth_service(tmp_path)
	req = _make_request_no_mfa()

	start = time.monotonic()
	try:
		svc.check_user_auth("timeduser@example.com", "WrongPassword!", req, test_db)
	except ValueError:
		pass
	elapsed_wrong = time.monotonic() - start

	start = time.monotonic()
	try:
		svc.check_user_auth("ghost@example.com", "anything", req, test_db)
	except ValueError:
		pass
	elapsed_nouser = time.monotonic() - start

	assert elapsed_wrong < 5.0, f"Wrong-password path took {elapsed_wrong:.2f}s"
	assert elapsed_nouser < 5.0, f"Nonexistent-user path took {elapsed_nouser:.2f}s"


# ---------------------------------------------------------------------------
# Password hash auto-upgrade
# ---------------------------------------------------------------------------


def test_sha512_hash_upgraded_to_bcrypt_on_login(test_db, tmp_path):
	"""A user stored with a SHA512-CRYPT hash should have it upgraded on login."""
	from passlib.hash import sha512_crypt

	pw = "Upgrade123!"
	raw = sha512_crypt.hash(pw)
	dovecot_hash = "{SHA512-CRYPT}" + raw

	# Insert the user directly with the legacy hash.
	db_path = test_db["STORAGE_ROOT"] + "/mail/db/users.sqlite"
	conn = sqlite3.connect(db_path)
	conn.execute(
		"INSERT INTO users (email, password, privileges, quota) VALUES (?, ?, ?, ?)",
		("legacy@example.com", dovecot_hash, "", "0"),
	)
	conn.commit()
	conn.close()

	svc = _make_auth_service(tmp_path)
	req = _make_request_no_mfa()
	svc.check_user_auth("legacy@example.com", pw, req, test_db)

	from mail.mailconfig.users import get_mail_password

	new_hash = get_mail_password("legacy@example.com", test_db)
	assert new_hash.startswith("{BLF-CRYPT}"), f"Hash was not upgraded from SHA512 to BLF-CRYPT; got: {new_hash[:30]}"


# ---------------------------------------------------------------------------
# Session creation / retrieval
# ---------------------------------------------------------------------------


def test_create_session_key_returns_unique_keys(test_db, tmp_path):
	_add_user("session@example.com", test_db)
	svc = _make_auth_service(tmp_path)
	key1 = svc.create_session_key("session@example.com", test_db, session_type="login")
	key2 = svc.create_session_key("session@example.com", test_db, session_type="login")
	assert key1 != key2


def test_get_session_returns_stored_session(test_db, tmp_path):
	_add_user("getsess@example.com", test_db)
	svc = _make_auth_service(tmp_path)
	key = svc.create_session_key("getsess@example.com", test_db, session_type="login")
	session = svc.get_session("getsess@example.com", key, "login", test_db)
	assert session is not None
	assert session["email"] == "getsess@example.com"


def test_get_session_wrong_key_returns_none(test_db, tmp_path):
	_add_user("badsess@example.com", test_db)
	svc = _make_auth_service(tmp_path)
	svc.create_session_key("badsess@example.com", test_db, session_type="login")
	result = svc.get_session("badsess@example.com", "completely_wrong_key", "login", test_db)
	assert result is None


def test_get_session_wrong_email_returns_none(test_db, tmp_path):
	_add_user("owner@example.com", test_db)
	svc = _make_auth_service(tmp_path)
	key = svc.create_session_key("owner@example.com", test_db, session_type="login")
	result = svc.get_session("thief@example.com", key, "login", test_db)
	assert result is None


def test_create_session_for_anonymous_raises(test_db, tmp_path):
	svc = _make_auth_service(tmp_path)
	with pytest.raises(ValueError):
		svc.create_session_key(None, test_db, session_type="login")


# ---------------------------------------------------------------------------
# Session invalidation on credential change (H2, M3)
# ---------------------------------------------------------------------------


def test_session_invalidated_when_password_changes(test_db, tmp_path):
	"""Changing a user's password hash must invalidate all outstanding sessions.
	Invariant: attacker holds a stolen session key; victim changes password; key dies."""
	_add_user("pwchange@example.com", test_db)
	svc = _make_auth_service(tmp_path)
	key = svc.create_session_key("pwchange@example.com", test_db, session_type="login")
	assert svc.get_session("pwchange@example.com", key, "login", test_db) is not None

	# Mutate the password hash directly - simulates a password-change operation.
	from passlib.hash import bcrypt as _bcrypt

	new_hash = "{BLF-CRYPT}" + _bcrypt.hash("NewPassword456!")
	db_path = test_db["STORAGE_ROOT"] + "/mail/db/users.sqlite"
	conn = sqlite3.connect(db_path)
	conn.execute("UPDATE users SET password=? WHERE email=?", (new_hash, "pwchange@example.com"))
	conn.commit()
	conn.close()

	result = svc.get_session("pwchange@example.com", key, "login", test_db)
	assert result is None, "session must be invalidated after password change"


def test_session_invalidated_when_mfa_enabled(test_db, tmp_path):
	"""Enabling MFA must invalidate all outstanding sessions.
	Invariant: attacker holds a stolen session; victim adds TOTP; attacker's session dies."""
	_add_user("mfachange@example.com", test_db)
	svc = _make_auth_service(tmp_path)
	key = svc.create_session_key("mfachange@example.com", test_db, session_type="login")
	assert svc.get_session("mfachange@example.com", key, "login", test_db) is not None

	# Enable TOTP - changes get_hash_mfa_state() which changes the password_state_token.
	import base64
	import secrets as _secrets
	import pyotp

	raw_bytes = _secrets.token_bytes(20)
	secret = base64.b32encode(raw_bytes).decode().ljust(32, "A")[:32]
	code = pyotp.TOTP(secret).now()
	from auth.mfa import enable_mfa

	enable_mfa("mfachange@example.com", "totp", secret, code, "ci-label", test_db)

	result = svc.get_session("mfachange@example.com", key, "login", test_db)
	assert result is None, "session must be invalidated after MFA is enabled"
