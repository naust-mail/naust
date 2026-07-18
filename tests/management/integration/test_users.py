"""Integration tests for mail/mailconfig/users.py.

All doveadm subprocess calls and kick() (which calls DNS/web update) are mocked
so the tests run without system daemons or network access.
"""

from unittest.mock import patch

import pytest

from passlib.hash import sha512_crypt

# Patch targets used throughout this module.
# kick is imported lazily via `from .sync import kick` inside each function,
# so the correct patch target is the sync module itself.
_KICK = "mail.mailconfig.sync.kick"
_DOVEADM = "mail.mailconfig.users.dovecot_quota_recalc"
# revoke_all_tokens is imported lazily inside remove_mail_user and add_remove_mail_user_privilege.
_REVOKE_ALL = "auth.api_tokens.revoke_all_tokens"


def _add_user(email, env, pw="Password123!", privs="", quota="100M"):
	"""Helper: add a mail user with kick and doveadm mocked out."""
	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		from mail.mailconfig.users import add_mail_user

		result = add_mail_user(email, pw, privs, quota, env)
	return result


# ---------------------------------------------------------------------------
# hash_password / verify_password
# ---------------------------------------------------------------------------


def test_hash_password_produces_blf_crypt_prefix():
	from mail.mailconfig.users import hash_password

	h = hash_password("testpass123")
	assert h.startswith("{BLF-CRYPT}"), f"Expected {{BLF-CRYPT}} prefix, got: {h[:20]}"


def test_verify_password_accepts_blf_crypt_hash():
	from mail.mailconfig.users import hash_password, verify_password

	pw = "CorrectHorse99"
	h = hash_password(pw)
	assert verify_password(h, pw) is True


def test_verify_password_rejects_wrong_password():
	from mail.mailconfig.users import hash_password, verify_password

	h = hash_password("CorrectHorse99")
	assert verify_password(h, "WrongPassword1") is False


def test_verify_password_accepts_legacy_sha512_crypt_hash():
	from mail.mailconfig.users import verify_password

	pw = "LegacyPass123"
	# Construct a valid SHA512-CRYPT hash using passlib directly.
	raw_hash = sha512_crypt.hash(pw)
	dovecot_hash = "{SHA512-CRYPT}" + raw_hash
	assert verify_password(dovecot_hash, pw) is True


def test_verify_password_rejects_wrong_password_against_sha512():
	from mail.mailconfig.users import verify_password

	raw_hash = sha512_crypt.hash("CorrectPass1")
	dovecot_hash = "{SHA512-CRYPT}" + raw_hash
	assert verify_password(dovecot_hash, "WrongPass999") is False


# ---------------------------------------------------------------------------
# add_mail_user
# ---------------------------------------------------------------------------


def test_add_mail_user_succeeds(test_db):
	result = _add_user("user@example.com", test_db)
	# kick returns a string; any non-tuple means success path was reached.
	assert not isinstance(result, tuple), f"Unexpected error: {result}"


def test_add_mail_user_duplicate_returns_error(test_db):
	_add_user("dup@example.com", test_db)
	result = _add_user("dup@example.com", test_db)
	assert isinstance(result, tuple)
	assert result[1] == 400
	assert "already exists" in result[0].lower()


def test_add_mail_user_short_password_raises_value_error(test_db):
	# validate_password raises ValueError which propagates out of add_mail_user.
	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		from mail.mailconfig.users import add_mail_user

		with pytest.raises(ValueError, match="eight characters"):
			add_mail_user("newuser@example.com", "short", "", "100M", test_db)


def test_add_mail_user_uppercase_email_returns_error(test_db):
	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		from mail.mailconfig.users import add_mail_user

		result = add_mail_user("Upper@Example.com", "Password123!", "", "0", test_db)
	assert isinstance(result, tuple)
	assert result[1] == 400


def test_add_mail_user_with_admin_privilege_stores_it(test_db):
	_add_user("admin@example.com", test_db, privs="admin")
	from mail.mailconfig.users import get_mail_user_privileges

	privs = get_mail_user_privileges("admin@example.com", test_db)
	assert "admin" in privs


# ---------------------------------------------------------------------------
# get_mail_password
# ---------------------------------------------------------------------------


def test_get_mail_password_returns_stored_hash(test_db):
	_add_user("pwcheck@example.com", test_db)
	from mail.mailconfig.users import get_mail_password

	h = get_mail_password("pwcheck@example.com", test_db)
	assert h.startswith("{BLF-CRYPT}")


def test_get_mail_password_raises_for_nonexistent_user(test_db):
	from mail.mailconfig.users import get_mail_password

	with pytest.raises(ValueError):
		get_mail_password("ghost@example.com", test_db)


# ---------------------------------------------------------------------------
# set_mail_password
# ---------------------------------------------------------------------------


def test_set_mail_password_updates_hash(test_db):
	_add_user("pwupdate@example.com", test_db)
	from mail.mailconfig.users import set_mail_password, get_mail_password, verify_password

	result = set_mail_password("pwupdate@example.com", "NewPass456!", test_db)
	assert result == "OK"
	h = get_mail_password("pwupdate@example.com", test_db)
	assert verify_password(h, "NewPass456!") is True


def test_set_mail_password_short_password_raises_value_error(test_db):
	# validate_password raises ValueError which propagates out of set_mail_password.
	_add_user("pwshort@example.com", test_db)
	from mail.mailconfig.users import set_mail_password

	with pytest.raises(ValueError, match="eight characters"):
		set_mail_password("pwshort@example.com", "short", test_db)


# ---------------------------------------------------------------------------
# get_mail_users
# ---------------------------------------------------------------------------


def test_get_mail_users_returns_sorted_list_including_test_user(test_db):
	_add_user("list@example.com", test_db)
	from mail.mailconfig.users import get_mail_users

	users = get_mail_users(test_db)
	assert isinstance(users, list)
	assert "list@example.com" in users


# ---------------------------------------------------------------------------
# add_remove_mail_user_privilege
# ---------------------------------------------------------------------------


def test_add_mail_user_privilege(test_db):
	_add_user("priv@example.com", test_db)
	from mail.mailconfig.users import add_remove_mail_user_privilege, get_mail_user_privileges

	result = add_remove_mail_user_privilege("priv@example.com", "admin", "add", test_db)
	assert result == "OK"
	privs = get_mail_user_privileges("priv@example.com", test_db)
	assert "admin" in privs


def test_remove_mail_user_privilege(test_db):
	_add_user("depriv@example.com", test_db, privs="admin")
	# revoke_all_tokens is lazily imported from auth.api_tokens inside the function.
	with patch(_REVOKE_ALL):
		from mail.mailconfig.users import add_remove_mail_user_privilege, get_mail_user_privileges

		result = add_remove_mail_user_privilege("depriv@example.com", "admin", "remove", test_db)
	assert result == "OK"
	privs = get_mail_user_privileges("depriv@example.com", test_db)
	assert "admin" not in privs


def test_removing_admin_revokes_api_tokens(test_db):
	"""When admin privilege is removed, revoke_all_tokens should be called."""
	_add_user("demote@example.com", test_db, privs="admin")
	with patch(_REVOKE_ALL) as mock_revoke:
		from mail.mailconfig.users import add_remove_mail_user_privilege

		add_remove_mail_user_privilege("demote@example.com", "admin", "remove", test_db)
	mock_revoke.assert_called_once_with("demote@example.com", test_db)


# ---------------------------------------------------------------------------
# remove_mail_user
# ---------------------------------------------------------------------------


def test_remove_mail_user_deletes_user(test_db):
	_add_user("gone@example.com", test_db)
	with patch(_KICK, return_value="ok"), patch(_REVOKE_ALL):
		from mail.mailconfig.users import remove_mail_user, get_mail_users

		result = remove_mail_user("gone@example.com", test_db)
	# Should not return a 400 tuple.
	assert not (isinstance(result, tuple) and result[1] == 400)
	from mail.mailconfig.users import get_mail_users

	assert "gone@example.com" not in get_mail_users(test_db)


def test_remove_nonexistent_user_returns_error(test_db):
	with patch(_KICK, return_value="ok"), patch(_REVOKE_ALL):
		from mail.mailconfig.users import remove_mail_user

		result = remove_mail_user("nobody@example.com", test_db)
	assert isinstance(result, tuple)
	assert result[1] == 400


# ---------------------------------------------------------------------------
# End-to-end: token invalidation on user delete / demotion
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_token_key_cache():
	"""Reset the api_tokens server-key cache so each test gets a fresh key."""
	import auth.api_tokens as _mod

	_mod._server_key_cache = None
	yield
	_mod._server_key_cache = None


def test_deleted_user_token_is_invalidated(test_db):
	"""Deleting a user must invalidate their tokens end-to-end (not just call revoke)."""
	_add_user("todelete@example.com", test_db, privs="admin")
	from auth.api_tokens import create_token, verify_token

	token = create_token("todelete@example.com", "ci-tok", "write", test_db)
	assert verify_token(token, test_db) is not None, "token should be valid before delete"

	with patch(_KICK, return_value="ok"):
		from mail.mailconfig.users import remove_mail_user

		remove_mail_user("todelete@example.com", test_db)

	assert verify_token(token, test_db) is None, "token must be invalid after user is deleted"


def test_demoted_admin_token_is_invalidated(test_db):
	"""Removing admin privilege must invalidate all of the user's tokens end-to-end."""
	_add_user("todemote@example.com", test_db, privs="admin")
	from auth.api_tokens import create_token, verify_token

	token = create_token("todemote@example.com", "ci-tok", "write", test_db)
	assert verify_token(token, test_db) is not None, "token should be valid before demotion"

	with patch(_KICK, return_value="ok"):
		from mail.mailconfig.users import add_remove_mail_user_privilege

		add_remove_mail_user_privilege("todemote@example.com", "admin", "remove", test_db)

	assert verify_token(token, test_db) is None, "token must be invalid after admin is removed"
