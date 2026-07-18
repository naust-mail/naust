"""Integration tests for auth/api_tokens.py.

Tests cover token creation, listing, verification, and revocation.
The server-key cache is reset between tests so each test gets a fresh key
from the tmp_path STORAGE_ROOT rather than a previous test's cached key.
"""

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

_KICK_USERS = "mail.mailconfig.sync.kick"
_DOVEADM = "mail.mailconfig.users.dovecot_quota_recalc"


def _add_user(email, env, pw="Password123!", privs="admin"):
	with patch(_KICK_USERS, return_value="ok"), patch(_DOVEADM):
		from mail.mailconfig.users import add_mail_user

		return add_mail_user(email, pw, privs, "0", env)


@pytest.fixture(autouse=True)
def _reset_server_key_cache():
	"""Clear the module-level key cache before each test so each tmp_path gets its own key."""
	import auth.api_tokens as _mod

	_mod._server_key_cache = None
	yield
	_mod._server_key_cache = None


# ---------------------------------------------------------------------------
# create_token
# ---------------------------------------------------------------------------


def test_create_token_write_scope_returns_naust_prefix(test_db):
	_add_user("tokuser@example.com", test_db)
	from auth.api_tokens import create_token

	token = create_token("tokuser@example.com", "ci-token", "write", test_db)
	assert isinstance(token, str)
	assert token.startswith("naust_")


def test_create_token_read_scope(test_db):
	_add_user("reader@example.com", test_db)
	from auth.api_tokens import create_token

	token = create_token("reader@example.com", "read-token", "read", test_db)
	assert token.startswith("naust_")


def test_create_token_invalid_scope_raises(test_db):
	_add_user("badscope@example.com", test_db)
	from auth.api_tokens import create_token

	with pytest.raises(ValueError, match="scope"):
		create_token("badscope@example.com", "bad", "invalid_scope", test_db)


def test_create_token_plaintext_not_stored(test_db):
	"""The plaintext naust_<secret> must never appear in the database."""
	_add_user("notstore@example.com", test_db)
	from auth.api_tokens import create_token

	token = create_token("notstore@example.com", "tok", "write", test_db)
	secret = token[len("naust_") :]

	import sqlite3

	conn = sqlite3.connect(test_db["STORAGE_ROOT"] + "/mail/db/users.sqlite")
	c = conn.cursor()
	c.execute("SELECT token_hash FROM api_tokens")
	hashes = [row[0] for row in c.fetchall()]
	conn.close()

	assert token not in hashes
	assert secret not in hashes


# ---------------------------------------------------------------------------
# list_tokens
# ---------------------------------------------------------------------------


def test_list_tokens_returns_metadata_without_hash(test_db):
	_add_user("list@example.com", test_db)
	from auth.api_tokens import create_token, list_tokens

	create_token("list@example.com", "my-token", "write", test_db)
	tokens = list_tokens("list@example.com", test_db)
	assert len(tokens) == 1
	t = tokens[0]
	# Must have id, name, scope, created_at, last_used.
	assert "id" in t
	assert "name" in t
	assert "scope" in t
	assert "created_at" in t
	assert "last_used" in t
	# Must NOT expose the hash.
	assert "token_hash" not in t
	assert "hash" not in t


def test_list_tokens_returns_all_tokens_for_user(test_db):
	_add_user("many@example.com", test_db)
	from auth.api_tokens import create_token, list_tokens

	create_token("many@example.com", "tok1", "read", test_db)
	create_token("many@example.com", "tok2", "write", test_db)
	tokens = list_tokens("many@example.com", test_db)
	assert len(tokens) == 2


# ---------------------------------------------------------------------------
# verify_token
# ---------------------------------------------------------------------------


def test_verify_token_returns_email_scope_token_id(test_db):
	_add_user("verify@example.com", test_db)
	from auth.api_tokens import create_token, verify_token

	token = create_token("verify@example.com", "vtok", "write", test_db)
	result = verify_token(token, test_db)
	assert result is not None
	email, scope, token_id = result
	assert email == "verify@example.com"
	assert scope == "write"
	assert isinstance(token_id, int)


def test_verify_token_wrong_secret_returns_none(test_db):
	_add_user("vsec@example.com", test_db)
	from auth.api_tokens import create_token, verify_token

	create_token("vsec@example.com", "tok", "write", test_db)
	result = verify_token("naust_wrongsecret", test_db)
	assert result is None


def test_verify_token_non_naust_format_returns_none(test_db):
	from auth.api_tokens import verify_token

	result = verify_token("not_naust_format_at_all", test_db)
	assert result is None


def test_verify_token_read_scope(test_db):
	_add_user("vread@example.com", test_db)
	from auth.api_tokens import create_token, verify_token

	token = create_token("vread@example.com", "rtok", "read", test_db)
	result = verify_token(token, test_db)
	assert result is not None
	_, scope, _ = result
	assert scope == "read"


# ---------------------------------------------------------------------------
# revoke_token
# ---------------------------------------------------------------------------


def test_revoke_token_makes_verify_return_none(test_db):
	_add_user("revoke@example.com", test_db)
	from auth.api_tokens import create_token, verify_token, revoke_token

	token = create_token("revoke@example.com", "tok", "write", test_db)
	_, _, token_id = verify_token(token, test_db)
	deleted = revoke_token("revoke@example.com", token_id, test_db)
	assert deleted is True
	assert verify_token(token, test_db) is None


def test_revoke_token_returns_false_for_nonexistent(test_db):
	_add_user("notoken@example.com", test_db)
	from auth.api_tokens import revoke_token

	result = revoke_token("notoken@example.com", 99999, test_db)
	assert result is False


# ---------------------------------------------------------------------------
# revoke_all_tokens
# ---------------------------------------------------------------------------


def test_revoke_all_tokens_removes_all_user_tokens(test_db):
	_add_user("revokeall@example.com", test_db)
	from auth.api_tokens import create_token, verify_token, revoke_all_tokens, list_tokens

	tok1 = create_token("revokeall@example.com", "t1", "read", test_db)
	tok2 = create_token("revokeall@example.com", "t2", "write", test_db)

	revoke_all_tokens("revokeall@example.com", test_db)

	assert verify_token(tok1, test_db) is None
	assert verify_token(tok2, test_db) is None
	assert list_tokens("revokeall@example.com", test_db) == []


def test_revoke_all_tokens_does_not_affect_other_users(test_db):
	"""Revoking user A's tokens must not touch user B's tokens."""
	_add_user("user-a@example.com", test_db)
	_add_user("user-b@example.com", test_db)
	from auth.api_tokens import create_token, verify_token, revoke_all_tokens

	tok_a = create_token("user-a@example.com", "a-tok", "write", test_db)
	tok_b = create_token("user-b@example.com", "b-tok", "write", test_db)

	revoke_all_tokens("user-a@example.com", test_db)

	assert verify_token(tok_a, test_db) is None, "user-a token should be gone"
	assert verify_token(tok_b, test_db) is not None, "user-b token must survive"


# ---------------------------------------------------------------------------
# Cross-user isolation
# ---------------------------------------------------------------------------


def test_revoke_token_cannot_revoke_other_users_token(test_db):
	"""The WHERE user_id = ? guard must prevent cross-user revocation."""
	_add_user("owner@example.com", test_db)
	_add_user("attacker@example.com", test_db)
	from auth.api_tokens import create_token, verify_token, revoke_token

	token = create_token("owner@example.com", "victim-tok", "write", test_db)
	_, _, token_id = verify_token(token, test_db)

	# attacker knows the token_id but is a different user.
	deleted = revoke_token("attacker@example.com", token_id, test_db)

	assert deleted is False, "revoke_token must return False for another user's token"
	assert verify_token(token, test_db) is not None, "token must still be valid"


def test_list_tokens_only_returns_own_tokens(test_db):
	"""list_tokens is scoped to the requesting user."""
	_add_user("alice@example.com", test_db)
	_add_user("bob@example.com", test_db)
	from auth.api_tokens import create_token, list_tokens

	create_token("alice@example.com", "alice-tok", "write", test_db)
	create_token("bob@example.com", "bob-tok", "write", test_db)

	alice_tokens = list_tokens("alice@example.com", test_db)
	bob_tokens = list_tokens("bob@example.com", test_db)

	alice_names = {t["name"] for t in alice_tokens}
	bob_names = {t["name"] for t in bob_tokens}

	assert alice_names == {"alice-tok"}, f"alice sees unexpected tokens: {alice_names}"
	assert bob_names == {"bob-tok"}, f"bob sees unexpected tokens: {bob_names}"


# ---------------------------------------------------------------------------
# last_used throttle
# ---------------------------------------------------------------------------


def _read_last_used(test_db, token_id: int) -> str | None:
	db_path = os.path.join(test_db["STORAGE_ROOT"], "mail", "db", "users.sqlite")
	conn = sqlite3.connect(db_path)
	row = conn.execute("SELECT last_used FROM api_tokens WHERE id = ?", (token_id,)).fetchone()
	conn.close()
	return row[0] if row else None


def test_verify_token_sets_last_used_on_first_call(test_db):
	"""last_used must be populated after the first successful verification."""
	_add_user("lu1@example.com", test_db)
	from auth.api_tokens import create_token, verify_token

	token = create_token("lu1@example.com", "tok", "write", test_db)
	_, _, token_id = verify_token(token, test_db)

	assert _read_last_used(test_db, token_id) is not None


def test_verify_token_throttles_last_used_update(test_db):
	"""A second verify within 60 s must NOT update last_used (avoids a write on
	every automated request)."""
	_add_user("lu2@example.com", test_db)
	from auth.api_tokens import create_token, verify_token

	token = create_token("lu2@example.com", "tok", "write", test_db)
	verify_token(token, test_db)
	_, _, token_id = verify_token(token, test_db)
	first_used = _read_last_used(test_db, token_id)

	# Second call immediately after - must not change last_used.
	verify_token(token, test_db)
	second_used = _read_last_used(test_db, token_id)

	assert first_used == second_used, "last_used must not be updated within the throttle window"


def test_verify_token_updates_last_used_after_window(test_db):
	"""A verify more than 60 s after last_used MUST update last_used.
	We fake the stored timestamp rather than sleeping 60 seconds."""
	_add_user("lu3@example.com", test_db)
	from auth.api_tokens import create_token, verify_token

	token = create_token("lu3@example.com", "tok", "write", test_db)
	_, _, token_id = verify_token(token, test_db)

	# Backdate last_used by 61 seconds directly in the DB.
	stale = (datetime.now(timezone.utc) - timedelta(seconds=61)).strftime('%Y-%m-%d %H:%M:%S')
	db_path = os.path.join(test_db["STORAGE_ROOT"], "mail", "db", "users.sqlite")
	conn = sqlite3.connect(db_path)
	conn.execute("UPDATE api_tokens SET last_used = ? WHERE id = ?", (stale, token_id))
	conn.commit()
	conn.close()

	verify_token(token, test_db)
	updated = _read_last_used(test_db, token_id)

	assert updated != stale, "last_used must refresh after the 60-second window expires"


# ---------------------------------------------------------------------------
# _server_key file fallback
# ---------------------------------------------------------------------------


def test_server_key_falls_back_to_file_when_no_secret_key_in_env(test_db):
	"""When SECRET_KEY is absent, _server_key must write+read a key file in
	STORAGE_ROOT and return a stable bytes value."""
	import auth.api_tokens as _mod

	_mod._server_key_cache = None

	env_without_key = {"STORAGE_ROOT": test_db["STORAGE_ROOT"]}
	key = _mod._server_key(env_without_key)

	assert isinstance(key, bytes)
	assert len(key) > 0

	key_path = os.path.join(test_db["STORAGE_ROOT"], "api_token_key.txt")
	assert os.path.exists(key_path), "key file must be created"
	assert oct(os.stat(key_path).st_mode)[-3:] == "600", "key file must be 0600"

	# Second call must return the same bytes (cached or re-read from file).
	_mod._server_key_cache = None
	key2 = _mod._server_key(env_without_key)
	assert key == key2, "key must be stable across cache resets (same file)"

	_mod._server_key_cache = None
