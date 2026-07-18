"""Integration tests for mail/mailconfig/database.py.

Covers initialize_database() and open_database() behaviour including schema,
pragmas, file permissions, and FK cascade rules.
"""

import os
import sqlite3


# ---------------------------------------------------------------------------
# Schema / pragma checks
# ---------------------------------------------------------------------------


def test_all_expected_tables_exist(test_db):
	# Every table created by initialize_database should appear in sqlite_master.
	conn = sqlite3.connect(test_db["STORAGE_ROOT"] + "/mail/db/users.sqlite")
	c = conn.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
	tables = {row[0] for row in c.fetchall()}
	conn.close()

	expected = {"users", "aliases", "auto_aliases", "mfa", "api_tokens", "webauthn_credentials"}
	assert expected.issubset(tables), f"Missing tables: {expected - tables}"


def test_wal_mode_enabled(test_db):
	conn = sqlite3.connect(test_db["STORAGE_ROOT"] + "/mail/db/users.sqlite")
	c = conn.cursor()
	c.execute("PRAGMA journal_mode")
	mode = c.fetchone()[0]
	conn.close()
	assert mode == "wal"


def test_foreign_keys_enabled_via_open_database(test_db):
	from mail.mailconfig.database import open_database

	conn, c = open_database(test_db, with_connection=True)
	c.execute("PRAGMA foreign_keys")
	value = c.fetchone()[0]
	conn.close()
	assert value == 1


def test_database_file_permissions(test_db):
	db_path = test_db["STORAGE_ROOT"] + "/mail/db/users.sqlite"
	stat = os.stat(db_path)
	# Mask to the lower 9 permission bits only.
	perms = stat.st_mode & 0o777
	assert perms == 0o660, f"Expected 0660, got {oct(perms)}"


# ---------------------------------------------------------------------------
# open_database return values
# ---------------------------------------------------------------------------


def test_open_database_without_connection_returns_cursor(test_db):
	from mail.mailconfig.database import open_database

	result = open_database(test_db)
	# Should be a cursor, not a tuple.
	assert isinstance(result, sqlite3.Cursor)


def test_open_database_with_connection_returns_conn_and_cursor(test_db):
	from mail.mailconfig.database import open_database

	result = open_database(test_db, with_connection=True)
	assert isinstance(result, tuple)
	assert len(result) == 2
	conn, c = result
	assert isinstance(conn, sqlite3.Connection)
	assert isinstance(c, sqlite3.Cursor)
	conn.close()


# ---------------------------------------------------------------------------
# FK cascade: deleting a user should cascade to mfa and api_tokens
# ---------------------------------------------------------------------------


def _insert_user(conn, email="test@cascade.example"):
	conn.execute(
		"INSERT INTO users (email, password, privileges, quota) VALUES (?, ?, ?, ?)",
		(email, "{BLF-CRYPT}fakehash", "", "0"),
	)
	conn.commit()
	c = conn.cursor()
	c.execute("SELECT id FROM users WHERE email=?", (email,))
	return c.fetchone()[0]


def test_delete_user_cascades_to_mfa(test_db):
	db_path = test_db["STORAGE_ROOT"] + "/mail/db/users.sqlite"
	conn = sqlite3.connect(db_path)
	conn.execute("PRAGMA foreign_keys = ON")

	user_id = _insert_user(conn)
	conn.execute(
		"INSERT INTO mfa (user_id, type, secret) VALUES (?, ?, ?)",
		(user_id, "totp", "A" * 32),
	)
	conn.commit()

	# Verify the mfa row exists before deletion.
	c = conn.cursor()
	c.execute("SELECT COUNT(*) FROM mfa WHERE user_id=?", (user_id,))
	assert c.fetchone()[0] == 1

	conn.execute("DELETE FROM users WHERE id=?", (user_id,))
	conn.commit()

	c.execute("SELECT COUNT(*) FROM mfa WHERE user_id=?", (user_id,))
	assert c.fetchone()[0] == 0, "MFA row was not cascade-deleted with its user"
	conn.close()


def test_delete_user_cascades_to_api_tokens(test_db):
	db_path = test_db["STORAGE_ROOT"] + "/mail/db/users.sqlite"
	conn = sqlite3.connect(db_path)
	conn.execute("PRAGMA foreign_keys = ON")

	user_id = _insert_user(conn, email="tokenuser@cascade.example")
	conn.execute(
		"INSERT INTO api_tokens (user_id, name, token_hash, scope) VALUES (?, ?, ?, ?)",
		(user_id, "ci-token", "deadbeef" * 8, "read"),
	)
	conn.commit()

	c = conn.cursor()
	c.execute("SELECT COUNT(*) FROM api_tokens WHERE user_id=?", (user_id,))
	assert c.fetchone()[0] == 1

	conn.execute("DELETE FROM users WHERE id=?", (user_id,))
	conn.commit()

	c.execute("SELECT COUNT(*) FROM api_tokens WHERE user_id=?", (user_id,))
	assert c.fetchone()[0] == 0, "api_tokens row was not cascade-deleted with its user"
	conn.close()


def test_delete_user_cascades_to_webauthn_credentials(test_db):
	db_path = test_db["STORAGE_ROOT"] + "/mail/db/users.sqlite"
	conn = sqlite3.connect(db_path)
	conn.execute("PRAGMA foreign_keys = ON")

	user_id = _insert_user(conn, email="passkey@cascade.example")
	conn.execute(
		"INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count) VALUES (?, ?, ?, ?)",
		(user_id, b"credid123", b"pubkey123", 0),
	)
	conn.commit()

	c = conn.cursor()
	c.execute("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=?", (user_id,))
	assert c.fetchone()[0] == 1

	conn.execute("DELETE FROM users WHERE id=?", (user_id,))
	conn.commit()

	c.execute("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=?", (user_id,))
	assert c.fetchone()[0] == 0, "webauthn_credentials row was not cascade-deleted with its user"
	conn.close()


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_initialize_database_is_idempotent(test_db):
	# Calling initialize_database a second time must not raise or destroy data.
	db_path = test_db["STORAGE_ROOT"] + "/mail/db/users.sqlite"
	conn = sqlite3.connect(db_path)
	conn.execute(
		"INSERT INTO users (email, password, privileges, quota) VALUES (?, ?, ?, ?)",
		("keep@example.com", "{BLF-CRYPT}x", "", "0"),
	)
	conn.commit()
	conn.close()

	from mail.mailconfig.database import initialize_database

	initialize_database(test_db)  # should not raise

	conn = sqlite3.connect(db_path)
	c = conn.cursor()
	c.execute("SELECT email FROM users WHERE email='keep@example.com'")
	assert c.fetchone() is not None, "Existing row was destroyed by re-initialization"
	conn.close()
