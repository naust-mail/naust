"""
API token (PAT) management for the admin control panel.

Tokens are formatted as naust_<secret> where secret is 256 bits of entropy. Only
the HMAC-SHA256 of the secret (keyed by a server-side pepper) is stored - never
the plaintext. The plaintext is returned once at creation and never retrievable
again. Because the HMAC is deterministic, verify_token recomputes it and does an
O(1) lookup on the unique token_hash index rather than scanning every row.

Scope is either 'read' (GET-only endpoints) or 'write' (all endpoints except
those explicitly restricted to session/basic auth - see auth_decorators.py).
Tokens cannot create other tokens or grant admin privileges regardless of scope.
"""

import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from mail.mailconfig.database import open_database
from auth.mfa import get_user_id

log = logging.getLogger(__name__)

_server_key_cache = None


def _server_key(env) -> bytes:
	"""Return the server-side pepper used to key the token HMAC. Prefers
	env["SECRET_KEY"]; otherwise a random key is generated once and persisted to
	STORAGE_ROOT/api_token_key.txt (0600) so it survives restarts and is shared
	across calls. Written atomically with O_EXCL so concurrent first-use callers
	cannot clobber each other's key."""
	global _server_key_cache
	if _server_key_cache is not None:
		return _server_key_cache
	key = env.get("SECRET_KEY")
	if key:
		_server_key_cache = key.encode()
		return _server_key_cache
	path = os.path.join(env["STORAGE_ROOT"], "api_token_key.txt")
	try:
		fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
		try:
			os.write(fd, secrets.token_hex(32).encode())
		finally:
			os.close(fd)
	except FileExistsError:
		pass
	with open(path, encoding="utf-8") as f:
		key = f.read().strip()
	if not key:
		raise ValueError("api_token_key.txt is empty")
	_server_key_cache = key.encode()
	return _server_key_cache


def _hash_secret(secret: str, env) -> str:
	return hmac.new(_server_key(env), secret.encode(), hashlib.sha256).hexdigest()


def create_token(email: str, name: str, scope: str, env) -> str:
	"""Generate a new token, store the HMAC of its secret, and return the
	plaintext once. The plaintext is never stored and cannot be recovered."""
	if scope not in ('read', 'write'):
		raise ValueError("scope must be 'read' or 'write'")
	secret = secrets.token_hex(32)
	token_hash = _hash_secret(secret, env)
	conn, c = open_database(env, with_connection=True)
	try:
		c.execute('INSERT INTO api_tokens (user_id, name, token_hash, scope) VALUES (?, ?, ?, ?)', (get_user_id(email, c), name, token_hash, scope))
		conn.commit()
	except sqlite3.IntegrityError as e:
		conn.close()
		raise ValueError("Failed to create token - please try again.") from e
	except sqlite3.OperationalError as e:
		conn.close()
		raise ValueError("Database error while creating token.") from e
	conn.close()
	return f"naust_{secret}"


def list_tokens(email: str, env) -> list:
	"""Return metadata for all tokens owned by this user. Never includes the hash."""
	conn, c = open_database(env, with_connection=True)
	c.execute('SELECT t.id, t.name, t.scope, t.created_at, t.last_used FROM api_tokens t WHERE t.user_id = ?', (get_user_id(email, c),))
	rows = c.fetchall()
	conn.close()
	return [{'id': r[0], 'name': r[1], 'scope': r[2], 'created_at': r[3], 'last_used': r[4]} for r in rows]


def revoke_token(email: str, token_id: int, env) -> bool:
	"""Revoke a single token by id. Scoped to the owner so one admin cannot
	revoke another admin's tokens. Returns True if a row was deleted."""
	conn, c = open_database(env, with_connection=True)
	c.execute('DELETE FROM api_tokens WHERE id = ? AND user_id = ?', (token_id, get_user_id(email, c)))
	deleted = c.rowcount > 0
	conn.commit()
	conn.close()
	return deleted


def revoke_all_tokens(email: str, env) -> None:
	"""Revoke every token for a user. Called on admin demotion and user deletion
	so that stripped access takes effect immediately without waiting for tokens
	to be manually revoked."""
	conn, c = open_database(env, with_connection=True)
	c.execute('DELETE FROM api_tokens WHERE user_id = ?', (get_user_id(email, c),))
	conn.commit()
	conn.close()


def verify_token(plaintext: str, env):
	"""Verify a plaintext token of the form naust_<secret>.

	Returns (email, scope, token_id) on success, None on failure.

	The secret's HMAC is recomputed and matched against the unique token_hash
	index for an O(1) lookup. SQLite's index comparison is not constant-time, but
	the value queried is the full keyed HMAC of a 256-bit secret, so a timing
	side channel reveals nothing useful about an unknown token.

	last_used is updated at most once per 60 seconds to avoid a database write
	on every request when tokens are used for automation."""
	if not plaintext.startswith("naust_"):
		return None
	secret = plaintext[len("naust_") :]
	if not secret:
		return None
	token_hash = _hash_secret(secret, env)
	conn, c = open_database(env, with_connection=True)
	c.execute('SELECT t.id, t.scope, u.email FROM api_tokens t JOIN users u ON t.user_id = u.id WHERE t.token_hash = ?', (token_hash,))
	row = c.fetchone()
	if row is None:
		conn.close()
		return None
	token_id, scope, email = row
	now = datetime.now(timezone.utc)
	fmt = '%Y-%m-%d %H:%M:%S'
	c.execute('UPDATE api_tokens SET last_used = ? WHERE id = ? AND (last_used IS NULL OR last_used < ?)', (now.strftime(fmt), token_id, (now - timedelta(seconds=60)).strftime(fmt)))
	conn.commit()
	conn.close()
	return (email, scope, token_id)
