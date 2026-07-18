# Confidence: 88%
#
# HTTP-level tests for the API token routes in auth_views.py:
#   GET    /tokens         - list tokens for the caller
#   POST   /tokens         - create a new token
#   DELETE /tokens/<id>    - revoke a token
#
# These routes require full-scope authentication (session or Basic auth).
# A read-scope API token may GET /tokens but cannot POST or DELETE.

from unittest.mock import patch


_TOKEN_KEY_CACHE = "auth.api_tokens._server_key_cache"


def _reset_token_cache():
	import auth.api_tokens as _mod

	_mod._server_key_cache = None


# ---------------------------------------------------------------------------
# POST /tokens - create
# ---------------------------------------------------------------------------


def test_create_token_returns_200(admin_client, admin_env):
	_reset_token_cache()
	resp = admin_client.post("/tokens", data={"name": "ci-token", "scope": "write"})
	assert resp.status_code == 200


def test_create_token_returns_plaintext_token(admin_client, admin_env):
	_reset_token_cache()
	resp = admin_client.post("/tokens", data={"name": "ci-token", "scope": "write"})
	data = resp.get_json()
	assert "token" in data
	assert data["token"].startswith("naust_")


def test_create_token_read_scope(admin_client, admin_env):
	_reset_token_cache()
	resp = admin_client.post("/tokens", data={"name": "read-token", "scope": "read"})
	assert resp.status_code == 200
	data = resp.get_json()
	assert data["token"].startswith("naust_")


def test_create_token_missing_name_returns_400(admin_client, admin_env):
	_reset_token_cache()
	resp = admin_client.post("/tokens", data={"scope": "write"})
	assert resp.status_code == 400


def test_create_token_empty_name_returns_400(admin_client, admin_env):
	_reset_token_cache()
	resp = admin_client.post("/tokens", data={"name": "", "scope": "write"})
	assert resp.status_code == 400


def test_create_token_invalid_scope_returns_400(admin_client, admin_env):
	_reset_token_cache()
	resp = admin_client.post("/tokens", data={"name": "bad-scope", "scope": "superadmin"})
	assert resp.status_code == 400


def test_create_token_name_too_long_returns_400(admin_client, admin_env):
	_reset_token_cache()
	resp = admin_client.post("/tokens", data={"name": "x" * 101, "scope": "write"})
	assert resp.status_code == 400


# ---------------------------------------------------------------------------
# GET /tokens - list
# ---------------------------------------------------------------------------


def test_list_tokens_returns_200(admin_client, admin_env):
	_reset_token_cache()
	resp = admin_client.get("/tokens")
	assert resp.status_code == 200


def test_list_tokens_returns_list(admin_client, admin_env):
	_reset_token_cache()
	resp = admin_client.get("/tokens")
	data = resp.get_json()
	assert isinstance(data, list)


def test_list_tokens_includes_created_token(admin_client, admin_env):
	_reset_token_cache()
	admin_client.post("/tokens", data={"name": "listed-token", "scope": "write"})
	resp = admin_client.get("/tokens")
	data = resp.get_json()
	names = [t["name"] for t in data]
	assert "listed-token" in names


def test_list_tokens_does_not_expose_hash(admin_client, admin_env):
	_reset_token_cache()
	admin_client.post("/tokens", data={"name": "secret-tok", "scope": "write"})
	resp = admin_client.get("/tokens")
	data = resp.get_json()
	for token in data:
		assert "token_hash" not in token
		assert "hash" not in token


def test_list_tokens_has_expected_fields(admin_client, admin_env):
	_reset_token_cache()
	admin_client.post("/tokens", data={"name": "field-check", "scope": "read"})
	resp = admin_client.get("/tokens")
	data = resp.get_json()
	assert len(data) >= 1
	tok = next(t for t in data if t["name"] == "field-check")
	assert "id" in tok
	assert "name" in tok
	assert "scope" in tok
	assert "created_at" in tok
	assert "last_used" in tok


# ---------------------------------------------------------------------------
# DELETE /tokens/<id> - revoke
# ---------------------------------------------------------------------------


def test_revoke_token_returns_200(admin_client, admin_env):
	_reset_token_cache()
	create_resp = admin_client.post("/tokens", data={"name": "to-revoke", "scope": "write"})
	token_id = _get_token_id_by_name(admin_client, "to-revoke")
	resp = admin_client.delete(f"/tokens/{token_id}")
	assert resp.status_code == 200


def test_revoke_token_no_longer_in_list(admin_client, admin_env):
	_reset_token_cache()
	admin_client.post("/tokens", data={"name": "to-delete", "scope": "write"})
	token_id = _get_token_id_by_name(admin_client, "to-delete")
	admin_client.delete(f"/tokens/{token_id}")
	resp = admin_client.get("/tokens")
	data = resp.get_json()
	names = [t["name"] for t in data]
	assert "to-delete" not in names


def test_revoke_nonexistent_token_returns_404(admin_client, admin_env):
	_reset_token_cache()
	resp = admin_client.delete("/tokens/999999")
	assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Scope enforcement on token routes
# ---------------------------------------------------------------------------


def test_read_scope_token_cannot_create_tokens(app, admin_client, admin_env):
	"""A read-scope API token must not be able to create new tokens."""
	_reset_token_cache()
	# Create a read-scope token via Basic auth (full scope).
	create_resp = admin_client.post("/tokens", data={"name": "read-tok", "scope": "read"})
	read_token = create_resp.get_json()["token"]

	c = app.test_client()
	resp = c.post("/tokens", data={"name": "injected", "scope": "write"}, headers={"Authorization": f"Bearer {read_token}"})
	# API tokens cannot create other API tokens (write scope required AND token_scope='full').
	assert resp.status_code in (400, 401, 403)


def test_api_token_cannot_create_other_tokens(app, admin_client, admin_env):
	"""Even a write-scope API token cannot create new tokens (token_scope != 'full')."""
	_reset_token_cache()
	create_resp = admin_client.post("/tokens", data={"name": "write-tok", "scope": "write"})
	write_token = create_resp.get_json()["token"]

	c = app.test_client()
	resp = c.post("/tokens", data={"name": "spawned", "scope": "write"}, headers={"Authorization": f"Bearer {write_token}"})
	assert resp.status_code in (400, 401, 403)


# ---------------------------------------------------------------------------
# Auth enforcement on token routes
# ---------------------------------------------------------------------------


def test_list_tokens_requires_auth(client):
	resp = client.get("/tokens")
	assert resp.status_code == 401


def test_create_token_requires_auth(client):
	resp = client.post("/tokens", data={"name": "t", "scope": "write"})
	assert resp.status_code == 401


def test_revoke_token_requires_auth(client):
	resp = client.delete("/tokens/1")
	assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Write-scope token limitations
# ---------------------------------------------------------------------------
# These routes have explicit `request.token_scope != 'full'` guards beyond the
# normal read/write scope check. Write-scope tokens pass auth but are still
# blocked from a small set of privileged operations.


def test_write_scope_token_can_revoke_itself(app, admin_client, admin_env):
	"""A write-scope token must be allowed to revoke itself."""
	_reset_token_cache()
	create_resp = admin_client.post("/tokens", data={"name": "self-revoke", "scope": "write"})
	plaintext = create_resp.get_json()["token"]
	token_id = _get_token_id_by_name(admin_client, "self-revoke")

	c = app.test_client()
	resp = c.delete(f"/tokens/{token_id}", headers={"Authorization": f"Bearer {plaintext}"})
	assert resp.status_code == 200


def test_write_scope_token_cannot_revoke_different_token(app, admin_client, admin_env):
	"""A write-scope token must not revoke any token other than itself."""
	_reset_token_cache()
	admin_client.post("/tokens", data={"name": "victim-token", "scope": "write"})
	victim_id = _get_token_id_by_name(admin_client, "victim-token")

	create_resp = admin_client.post("/tokens", data={"name": "attacker-token", "scope": "write"})
	attacker_plaintext = create_resp.get_json()["token"]

	c = app.test_client()
	resp = c.delete(f"/tokens/{victim_id}", headers={"Authorization": f"Bearer {attacker_plaintext}"})
	assert resp.status_code == 403

	# Victim token must still be listed.
	list_resp = admin_client.get("/tokens")
	names = [t["name"] for t in list_resp.get_json()]
	assert "victim-token" in names


def test_write_scope_token_cannot_grant_admin_privilege(app, admin_client, admin_env):
	"""Granting admin privilege via /mail/users/privileges/add is blocked for write-scope tokens.
	Adding a regular user is allowed; only the privilege-escalation route is restricted."""
	_reset_token_cache()
	# First add the user via Basic auth (full scope) so the account exists.

	with patch("mail.mailconfig.sync.kick", return_value="ok"), patch("mail.mailconfig.users.dovecot_quota_recalc"):
		admin_client.post("/mail/users/add", data={"email": "privtarget@box.example.com", "password": "Password123!"})

	create_resp = admin_client.post("/tokens", data={"name": "write-priv-tok", "scope": "write"})
	write_token = create_resp.get_json()["token"]

	c = app.test_client()
	resp = c.post("/mail/users/privileges/add", data={"email": "privtarget@box.example.com", "privilege": "admin"}, headers={"Authorization": f"Bearer {write_token}"})
	assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _get_token_id_by_name(admin_client, name: str) -> int:
	resp = admin_client.get("/tokens")
	data = resp.get_json()
	match = next(t for t in data if t["name"] == name)
	return match["id"]
