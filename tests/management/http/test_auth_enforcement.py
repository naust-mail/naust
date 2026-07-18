# Confidence: 90%
#
# Tests for authentication enforcement across the management API.
#
# Covers:
#   - Unauthenticated requests to admin-guarded routes return 401
#   - Non-admin users are rejected from admin-only routes
#   - Read-scope API tokens can reach @read_scope routes but not write routes
#   - The /whoami endpoint returns the caller's identity when authenticated

import base64
from unittest.mock import patch

import pytest

_KICK = "mail.mailconfig.sync.kick"
_DOVEADM = "mail.mailconfig.users.dovecot_quota_recalc"
_TOKEN_MOD = "auth.api_tokens"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64_basic(username: str, password: str) -> str:
	return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


def _make_read_token(email: str, env: dict) -> str:
	"""Create a read-scope API token for the given admin user."""
	import auth.api_tokens as _mod

	_mod._server_key_cache = None
	from auth.api_tokens import create_token

	return create_token(email, "read-only-ci", "read", env)


def _make_write_token(email: str, env: dict) -> str:
	"""Create a write-scope API token for the given admin user."""
	import auth.api_tokens as _mod

	_mod._server_key_cache = None
	from auth.api_tokens import create_token

	return create_token(email, "write-ci", "write", env)


# ---------------------------------------------------------------------------
# Unauthenticated requests return 401
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
	"method,path",
	[
		("GET", "/mail/users"),
		("GET", "/mail/aliases"),
		("GET", "/system/relay"),
		("GET", "/whoami"),
		("GET", "/tokens"),
	],
)
def test_unauthenticated_get_returns_401(client, method, path):
	resp = client.get(path)
	assert resp.status_code == 401


def test_unauthenticated_post_mail_users_add_returns_401(client):
	resp = client.post("/mail/users/add", data={"email": "x@example.com", "password": "Password123!"})
	assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Admin routes reject non-admin authenticated users
# ---------------------------------------------------------------------------


def test_non_admin_get_mail_users_returns_401(user_client):
	resp = user_client.get("/mail/users")
	assert resp.status_code == 401


def test_non_admin_get_relay_returns_401(user_client):
	resp = user_client.get("/system/relay")
	assert resp.status_code == 401


def test_non_admin_get_whoami_returns_401(user_client):
	resp = user_client.get("/whoami")
	assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Admin user is accepted
# ---------------------------------------------------------------------------


def test_admin_get_mail_users_returns_200(admin_client):
	resp = admin_client.get("/mail/users")
	assert resp.status_code == 200


def test_admin_whoami_returns_email(admin_client):
	resp = admin_client.get("/whoami")
	assert resp.status_code == 200
	data = resp.get_json()
	assert data["email"] == admin_client.email
	assert "admin" in data["privileges"]


# ---------------------------------------------------------------------------
# Read-scope token: allowed on @read_scope endpoints, blocked on write endpoints
# ---------------------------------------------------------------------------


def test_read_scope_token_can_get_mail_users(app, admin_client, admin_env):
	import auth.api_tokens as _mod

	_mod._server_key_cache = None
	token = _make_read_token(admin_client.email, admin_env)

	c = app.test_client()
	resp = c.get("/mail/users", headers={"Authorization": f"Bearer {token}"})
	assert resp.status_code == 200


def test_read_scope_token_cannot_post_mail_users_add(app, admin_client, admin_env):
	import auth.api_tokens as _mod

	_mod._server_key_cache = None
	token = _make_read_token(admin_client.email, admin_env)

	c = app.test_client()
	resp = c.post("/mail/users/add", data={"email": "new@example.com", "password": "Password123!"}, headers={"Authorization": f"Bearer {token}"})
	# Read-scope token on a write route - should be 401 or 403
	assert resp.status_code in (401, 403)


def test_write_scope_token_can_call_write_endpoint(app, admin_client, admin_env):
	"""A write-scope token is permitted on write endpoints (the call may fail for
	other reasons - e.g. kick() - but auth itself must pass)."""
	import auth.api_tokens as _mod

	_mod._server_key_cache = None
	token = _make_write_token(admin_client.email, admin_env)

	c = app.test_client()
	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		resp = c.post("/mail/users/add", data={"email": "tokenuser@example.com", "password": "Password123!", "privileges": ""}, headers={"Authorization": f"Bearer {token}"})
	# Auth passed - result depends on mailconfig (expect 200 or 4xx, but not 401/403)
	assert resp.status_code not in (401, 403)


def test_read_scope_token_cannot_post_relay(app, admin_client, admin_env):
	import auth.api_tokens as _mod

	_mod._server_key_cache = None
	token = _make_read_token(admin_client.email, admin_env)

	c = app.test_client()
	resp = c.post("/system/relay", data={"host": "smtp.example.com", "port": "587"}, headers={"Authorization": f"Bearer {token}"})
	assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Invalid / malformed credentials
# ---------------------------------------------------------------------------


def test_wrong_password_returns_401(client):
	auth = _b64_basic("admin@box.example.com", "WrongPassword!")
	resp = client.get("/mail/users", headers={"Authorization": auth})
	assert resp.status_code == 401


def test_invalid_bearer_token_returns_401(client):
	resp = client.get("/mail/users", headers={"Authorization": "Bearer naust_fake_token"})
	assert resp.status_code == 401


def test_non_naust_bearer_token_falls_through_to_basic_auth_failure(client):
	# A Bearer token without the naust_ prefix is not a user API token; the auth
	# layer falls through to Basic auth which fails (no Basic credentials).
	resp = client.get("/mail/users", headers={"Authorization": "Bearer not_a_naust_token"})
	assert resp.status_code == 401


# ---------------------------------------------------------------------------
# CSRF gate: cookie-authenticated requests must include X-Requested-With (H3, M1)
# ---------------------------------------------------------------------------


def _cookie_session(app, email: str, password: str):
	"""Log in via /login (Basic auth) and return a test client carrying the session cookie."""
	import base64

	c = app.test_client()
	creds = base64.b64encode(f"{email}:{password}".encode()).decode()
	resp = c.post("/login", headers={"Authorization": f"Basic {creds}"})
	assert resp.status_code == 200, f"/login failed: {resp.get_data(as_text=True)}"
	return c


def test_csrf_gate_blocks_cookie_post_to_admin_route_without_xhr_header(app, admin_client):
	"""Cookie-auth POST to a mutating admin route without X-Requested-With must be blocked.
	Without this header a cross-origin form submission would succeed (CSRF)."""
	c = _cookie_session(app, admin_client.email, admin_client.password)
	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		resp = c.post("/mail/users/add", data={"email": "csrf-victim@box.example.com", "password": "Password123!"})
	# No X-Requested-With on a cookie session - CSRF check fires, request blocked.
	assert resp.status_code in (401, 403)


def test_csrf_gate_allows_cookie_post_with_xhr_header(app, admin_client):
	"""Cookie-auth POST WITH X-Requested-With must be permitted through the CSRF gate."""
	c = _cookie_session(app, admin_client.email, admin_client.password)
	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		resp = c.post("/mail/users/add", data={"email": "legit@box.example.com", "password": "Password123!"}, headers={"X-Requested-With": "XMLHttpRequest"})
	# CSRF gate passes; route may succeed or return 4xx for other reasons but not 401/403.
	assert resp.status_code not in (401, 403)


def test_csrf_on_logout_blocked_without_xhr_header(app, admin_client):
	"""Cookie-session POST to /logout without X-Requested-With must return 403.
	The logout route checks validate_csrf() explicitly and returns 403 directly."""
	c = _cookie_session(app, admin_client.email, admin_client.password)
	resp = c.post("/logout")
	assert resp.status_code == 403


def test_csrf_on_logout_allowed_with_xhr_header(app, admin_client):
	"""Cookie-session POST to /logout WITH X-Requested-With must succeed."""
	c = _cookie_session(app, admin_client.email, admin_client.password)
	resp = c.post("/logout", headers={"X-Requested-With": "XMLHttpRequest"})
	assert resp.status_code == 200
