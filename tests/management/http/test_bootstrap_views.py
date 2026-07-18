# Confidence: 85%
#
# HTTP-level tests for management/core/views/bootstrap_views.py
#
# Routes under test:
#   GET  /bootstrap/status  - unauthenticated; returns {needs_bootstrap: bool}
#   POST /bootstrap/setup   - unauthenticated but gated by:
#                               1. X-Requested-With: XMLHttpRequest header
#                               2. no admin users in DB
#                               3. token file present on disk
#
# The token file is written into STORAGE_ROOT by bootstrap.generate_token().
# bootstrap_views.py calls auth.bootstrap.{has_admin_users, validate_code,
# consume_token, bootstrap_first_admin, _load_token}.
#
# External callouts mocked where needed:
#   - _load_token: patched to control whether a token file "exists"
#   - validate_code: patched to bypass cryptographic token check
#   - consume_token: patched to avoid filesystem writes
# For tests that go through the full code path (generate_token -> submit),
# a real token file is written via generate_token().

from unittest.mock import patch


# The bootstrap module uses module-level globals for attempt tracking.
# Reset them between tests to avoid cross-contamination.
_BOOTSTRAP_MOD = "auth.bootstrap"


def _reset_bootstrap_state():
	import auth.bootstrap as _mod

	_mod._current_uuid = None
	_mod._attempt_count = 0


# ---------------------------------------------------------------------------
# GET /bootstrap/status
# ---------------------------------------------------------------------------


def test_bootstrap_status_returns_200(client):
	resp = client.get("/bootstrap/status")
	assert resp.status_code == 200


def test_bootstrap_status_returns_json(client):
	resp = client.get("/bootstrap/status")
	data = resp.get_json()
	assert data is not None
	assert "needs_bootstrap" in data


def test_bootstrap_status_needs_bootstrap_when_no_admins(client):
	resp = client.get("/bootstrap/status")
	data = resp.get_json()
	assert data["needs_bootstrap"] is True


def test_bootstrap_status_no_bootstrap_needed_after_admin_created(client, admin_client):
	# admin_client fixture creates an admin user; status should now say False.
	resp = client.get("/bootstrap/status")
	data = resp.get_json()
	assert data["needs_bootstrap"] is False


# ---------------------------------------------------------------------------
# POST /bootstrap/setup - header check
# ---------------------------------------------------------------------------


def test_setup_without_xhr_header_returns_404(client, admin_env):
	"""The XHR header guard must return 404 (not 403) to keep the endpoint invisible."""
	resp = client.post(
		"/bootstrap/setup",
		data={
			"code": "ABCD1234",
			"email": "admin@box.example.com",
			"password": "StrongPass99!",
		},
	)
	assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /bootstrap/setup - hard gate: already bootstrapped
# ---------------------------------------------------------------------------


def test_setup_returns_404_when_admin_already_exists(client, admin_client, admin_env):
	"""Once an admin user exists the endpoint must be invisible (404)."""
	resp = client.post(
		"/bootstrap/setup",
		data={
			"code": "ABCD1234",
			"email": "second@box.example.com",
			"password": "StrongPass99!",
		},
		headers={"X-Requested-With": "XMLHttpRequest"},
	)
	assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /bootstrap/setup - no token file on disk
# ---------------------------------------------------------------------------


def test_setup_returns_404_when_no_token_file(client, admin_env):
	"""Without a token file on disk the endpoint must appear to not exist."""
	_reset_bootstrap_state()
	with patch(f"{_BOOTSTRAP_MOD}._load_token", return_value=None):
		resp = client.post(
			"/bootstrap/setup",
			data={
				"code": "ABCD1234",
				"email": "admin@box.example.com",
				"password": "StrongPass99!",
			},
			headers={"X-Requested-With": "XMLHttpRequest"},
		)
	assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /bootstrap/setup - validation: missing fields
# ---------------------------------------------------------------------------


def test_setup_missing_code_returns_400(client, admin_env):
	_reset_bootstrap_state()
	with patch(f"{_BOOTSTRAP_MOD}._load_token", return_value={"uuid": "x", "code": "ABCD1234", "expires": 9999999999}), patch(f"{_BOOTSTRAP_MOD}.has_admin_users", return_value=False):
		resp = client.post("/bootstrap/setup", data={"email": "admin@box.example.com", "password": "StrongPass99!"}, headers={"X-Requested-With": "XMLHttpRequest"})
	assert resp.status_code == 400


def test_setup_missing_email_returns_400(client, admin_env):
	_reset_bootstrap_state()
	with patch(f"{_BOOTSTRAP_MOD}._load_token", return_value={"uuid": "x", "code": "ABCD1234", "expires": 9999999999}), patch(f"{_BOOTSTRAP_MOD}.has_admin_users", return_value=False):
		resp = client.post("/bootstrap/setup", data={"code": "ABCD1234", "password": "StrongPass99!"}, headers={"X-Requested-With": "XMLHttpRequest"})
	assert resp.status_code == 400


def test_setup_missing_password_returns_400(client, admin_env):
	_reset_bootstrap_state()
	with patch(f"{_BOOTSTRAP_MOD}._load_token", return_value={"uuid": "x", "code": "ABCD1234", "expires": 9999999999}), patch(f"{_BOOTSTRAP_MOD}.has_admin_users", return_value=False):
		resp = client.post("/bootstrap/setup", data={"code": "ABCD1234", "email": "admin@box.example.com"}, headers={"X-Requested-With": "XMLHttpRequest"})
	assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /bootstrap/setup - wrong code
# ---------------------------------------------------------------------------


def test_setup_wrong_code_returns_400(client, admin_env):
	_reset_bootstrap_state()
	with patch(f"{_BOOTSTRAP_MOD}._load_token", return_value={"uuid": "x", "code": "ABCD1234", "expires": 9999999999}), patch(f"{_BOOTSTRAP_MOD}.has_admin_users", return_value=False):
		resp = client.post(
			"/bootstrap/setup",
			data={
				"code": "WRONGCOD",
				"email": "admin@box.example.com",
				"password": "StrongPass99!",
			},
			headers={"X-Requested-With": "XMLHttpRequest"},
		)
	assert resp.status_code == 400
	data = resp.get_json()
	assert data["error"] == "invalid_code"
	assert "attempts_remaining" in data


# ---------------------------------------------------------------------------
# POST /bootstrap/setup - successful creation
# ---------------------------------------------------------------------------


def test_setup_success_creates_admin_and_returns_ok(client, admin_env):
	"""Full happy path: generate token, submit correct code, get 200."""
	_reset_bootstrap_state()
	from auth.bootstrap import generate_token

	code, _ = generate_token(admin_env)

	resp = client.post(
		"/bootstrap/setup",
		data={
			"code": code,
			"email": "firstadmin@box.example.com",
			"password": "StrongPass99!",
		},
		headers={"X-Requested-With": "XMLHttpRequest"},
	)
	assert resp.status_code == 200
	data = resp.get_json()
	assert data["status"] == "ok"


def test_setup_success_creates_actual_admin_user(client, admin_env):
	"""After successful bootstrap, the user must exist with admin privileges."""
	_reset_bootstrap_state()
	from auth.bootstrap import generate_token

	code, _ = generate_token(admin_env)

	client.post(
		"/bootstrap/setup",
		data={
			"code": code,
			"email": "realadmin@box.example.com",
			"password": "StrongPass99!",
		},
		headers={"X-Requested-With": "XMLHttpRequest"},
	)

	from mail.mailconfig.users import get_mail_user_privileges

	privs = get_mail_user_privileges("realadmin@box.example.com", admin_env)
	assert "admin" in privs


def test_setup_second_call_after_bootstrap_returns_404(client, admin_env):
	"""After bootstrap completes, a second call must return 404."""
	_reset_bootstrap_state()
	from auth.bootstrap import generate_token

	code, _ = generate_token(admin_env)

	client.post(
		"/bootstrap/setup",
		data={
			"code": code,
			"email": "onlyadmin@box.example.com",
			"password": "StrongPass99!",
		},
		headers={"X-Requested-With": "XMLHttpRequest"},
	)

	# Second attempt - admin now exists, should be 404.
	resp = client.post(
		"/bootstrap/setup",
		data={
			"code": "ANYTHING",
			"email": "second@box.example.com",
			"password": "StrongPass99!",
		},
		headers={"X-Requested-With": "XMLHttpRequest"},
	)
	assert resp.status_code == 404
