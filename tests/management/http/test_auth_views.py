# HTTP-level tests for auth routes that don't fit the scope of test_auth_enforcement.py:
#   POST /auth/verify - internal credential check for Radicale/FileBrowser, with rate limiter
#   GET  /auth/methods - login path discovery, must not leak user existence


_KICK = "mail.mailconfig.sync.kick"
_DOVEADM = "mail.mailconfig.users.dovecot_quota_recalc"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clear_verify_failures_for(ip: str) -> None:
	"""Remove any recorded failures for a specific IP so tests don't bleed into each other."""
	from core.views.auth_views import _verify_failures, _verify_lock

	with _verify_lock:
		_verify_failures.pop(ip, None)


# ---------------------------------------------------------------------------
# POST /auth/verify - rate limiter (H1)
# ---------------------------------------------------------------------------


def test_auth_verify_succeeds_for_valid_credentials(app, admin_client, admin_env):
	"""Valid credentials must return 200 with email and privileges."""
	test_ip = "192.168.100.1"
	_clear_verify_failures_for(test_ip)
	c = app.test_client()
	resp = c.post("/auth/verify", data={"email": admin_client.email, "password": admin_client.password}, environ_base={"REMOTE_ADDR": test_ip})
	assert resp.status_code == 200
	data = resp.get_json()
	assert data["email"] == admin_client.email


def test_auth_verify_returns_401_for_wrong_password(app, admin_client, admin_env):
	test_ip = "192.168.100.2"
	_clear_verify_failures_for(test_ip)
	c = app.test_client()
	resp = c.post("/auth/verify", data={"email": admin_client.email, "password": "definitelywrong"}, environ_base={"REMOTE_ADDR": test_ip})
	assert resp.status_code == 401


def test_auth_verify_returns_400_for_missing_credentials(app, admin_env):
	test_ip = "192.168.100.3"
	_clear_verify_failures_for(test_ip)
	c = app.test_client()
	resp = c.post("/auth/verify", data={}, environ_base={"REMOTE_ADDR": test_ip})
	assert resp.status_code == 400


def test_auth_verify_rate_limited_after_five_failures(app, admin_client, admin_env):
	"""After 5 failed attempts from one IP, the 6th must return 429.
	This guards /auth/verify against brute-force from a compromised internal container."""
	test_ip = "192.168.100.10"
	_clear_verify_failures_for(test_ip)
	c = app.test_client()

	for i in range(5):
		resp = c.post("/auth/verify", data={"email": admin_client.email, "password": f"wrong{i}"}, environ_base={"REMOTE_ADDR": test_ip})
		assert resp.status_code in (400, 401), f"attempt {i + 1} should fail, not be rate-limited yet"

	# 6th attempt from the same IP must be rate-limited.
	resp = c.post("/auth/verify", data={"email": admin_client.email, "password": "wrong6"}, environ_base={"REMOTE_ADDR": test_ip})
	assert resp.status_code == 429
	assert "Retry-After" in resp.headers


def test_auth_verify_rate_limit_is_per_ip(app, admin_client, admin_env):
	"""Failures from one IP must not affect a different IP."""
	ip_a = "192.168.100.20"
	ip_b = "192.168.100.21"
	_clear_verify_failures_for(ip_a)
	_clear_verify_failures_for(ip_b)
	c = app.test_client()

	for i in range(5):
		c.post("/auth/verify", data={"email": admin_client.email, "password": "wrong"}, environ_base={"REMOTE_ADDR": ip_a})

	# ip_b has no failures - must not be blocked.
	resp = c.post("/auth/verify", data={"email": admin_client.email, "password": admin_client.password}, environ_base={"REMOTE_ADDR": ip_b})
	assert resp.status_code == 200


# ---------------------------------------------------------------------------
# GET /auth/methods - user-existence non-disclosure (M5)
# ---------------------------------------------------------------------------


def test_auth_methods_unknown_user_returns_password_path(app):
	c = app.test_client()
	resp = c.get("/auth/methods?email=nobody@definitely-does-not-exist.example.com")
	assert resp.status_code == 200
	data = resp.get_json()
	assert data == {"paths": ["password"]}


def test_auth_methods_real_user_no_mfa_matches_unknown_user(app, admin_client, admin_env):
	"""A real admin with no MFA enrolled must return the same structure as an unknown user.
	Structural identity is the anti-enumeration guarantee."""
	c = app.test_client()

	real_resp = c.get(f"/auth/methods?email={admin_client.email}")
	fake_resp = c.get("/auth/methods?email=ghost@definitely-not-real.example.com")

	assert real_resp.status_code == 200
	assert fake_resp.status_code == 200
	assert real_resp.get_json() == fake_resp.get_json()
