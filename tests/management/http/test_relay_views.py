# Confidence: 82%
#
# HTTP-level tests for management/core/views/relay_views.py
#
# Routes under test:
#   GET  /system/relay  - return current relay configuration
#   POST /system/relay  - save relay configuration
#
# relay_set calls _apply_relay_config which in turn calls Postfix tools or
# the control-plane socket. Both are mocked so no system processes are touched.
# DNS update (do_dns_update) is also mocked.

from unittest.mock import patch


_APPLY_RELAY = "core.views.relay_views._apply_relay_config"
_DNS_UPDATE = "services.dns_update.do_dns_update"


# ---------------------------------------------------------------------------
# GET /system/relay
# ---------------------------------------------------------------------------


def test_get_relay_returns_200(admin_client):
	resp = admin_client.get("/system/relay")
	assert resp.status_code == 200


def test_get_relay_returns_json(admin_client):
	resp = admin_client.get("/system/relay")
	data = resp.get_json()
	assert data is not None


def test_get_relay_has_expected_fields(admin_client):
	resp = admin_client.get("/system/relay")
	data = resp.get_json()
	assert "host" in data
	assert "port" in data
	assert "user" in data
	assert "password_set" in data
	assert "spf_include" in data


def test_get_relay_empty_by_default(admin_client):
	resp = admin_client.get("/system/relay")
	data = resp.get_json()
	assert data["host"] == ""
	assert data["user"] == ""
	assert data["password_set"] is False


# ---------------------------------------------------------------------------
# POST /system/relay - valid config
# ---------------------------------------------------------------------------


def test_post_relay_valid_config_returns_200(admin_client, admin_env):
	with patch(_APPLY_RELAY), patch(_DNS_UPDATE):
		resp = admin_client.post(
			"/system/relay",
			data={
				"host": "smtp.sendgrid.net",
				"port": "587",
				"user": "apikey",
				"password": "SG.testkey",
				"spf_include": "",
			},
		)
	assert resp.status_code == 200


def test_post_relay_stores_config(admin_client, admin_env):
	with patch(_APPLY_RELAY), patch(_DNS_UPDATE):
		admin_client.post(
			"/system/relay",
			data={
				"host": "smtp.mailgun.org",
				"port": "587",
				"user": "mg-user",
				"password": "mg-pass",
				"spf_include": "mailgun.org",
			},
		)
	resp = admin_client.get("/system/relay")
	data = resp.get_json()
	assert data["host"] == "smtp.mailgun.org"
	assert data["port"] == 587
	assert data["user"] == "mg-user"
	assert data["spf_include"] == "mailgun.org"


def test_post_relay_password_not_stored_in_settings(admin_client, admin_env):
	"""Password must never appear in the settings JSON response."""
	with patch(_APPLY_RELAY), patch(_DNS_UPDATE):
		admin_client.post(
			"/system/relay",
			data={
				"host": "smtp.example.com",
				"port": "587",
				"user": "user",
				"password": "super-secret-password",
			},
		)
	resp = admin_client.get("/system/relay")
	assert b"super-secret-password" not in resp.data


def test_post_relay_empty_host_clears_config(admin_client, admin_env):
	"""Posting an empty host removes the relay configuration."""
	with patch(_APPLY_RELAY), patch(_DNS_UPDATE):
		admin_client.post(
			"/system/relay",
			data={
				"host": "smtp.example.com",
				"port": "587",
				"user": "u",
				"password": "p",
			},
		)
		admin_client.post(
			"/system/relay",
			data={
				"host": "",
				"port": "587",
				"user": "",
				"password": "",
			},
		)
	resp = admin_client.get("/system/relay")
	data = resp.get_json()
	assert data["host"] == ""


# ---------------------------------------------------------------------------
# POST /system/relay - validation errors
# ---------------------------------------------------------------------------


def test_post_relay_invalid_host_returns_400(admin_client, admin_env):
	resp = admin_client.post(
		"/system/relay",
		data={
			"host": "bad host!",
			"port": "587",
			"user": "",
			"password": "",
		},
	)
	assert resp.status_code == 400


def test_post_relay_invalid_port_returns_400(admin_client, admin_env):
	resp = admin_client.post(
		"/system/relay",
		data={
			"host": "smtp.example.com",
			"port": "99999",
			"user": "",
			"password": "",
		},
	)
	assert resp.status_code == 400


def test_post_relay_non_numeric_port_returns_400(admin_client, admin_env):
	resp = admin_client.post(
		"/system/relay",
		data={
			"host": "smtp.example.com",
			"port": "notaport",
			"user": "",
			"password": "",
		},
	)
	assert resp.status_code == 400


def test_post_relay_invalid_spf_include_returns_400(admin_client, admin_env):
	resp = admin_client.post(
		"/system/relay",
		data={
			"host": "smtp.example.com",
			"port": "587",
			"user": "",
			"password": "",
			"spf_include": "bad spf!",
		},
	)
	assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Auth enforcement on relay routes
# ---------------------------------------------------------------------------


def test_relay_get_requires_auth(client):
	resp = client.get("/system/relay")
	assert resp.status_code == 401


def test_relay_post_requires_auth(client):
	resp = client.post("/system/relay", data={"host": "smtp.example.com", "port": "587"})
	assert resp.status_code == 401
