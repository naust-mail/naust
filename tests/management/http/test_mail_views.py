# Confidence: 87%
#
# HTTP-level tests for management/core/views/mail_views.py
#
# Routes under test:
#   GET  /mail/users          - list users (text or JSON)
#   POST /mail/users/add      - create user
#   POST /mail/users/remove   - delete user
#   GET  /mail/aliases        - list aliases (text or JSON)
#   POST /mail/aliases/add    - create alias
#   POST /mail/aliases/remove - delete alias
#
# External effects mocked:
#   mail.mailconfig.sync.kick              - triggers DNS/web update on user changes
#   mail.mailconfig.users.dovecot_quota_recalc - doveadm subprocess call
#   auth.api_tokens.revoke_all_tokens      - called when a user is removed

from unittest.mock import patch


_KICK = "mail.mailconfig.sync.kick"
_DOVEADM = "mail.mailconfig.users.dovecot_quota_recalc"
_REVOKE_ALL = "auth.api_tokens.revoke_all_tokens"


# ---------------------------------------------------------------------------
# GET /mail/users
# ---------------------------------------------------------------------------


def test_get_mail_users_returns_200(admin_client):
	resp = admin_client.get("/mail/users")
	assert resp.status_code == 200


def test_get_mail_users_text_contains_admin_email(admin_client):
	resp = admin_client.get("/mail/users")
	assert resp.status_code == 200
	text = resp.data.decode()
	assert admin_client.email in text


def test_get_mail_users_json_format_returns_list(admin_client):
	resp = admin_client.get("/mail/users?format=json")
	assert resp.status_code == 200
	data = resp.get_json()
	assert isinstance(data, list)


def test_get_mail_users_json_contains_email_field(admin_client):
	resp = admin_client.get("/mail/users?format=json")
	data = resp.get_json()
	# The JSON format returns domain groupings; emails live in nested structure.
	# Flatten all emails from the response.
	all_emails = []
	for domain_entry in data:
		for user in domain_entry.get("users", []):
			all_emails.append(user.get("email", ""))
	assert admin_client.email in all_emails


# ---------------------------------------------------------------------------
# POST /mail/users/add
# ---------------------------------------------------------------------------


def test_add_mail_user_success_returns_200(admin_client, admin_env):
	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		resp = admin_client.post(
			"/mail/users/add",
			data={
				"email": "newuser@box.example.com",
				"password": "StrongPass99!",
				"privileges": "",
			},
		)
	assert resp.status_code == 200


def test_add_mail_user_appears_in_list_after_creation(admin_client, admin_env):
	new_email = "listeduser@box.example.com"
	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		admin_client.post(
			"/mail/users/add",
			data={
				"email": new_email,
				"password": "StrongPass99!",
				"privileges": "",
			},
		)
	resp = admin_client.get("/mail/users")
	assert new_email in resp.data.decode()


def test_add_mail_user_duplicate_returns_4xx(admin_client, admin_env):
	data = {
		"email": "dup@box.example.com",
		"password": "StrongPass99!",
		"privileges": "",
	}
	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		admin_client.post("/mail/users/add", data=data)
		resp = admin_client.post("/mail/users/add", data=data)
	assert 400 <= resp.status_code < 500


def test_add_mail_user_weak_password_returns_400(admin_client, admin_env):
	resp = admin_client.post(
		"/mail/users/add",
		data={
			"email": "weakpw@box.example.com",
			"password": "abc",
			"privileges": "",
		},
	)
	assert resp.status_code == 400


def test_add_mail_user_invalid_email_returns_400(admin_client, admin_env):
	resp = admin_client.post(
		"/mail/users/add",
		data={
			"email": "not-an-email",
			"password": "StrongPass99!",
			"privileges": "",
		},
	)
	assert resp.status_code == 400


def test_add_mail_user_missing_email_returns_400(admin_client, admin_env):
	resp = admin_client.post(
		"/mail/users/add",
		data={
			"password": "StrongPass99!",
			"privileges": "",
		},
	)
	assert resp.status_code == 400


# ---------------------------------------------------------------------------
# POST /mail/users/remove
# ---------------------------------------------------------------------------


def test_remove_mail_user_success(admin_client, admin_env):
	target = "removeme@box.example.com"
	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		admin_client.post(
			"/mail/users/add",
			data={
				"email": target,
				"password": "StrongPass99!",
				"privileges": "",
			},
		)
	with patch(_KICK, return_value="ok"), patch(_REVOKE_ALL):
		resp = admin_client.post("/mail/users/remove", data={"email": target})
	assert resp.status_code == 200


def test_remove_mail_user_no_longer_in_list(admin_client, admin_env):
	target = "removecheck@box.example.com"
	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		admin_client.post(
			"/mail/users/add",
			data={
				"email": target,
				"password": "StrongPass99!",
				"privileges": "",
			},
		)
	with patch(_KICK, return_value="ok"), patch(_REVOKE_ALL):
		admin_client.post("/mail/users/remove", data={"email": target})
	resp = admin_client.get("/mail/users")
	assert target not in resp.data.decode()


def test_remove_nonexistent_user_returns_4xx(admin_client, admin_env):
	with patch(_KICK, return_value="ok"), patch(_REVOKE_ALL):
		resp = admin_client.post("/mail/users/remove", data={"email": "nobody@box.example.com"})
	assert 400 <= resp.status_code < 500


# ---------------------------------------------------------------------------
# GET /mail/aliases
# ---------------------------------------------------------------------------


def test_get_mail_aliases_returns_200(admin_client):
	resp = admin_client.get("/mail/aliases")
	assert resp.status_code == 200


def test_get_mail_aliases_json_format_returns_list(admin_client):
	resp = admin_client.get("/mail/aliases?format=json")
	assert resp.status_code == 200
	data = resp.get_json()
	assert isinstance(data, list)


# ---------------------------------------------------------------------------
# POST /mail/aliases/add
# ---------------------------------------------------------------------------


def test_add_alias_success_returns_200(admin_client, admin_env):
	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		resp = admin_client.post(
			"/mail/aliases/add",
			data={
				"address": "alias@box.example.com",
				"forwards_to": admin_client.email,
				"permitted_senders": "",
			},
		)
	assert resp.status_code == 200


def test_add_alias_appears_in_list(admin_client, admin_env):
	alias_addr = "visible@box.example.com"
	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		admin_client.post(
			"/mail/aliases/add",
			data={
				"address": alias_addr,
				"forwards_to": admin_client.email,
				"permitted_senders": "",
			},
		)
	resp = admin_client.get("/mail/aliases")
	assert alias_addr in resp.data.decode()


def test_add_alias_json_list_contains_new_alias(admin_client, admin_env):
	alias_addr = "jsonalias@box.example.com"
	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		admin_client.post(
			"/mail/aliases/add",
			data={
				"address": alias_addr,
				"forwards_to": admin_client.email,
				"permitted_senders": "",
			},
		)
	resp = admin_client.get("/mail/aliases?format=json")
	data = resp.get_json()
	all_addresses = []
	for domain_entry in data:
		for alias in domain_entry.get("aliases", []):
			all_addresses.append(alias.get("address", ""))
	assert alias_addr in all_addresses


# ---------------------------------------------------------------------------
# POST /mail/aliases/remove
# ---------------------------------------------------------------------------


def test_remove_alias_success(admin_client, admin_env):
	alias_addr = "toremove@box.example.com"
	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		admin_client.post(
			"/mail/aliases/add",
			data={
				"address": alias_addr,
				"forwards_to": admin_client.email,
				"permitted_senders": "",
			},
		)
		resp = admin_client.post("/mail/aliases/remove", data={"address": alias_addr})
	assert resp.status_code == 200


def test_remove_alias_no_longer_in_list(admin_client, admin_env):
	alias_addr = "gone@box.example.com"
	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		admin_client.post(
			"/mail/aliases/add",
			data={
				"address": alias_addr,
				"forwards_to": admin_client.email,
				"permitted_senders": "",
			},
		)
		admin_client.post("/mail/aliases/remove", data={"address": alias_addr})
	resp = admin_client.get("/mail/aliases")
	assert alias_addr not in resp.data.decode()
