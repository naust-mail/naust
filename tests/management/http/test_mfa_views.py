# HTTP-level tests for MFA management routes (/mfa/*):
#   M2: Admin cannot disable MFA for another administrator account
#   M4: WebAuthn nonce type isolation (register nonce rejected by authenticate endpoint and vice versa)
#   M6: Non-admin /mfa/status is always scoped to the caller, not an arbitrary user= param

import secrets

from unittest.mock import patch

_KICK = "mail.mailconfig.sync.kick"
_DOVEADM = "mail.mailconfig.users.dovecot_quota_recalc"


# ---------------------------------------------------------------------------
# M2: admin cannot disable another admin's MFA
# ---------------------------------------------------------------------------


def test_admin_cannot_disable_mfa_for_other_admin(app, admin_client, admin_env):
	"""POST /mfa/disable with user=<other_admin> must return 403.
	This prevents privilege escalation via MFA removal."""
	admin2_email = "admin2@box.example.com"
	admin2_pw = "Admin2Pass99!"

	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		from mail.mailconfig.users import add_mail_user

		result = add_mail_user(admin2_email, admin2_pw, "admin", "0", admin_env)
	assert not isinstance(result, tuple), f"failed to create admin2: {result}"

	resp = admin_client.post("/mfa/disable", data={"user": admin2_email})
	assert resp.status_code == 403


def test_admin_can_disable_own_mfa(app, admin_client, admin_env):
	"""Admin disabling their own MFA (no MFA enrolled) must not be blocked by the cross-admin guard.
	Should return 400 (no MFA to disable) rather than 403."""
	resp = admin_client.post("/mfa/disable", data={"user": admin_client.email})
	# No MFA was enrolled - disable returns failure, not a 403 privilege error.
	assert resp.status_code != 403


def test_admin_can_disable_non_admin_mfa(app, admin_client, admin_env):
	"""Admin disabling MFA for a non-admin user must succeed (or return 400 if no MFA enrolled),
	not 403."""
	non_admin_email = "plain@box.example.com"
	non_admin_pw = "PlainPass99!"

	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		from mail.mailconfig.users import add_mail_user

		result = add_mail_user(non_admin_email, non_admin_pw, "", "0", admin_env)
	assert not isinstance(result, tuple), f"failed to create non-admin: {result}"

	resp = admin_client.post("/mfa/disable", data={"user": non_admin_email})
	assert resp.status_code != 403


# ---------------------------------------------------------------------------
# M4: WebAuthn nonce type isolation
# ---------------------------------------------------------------------------


def test_register_complete_rejects_authenticate_nonce(app, admin_client, admin_env):
	"""POST /mfa/webauthn/register/complete must return 400 when the nonce
	was issued by the authenticate/begin endpoint (type mismatch)."""
	import core.app_context as _ctx

	nonce = secrets.token_hex(32)
	_ctx.auth_service.webauthn_challenges[nonce] = {
		"state": {"dummy": True},
		"email": admin_client.email,
		"type": "authenticate",  # wrong type for register/complete
	}

	resp = admin_client.post(
		"/mfa/webauthn/register/complete",
		data={
			"nonce": nonce,
			"name": "My Key",
			"credential": "{}",
		},
	)
	assert resp.status_code == 400


def test_authenticate_complete_rejects_register_nonce(app, admin_client, admin_env):
	"""POST /mfa/webauthn/authenticate/complete must return 400 when the nonce
	was issued by the register/begin endpoint (type mismatch)."""
	import core.app_context as _ctx

	nonce = secrets.token_hex(32)
	_ctx.auth_service.webauthn_challenges[nonce] = {
		"state": {"dummy": True},
		"email": admin_client.email,
		"type": "register",  # wrong type for authenticate/complete
	}

	c = app.test_client()
	resp = c.post(
		"/mfa/webauthn/authenticate/complete",
		data={
			"nonce": nonce,
			"credential": "{}",
		},
	)
	assert resp.status_code == 400


def test_authenticate_complete_rejects_missing_nonce(app):
	"""POST /mfa/webauthn/authenticate/complete with an unknown nonce must return 400."""
	c = app.test_client()
	resp = c.post(
		"/mfa/webauthn/authenticate/complete",
		data={
			"nonce": secrets.token_hex(32),
			"credential": "{}",
		},
	)
	assert resp.status_code == 400


# ---------------------------------------------------------------------------
# M6: non-admin /mfa/status is scoped to self
# ---------------------------------------------------------------------------


def test_non_admin_mfa_status_ignores_user_param(app, admin_client, user_client, admin_env):
	"""A non-admin calling POST /mfa/status with user=<admin> must receive their own
	(empty) MFA state, not the admin's. The user= field is silently ignored."""
	import base64
	import pyotp
	from auth.mfa import enable_mfa

	# Give the admin a TOTP credential so their MFA state is non-empty.
	raw_secret = "A" * 20
	secret = base64.b32encode(raw_secret.encode()).decode()[:32]
	code = pyotp.TOTP(secret).now()
	enable_mfa(admin_client.email, "totp", secret, code, "ci-label", admin_env)

	# Non-admin POSTs with user=admin email.
	resp = user_client.post("/mfa/status", data={"user": admin_client.email})
	assert resp.status_code == 200

	data = resp.get_json()
	# Must see own MFA state (empty), not admin's (non-empty).
	assert data["enabled_mfa"] == [], "non-admin must see their own empty MFA state, not the admin's TOTP"
