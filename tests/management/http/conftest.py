# Confidence: 88%
#
# HTTP-level test fixtures for the Flask management API.
#
# Strategy:
#   - core.app_context loads at import time (reads /etc/naust.conf and the
#     api.key file). We patch both before the daemon module is first imported so
#     the module-level singletons (`env`, `auth_service`) are wired to tmp dirs.
#   - After import, we update core.app_context.env in-place so all view modules
#     that do `from core.app_context import env` pick up the test values (they
#     hold a reference to the same dict object).
#   - The daemon `app` is a module-level singleton; once created it is reused
#     across all tests. Each test operates on its own tmp SQLite DB but shares
#     the same Flask app object - this is safe because no DB path is stored on
#     the app itself.
#   - Basic auth with email:password is used for admin_client/user_client.
#     CSRF: `validate_csrf` only applies to cookie sessions; Basic/Bearer callers
#     are exempt. The `check_origin` before_request is satisfied by omitting the
#     Origin header entirely (curl/API style).
#   - External effects (kick, DNS update, relay postconf, etc.) are mocked at
#     the module level in each test file or in the fixtures below.

import base64
import os
import secrets

import pytest
import pathlib

# Patch targets for side-effectful callouts used by mail/relay views.
_KICK = "mail.mailconfig.sync.kick"
_DOVEADM = "mail.mailconfig.users.dovecot_quota_recalc"


def _b64_basic(username: str, password: str) -> str:
	"""Return a Basic auth header value for the given credentials."""
	return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


# ---------------------------------------------------------------------------
# Low-level: bootstrap the app singleton (runs once per session)
# ---------------------------------------------------------------------------


def _ensure_app_imported(tmp_path_factory, api_key: str) -> tuple:
	"""
	Import core.daemon (and therefore core.app_context) with test doubles.

	Returns (app, env_dict, key_file_path).

	Calling this multiple times is safe: after the first call Python's import
	cache means the `with patch(...)` guards are no-ops for the already-imported
	modules, but we still update `core.app_context.env` in place.
	"""
	from unittest.mock import patch

	tmp = tmp_path_factory.mktemp("storage")
	os.makedirs(str(tmp / "mail" / "db"), exist_ok=True)
	# get_mail_users_ex(with_archived=True) scans this directory for archived mailboxes.
	os.makedirs(str(tmp / "mail" / "mailboxes"), exist_ok=True)

	env = {
		"STORAGE_ROOT": str(tmp),
		"PRIMARY_HOSTNAME": "box.example.com",
		"PUBLIC_IP": "1.2.3.4",
	}

	key_file = str(tmp / "api.key")
	pathlib.Path(key_file).write_text(api_key)

	def _fake_auth_init(self):
		from datetime import timedelta
		from expiringdict import ExpiringDict

		self.auth_realm = "Naust Management Server"
		self.key_path = key_file
		self.max_session_duration = timedelta(hours=1)
		self.key = api_key
		duration = self.max_session_duration.total_seconds()
		self.login_sessions = ExpiringDict(max_len=1024, max_age_seconds=duration)
		self.cookie_sessions = ExpiringDict(max_len=1024, max_age_seconds=60 * 30)
		self.webauthn_challenges = ExpiringDict(max_len=512, max_age_seconds=300)

	# These patches only matter on the very first import. On subsequent calls
	# the modules are already cached, but patching is harmless.
	with patch("core.utils.load_environment", return_value=env), patch("auth.auth.AuthService.__init__", _fake_auth_init):
		from core.daemon import app  # noqa: PLC0415 - intentional deferred import

	# Initialize the test DB (creates tables).
	from mail.mailconfig.database import initialize_database  # noqa: PLC0415

	initialize_database(env)

	# Update the module-level env dict in place so view modules that already
	# imported `env` by reference get the test values.
	#
	# IMPORTANT: on the first import, `_ctx.env` IS the same object as our local
	# `env` (because `load_environment` was patched to return it). We must copy
	# the values out BEFORE clearing, otherwise clear() empties our source too
	# and the subsequent update() is a no-op.
	import core.app_context as _ctx  # noqa: PLC0415

	new_values = dict(env)  # snapshot before any mutation
	_ctx.env.clear()
	_ctx.env.update(new_values)
	_ctx.auth_service.key = api_key
	_ctx.auth_service.key_path = key_file
	# Clear any sessions left over from a previous fixture invocation.
	_ctx.auth_service.login_sessions.clear()

	return app, env, key_file


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def _api_key() -> str:
	"""Stable API key for the test session."""
	return secrets.token_hex(32)


@pytest.fixture()
def app(tmp_path_factory, _api_key):
	"""
	Flask test app wired to a fresh SQLite DB in a tmp directory.

	Yields the Flask app object with TESTING=True and debug=True (so the
	'secure' flag is not set on cookies, making them usable in test_client).
	"""
	flask_app, env, _key_file = _ensure_app_imported(tmp_path_factory, _api_key)
	flask_app.config["TESTING"] = True
	flask_app.debug = True
	yield flask_app


@pytest.fixture()
def client(app):
	"""Unauthenticated Flask test client."""
	return app.test_client()


@pytest.fixture()
def admin_env(app):
	"""
	Returns the current env dict after the app fixture has set it up.
	Useful for test code that needs to call mailconfig functions directly.
	"""
	import core.app_context as _ctx  # noqa: PLC0415

	return _ctx.env


@pytest.fixture()
def admin_client(app, admin_env, _api_key):
	"""
	Test client authenticated as an admin user via Basic auth.

	Creates `admin@box.example.com` with admin privileges directly in the DB,
	then returns a FixedAuthClient that injects Basic auth on every request.
	"""
	from unittest.mock import patch  # noqa: PLC0415

	admin_email = "admin@box.example.com"
	admin_pw = "AdminPass99!"

	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		from mail.mailconfig.users import add_mail_user  # noqa: PLC0415

		result = add_mail_user(admin_email, admin_pw, "admin", "0", admin_env)
	assert not isinstance(result, tuple), f"Failed to create admin user: {result}"

	return _BasicAuthClient(app.test_client(), admin_email, admin_pw)


@pytest.fixture()
def user_client(app, admin_env):
	"""
	Test client authenticated as a non-admin user via Basic auth.

	Creates `user@box.example.com` with no admin privileges.
	"""
	from unittest.mock import patch  # noqa: PLC0415

	user_email = "user@box.example.com"
	user_pw = "UserPass99!"

	with patch(_KICK, return_value="ok"), patch(_DOVEADM):
		from mail.mailconfig.users import add_mail_user  # noqa: PLC0415

		result = add_mail_user(user_email, user_pw, "", "0", admin_env)
	assert not isinstance(result, tuple), f"Failed to create regular user: {result}"

	return _BasicAuthClient(app.test_client(), user_email, user_pw)


# ---------------------------------------------------------------------------
# Helper: thin wrapper that injects Basic auth on every request
# ---------------------------------------------------------------------------


class _BasicAuthClient:
	"""Wraps a Flask test client and injects a fixed Basic auth header."""

	def __init__(self, test_client, email: str, password: str):
		self._client = test_client
		self._auth = _b64_basic(email, password)
		self.email = email
		self.password = password

	def _inject(self, kwargs: dict) -> dict:
		headers = dict(kwargs.pop("headers", {}) or {})
		headers.setdefault("Authorization", self._auth)
		kwargs["headers"] = headers
		return kwargs

	def get(self, *args, **kwargs):
		return self._client.get(*args, **self._inject(kwargs))

	def post(self, *args, **kwargs):
		return self._client.post(*args, **self._inject(kwargs))

	def delete(self, *args, **kwargs):
		return self._client.delete(*args, **self._inject(kwargs))

	def put(self, *args, **kwargs):
		return self._client.put(*args, **self._inject(kwargs))
