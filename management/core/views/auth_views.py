# This blueprint deliberately mixes public and protected routes - you can't
# require a login to use the login route. Routes with no decorator below are
# intentionally public; everything else uses require_admin_route.
#
# PUBLIC: /login, /auth/methods, /logout, /auth/verify
# PROTECTED (admin): /whoami

import collections
import threading
import time

from flask import Blueprint, Response, current_app, make_response, request

from core.app_context import env, auth_service
from core.auth_decorators import require_admin_route, read_scope
from core.web_helpers import json_response, validate_csrf, validate_email, log_failed_login
from mail.mailconfig import get_mail_password, get_mail_user_privileges
from mail.mailconfig.users import verify_password
from auth.auth import _get_dummy_hash

bp = Blueprint("auth", __name__)

# In-memory rate limiter for /auth/verify. This endpoint is not proxied by nginx
# (so fail2ban cannot see it) but is reachable from the Docker internal network,
# where a compromised container could otherwise brute-force mail passwords.
# remote_addr is used as the key rather than X-Forwarded-For because this endpoint
# is never behind a proxy - remote_addr is always the actual TCP peer.
_VERIFY_WINDOW_SECONDS = 60
_VERIFY_MAX_FAILURES = 5
_VERIFY_MAX_IPS = 1000
_verify_failures: collections.OrderedDict[str, list[float]] = collections.OrderedDict()
_verify_lock = threading.Lock()


def _verify_rate_limited(ip: str) -> bool:
	now = time.monotonic()
	cutoff = now - _VERIFY_WINDOW_SECONDS
	with _verify_lock:
		attempts = [t for t in _verify_failures.get(ip, []) if t > cutoff]
		_verify_failures[ip] = attempts
		_verify_failures.move_to_end(ip)
		return len(attempts) >= _VERIFY_MAX_FAILURES


def _verify_record_failure(ip: str) -> None:
	now = time.monotonic()
	cutoff = now - _VERIFY_WINDOW_SECONDS
	with _verify_lock:
		attempts = [t for t in _verify_failures.get(ip, []) if t > cutoff]
		attempts.append(now)
		_verify_failures[ip] = attempts
		_verify_failures.move_to_end(ip)
		if len(_verify_failures) > _VERIFY_MAX_IPS:
			_verify_failures.popitem(last=False)


# Create a session key by checking the username/password in the Authorization header.
@bp.route('/login', methods=["POST"])
def login():
	# Is the caller authorized?
	try:
		email, privs = auth_service.authenticate(request, env, login_only=True)
	except ValueError as e:
		if "missing-totp-token" in str(e):
			# Log this too - a correct password with missing TOTP confirms valid credentials
			# to an attacker and must be rate-limited by fail2ban the same as any bad login.
			log_failed_login(request)
			return json_response({
				"status": "missing-totp-token",
				"reason": str(e),
			})
		# Log the failed login
		log_failed_login(request)
		return json_response({
			"status": "invalid",
			"reason": str(e),
		})

	# Create a session and deliver it as an HttpOnly cookie so the key is
	# never accessible to JavaScript.
	session_key = auth_service.create_session_key(email, env, session_type='login')
	current_app.logger.info("New login session created for %s", email)

	from core.views.spa_views import _build_capabilities

	monitoring = env.get('MONITORING_TOOL', 'none')
	response = make_response(
		json_response({
			"status": "ok",
			"email": email,
			"privileges": privs,
			"monitoringTool": monitoring if monitoring != 'none' else None,
			"capabilities": _build_capabilities(env),
		})
	)
	response.set_cookie(
		'admin_session',
		session_key,
		httponly=True,
		secure=not current_app.debug,
		samesite='Strict',
	)
	return response


@bp.route('/auth/methods')
def auth_methods():
	# Returns the available login paths for an email address.
	# Unknown emails return the password path to avoid account enumeration.
	from auth.mfa import get_public_mfa_state, get_public_webauthn_credentials

	email_raw = request.args.get('email', '')
	try:
		email = validate_email(email_raw)
		mfa_state = get_public_mfa_state(email, env)
		webauthn_creds = get_public_webauthn_credentials(email, env)
	except ValueError:
		return json_response({"paths": ["password"]})

	has_totp = any(m["type"] == "totp" for m in mfa_state)
	has_webauthn = len(webauthn_creds) > 0

	paths = []
	if has_webauthn:
		paths.append("passkey")
	if has_totp:
		paths.append("password+totp")
	if not has_webauthn:
		paths.append("password")

	return json_response({"paths": paths})


@bp.route('/logout', methods=["POST"])
def logout():
	if 'Authorization' not in request.headers and not validate_csrf():
		return Response("Forbidden\n", status=403, mimetype='text/plain')

	if 'Authorization' in request.headers:
		try:
			email, _ = auth_service.authenticate(request, env, logout=True)
			current_app.logger.info("%s logged out", email)
		except ValueError:
			pass
	else:
		cookie_key = request.cookies.get('admin_session', '')
		if cookie_key and cookie_key in auth_service.login_sessions:
			session = auth_service.login_sessions[cookie_key]
			current_app.logger.info("%s logged out (cookie)", session.get('email', 'unknown'))
			del auth_service.login_sessions[cookie_key]

	response = make_response(json_response({"status": "ok"}))
	response.delete_cookie('admin_session', httponly=True, secure=not current_app.debug, samesite='Strict')
	return response


@bp.route('/auth/verify', methods=['POST'])
def auth_verify():
	# Internal credential verification endpoint used by Radicale, FileBrowser,
	# and any other service that needs to authenticate a mail user without going
	# through Dovecot. Not proxied by nginx - only reachable on the internal
	# network (Docker) or localhost (bare metal). No admin session is involved
	# here, by design - that's the whole point of this endpoint.
	client_ip = request.remote_addr or "unknown"
	if _verify_rate_limited(client_ip):
		resp = Response("Too many failed attempts. Try again later.\n", status=429, mimetype='text/plain')
		resp.headers["Retry-After"] = str(_VERIFY_WINDOW_SECONDS)
		return resp

	email = request.form.get('email', '').strip()
	password = request.form.get('password', '')

	if not email or not password:
		_verify_record_failure(client_ip)
		return Response("Missing credentials.\n", status=400, mimetype='text/plain')

	# Constant-time: always run verify even for unknown users.
	try:
		pw_hash = get_mail_password(email, env)
		user_exists = True
	except ValueError:
		pw_hash = _get_dummy_hash()
		user_exists = False

	pw_ok = verify_password(pw_hash, password)

	if not pw_ok or not user_exists:
		_verify_record_failure(client_ip)
		current_app.logger.warning("auth/verify failed for %s", email)
		return Response("Invalid credentials.\n", status=401, mimetype='text/plain')

	privs = get_mail_user_privileges(email, env)
	return json_response({
		"email": email,
		"privileges": privs if not isinstance(privs, tuple) else [],
	})


@bp.route('/whoami')
@read_scope
@require_admin_route
def whoami():
	response = json_response({
		"email": request.user_email,
		"privileges": request.user_privs,
	})
	# X-Admin-Email is read by nginx auth_request_set for trusted-header proxy auth
	# (e.g. Beszel). Never reaches the browser - nginx consumes it internally.
	response.headers['X-Admin-Email'] = request.user_email
	return response


@bp.route('/tokens', methods=['GET'])
@read_scope
@require_admin_route
def list_tokens():
	from auth.api_tokens import list_tokens as _list_tokens

	return json_response(_list_tokens(request.user_email, env))


@bp.route('/tokens', methods=['POST'])
@require_admin_route
def create_token():
	# API tokens may not create other API tokens - only session/basic auth callers can.
	if request.token_scope != 'full':  # noqa: S105 -- access scope label, not a secret
		return ('API tokens cannot create other API tokens.', 403)
	from auth.api_tokens import create_token as _create_token

	name = request.form.get('name', '').strip()
	scope = request.form.get('scope', 'write').strip()
	if not name:
		return ('Token name is required.', 400)
	if len(name) > 100:
		return ('Token name must be 100 characters or fewer.', 400)
	if scope not in ('read', 'write'):
		return ('scope must be read or write.', 400)
	try:
		plaintext = _create_token(request.user_email, name, scope, env)
	except ValueError as e:
		return (str(e), 400)
	return json_response({'token': plaintext})


@bp.route('/tokens/<int:token_id>', methods=['DELETE'])
@require_admin_route
def revoke_token(token_id: int):
	# API tokens can only revoke themselves, not other tokens.
	if request.token_scope != 'full' and request.caller_token_id != token_id:  # noqa: S105 -- access scope label, not a secret
		return ('API tokens can only revoke themselves.', 403)
	from auth.api_tokens import revoke_token as _revoke_token

	if not _revoke_token(request.user_email, token_id, env):
		return ('Token not found.', 404)
	return ('OK', 200)
