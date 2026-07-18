# Access control for views. Two ways to apply it:
#
# 1. Per-route decorator (@require_admin_route / @require_user_route) -
#    used by auth_views.py and mfa_views.py, which deliberately mix public and
#    protected routes in the same blueprint and need per-route control.
#
# 2. Blueprint-wide guard (require_admin) - registered once via
#    bp.before_request(require_admin) on blueprints where every single route
#    needs the same admin check (mail, dns, ssl, web, system). New routes
#    added to those blueprints are protected automatically; there's no
#    per-route step to forget.
#
# All forms call resolve_caller(), the single credential-resolution function.
# Auth logic lives in one place; decorators and blueprint guards cannot drift apart.
#
# API token scope enforcement:
# @read_scope marks a route as accessible to read-only tokens. Unannotated routes
# implicitly require write scope - read-only tokens are rejected at the auth layer.

import json
from functools import wraps

from flask import Response, current_app, request

from core.app_context import env, auth_service
from core.web_helpers import validate_csrf, log_failed_login
from mail.mailconfig import get_mail_user_privileges


def read_scope(viewfunc):
	"""Marks a route as accessible to read-only API tokens. Apply before the auth decorator."""
	viewfunc._read_scope = True
	return viewfunc


def _is_read_scope(endpoint: str) -> bool:
	"""Check whether the current endpoint is marked as read-safe."""
	view_func = current_app.view_functions.get(endpoint)
	return getattr(view_func, '_read_scope', False)


def resolve_caller(req):
	"""
	Resolve credentials from the request. Tries in order:
	  1. Bearer token (naust_ prefix) - user API token
	  2. Basic Auth - master API key or legacy basic auth
	  3. HttpOnly admin_session cookie

	Returns (email, privs, scope, error, token_id).
	  scope is 'read', 'write', or 'full' (session/basic auth = full).
	  token_id is the db id of the token when caller authenticated via API token, else None.
	  error is None on success.
	"""
	auth_header = req.headers.get('Authorization', '')

	if auth_header.startswith('Bearer '):
		token = auth_header[7:].strip()
		if token.startswith('naust_'):
			from auth.api_tokens import verify_token

			result = verify_token(token, env)
			if result is None:
				log_failed_login(req)
				return None, [], 'full', 'Invalid API token.', None
			email, scope, token_id = result
			privs = get_mail_user_privileges(email, env)
			if isinstance(privs, tuple):
				return None, [], 'full', 'Account error.', None
			if 'admin' not in privs:
				return None, [], 'full', 'You are not an administrator.', None
			return email, privs, scope, None, token_id

	if auth_header.startswith('Basic '):
		try:
			email, privs = auth_service.authenticate(req, env)
		except ValueError as e:
			log_failed_login(req)
			return None, [], 'full', str(e), None
		if 'admin' not in privs:
			return None, [], 'full', 'You are not an administrator.', None
		return email, privs, 'full', None, None

	# Cookie-based session.
	cookie_key = req.cookies.get('admin_session', '')
	session = auth_service.get_session_by_key_only(cookie_key, env) if cookie_key else None
	if not session:
		return None, [], 'full', 'No authentication provided.', None
	email = session['email']
	privs = get_mail_user_privileges(email, env)
	if isinstance(privs, tuple):
		return None, [], 'full', 'Account error.', None
	if 'admin' not in privs:
		return None, [], 'full', 'You are not an administrator.', None
	# CSRF check only applies to cookie auth - Bearer/Basic callers cannot be
	# targeted by CSRF because the attacker cannot inject those credentials cross-origin.
	if not validate_csrf():
		return None, [], 'full', 'Potential CSRF attack detected.', None
	return email, privs, 'full', None, None


def _resolve_any_user(req):
	"""Like resolve_caller but accepts any authenticated user, not just admins."""
	auth_header = req.headers.get('Authorization', '')

	if auth_header.startswith('Basic '):
		try:
			email, privs = auth_service.authenticate(req, env)
		except ValueError as e:
			log_failed_login(req)
			return None, [], str(e)
		return email, privs, None

	cookie_key = req.cookies.get('admin_session', '')
	session = auth_service.get_session_by_key_only(cookie_key, env) if cookie_key else None
	if not session:
		return None, [], 'No authentication provided.'
	email = session['email']
	privs = get_mail_user_privileges(email, env)
	if isinstance(privs, tuple):
		return None, [], 'Account error.'
	if not validate_csrf():
		return None, [], 'Potential CSRF attack detected.'
	return email, privs, None


def _scope_error(scope: str, endpoint: str):
	"""Return a 403 response if a read-only token is hitting a write-only endpoint."""
	if scope == 'read' and not _is_read_scope(endpoint):
		return _unauthorized_response('This endpoint requires write access.')
	return None


def _unauthorized_response(error):
	status = 401
	headers = {
		'WWW-Authenticate': f'Basic realm="{auth_service.auth_realm}"',
		'X-Reason': error,
	}

	if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
		# Don't issue a 401 to an AJAX request because the user will
		# be prompted for credentials, which is not helpful.
		status = 403
		headers = None

	if request.headers.get('Accept') in {None, "", "*/*"}:
		return Response(error + "\n", status=status, mimetype='text/plain', headers=headers)
	return Response(
		json.dumps({
			"status": "error",
			"reason": error,
		})
		+ "\n",
		status=status,
		mimetype='application/json',
		headers=headers,
	)


def require_admin_route(viewfunc):
	"""Per-route decorator for blueprints that mix public and admin-only routes."""

	@wraps(viewfunc)
	def newview(*args, **kwargs):
		email, privs, scope, error, token_id = resolve_caller(request)
		if error:
			return _unauthorized_response(error)
		err = _scope_error(scope, request.endpoint)
		if err:
			return err
		request.user_email = email
		request.user_privs = privs
		request.token_scope = scope
		request.caller_token_id = token_id
		return viewfunc(*args, **kwargs)

	return newview


def require_user_route(viewfunc):
	"""Per-route decorator requiring any authenticated user (not necessarily admin)."""

	@wraps(viewfunc)
	def newview(*args, **kwargs):
		email, privs, error = _resolve_any_user(request)
		if error:
			return _unauthorized_response(error)
		request.user_email = email
		request.user_privs = privs
		request.token_scope = 'full'  # noqa: S105 -- access scope label, not a secret
		request.caller_token_id = None
		return viewfunc(*args, **kwargs)

	return newview


def require_admin():
	"""Blueprint-wide before_request guard - register with bp.before_request(require_admin)
	on blueprints where every route needs admin privileges. Returning a Response here
	short-circuits the request before the view function runs; returning None lets it
	continue."""
	email, privs, scope, error, token_id = resolve_caller(request)
	if error:
		return _unauthorized_response(error)
	err = _scope_error(scope, request.endpoint)
	if err:
		return err
	request.user_email = email
	request.user_privs = privs
	request.token_scope = scope
	request.caller_token_id = token_id
	return None
