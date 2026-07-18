# The first route (starting a munin session) uses the normal admin check.
# The other two routes use a *different*, munin-specific cookie (not the
# admin_session cookie) - they can't use require_admin or require_admin_route,
# so this file defines its own decorator for them.

import re
from functools import wraps

from flask import Blueprint, Response, current_app, make_response, request, send_from_directory

from core.app_context import env, auth_service
from core.auth_decorators import require_admin_route
from core import utils
from mail.mailconfig import get_mail_user_privileges

bp = Blueprint("munin", __name__, url_prefix="/munin")


@bp.route('/')
@require_admin_route
def munin_start():
	# Munin pages, static images, and dynamically generated images are served
	# outside of the AJAX API. We'll start with a 'start' API that sets a cookie
	# that subsequent requests will read for authorization. (We don't use cookies
	# for the API to avoid CSRF vulnerabilities.)
	response = make_response("OK")
	response.set_cookie("session", auth_service.create_session_key(request.user_email, env, session_type='cookie'), max_age=60 * 30, secure=True, httponly=True, samesite="Strict")  # 30 minute duration
	return response


def check_request_cookie_for_admin_access():
	session = auth_service.get_session(None, request.cookies.get("session", ""), "cookie", env)
	if not session:
		return False
	privs = get_mail_user_privileges(session["email"], env)
	if not isinstance(privs, list):
		return False
	return "admin" in privs


def authorized_personnel_only_via_cookie(f):
	@wraps(f)
	def g(*args, **kwargs):
		if not check_request_cookie_for_admin_access():
			return Response("Unauthorized", status=403, mimetype='text/plain', headers={})
		return f(*args, **kwargs)

	return g


@bp.route('/<path:filename>')
@authorized_personnel_only_via_cookie
def munin_static_file(filename=""):
	# Proxy the request to static files.
	if filename == "":
		filename = "index.html"
	return send_from_directory("/var/cache/munin/www", filename)


@bp.route('/cgi-graph/<path:filename>')
@authorized_personnel_only_via_cookie
def munin_cgi(filename):
	"""Relay munin cgi dynazoom requests
	/usr/lib/munin/cgi/munin-cgi-graph is a perl cgi script in the munin package
	that is responsible for generating binary png images _and_ associated HTTP
	headers based on parameters in the requesting URL. All output is written
	to stdout which munin_cgi splits into response headers and binary response
	data.
	munin-cgi-graph reads environment variables to determine
	what it should do. It expects a path to be in the env-var PATH_INFO, and a
	querystring to be in the env-var QUERY_STRING.
	munin-cgi-graph has several failure modes. Some write HTTP Status headers and
	others return nonzero exit codes.
	Situating munin_cgi between the user-agent and munin-cgi-graph enables keeping
	the cgi script behind naust's auth mechanisms and avoids additional
	support infrastructure like spawn-fcgi.
	"""

	COMMAND = 'su munin --preserve-environment --shell=/bin/bash -c /usr/lib/munin/cgi/munin-cgi-graph'
	# su changes user, we use the munin user here
	# --preserve-environment retains the environment, which is where Popen's `env` data is
	# --shell=/bin/bash ensures the shell used is bash
	# -c "/usr/lib/munin/cgi/munin-cgi-graph" passes the command to run as munin
	# "%s" is a placeholder for where the request's querystring will be added

	if filename == "":
		return ("a path must be specified", 404)
	if not re.fullmatch(r"[\w.\-/]+", filename) or ".." in filename:
		return ("invalid path", 400)

	query_str = request.query_string.decode("utf-8", 'ignore')

	# Note: this 'env' is the subprocess environment for the CGI call, unrelated
	# to the module-level naust settings 'env' imported above - same name,
	# same as the original code, scoped to this function only.
	cgi_env = {'PATH_INFO': f'/{filename}/', 'REQUEST_METHOD': 'GET', 'QUERY_STRING': query_str}
	code, binout = utils.shell(
		'check_output',
		COMMAND.split(" ", 5),
		# Using a maxsplit of 5 keeps the last arguments together
		env=cgi_env,
		return_bytes=True,
		trap=True,
	)

	if code != 0:
		# nonzero returncode indicates error
		current_app.logger.error("munin_cgi: munin-cgi-graph returned nonzero exit code, %s", code)
		return ("error processing graph image", 500)

	# /usr/lib/munin/cgi/munin-cgi-graph returns both headers and binary png when successful.
	# A double-Windows-style-newline always indicates the end of HTTP headers.
	try:
		headers, image_bytes = binout.split(b'\r\n\r\n', 1)
	except ValueError:
		current_app.logger.error("munin_cgi: malformed response from munin-cgi-graph (missing header separator)")
		return ("error processing graph image", 500)

	# Whitelist of safe headers to prevent header injection attacks
	ALLOWED_HEADERS = {'Content-Type', 'Content-Length', 'Last-Modified', 'Expires', 'Cache-Control', 'Status'}

	response = make_response(image_bytes)
	for line in headers.splitlines():
		try:
			name, value = line.decode("utf8").split(':', 1)
			# Only copy whitelisted headers
			if name.strip() in ALLOWED_HEADERS:
				response.headers[name.strip()] = value.strip()
		except (ValueError, UnicodeDecodeError):
			# Malformed header line, skip it
			current_app.logger.warning("munin_cgi: skipping malformed header line")
			continue

	if 'Status' in response.headers and '404' in response.headers['Status']:
		current_app.logger.warning("munin_cgi: munin-cgi-graph returned 404 status code. PATH_INFO=%s", cgi_env['PATH_INFO'])
	return response
