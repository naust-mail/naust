#!/usr/local/lib/naust/env/bin/python3
#
# The API can be accessed on the command line, e.g. use `curl` like so:
#    curl --user $(</var/lib/naust/api.key): http://localhost:10222/mail/users
#
# During development, you can start the Naust control panel
# by running this script, e.g.:
#
# service naust stop # stop the system process
# DEBUG=1 management/core/daemon.py
# service naust start # when done debugging, start it up again
#
# This file just assembles the app and registers each resource's routes
# (see core/views/). The actual route handlers live in core/views/*.py,
# shared auth logic in core/auth_decorators.py, and the env/auth_service
# singletons in core/app_context.py.

import contextlib
import os
import os.path
import sys

from flask import Flask, abort, request

# Allow running this file directly as well as importing it as part of the
# management package - both need management/ on sys.path.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import utils
from core.app_context import env, auth_service

# ---------------------------------------------------------------------------
# We may deploy via a symbolic link, which confuses flask's template finding.
me = __file__
with contextlib.suppress(OSError):
	me = os.readlink(__file__)

# Prefer the installed frontend path so the daemon works even if the source
# repo is no longer present. Fall back to the repo-relative path for local dev
# (running daemon.py directly without having run setup).
_INSTALLED_DIST = "/usr/local/share/naust/frontend/dist"
if os.path.isdir(_INSTALLED_DIST):
	static_dir = _INSTALLED_DIST
else:
	repo_root = os.path.dirname(os.path.dirname(os.path.dirname(me)))
	static_dir = os.path.abspath(os.path.join(repo_root, "frontend", "dist"))

app = Flask(__name__, static_folder=static_dir)


# Super simple CSRF protection: require a custom header on state-changing requests.
# In the future, it may be worth implementing proper CSRF tokens, or at least checking the
# Origin/Referer headers, as well as Sec-Fetch-Site (however these are only sent by modern browsers).
@app.before_request
def check_origin():
	if request.method in ('GET', 'HEAD', 'OPTIONS'):
		return
	origin = request.headers.get('Origin', '')
	# Requests with no Origin header are allowed (curl, server-to-server, local API calls).
	# Only reject requests that explicitly send a mismatched Origin header.
	if origin and origin != f'https://{env["PRIMARY_HOSTNAME"]}':
		abort(403)


@app.errorhandler(401)
def unauthorized(error):
	return auth_service.make_unauthorized_response()


@app.errorhandler(500)
def internal_error(error):
	# API callers get a JSON error; browser requests get the static error page.
	if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept', ''):
		from flask import jsonify

		return jsonify({'status': 'error', 'reason': 'Internal server error.'}), 500
	try:
		with open('/var/lib/naust/500.html', encoding='utf-8') as f:
			return f.read(), 500, {'Content-Type': 'text/html; charset=utf-8'}
	except FileNotFoundError:
		pass
	except OSError as e:
		app.logger.error("Could not read 500.html: %s", e)
	return (
		(
			'<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Server error</title></head>'
			'<body style="font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f8f8f8">'
			'<div style="text-align:center"><p style="color:#9b9b9b;font-size:0.9rem">Something went wrong. Check <code>sudo journalctl -u naust</code> for details.</p></div>'
			'</body></html>'
		),
		500,
		{'Content-Type': 'text/html; charset=utf-8'},
	)


# Register each resource's routes. Order matters only for the spa blueprint,
# which has to be last - see the comment in core/views/spa_views.py.
from core.views import auth_views, mail_views, dns_views, ssl_views, mfa_views, encryption_views, web_views, system_views, relay_views, munin_views, bootstrap_views, spa_views

app.register_blueprint(auth_views.bp)
app.register_blueprint(mail_views.bp)
app.register_blueprint(dns_views.bp)
app.register_blueprint(ssl_views.bp)
app.register_blueprint(mfa_views.bp)
app.register_blueprint(encryption_views.bp)
app.register_blueprint(web_views.bp)
app.register_blueprint(system_views.bp)
app.register_blueprint(relay_views.bp)
app.register_blueprint(munin_views.bp)
app.register_blueprint(bootstrap_views.bp)
app.register_blueprint(spa_views.bp)

# Env var bootstrap: if MAILINABOX_BOOTSTRAP_EMAIL and MAILINABOX_BOOTSTRAP_PASSWORD
# are set and no admin users exist, create the first admin at startup.
# This supports automated / Docker installs that bypass the onboarding UI.
# The variables are inert on subsequent restarts once an admin exists.
_bootstrap_email = os.environ.pop('MAILINABOX_BOOTSTRAP_EMAIL', '').strip()
_bootstrap_password = os.environ.pop('MAILINABOX_BOOTSTRAP_PASSWORD', '').strip()
if _bootstrap_email and _bootstrap_password:
	from auth.bootstrap import has_admin_users, bootstrap_first_admin

	if not has_admin_users(env):
		_result = bootstrap_first_admin(_bootstrap_email, _bootstrap_password, env)
		if isinstance(_result, tuple):
			import sys

			print(f"[bootstrap] Failed to create admin from env vars: {_result[0]}", file=sys.stderr)
		else:
			print(f"[bootstrap] Created first admin from env vars: {_bootstrap_email}", file=sys.stderr)
			print("[bootstrap] Remove MAILINABOX_BOOTSTRAP_EMAIL and MAILINABOX_BOOTSTRAP_PASSWORD from your environment.", file=sys.stderr)

if __name__ == '__main__':
	if "DEBUG" in os.environ:
		# Turn on Flask debugging.
		app.debug = True

	if not app.debug:
		app.logger.addHandler(utils.create_syslog_handler())

	# Start the application server. Listens on 127.0.0.1 (IPv4 only).
	app.run(port=10222)
