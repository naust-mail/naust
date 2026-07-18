# Static file serving and the SPA catch-all. Registered last in daemon.py so
# Flask's specificity-based routing always tries every other blueprint's
# routes first - this file's '/<path:path>' is the least specific possible
# rule and must never shadow a real API route.

import json
import os

from flask import Blueprint, make_response, request

from core.app_context import env, auth_service
from auth.bootstrap import has_admin_users
from mail.mailconfig import get_mail_users, get_admins, get_mail_user_privileges
import pathlib

bp = Blueprint("spa", __name__)


# Attempt to get the S3 regions dynamically from boto3, but if that fails (e.g. boto3 not installed), return a comprehensive hardcoded list of major AWS regions.
def get_s3_backup_regions():
	"""
	Safely retrieves AWS S3 regions.
	Defaults to a comprehensive list of major global regions if boto3 is missing.
	"""
	try:
		import boto3

		# Dynamically fetch the absolute newest list from the installed AWS SDK
		regions = boto3.session.Session().get_available_regions('s3')
		if regions:
			return [(r, f"s3.{r}.amazonaws.com") for r in regions]
	except (ImportError, Exception):
		print("Warning: boto3 not available or failed to fetch regions. Using fallback list.")

	# Fallback: A robust list covering all major global AWS regions
	fallback_regions = [
		# North America
		("us-east-1", "s3.us-east-1.amazonaws.com"),  # N. Virginia
		("us-east-2", "s3.us-east-2.amazonaws.com"),  # Ohio
		("us-west-1", "s3.us-west-1.amazonaws.com"),  # N. California
		("us-west-2", "s3.us-west-2.amazonaws.com"),  # Oregon
		("ca-central-1", "s3.ca-central-1.amazonaws.com"),  # Canada Central
		# Europe
		("eu-west-1", "s3.eu-west-1.amazonaws.com"),  # Ireland
		("eu-west-2", "s3.eu-west-2.amazonaws.com"),  # London
		("eu-west-3", "s3.eu-west-3.amazonaws.com"),  # Paris
		("eu-central-1", "s3.eu-central-1.amazonaws.com"),  # Frankfurt
		("eu-north-1", "s3.eu-north-1.amazonaws.com"),  # Stockholm
		# Asia Pacific
		("ap-southeast-1", "s3.ap-southeast-1.amazonaws.com"),  # Singapore
		("ap-southeast-2", "s3.ap-southeast-2.amazonaws.com"),  # Sydney
		("ap-northeast-1", "s3.ap-northeast-1.amazonaws.com"),  # Tokyo
		("ap-northeast-2", "s3.ap-northeast-2.amazonaws.com"),  # Seoul
		("ap-south-1", "s3.ap-south-1.amazonaws.com"),  # Mumbai
		# South America & Middle East
		("sa-east-1", "s3.sa-east-1.amazonaws.com"),  # São Paulo
		("me-south-1", "s3.me-south-1.amazonaws.com"),  # Bahrain
	]
	return fallback_regions


# Outlook autodiscover - must handle POST (Outlook POSTs an XML body).
# Served at both casings since clients vary.
@bp.route('/autodiscover/autodiscover.xml', methods=['GET', 'POST'])
@bp.route('/Autodiscover/Autodiscover.xml', methods=['GET', 'POST'])
def autodiscover():
	from flask import Response

	autodiscover_path = '/var/lib/naust/autodiscover.xml'
	if not os.path.exists(autodiscover_path):
		return ('Autodiscover not configured.', 404)
	xml = pathlib.Path(autodiscover_path).read_text()
	return Response(xml, mimetype='application/xml')


# The Vue SPA's assets live under /static/app/assets/.
@bp.route('/static/<path:filename>')
def static_files(filename):
	from flask import current_app, send_from_directory

	return send_from_directory(current_app.static_folder, filename)


def _build_required_page() -> str:
	return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin Panel - Setup Required</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #f9fafb; --card: #ffffff; --border: #e5e7eb;
    --text: #111827; --muted: #6b7280; --mono-bg: #f3f4f6;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #030712; --card: #111827; --border: #1f2937;
      --text: #f9fafb; --muted: #9ca3af; --mono-bg: #1f2937;
    }
  }
  html, body { min-height: 100vh; background: var(--bg); color: var(--text);
    font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
    font-size: 15px; line-height: 1.6; }
  body { display: flex; align-items: center; justify-content: center; padding: 2rem 1rem; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 16px;
    padding: 2.5rem 2rem; max-width: 440px; width: 100%; }
  .icon { width: 40px; height: 40px; margin-bottom: 1.25rem; color: var(--muted); }
  h1 { font-size: 1.125rem; font-weight: 600; margin-bottom: 0.5rem; }
  p { color: var(--muted); font-size: 0.875rem; margin-bottom: 0.75rem; }
  p:last-child { margin-bottom: 0; }
  code { font-family: ui-monospace, monospace; font-size: 0.8125rem;
    background: var(--mono-bg); padding: 0.15em 0.4em; border-radius: 4px; color: var(--text); }
  .cmd { margin-top: 1.25rem; background: var(--mono-bg); border: 1px solid var(--border);
    border-radius: 8px; padding: 0.75rem 1rem; font-family: ui-monospace, monospace;
    font-size: 0.875rem; color: var(--text); }
</style>
</head>
<body>
<div class="card">
  <svg class="icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
    <path stroke-linecap="round" stroke-linejoin="round" d="M11.42 15.17 17.25 21A2.652 2.652 0 0 0 21 17.25l-5.877-5.877M11.42 15.17l2.496-3.03c.317-.384.74-.626 1.208-.766M11.42 15.17l-4.655 5.653a2.548 2.548 0 1 1-3.586-3.586l5.654-4.654m5.546-4.666A9.004 9.004 0 0 1 21 12a9 9 0 0 1-9 9 9.004 9.004 0 0 1-8.354-5.646" />
  </svg>
  <h1>Admin Panel Not Built</h1>
  <p>The admin frontend has not been compiled for this installation. This can happen after a fresh clone or a failed update.</p>
  <p>Re-run setup to build it:</p>
  <div class="cmd">sudo naust</div>
</div>
</body>
</html>"""


def _build_capabilities(env: dict) -> list[str]:
	caps: list[str] = []
	if env.get('ENCRYPTION_AT_REST', 'false') == 'true':
		caps.append('encryption_at_rest')
	return caps


@bp.route('/', defaults={'path': ''})
@bp.route('/<path:path>')
def spa_fallback(path):
	from flask import current_app

	static_dir = current_app.static_folder
	spa_index = os.path.join(static_dir, 'app', 'index.html')
	if not os.path.exists(spa_index):
		return (
			_build_required_page(),
			503,
			{"Content-Type": "text/html; charset=utf-8"},
		)

	# Check the HttpOnly admin session cookie to determine how much to inject.
	cookie_key = request.cookies.get('admin_session', '')
	session = auth_service.get_session_by_key_only(cookie_key, env) if cookie_key else None

	if session:
		email = session['email']
		privs = get_mail_user_privileges(email, env)
		if isinstance(privs, tuple):
			privs = []

		backup_s3_hosts = get_s3_backup_regions()

		monitoring = env.get('MONITORING_TOOL', 'none')
		init_data = {
			"hostname": env['PRIMARY_HOSTNAME'],
			"authenticated": True,
			"email": email,
			"privileges": privs,
			"noUsersExist": len(get_mail_users(env)) == 0,
			"noAdminsExist": len(get_admins(env)) == 0,
			"backupS3Hosts": backup_s3_hosts,
			"monitoringTool": monitoring if monitoring != 'none' else None,
			"capabilities": _build_capabilities(env),
		}
	else:
		init_data = {
			"hostname": env['PRIMARY_HOSTNAME'],
			"authenticated": False,
			"needsBootstrap": not has_admin_users(env),
		}

	html = pathlib.Path(spa_index).read_text(encoding='utf-8')

	# Escape HTML-special chars so a value containing </script> can never break
	# out of the script tag. This produces valid JSON (unicode escapes are legal).
	config_json = json.dumps(init_data).replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e')
	html = html.replace(
		'<script type="application/json" id="__INIT__"></script>',
		f'<script type="application/json" id="__INIT__">{config_json}</script>',
		1,
	)
	response = make_response(html)
	response.headers['Cache-Control'] = 'no-store'
	response.headers['Vary'] = 'Cookie'
	return response
