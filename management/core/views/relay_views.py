import os
import re

from flask import Blueprint, request

from core import utils
from core.app_context import env
from core.auth_decorators import require_admin, read_scope
from core.web_helpers import json_response, sanitize_error_message
import pathlib

bp = Blueprint("relay", __name__, url_prefix="/system")
bp.before_request(require_admin)

# Strict hostname/IP validation - prevents newline injection into postconf -e values.
_HOSTNAME_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$')


def _validate_host(host: str) -> bool:
	return bool(_HOSTNAME_RE.match(host))


def _relay_sasl_dir() -> str:
	return os.path.join(env["STORAGE_ROOT"], "mail", "relay")


def _relay_sasl_passwd() -> str:
	return os.path.join(_relay_sasl_dir(), "sasl_passwd")


def _relay_sasl_passwd_db() -> str:
	return os.path.join(_relay_sasl_dir(), "sasl_passwd.db")


@bp.route('/relay/test', methods=["POST"])
def relay_test():
	# Pre-save connectivity probe. Uses STARTTLS on port 587 (submission), which
	# is what Postfix will use. Does not save anything or touch Postfix config.
	import smtplib
	import ssl as _ssl

	host = request.form.get("host", "").strip()
	port_str = request.form.get("port", "587").strip()
	user = request.form.get("user", "").strip()
	password = request.form.get("password", "").strip()

	if not host:
		return ("No relay host specified.", 400)
	if not _validate_host(host):
		return ("Invalid relay host.", 400)
	try:
		port = int(port_str)
		# Allowlist of ports used by known SMTP relay providers. Prevents relay_test
		# being used as an internal port-scanning oracle.
		if port not in (25, 465, 587, 2525):
			raise ValueError
	except ValueError:
		return ("Invalid port number. Use 25, 465, 587, or 2525.", 400)

	try:
		ctx = _ssl.create_default_context()
		with smtplib.SMTP(host, port, timeout=10) as smtp:
			smtp.ehlo()
			smtp.starttls(context=ctx)
			smtp.ehlo()
			if user and password:
				smtp.login(user, password)
	except smtplib.SMTPAuthenticationError:
		return ("Authentication failed. Check your username and password.", 400)
	except smtplib.SMTPException as e:
		return (f"SMTP error: {sanitize_error_message(str(e))}", 400)
	except OSError as e:
		return (f"Connection failed: {sanitize_error_message(str(e))}", 400)

	if user and password:
		return "Connected and authenticated successfully."
	return "Connected successfully. Enter a password to also verify authentication."


@bp.route('/relay/send-test', methods=["POST"])
def relay_send_test():
	# End-to-end test: submits a real message to Postfix on port 25 so it routes
	# through the configured relay. This catches relay-side rejections (bad sender
	# domain, IP not whitelisted, DKIM required) that the connection test cannot.
	# In Docker, Postfix runs in a separate container - use MAIL_HOST env var.
	import smtplib
	from email.message import EmailMessage

	config = utils.load_settings(env)
	if not config.get("smtp_relay", {}).get("host"):
		return ("No relay is configured. Save a relay configuration first.", 400)

	admin_email = getattr(request, "user_email", None)
	if not admin_email:
		from mail.mailconfig.sync import get_system_administrator

		admin_email = get_system_administrator(env)
	if not admin_email:
		return ("No admin email address could be determined. Ensure at least one admin user exists.", 500)

	msg = EmailMessage()
	msg["Subject"] = "Naust relay test"
	msg["From"] = admin_email
	msg["To"] = admin_email
	msg.set_content("This is a test email sent through your configured SMTP relay to confirm that outbound mail is working correctly.")

	smtp_host = os.environ.get("MAIL_HOST", "localhost")
	try:
		with smtplib.SMTP(smtp_host, 25, timeout=15) as smtp:
			smtp.send_message(msg)
	except Exception as e:
		return (f"Failed to send: {sanitize_error_message(str(e))}", 400)

	return f"Test email sent to {admin_email}. Check your inbox."


@bp.route('/relay', methods=["GET"])
@read_scope
def relay_get():
	config = utils.load_settings(env)
	relay = config.get("smtp_relay", {})
	return json_response({
		"host": relay.get("host", ""),
		"port": relay.get("port", 587),
		"user": relay.get("user", ""),
		# Password is never stored in settings.yaml - check the Postfix credential db.
		"password_set": os.path.exists(_relay_sasl_passwd_db()),
		"spf_include": relay.get("spf_include", ""),
	})


@bp.route('/relay', methods=["POST"])
def relay_set():
	host = request.form.get("host", "").strip()
	port_str = request.form.get("port", "587").strip()
	user = request.form.get("user", "").strip()
	password = request.form.get("password", "").strip()
	spf_include = request.form.get("spf_include", "").strip()

	if host and not _validate_host(host):
		return ("Invalid relay host.", 400)
	if spf_include and not _validate_host(spf_include):
		return ("Invalid SPF include hostname.", 400)
	if '\n' in user or '\r' in user or '\n' in password or '\r' in password:
		return ("Relay username and password may not contain newlines.", 400)
	try:
		port = int(port_str)
		if not (1 <= port <= 65535):
			raise ValueError
	except ValueError:
		return ("Invalid port number.", 400)

	# Apply to Postfix before persisting so a failure leaves settings unchanged.
	try:
		_apply_relay_config(host, port, user, password)
	except Exception as e:
		return (f"Failed to apply relay config to Postfix: {sanitize_error_message(str(e))}", 500)

	config = utils.load_settings(env)
	if not host:
		config.pop("smtp_relay", None)
	else:
		# Password intentionally excluded - stored only in the Postfix credential db.
		config["smtp_relay"] = {
			"host": host,
			"port": port,
			"user": user,
			"spf_include": spf_include,
		}
	utils.write_settings(config, env)

	# Regenerate DNS zones so the SPF record picks up the new spf_include.
	try:
		from services.dns_update import do_dns_update

		do_dns_update(env)
	except Exception as e:
		from flask import current_app

		current_app.logger.warning("DNS update after relay change failed: %s", e)

	return "OK"


def _apply_relay_config(host: str, port: int, user: str, password: str) -> None:
	"""Apply relay settings to Postfix and reload.

	Credentials are stored on the shared storage volume (not /etc/postfix/) so
	they survive Docker container restarts. On bare metal, postmap/postconf run
	here directly. On Docker, the management container has no Postfix tools, so
	the plaintext credential file is staged on the shared volume and the mail
	container's 'configure-relay' handler runs postmap/postconf there instead.

	The plaintext sasl_passwd file exists only briefly during the postmap step.
	Only sasl_passwd.db (Berkeley DB format, not directly human-readable) persists.
	A blank password preserves the existing .db unchanged.
	"""
	from services.control_plane import RUNTIME

	sasl_dir = _relay_sasl_dir()
	sasl_passwd = _relay_sasl_passwd()
	sasl_passwd_db = _relay_sasl_passwd_db()
	os.makedirs(sasl_dir, mode=0o700, exist_ok=True)

	if host:
		if password:
			# Stage plaintext credentials on the shared volume (600, root-only).
			# On bare metal: we postmap here and delete immediately.
			# On Docker:     mail container handler reads, postmaps, and deletes.
			try:
				pathlib.Path(sasl_passwd).write_text(f"[{host}]:{port} {user}:{password}\n", encoding="utf-8")
				os.chmod(sasl_passwd, 0o600)

				if RUNTIME != "docker":
					utils.shell("check_call", ["postmap", sasl_passwd])
					os.chmod(sasl_passwd_db, 0o600)
			except Exception:
				if os.path.exists(sasl_passwd):
					os.remove(sasl_passwd)
				raise
			finally:
				# On bare metal the plaintext is deleted here. On Docker the
				# handler deletes it after postmap - but clean up if it lingered.
				if RUNTIME != "docker" and os.path.exists(sasl_passwd):
					os.remove(sasl_passwd)

		if RUNTIME == "docker":
			# Delegate postmap + postconf to the mail container (it has Postfix tools).
			# The handler reads sasl_passwd from the shared volume if present,
			# runs postmap, deletes the plaintext, then updates main.cf.
			from services.control_plane import _send

			_send("postfix", "configure-relay")
		else:
			from services.control_plane import postfix_set

			postfix_set({
				"relayhost": f"[{host}]:{port}",
				"smtp_sasl_auth_enable": "yes",
				"smtp_sasl_password_maps": f"hash:{sasl_passwd_db[:-3]}",  # path without .db
				"smtp_sasl_security_options": "noanonymous",
				"smtp_tls_security_level": "verify",
			})
	elif RUNTIME == "docker":
		from services.control_plane import _send

		_send("postfix", "configure-relay")
	else:
		from services.control_plane import postfix_set

		postfix_set({
			"relayhost": "",
			"smtp_sasl_auth_enable": "no",
			"smtp_sasl_password_maps": "",
			"smtp_sasl_security_options": "",
			"smtp_tls_security_level": "dane",
		})
		for path in [sasl_passwd, sasl_passwd_db]:
			if os.path.exists(path):
				os.remove(path)
