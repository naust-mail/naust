# Shared, app-independent helpers used across view modules. None of these
# touch the Flask `app` object directly - they use `current_app` where a
# logger is needed, so view modules never have to import daemon.py.

import json
import re
import time

from flask import Response, current_app, request


def validate_csrf():
	if request.method in ('POST', 'PUT', 'DELETE'):
		xhr_header = request.headers.get('X-Requested-With')
		if xhr_header != 'XMLHttpRequest':
			return False
	return True


def json_response(data, status=200):
	return Response(json.dumps(data, indent=2, sort_keys=True) + '\n', status=status, mimetype='application/json')


def sanitize_error_message(error_msg):
	"""
	Sanitize error messages to prevent credential disclosure.
	Full tracebacks are replaced with a generic message.
	Credentials embedded in backup target URLs are stripped.
	File paths and line numbers are redacted.
	"""
	if not isinstance(error_msg, str):
		error_msg = str(error_msg)

	if 'Traceback' in error_msg or 'File "' in error_msg:
		return "An internal error occurred. Please contact your administrator."

	# Strip credentials from backup target URLs (s3://, b2://, sftp://, etc.)
	error_msg = re.sub(r'(\w+://)([^:@\s]+):([^@\s]+)@', r'\1***:***@', error_msg)

	# Redact Python source file paths.
	error_msg = re.sub(r'/\S+\.py', '[file]', error_msg)

	# Shorten well-known internal path prefixes.
	error_msg = re.sub(r'/var/lib/naust/([^\s]*)', r'[storage]/\1', error_msg)
	error_msg = re.sub(r'/home/[^/\s]+/([^\s]*)', r'[home]/\1', error_msg)

	# Redact line numbers.
	error_msg = re.sub(r'\bline \d+\b', 'line [redacted]', error_msg)

	return error_msg


def validate_email(email):
	"""
	Validate email address format to prevent injection attacks.
	Raises ValueError if email is invalid.
	"""
	if not email or not isinstance(email, str):
		raise ValueError("Email address is required")

	email = email.strip()
	if not email:
		raise ValueError("Email address is required")

	if any(char in email for char in [';', '|', '&', '$', '`', '\n', '\r', '\0']):
		raise ValueError("Email address contains invalid characters")

	if '@' not in email:
		raise ValueError("Email address must contain @")

	parts = email.rsplit('@', 1)
	if len(parts) != 2 or not parts[0] or not parts[1]:
		raise ValueError("Invalid email format")

	localpart, domain = parts

	if len(localpart) > 64 or len(localpart) < 1:
		raise ValueError("Email local part must be between 1 and 64 characters")

	if len(domain) > 253 or len(domain) < 1:
		raise ValueError("Email domain must be between 1 and 253 characters")

	if '.' not in domain:
		raise ValueError("Email domain must contain a TLD")

	if '..' in email:
		raise ValueError("Email address cannot contain consecutive dots")

	if email[0] in ['.', '@'] or email[-1] in ['.', '@']:
		raise ValueError("Email address has invalid format")

	return email.strip()


def validate_hostname(hostname):
	"""
	Validate hostname/domain format to prevent command injection attacks.
	Raises ValueError if hostname is invalid.
	"""
	if not hostname or not isinstance(hostname, str):
		raise ValueError("Hostname is required")

	hostname = hostname.strip()
	if not hostname:
		raise ValueError("Hostname is required")

	if any(char in hostname for char in [';', '|', '&', '$', '`', '\n', '\r', '\0', ' ', '/', '\\', '"', "'", '<', '>', '(', ')', '{', '}', '[', ']']):
		raise ValueError("Hostname contains invalid characters")

	if len(hostname) > 253:
		raise ValueError("Hostname must not exceed 253 characters")

	labels = hostname.split('.')
	for label in labels:
		if not label:
			raise ValueError("Hostname cannot have empty labels")
		if len(label) > 63:
			raise ValueError("Hostname label must not exceed 63 characters")
		if not label[0].isalnum() or not label[-1].isalnum():
			raise ValueError("Hostname labels must start and end with alphanumeric characters")
		if not all(c.isalnum() or c == '-' for c in label):
			raise ValueError("Hostname labels can only contain alphanumeric characters and hyphens")

	if '.' not in hostname:
		raise ValueError("Hostname must contain a TLD")

	return hostname.strip()


def log_failed_login(req):
	# We need to figure out the ip to list in the message, all our calls are routed
	# through nginx who will put the original ip in X-Forwarded-For.
	# During setup we call the management interface directly to determine the user
	# status. So we can't always use X-Forwarded-For because during setup that header
	# will not be present.
	ip = req.headers.getlist("X-Forwarded-For")[0] if req.headers.getlist("X-Forwarded-For") else req.remote_addr

	# We need to add a timestamp to the log message, otherwise /dev/log will eat the "duplicate"
	# message.
	current_app.logger.warning("Naust Management Daemon: Failed login attempt from ip %s - timestamp %s", ip, time.time())
