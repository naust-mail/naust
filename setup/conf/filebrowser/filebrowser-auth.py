# FileBrowser auth hook for Naust. Verifies credentials against
# managerd's /internal/auth/verify endpoint; ${FILES_ROOT} and
# ${MANAGEMENT_HOST} are substituted at setup time.
import hashlib
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

FILES_ROOT = '${FILES_ROOT}'
MANAGEMENT_HOST = '${MANAGEMENT_HOST}'

username = os.environ.get('USERNAME', '')
password = os.environ.get('PASSWORD', '')

if not username or not password:
	print('hook.action=block')
	sys.exit(0)

try:
	data = urllib.parse.urlencode({'email': username, 'password': password}).encode()
	req = urllib.request.Request(
		f'http://{MANAGEMENT_HOST}:10223/internal/auth/verify',
		data=data,
		method='POST',
	)
	with urllib.request.urlopen(req, timeout=5) as resp:
		resp.read()

	# Hash the email to avoid exposing addresses in the filesystem.
	# SHA-256 of raw email bytes (lowercase hex) to match other systems.
	user_hash = hashlib.sha256(username.encode()).hexdigest()
	os.makedirs(os.path.join(FILES_ROOT, user_hash), mode=0o750, exist_ok=True)

	print('hook.action=auth')
	print(f'user.scope={user_hash}')
	sys.exit(0)
except urllib.error.HTTPError as e:
	# 429 = the email's verify window is exhausted; block like a
	# bad password instead of surfacing a 500.
	if e.code in {401, 429}:
		print('hook.action=block')
		sys.exit(0)
	sys.exit(1)
except Exception:  # noqa: BLE001 - auth hook: any unexpected failure must deny, never fail open
	sys.exit(1)
