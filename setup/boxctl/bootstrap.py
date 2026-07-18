"""Generate a one-time bootstrap code for first-admin onboarding via the web UI."""

import json
import os
import secrets
import shutil
import sqlite3
import sys
import time
import uuid

BARE_METAL_CONF = "/etc/naust.conf"


def run(show_cert: bool = False, install: bool = False, from_installer: bool = False) -> None:
	from .ui import bold, green, gray_desc, lavender, red, _term_width

	def line():
		return gray_desc("─" * (_term_width() - 2))

	if os.geteuid() != 0:
		print(f"\n  {red('boxctl bootstrap must be run as root (sudo boxctl bootstrap).')}\n")
		sys.exit(1)

	conf = {}
	try:
		with open(BARE_METAL_CONF, encoding="utf-8") as f:
			for raw_ln in f:
				ln = raw_ln.strip()
				if not ln or ln.startswith('#') or '=' not in ln:
					continue
				k, _, v = ln.partition('=')
				conf[k.strip()] = v.strip().strip("'\"")
	except FileNotFoundError:
		print(f"\n  {red('Config file not found:')} {BARE_METAL_CONF}")
		print(f"  {gray_desc('Has setup been run?')}\n")
		sys.exit(1)

	storage_root = conf.get('STORAGE_ROOT', '')
	hostname = conf.get('PRIMARY_HOSTNAME', '')
	if not storage_root or not hostname:
		print(f"\n  {red('STORAGE_ROOT or PRIMARY_HOSTNAME missing from config. Has setup been run?')}\n")
		sys.exit(1)

	db_path = os.path.join(storage_root, 'control/manager.sqlite')
	if not os.path.exists(db_path):
		print(f"\n  {red('Database not found. Is naust-managerd running? Has setup been run?')}\n")
		sys.exit(1)

	conn = sqlite3.connect(db_path)
	admins = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
	conn.close()
	if admins > 0:
		if install:
			print()
			print(f"  {bold('Naust setup complete.')}")
			print(f"  {line()}")
			print(f"  {'Admin panel':<18} {lavender(f'https://{hostname}/admin')}")
			if show_cert:
				cert_path = os.path.join(storage_root, 'ssl/ssl_certificate.pem')
				if os.path.exists(cert_path):
					import subprocess

					result = subprocess.run(
						['openssl', 'x509', '-in', cert_path, '-noout', '-fingerprint', '-sha256'],
						capture_output=True,
						text=True,
					)
					fingerprint = result.stdout.strip().replace('sha256 Fingerprint=', '').replace('SHA256 Fingerprint=', '')
					if fingerprint:
						print(f"  {'TLS fingerprint':<18} {gray_desc(fingerprint)}")
			print(f"  {line()}")
			print()
			return
		print(f"\n  {red('An admin account already exists. Bootstrap is not available.')}\n")
		sys.exit(1)

	CODE_CHARS = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
	code = ''.join(secrets.choice(CODE_CHARS) for _ in range(8))
	token_id = str(uuid.uuid4())
	expires_at = int(time.time()) + 15 * 60

	# Lives in the daemon-owned control/ directory: managerd must be able
	# to bump the attempt counter and delete the file once consumed.
	token_path = os.path.join(storage_root, 'control', 'bootstrap.token')
	tmp_path = token_path + '.tmp'
	fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
	with os.fdopen(fd, 'w') as f:
		json.dump({'uuid': token_id, 'code': code, 'expires': expires_at, 'attempts': 0}, f)
	shutil.chown(tmp_path, 'naust', 'naust')
	os.replace(tmp_path, token_path)

	url = f"https://{hostname}/admin/setup?code={code}"
	public_ip = conf.get('PUBLIC_IP', '')
	ip_url = f"https://{public_ip}/admin/setup?code={code}" if public_ip else None
	expiry_str = time.strftime('%H:%M:%S', time.localtime(expires_at))
	col = 18

	display_code = f"{code[:4]} {code[4:]}"

	print()
	print(f"  {bold('Welcome to Naust')}")
	print(f"  {line()}")
	print(f"  {'Setup code':<{col}} {green(bold(display_code))}")
	print(f"  {'Open':<{col}} {lavender(url)}")
	if ip_url:
		print(f"  {'Or (by IP)':<{col}} {gray_desc(ip_url)}")
	print(f"  {'Code expires':<{col}} {gray_desc(expiry_str + ' (15 minutes)')}")

	if show_cert:
		cert_path = os.path.join(storage_root, 'ssl/ssl_certificate.pem')
		if os.path.exists(cert_path):
			import subprocess

			result = subprocess.run(
				['openssl', 'x509', '-in', cert_path, '-noout', '-fingerprint', '-sha256'],
				capture_output=True,
				text=True,
			)
			fingerprint = result.stdout.strip().replace('sha256 Fingerprint=', '').replace('SHA256 Fingerprint=', '')
			if fingerprint:
				print(f"  {'TLS fingerprint':<{col}} {gray_desc(fingerprint)}")

	print(f"  {line()}")
	print(f"  {gray_desc('Enter the code on the setup page, or open the link above.')}")
	expire_hint = "Run sudo boxctl bootstrap if the code expires." if from_installer else "Run this command again if the code expires."
	print(f"  {gray_desc(expire_hint)}")
	print()
