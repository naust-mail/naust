#!/usr/bin/python3
#
# This is a command-line script for calling management APIs
# on the Naust control panel backend. The script
# reads /var/lib/naust/api.key for the backend's
# root API key. This file is readable only by root, so this
# tool can only be used as root.

import sys
import getpass
import urllib.request
import urllib.error
import json
import csv
import contextlib
import pathlib


def mgmt(cmd, data=None, is_json=False):
	# The base URL for the management daemon. (Listens on IPv4 only.)
	mgmt_uri = 'http://127.0.0.1:10222'

	setup_key_auth(mgmt_uri)

	req = urllib.request.Request(mgmt_uri + cmd, urllib.parse.urlencode(data).encode("utf8") if data else None)
	try:
		response = urllib.request.urlopen(req)
	except urllib.error.HTTPError as e:
		if e.code == 401:
			with contextlib.suppress(Exception):
				print(e.read().decode("utf8"))
			print("The management daemon refused access. The API key file may be out of sync. Try 'service naust restart'.", file=sys.stderr)
		elif hasattr(e, 'read'):
			print(e.read().decode('utf8'), file=sys.stderr)
		else:
			print(e, file=sys.stderr)
		sys.exit(1)
	resp = response.read().decode('utf8')
	if is_json:
		resp = json.loads(resp)
	return resp


def read_password():
	while True:
		first = getpass.getpass('password: ')
		if len(first) < 8:
			print("Passwords must be at least eight characters.", file=sys.stderr, flush=True)
			continue
		second = getpass.getpass(' (again): ')
		if first != second:
			print("Passwords not the same. Try again.", file=sys.stderr, flush=True)
			continue
		break
	return first


def setup_key_auth(mgmt_uri):
	try:
		with open('/var/lib/naust/api.key', encoding='utf-8') as f:
			key = f.read().strip()
	except FileNotFoundError:
		print("Management daemon is not running yet. Wait for startup to complete and try again.")
		sys.exit(1)

	auth_handler = urllib.request.HTTPBasicAuthHandler()
	auth_handler.add_password(realm='Naust Management Server', uri=mgmt_uri, user=key, passwd='')
	opener = urllib.request.build_opener(auth_handler)
	urllib.request.install_opener(opener)


if len(sys.argv) < 2:
	print(
		"""Usage:
  {cli} user                                     (lists users)
  {cli} user add user@domain.com [password]
  {cli} user password user@domain.com [password]
  {cli} user remove user@domain.com
  {cli} user make-admin user@domain.com
  {cli} user quota user@domain [new-quota]       (get or set user quota)
  {cli} user remove-admin user@domain.com
  {cli} user admins                              (lists admins)
  {cli} user mfa show user@domain.com            (shows MFA devices for user, if any)
  {cli} user mfa disable user@domain.com [id]    (disables MFA for user)
  {cli} user encryption status user@domain.com   (shows encryption status and active key slots)
  {cli} user encryption list                     (lists all users with encryption enabled)
  {cli} user encryption disable user@domain.com  (removes encryption key slots - any encrypted mail becomes unrecoverable)
  {cli} alias                                    (lists aliases)
  {cli} alias add incoming.name@domain.com sent.to@other.domain.com
  {cli} alias add incoming.name@domain.com 'sent.to@other.domain.com, multiple.people@other.domain.com'
  {cli} alias remove incoming.name@domain.com
  {cli} filebrowser enable                       (enable FileBrowser, takes effect on next setup run)
  {cli} filebrowser disable                      (disable FileBrowser and stop the service immediately)
  {cli} filebrowser status                       (show whether FileBrowser is enabled)

Removing a mail user does not delete their mail folders on disk. It only prevents IMAP/SMTP login.
""".format(cli="management/cli.py")
	)

elif sys.argv[1] == "user" and len(sys.argv) == 2:
	# Dump a list of users, one per line. Mark admins with an asterisk.
	users = mgmt("/mail/users?format=json", is_json=True)
	for domain in users:
		for user in domain["users"]:
			if user['status'] == 'inactive':
				continue
			print(user['email'], end='')
			if "admin" in user['privileges']:
				print("*", end='')
			print()

elif sys.argv[1] == "user" and sys.argv[2] in {"add", "password"}:
	args = [a for a in sys.argv[3:] if a != "--stdin-password"]
	stdin_pw = "--stdin-password" in sys.argv
	if stdin_pw:
		email = args[0] if args else input('email: ')
		pw = sys.stdin.readline().rstrip('\n')
	elif len(sys.argv[3:]) < 2:
		email = args[0] if args else input('email: ')
		pw = read_password()
	else:
		email, pw = args[0], args[1]

	if sys.argv[2] == "add":
		print(mgmt("/mail/users/add", {"email": email, "password": pw}))
	elif sys.argv[2] == "password":
		print(mgmt("/mail/users/password", {"email": email, "password": pw}))

elif sys.argv[1] == "user" and sys.argv[2] == "remove" and len(sys.argv) == 4:
	print(mgmt("/mail/users/remove", {"email": sys.argv[3]}))

elif sys.argv[1] == "user" and sys.argv[2] in {"make-admin", "remove-admin"} and len(sys.argv) == 4:
	action = 'add' if sys.argv[2] == 'make-admin' else 'remove'
	print(mgmt("/mail/users/privileges/" + action, {"email": sys.argv[3], "privilege": "admin"}))

elif sys.argv[1] == "user" and sys.argv[2] == "admins":
	# Dump a list of admin users.
	users = mgmt("/mail/users?format=json", is_json=True)
	for domain in users:
		for user in domain["users"]:
			if "admin" in user['privileges']:
				print(user['email'])

elif sys.argv[1] == "user" and sys.argv[2] == "quota" and len(sys.argv) == 4:
	# Get a user's quota
	print(mgmt(f"/mail/users/quota?text=1&email={sys.argv[3]}"))

elif sys.argv[1] == "user" and sys.argv[2] == "quota" and len(sys.argv) == 5:
	# Set a user's quota
	users = mgmt("/mail/users/quota", {"email": sys.argv[3], "quota": sys.argv[4]})

elif sys.argv[1] == "user" and len(sys.argv) == 5 and sys.argv[2:4] == ["mfa", "show"]:
	# Show MFA status for a user.
	status = mgmt("/mfa/status", {"user": sys.argv[4]}, is_json=True)
	W = csv.writer(sys.stdout)
	W.writerow(["id", "type", "label/name", "last_used"])
	for mfa in status["enabled_mfa"]:
		W.writerow([mfa["id"], mfa["type"], mfa.get("label") or mfa.get("name", ""), mfa.get("last_used", "")])

elif sys.argv[1] == "user" and len(sys.argv) in {5, 6} and sys.argv[2:4] == ["mfa", "disable"]:
	# Disable MFA (all or a particular device) for a user.
	print(mgmt("/mfa/disable", {"user": sys.argv[4], "mfa-id": sys.argv[5] if len(sys.argv) == 6 else None}))

elif sys.argv[1] == "user" and len(sys.argv) == 5 and sys.argv[2:4] == ["encryption", "status"]:
	email = sys.argv[4]
	import os as _os

	_sys_path_base = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
	sys.path.insert(0, _sys_path_base)
	from core.utils import load_environment
	from mail.mailconfig.database import open_database

	_env = load_environment()
	conn, c = open_database(_env, with_connection=True)
	try:
		c.execute("SELECT id FROM users WHERE email=?", (email,))
		row = c.fetchone()
		if not row:
			print("User not found:", email)
			sys.exit(1)
		c.execute("SELECT slot_type, slot_label FROM mail_keys WHERE user_id=?", (row[0],))
		slots = c.fetchall()
	finally:
		conn.close()
	if not slots:
		print(email, "- encryption disabled (no key slots)")
	else:
		print(email, "- encryption enabled")
		for slot_type, slot_label in sorted(slots):
			print(f"  {slot_type}:{slot_label}")

elif sys.argv[1] == "user" and len(sys.argv) == 4 and sys.argv[2:4] == ["encryption", "list"]:
	import os as _os

	_sys_path_base = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
	sys.path.insert(0, _sys_path_base)
	from core.utils import load_environment
	from mail.mailconfig.database import open_database

	_env = load_environment()
	conn, c = open_database(_env, with_connection=True)
	try:
		c.execute("SELECT u.email, mk.slot_type FROM users u JOIN mail_keys mk ON mk.user_id = u.id ORDER BY u.email, mk.slot_type")
		rows = c.fetchall()
	finally:
		conn.close()
	if not rows:
		print("No users have encryption enabled.")
	else:
		current = None
		for email, slot_type in rows:
			if email != current:
				print(email)
				current = email
			print(f"  {slot_type}")

elif sys.argv[1] == "user" and len(sys.argv) == 5 and sys.argv[2:4] == ["encryption", "disable"]:
	email = sys.argv[4]
	print("WARNING: This removes all encryption key slots for", email)
	print("Any mail that was encrypted at rest will be permanently unrecoverable.")
	print("Only proceed if the mailbox has no encrypted mail.")
	print()
	confirm = input("Type the email address to confirm: ").strip()
	if confirm != email:
		print("Confirmation did not match. Aborting.")
		sys.exit(1)
	import os as _os

	_sys_path_base = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
	sys.path.insert(0, _sys_path_base)
	from core.utils import load_environment
	from mail.mailconfig.database import open_database

	_env = load_environment()
	conn, c = open_database(_env, with_connection=True)
	try:
		c.execute("SELECT id FROM users WHERE email=?", (email,))
		row = c.fetchone()
		if not row:
			print("User not found:", email)
			sys.exit(1)
		user_id = row[0]
		c.execute("SELECT COUNT(*) FROM mail_keys WHERE user_id=?", (user_id,))
		count = c.fetchone()[0]
		if count == 0:
			print("No encryption key slots found for", email)
			sys.exit(0)
		c.execute("DELETE FROM mail_keys WHERE user_id=?", (user_id,))
		conn.commit()
	finally:
		conn.close()
	print(f"Removed {count} key slot(s) for {email}. Encryption is now disabled.")

elif sys.argv[1] == "alias" and len(sys.argv) == 2:
	print(mgmt("/mail/aliases"))

elif sys.argv[1] == "alias" and sys.argv[2] == "add" and len(sys.argv) == 5:
	print(mgmt("/mail/aliases/add", {"address": sys.argv[3], "forwards_to": sys.argv[4]}))

elif sys.argv[1] == "alias" and sys.argv[2] == "remove" and len(sys.argv) == 4:
	print(mgmt("/mail/aliases/remove", {"address": sys.argv[3]}))

elif sys.argv[1] == "filebrowser" and len(sys.argv) == 3 and sys.argv[2] in {"enable", "disable", "status"}:
	import re

	conf = "/etc/naust.conf"
	content = pathlib.Path(conf).read_text(encoding="utf-8")
	current = re.search(r'^ENABLE_FILEBROWSER=(.*)$', content, re.MULTILINE)
	current_val = current.group(1).strip() if current else "true"

	if sys.argv[2] == "status":
		print("FileBrowser is", "enabled" if current_val == "true" else "disabled")
	elif sys.argv[2] == "enable":
		content = re.sub(r'^ENABLE_FILEBROWSER=.*$', 'ENABLE_FILEBROWSER=true', content, flags=re.MULTILINE)
		pathlib.Path(conf).write_text(content, encoding="utf-8")
		print("FileBrowser enabled. Run 'sudo naust' to install and start it.")
	elif sys.argv[2] == "disable":
		content = re.sub(r'^ENABLE_FILEBROWSER=.*$', 'ENABLE_FILEBROWSER=false', content, flags=re.MULTILINE)
		pathlib.Path(conf).write_text(content, encoding="utf-8")
		import os

		sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
		from services.control_plane import stop as cp_stop, disable as cp_disable

		try:
			cp_stop("filebrowser")
		except Exception:
			pass
		cp_disable("filebrowser")
		print("FileBrowser disabled and stopped.")

else:
	print("Invalid command-line arguments.")
	sys.exit(1)
