"""
User authentication and mail routing.

Postfix and Dovecot read materialized map files written by managerd at
STORAGE_ROOT/mail/materialized/ - the manager is never in the mail hot
path. Setup points them at those files and seeds empty ones so both
daemons start cleanly before the manager's first write.

Steps:
  db-group        - create mail-db group; add postfix + dovecot; set DB dir perms
  seed-maps       - create empty materialized maps so postfix/dovecot can start
  postfix-main    - editconf main.cf for map paths and SASL settings [dep: postfix:spam-filter]
  dovecot-auth    - write the auth unix-listener config for Postfix SASL

Both postfix and dovecot are restarted when any task runs.
"""

import os
import subprocess

from doit.tools import config_changed

from .. import artifacts
from ..component import Component
from ..task_names import POSTFIX_SPAM_FILTER
import contextlib

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="users",
	packages=[],
	# Both postfix and dovecot pick up the map changes after their restarts.
	services=["postfix", "dovecot"],
	docker_services=["postfix", "dovecot"],
)


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	storage_root = env["STORAGE_ROOT"]
	db_path = os.path.join(storage_root, "mail", "db", "users.sqlite")
	db_dir = os.path.dirname(db_path)
	maps_dir = os.path.join(storage_root, "mail", "materialized")

	return [
		{
			"name": "db-group",
			# Create the shared group that allows both Dovecot auth-workers and
			# Postfix proxymap to write to SQLite's WAL -shm file. The setgid bit
			# on the DB directory ensures new files (including -shm) inherit the group.
			"uptodate": [config_changed(f"{db_dir}:{artifacts.fn_stamp(_db_group)}")],
			"actions": [(_db_group, [db_dir])],
		},
		{
			"name": "seed-maps",
			# Postfix aborts on a missing hash map and Dovecot on a missing
			# passwd-file; on a fresh box managerd has not written yet.
			"uptodate": [config_changed(f"{maps_dir}:{artifacts.fn_stamp(_seed_maps)}")],
			"actions": [(_seed_maps, [maps_dir])],
		},
		{
			"name": "postfix-main",
			# editconf main.cf to wire in map paths and SASL settings.
			# Shares main.cf with postfix component; dep ensures we run after it.
			"uptodate": [config_changed(f"{maps_dir}:{artifacts.fn_stamp(_postfix_main)}")],
			"task_dep": [POSTFIX_SPAM_FILTER, "users:seed-maps"],
			"actions": [(_postfix_main, [maps_dir])],
		},
		{
			"name": "dovecot-auth",
			# Auth unix-listener conf: Postfix connects to Dovecot's auth
			# socket for SASL. The passdb/userdb themselves live in the
			# dovecot component's 95-auth.conf (version-dialect templates).
			"uptodate": [config_changed(f"{artifacts.fn_stamp(_dovecot_auth)}")],
			"actions": [(_dovecot_auth,)],
		},
	]


# ── Action functions ──────────────────────────────────────────────────────────


def _db_group(db_dir: str) -> None:
	"""Create the mail-db group and grant postfix + dovecot access to the DB dir.

	The setgid bit on db_dir ensures that SQLite's -shm and -wal files created
	at runtime inherit the mail-db group and become group-writable (SQLite copies
	the database file's mode to -shm via fchmod, bypassing the process umask).
	"""
	subprocess.run(["groupadd", "--system", "mail-db"], check=False)
	subprocess.run(["usermod", "-aG", "mail-db", "postfix"], check=True)
	subprocess.run(["usermod", "-aG", "mail-db", "dovecot"], check=True)

	os.makedirs(db_dir, exist_ok=True)
	subprocess.run(["chown", "root:mail-db", db_dir], check=True)
	subprocess.run(["chmod", "2770", db_dir], check=True)


def _seed_maps(maps_dir: str) -> None:
	"""Seed empty materialized maps so the mail daemons can start.

	managerd owns these files at runtime; setup only guarantees they exist
	with the right shape before postfix/dovecot first start. Ownership goes
	to the naust user where it exists (bare metal) so the daemon can replace
	them; missing pieces are skipped rather than failed in Docker, where the
	manager runs in another container.
	"""
	import grp
	import pwd

	os.makedirs(maps_dir, exist_ok=True)
	os.chmod(maps_dir, 0o755)

	uid = gid = -1
	try:
		uid = pwd.getpwnam("naust").pw_uid
		gid = grp.getgrnam("naust").gr_gid
	except KeyError:
		pass

	for name in [
		"virtual-mailbox-domains",
		"virtual-mailbox-maps",
		"virtual-alias-maps",
		"sender-login-maps",
	]:
		path = os.path.join(maps_dir, name)
		if not os.path.exists(path):
			artifacts.write_file(path, "", mode=0o644)
		if not os.path.exists(path + ".db"):
			subprocess.run(["postmap", f"hash:{path}"], check=True, capture_output=True)
		for p in (path, path + ".db"):
			if uid != -1 and os.path.exists(p):
				os.chown(p, uid, gid)

	users_path = os.path.join(maps_dir, "dovecot-users")
	if not os.path.exists(users_path):
		artifacts.write_file(users_path, "", mode=0o640)
	if uid != -1:
		dovecot_gid = gid
		with contextlib.suppress(KeyError):
			dovecot_gid = grp.getgrnam("dovecot").gr_gid
		os.chown(users_path, uid, dovecot_gid)


def _postfix_main(maps_dir: str) -> None:
	"""Point Postfix at the materialized maps and configure SASL auth via Dovecot.

	proxy:hash routes lookups through proxymap, which runs un-chrooted and
	re-opens the .db when managerd swaps it. The chrooted smtpd could not
	reach these paths directly.

	SMTP AUTH is disabled on port 25 (smtpd_sasl_auth_enable=no) to prevent
	outbound relay without DKIM signing; it is enabled explicitly for the
	submission port in master.cf.
	"""
	# Prevent intra-domain spoofing: MAIL FROM must be owned by the logged-in user.
	artifacts.editconf(
		"/etc/postfix/main.cf",
		f"smtpd_sender_login_maps=proxy:hash:{os.path.join(maps_dir, 'sender-login-maps')}",
	)

	# SMTPUTF8 is disabled because Dovecot's LMTP doesn't support it; any message
	# received with the SMTPUTF8 flag would bounce on delivery.
	artifacts.editconf(
		"/etc/postfix/main.cf",
		"smtputf8_enable=no",
		f"virtual_mailbox_domains=proxy:hash:{os.path.join(maps_dir, 'virtual-mailbox-domains')}",
		f"virtual_mailbox_maps=proxy:hash:{os.path.join(maps_dir, 'virtual-mailbox-maps')}",
		f"virtual_alias_maps=proxy:hash:{os.path.join(maps_dir, 'virtual-alias-maps')}",
		r"local_recipient_maps=$virtual_mailbox_maps",
	)

	# Point Postfix at Dovecot's auth socket. Auth is disabled on port 25 (see #830):
	# port 25 does not run DKIM on relayed mail, so outbound authenticated mail
	# wouldn't be signed. Auth is enabled explicitly for the submission ports in master.cf.
	artifacts.editconf(
		"/etc/postfix/main.cf",
		"smtpd_sasl_type=dovecot",
		"smtpd_sasl_path=private/auth",
		"smtpd_sasl_auth_enable=no",
	)


def _dovecot_auth() -> None:
	"""Write the Dovecot auth unix-listener config.

	99-local-auth.conf exposes Dovecot's auth service on a socket that Postfix
	can reach (it lives inside /var/spool/postfix/private, within Postfix's
	chroot jail). Mode 0666 + postfix user/group so smtpd can connect.
	"""
	artifacts.write_file(
		"/etc/dovecot/conf.d/99-local-auth.conf",
		"service auth {\n  unix_listener /var/spool/postfix/private/auth {\n    mode = 0666\n    user = postfix\n    group = postfix\n  }\n}\n",
	)

	# The pre-flip SQL auth config; nothing references it anymore.
	for stale in ["/etc/dovecot/dovecot-sql.conf.ext"]:
		if os.path.exists(stale):
			os.remove(stale)
