"""
Management daemon (managerd, Go) - system integration.

managerd is the unprivileged control plane: it owns user/alias/DNS/TLS/
backup state and serves the admin API on 127.0.0.1:10223. This component
gives it an identity and a place to stand: the naust system user, the
directories it owns, its systemd unit, and the scoped secret for the
mail-key unwrap endpoint. The binary itself is installed by the daemon
component (defs/daemon.py), which owns all Go binaries as one artifact set.

Steps:
  user - create the naust system user and its group memberships
  dirs - create and hand over the directories managerd writes
  key  - generate the mailcrypt unwrap secret (only when encryption is on)
  unit - install and enable the systemd unit [dep: user, dirs, binary]

Bare metal only: Docker wires managerd into its own container.
"""

import grp
import os
import pwd
import subprocess

from doit.tools import config_changed

from .. import artifacts, SETUP_DIR
from ..component import Component
from ..task_names import DAEMON_MANAGERD, HELPER_GROUP

COMPONENT = Component(
	name="managerd",
	packages=[],
	services=["naust-managerd"],
	docker_services=[],
	skip_on=["docker"],
)

_UNIT_DEST = "/lib/systemd/system/naust-managerd.service"
_USER = "naust"
_UNWRAP_KEY = "/var/lib/naust/mailcrypt-unwrap.key"


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	storage_root = env["STORAGE_ROOT"]
	repo_root = os.path.dirname(SETUP_DIR)
	unit_src = os.path.join(repo_root, "daemon", "systemd", "naust-managerd.service")
	encryption = env.get("ENCRYPTION_AT_REST", "false").lower() == "true" and artifacts.ubuntu_supports_encryption()

	tasks = [
		{
			"name": "user",
			# helper:group creates the naust socket group first; all
			# other groups come from packages, which install before tasks.
			"uptodate": [config_changed(artifacts.fn_stamp(_user))],
			"task_dep": [HELPER_GROUP],
			"actions": [(_user,)],
		},
		{
			"name": "dirs",
			"uptodate": [config_changed(f"{storage_root}:{artifacts.fn_stamp(_dirs)}")],
			"task_dep": ["managerd:user"],
			"actions": [(_dirs, [storage_root])],
		},
		{
			"name": "unit",
			"uptodate": [config_changed((artifacts.hash_files(unit_src) if os.path.exists(unit_src) else artifacts.hash_files(_UNIT_DEST) if os.path.exists(_UNIT_DEST) else "") + f":{storage_root}:" + artifacts.fn_stamp(_unit))],
			"task_dep": ["managerd:user", "managerd:dirs", DAEMON_MANAGERD],
			"actions": [(_unit, [unit_src, storage_root])],
		},
	]

	if encryption:
		tasks.insert(
			2,
			{
				"name": "key",
				# targets= only skips the normal case; --force (doit
				# --always-execute) bypasses it. The action's own existence
				# check is the never-rotate guarantee.
				"targets": [_UNWRAP_KEY],
				"task_dep": ["managerd:user"],
				"actions": [(_unwrap_key,)],
			},
		)

	return tasks


def _user() -> None:
	"""Create the naust system user and attach its group memberships.

	No home directory and no shell: the daemon's writable state lives in
	the dirs step's directories plus the unit's StateDirectory.

	The primary group is the naust socket group created by helper:group
	(also why -g: useradd would otherwise try to create a group with the
	same name and collide with it). Supplementary groups: mail lets the
	backup engine read the mail store; dovecot covers the two 0640 files
	shared with Dovecot (dovecot-users, mailcrypt-unwrap.key); opendkim
	lets the DNS zone builder read mail.txt; www-data covers backup reads
	of radicale/filebrowser app state; ssl-cert lets writeCertFile's
	chown-to-ssl-cert-group actually succeed (a non-root process can only
	change a file's group to one it belongs to - without this, issued
	certs stay owned by naust's own primary group instead, silently
	failing acmeprov's best-effort chown in issue.go). Absent groups are
	skipped.
	"""
	try:
		pwd.getpwnam(_USER)
	except KeyError:
		subprocess.run(
			["useradd", "--system", "--no-create-home", "-g", _USER, "-d", "/nonexistent", "-s", "/usr/sbin/nologin", _USER],
			check=True,
			capture_output=True,
		)
	for group in ["mail", "dovecot", "opendkim", "www-data", "ssl-cert"]:
		try:
			grp.getgrnam(group)
		except KeyError:
			continue
		subprocess.run(["usermod", "-aG", group, _USER], check=True, capture_output=True)


def _dirs(storage_root: str) -> None:
	"""Create and hand over every directory managerd writes.

	Ownership follows the write surface: the daemon owns its own state
	dirs outright; nsd's include dirs are naust-writable so zone pushes
	need no root; /var/lib/naust is naust-owned for atomic writes
	(mta-sts.txt renames need directory write access).
	"""
	uid = pwd.getpwnam(_USER).pw_uid
	gid = grp.getgrnam(_USER).gr_gid

	own = [
		(os.path.join(storage_root, "control"), 0o700),
		(os.path.join(storage_root, "mail", "materialized"), 0o755),
		(os.path.join(storage_root, "mail", "relay"), 0o700),
		(os.path.join(storage_root, "ssl"), 0o750),
		(os.path.join(storage_root, "backup"), 0o700),
		(os.path.join(storage_root, "dns", "dnssec"), 0o700),
		("/etc/nsd/zones", 0o755),
		("/etc/nsd/nsd.conf.d", 0o755),
		("/var/lib/naust", 0o755),
	]
	for path, mode in own:
		os.makedirs(path, exist_ok=True)
		os.chmod(path, mode)
		os.chown(path, uid, gid)

	# Existing secrets and key material created root-owned by earlier
	# components move to the daemon that actually uses them. Recursive:
	# backup/ holds the encryption key and ssh identity, ssl/ holds the
	# private key and installed certs, dnssec/ holds signing keys.
	for tree in [
		os.path.join(storage_root, "ssl"),
		os.path.join(storage_root, "backup"),
		os.path.join(storage_root, "dns", "dnssec"),
	]:
		for root, dirs, files in os.walk(tree):
			for name in dirs + files:
				os.chown(os.path.join(root, name), uid, gid)

	# Backup reads the mail store via the mail group: group execute/read
	# bits on the top-level path make the tree reachable. Kept shallow -
	# per-file group bits inside mailboxes are verified on the test box
	# before any recursive enforcement is added here.
	for path in [
		storage_root,
		os.path.join(storage_root, "mail"),
		os.path.join(storage_root, "mail", "mailboxes"),
	]:
		if os.path.isdir(path):
			subprocess.run(["chmod", "g+rX", path], check=True)


def _unwrap_key() -> None:
	"""Generate the shared secret gating the mail-key unwrap endpoint.

	Dovecot's Lua passdb presents this to managerd at login to fetch a
	user's mail decryption key; naust owns it, group dovecot reads it.
	Created once; a rotation would only invalidate in-flight logins but
	stable is one less moving part.
	"""
	if os.path.exists(_UNWRAP_KEY):
		return
	os.makedirs(os.path.dirname(_UNWRAP_KEY), exist_ok=True)
	result = subprocess.run(["openssl", "rand", "-hex", "32"], check=True, capture_output=True)
	old_umask = os.umask(0o077)
	try:
		artifacts.write_file(_UNWRAP_KEY, result.stdout.decode().strip() + "\n")
	finally:
		os.umask(old_umask)
	os.chown(_UNWRAP_KEY, pwd.getpwnam(_USER).pw_uid, grp.getgrnam("dovecot").gr_gid)
	os.chmod(_UNWRAP_KEY, 0o640)


def _unit(unit_src: str, storage_root: str) -> None:
	"""Install and enable the managerd systemd unit.

	The unit is a ${STORAGE_ROOT} template: ReadWritePaths must name the
	real storage location. The installed copy is the durable one; the
	repo source is only needed when the unit changes.
	"""
	if os.path.exists(unit_src):
		artifacts.write_file(_UNIT_DEST, artifacts.render_template(unit_src, {"STORAGE_ROOT": storage_root}))
	elif not os.path.exists(_UNIT_DEST):
		msg = f"managerd unit file not found at {unit_src} or {_UNIT_DEST}"
		raise RuntimeError(msg)
	subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)
	subprocess.run(["systemctl", "enable", "naust-managerd.service"], check=True, capture_output=True)
