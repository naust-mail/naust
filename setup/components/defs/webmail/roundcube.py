"""
Roundcube webmail.

Uses the -complete release archive which already bundles vendor/ with all PHP
dependencies pre-installed. Running composer install against it is redundant at
best and risks the live vendor/ tree diverging from what this exact release was
tested with.

Steps:
  fetch         - download and deploy the pinned Roundcube release (SHA256 stamp)
  dirs          - create STORAGE_ROOT/roundcube/{temp,logs} and fix ownership
  des-key       - generate des_key once for session/credential encryption
  carddav-fetch - download rcmcarddav plugin (only when ENABLE_RADICALE=true)
  carddav-conf  - write rcmcarddav/config.inc.php pointing to this box's Radicale
  config        - write Roundcube config.inc.php (depends on des-key + carddav-conf)
  db-init       - initialise/upgrade Roundcube SQLite schema via initdb.sh
  carddav-db    - run rcmcarddav SQLite migrations (only when ENABLE_RADICALE=true)
"""

import os
import subprocess
import shutil
import tempfile

from doit.tools import config_changed

from ... import artifacts
from ...component import Component
import pathlib

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="roundcube",
	packages=[
		"php-cli",
		"php-fpm",
		"php-sqlite3",
		"php-intl",
		"php-json",
		"php-common",
		"php-xml",
		"php-mbstring",
		"php-curl",
		"php-zip",
		"php-gd",
		"php-imagick",
		"php-pear",
		"unzip",
		"sqlite3",
		"ca-certificates",
	],
	services=[],  # runs under PHP-FPM, no own service
	docker_services=[],
	enabled=lambda env: env.get("WEBMAIL_CLIENT", "rav") == "roundcube",
)

ROUNDCUBE_VERSION = "1.7.2"
# GitHub's own computed digest for this asset, cross-checked against the
# maintainer's .asc signature when bumping - never trust a hash fetched from
# the same place as the archive at install time.
ROUNDCUBE_SHA256 = "01bf9ede1665e507db94bab1361ebed20ee353dba04bc628b00fb6eca05af3d1"
ROUNDCUBE_URL = f"https://github.com/roundcube/roundcubemail/releases/download/{ROUNDCUBE_VERSION}/roundcubemail-{ROUNDCUBE_VERSION}-complete.tar.gz"

RCMCARDDAV_VERSION = "5.1.3"
RCMCARDDAV_SHA256 = "f6c84fcbb7726292f13cdec7cd74bd93cb4241f6f4650e8dde3bca004b39908a"
RCMCARDDAV_URL = f"https://github.com/mstilkerich/rcmcarddav/releases/download/v{RCMCARDDAV_VERSION}/carddav-v{RCMCARDDAV_VERSION}.tar.gz"

_RC_SRC = "/usr/local/src/roundcube"
_RC_TARGET = "/usr/local/share/roundcube"
_RC_STAMP = "/usr/local/share/roundcube.version"
_CARDDAV_DIR = f"{_RC_TARGET}/plugins/carddav"
_CARDDAV_STAMP = "/usr/local/share/roundcube-carddav.version"


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	storage_root = env["STORAGE_ROOT"]
	hostname = env.get("PRIMARY_HOSTNAME", "localhost")
	enable_radicale = env.get("ENABLE_RADICALE", "true").lower() != "false"
	# Enigma ships with every Roundcube release, so enabling PGP is just a matter
	# of adding it to the plugin list - no extra download or dependency.
	enable_pgp = env.get("WEBMAIL_PGP", "false").lower() == "true"
	rc_db = os.path.join(storage_root, "roundcube", "sqlite.db")
	des_key_file = os.path.join(storage_root, "roundcube", "des_key.txt")

	tasks = [
		{
			"name": "fetch",
			# A directory-exists check alone would mean bumping ROUNDCUBE_VERSION
			# silently never re-downloads on an already-installed box. The stamp
			# file records the installed version and triggers redeploy on change.
			"targets": [_RC_STAMP],
			"uptodate": [config_changed(ROUNDCUBE_VERSION)],
			"actions": [(_fetch,)],
		},
		{
			"name": "dirs",
			"uptodate": [config_changed(f"{storage_root}:{artifacts.fn_stamp(_dirs)}")],
			"actions": [(_dirs, [storage_root])],
		},
		{
			"name": "des-key",
			# Generate once; never regenerate - regeneration would invalidate all sessions.
			"targets": [des_key_file],
			"task_dep": ["roundcube:dirs"],
			"actions": [(_des_key, [des_key_file])],
		},
		{
			"name": "config",
			"targets": [f"{_RC_TARGET}/config/config.inc.php"],
			"uptodate": [config_changed(f"{storage_root}:{hostname}:{enable_radicale}:{enable_pgp}:{artifacts.fn_stamp(_config)}")],
			"task_dep": ["roundcube:des-key"],
			"actions": [(_config, [storage_root, hostname, des_key_file, enable_radicale, enable_pgp])],
		},
		{
			"name": "db-init",
			# Always run: initdb.sh is idempotent and handles both init and migration.
			"uptodate": [config_changed(artifacts.fn_stamp(_db_init))],
			"task_dep": ["roundcube:config"],
			"actions": [(_db_init,)],
		},
	]

	if enable_radicale:
		tasks += [
			{
				"name": "carddav-fetch",
				"targets": [_CARDDAV_STAMP],
				"uptodate": [config_changed(RCMCARDDAV_VERSION)],
				"actions": [(_carddav_fetch,)],
			},
			{
				"name": "carddav-conf",
				"targets": [f"{_CARDDAV_DIR}/config.inc.php"],
				"uptodate": [config_changed(f"{hostname}:{artifacts.fn_stamp(_carddav_conf)}")],
				"task_dep": ["roundcube:carddav-fetch"],
				"actions": [(_carddav_conf, [hostname])],
			},
			{
				"name": "carddav-db",
				# rcmcarddav migrations are idempotent; re-runs when rcmcarddav version changes.
				"uptodate": [config_changed(RCMCARDDAV_VERSION)],
				"task_dep": ["roundcube:db-init", "roundcube:carddav-fetch"],
				"actions": [(_carddav_db, [rc_db])],
			},
		]
		# config must include the carddav plugin; rebuild when carddav-conf runs.
		tasks[3]["task_dep"] = ["roundcube:des-key", "roundcube:carddav-conf"]

	return tasks


# ── Action functions ──────────────────────────────────────────────────────────


def _fetch() -> None:
	"""Download, verify, and deploy the pinned Roundcube release."""
	tmp_fd, tmp = tempfile.mkstemp(suffix=".tar.gz")
	os.close(tmp_fd)
	try:
		print(f"Downloading Roundcube {ROUNDCUBE_VERSION}...", flush=True)
		subprocess.run(["wget", "-q", "-O", tmp, ROUNDCUBE_URL], check=True)
		result = subprocess.run(
			["sha256sum", "--check", "--strict"],
			input=f"{ROUNDCUBE_SHA256}  {tmp}",
			text=True,
			capture_output=True,
			check=False,
		)
		if result.returncode != 0:
			msg = f"Roundcube SHA256 mismatch: {result.stderr.strip()}"
			raise RuntimeError(msg)

		shutil.rmtree(_RC_SRC, ignore_errors=True)
		os.makedirs(_RC_SRC, exist_ok=True)
		subprocess.run(["tar", "-xzf", tmp, "--strip-components=1", "-C", _RC_SRC], check=True)
	finally:
		if os.path.exists(tmp):
			os.unlink(tmp)

	os.makedirs(_RC_TARGET, exist_ok=True)
	subprocess.run(
		["rsync", "-a", "--delete", _RC_SRC + "/", _RC_TARGET + "/"],
		check=True,
		capture_output=True,
	)
	subprocess.run(["chown", "-R", "root:root", _RC_TARGET], check=True)
	subprocess.run(["chmod", "-R", "755", _RC_TARGET], check=True)

	pathlib.Path(_RC_STAMP).write_text(ROUNDCUBE_VERSION, encoding="utf-8")


def _dirs(storage_root: str) -> None:
	"""Create Roundcube data directories. chown -R only on first creation."""
	rc_dir = os.path.join(storage_root, "roundcube")
	logs_dir = os.path.join(rc_dir, "logs")
	temp_dir = os.path.join(rc_dir, "temp")
	login_log = os.path.join(logs_dir, "userlogins.log")
	first_creation = not os.path.exists(rc_dir)

	os.makedirs(logs_dir, exist_ok=True)
	os.makedirs(temp_dir, exist_ok=True)

	if first_creation:
		# Ensure the log file exists before fail2ban starts watching it -
		# log_logins only creates it on the first actual login attempt otherwise.
		open(login_log, "a", encoding="utf-8").close()
		subprocess.run(["chown", "-R", "www-data:www-data", rc_dir], check=True)
	else:
		if not os.path.exists(login_log):
			open(login_log, "a", encoding="utf-8").close()
		subprocess.run(["chown", "www-data:www-data", login_log], check=True)

	subprocess.run(["chmod", "750", rc_dir], check=True)


def _des_key(des_key_file: str) -> None:
	"""Generate des_key once for session/credential encryption.

	This key is never regenerated on subsequent setup runs - doing so would
	invalidate all existing sessions and any stored credentials.

	This is purposely gated behind a file existence so that in the case of a
	forceful re-run with --always-execute, the des_key is preserved and not regenerated.
	"""
	if os.path.exists(des_key_file):
		print("DES key for Roundcube already exists - refusing to regenerate.")
		print(f"(Regenerating des_key invalidates existing sessions/encrypted stored credentials. Key file: {des_key_file})")
		return
	result = subprocess.run(
		["openssl", "rand", "-base64", "24"],
		capture_output=True,
		text=True,
		check=True,
	)
	key = result.stdout.strip()[:24]
	old_umask = os.umask(0o177)
	try:
		pathlib.Path(des_key_file).write_text(key, encoding="utf-8")
	finally:
		os.umask(old_umask)


def _config(storage_root: str, _hostname: str, des_key_file: str, enable_radicale: bool, enable_pgp: bool = False) -> None:
	"""Write Roundcube runtime config and fix ownership."""
	des_key = pathlib.Path(des_key_file).read_text(encoding="utf-8").strip()

	plugin_list = ["'archive'", "'zipdownload'"]
	if enable_radicale:
		plugin_list.append("'carddav'")
	if enable_pgp:
		# Enigma provides OpenPGP encryption/signing in the webmail UI.
		plugin_list.append("'enigma'")
	plugins = ", ".join(plugin_list)

	artifacts.write_file(
		f"{_RC_TARGET}/config/config.inc.php",
		"<?php\n"
		"$config = [];\n"
		"\n"
		# mode=0646: SQLite creates the DB file with these permissions so PHP-FPM
		# (www-data) can read/write it while root-owned config files stay unreadable.
		f"$config['db_dsnw'] = 'sqlite:///{storage_root}/roundcube/sqlite.db?mode=0646';\n"
		"\n"
		"$config['imap_host'] = '127.0.0.1:143';\n"
		"$config['smtp_host'] = '127.0.0.1:587';\n"
		"$config['smtp_user'] = '%u';\n"
		"$config['smtp_pass'] = '%p';\n"
		"\n"
		f"$config['temp_dir'] = '{storage_root}/roundcube/temp';\n"
		f"$config['log_dir'] = '{storage_root}/roundcube/logs';\n"
		"\n"
		"// Writes logs/userlogins.log on every login attempt for fail2ban.\n"
		"$config['log_logins'] = true;\n"
		"\n"
		f"$config['des_key'] = '{des_key}';\n"
		"$config['session_lifetime'] = 1440; // 24 Hours\n"
		"\n"
		f"$config['plugins'] = [{plugins}];\n",
	)
	subprocess.run(["chown", "-R", "root:www-data", f"{_RC_TARGET}/config"], check=True)
	subprocess.run(["chmod", "640", f"{_RC_TARGET}/config/config.inc.php"], check=True)


def _db_init() -> None:
	"""Initialise or upgrade the Roundcube SQLite schema.

	--update makes initdb.sh check for the system table first: if found it runs
	db_update (idempotent migrations) rather than db_init. SQLite auto-initializes
	on first connect so the system table always exists on fresh SQLite DBs;
	MySQL/PostgreSQL on a fresh DB fall through to db_init instead.
	Safe to re-run on every setup pass.
	"""
	print("Initialising the Roundcube database...", flush=True)
	result = subprocess.run(
		["php", f"{_RC_TARGET}/bin/initdb.sh", "--update", "--dir", f"{_RC_TARGET}/SQL"],
		check=False,
		capture_output=True,
		text=True,
	)
	if result.returncode != 0:
		print(f"WARNING: Roundcube initdb.sh reported an error:\n{result.stdout}{result.stderr}")


def _carddav_fetch() -> None:
	"""Download and install the pinned rcmcarddav plugin."""
	tmp_fd, tmp = tempfile.mkstemp(suffix=".tar.gz")
	os.close(tmp_fd)
	try:
		print(f"Downloading rcmcarddav {RCMCARDDAV_VERSION}...", flush=True)
		subprocess.run(["wget", "-q", "-O", tmp, RCMCARDDAV_URL], check=True)
		result = subprocess.run(
			["sha256sum", "--check", "--strict"],
			input=f"{RCMCARDDAV_SHA256}  {tmp}",
			text=True,
			capture_output=True,
			check=False,
		)
		if result.returncode != 0:
			msg = f"rcmcarddav SHA256 mismatch: {result.stderr.strip()}"
			raise RuntimeError(msg)

		shutil.rmtree(_CARDDAV_DIR, ignore_errors=True)
		os.makedirs(_CARDDAV_DIR, exist_ok=True)
		subprocess.run(["tar", "-xzf", tmp, "--strip-components=1", "-C", _CARDDAV_DIR], check=True)
	finally:
		if os.path.exists(tmp):
			os.unlink(tmp)

	pathlib.Path(_CARDDAV_STAMP).write_text(RCMCARDDAV_VERSION, encoding="utf-8")


def _carddav_conf(hostname: str) -> None:
	"""Write rcmcarddav plugin config pointing to this box's Radicale server.

	%u expands to the IMAP username, which is the full email address in NAUST.
	"""
	artifacts.write_file(
		f"{_CARDDAV_DIR}/config.inc.php",
		"<?php\n"
		"$prefs['_GLOBAL']['pwstore_scheme'] = 'encrypted';\n"
		"$prefs['_GLOBAL']['loglevel'] = \\Psr\\Log\\LogLevel::WARNING;\n"
		"\n"
		"$prefs['radicale'] = [\n"
		"    'name'           => 'Contacts',\n"
		f"    'url'            => 'https://{hostname}/radicale/%u/',\n"
		"    'active'         => true,\n"
		"    'use_categories' => true,\n"
		"    'fixed'          => ['url'],\n"
		"];\n",
		mode=0o640,
	)
	subprocess.run(["chown", "root:www-data", f"{_CARDDAV_DIR}/config.inc.php"], check=True)
	subprocess.run(["chmod", "644", f"{_CARDDAV_DIR}/config.inc.php"], check=True)


def _carddav_db(rc_db: str) -> None:
	"""Run rcmcarddav SQLite migrations against the Roundcube database."""
	migrations_dir = f"{_CARDDAV_DIR}/dbmigrations/sqlite3"
	if not os.path.isdir(migrations_dir):
		return
	sql_files = sorted(os.path.join(migrations_dir, f) for f in os.listdir(migrations_dir) if f.endswith(".sql"))
	for sql_file in sql_files:
		sql = pathlib.Path(sql_file).read_text(encoding="utf-8")
		subprocess.run(["sqlite3", rc_db], input=sql, text=True, check=True)
