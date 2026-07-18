"""
SnappyMail webmail.

Steps:
  fetch   - download, patch (wildcard-domain bug), and deploy the pinned release
  dirs    - create STORAGE_ROOT/snappymail data directories
  config  - write config.ini (security settings, fail2ban logging)
  domain  - write default.json (IMAP/SMTP domain config for all mail domains)
"""

import os
import subprocess

from doit.tools import config_changed

from ... import artifacts
from ...component import Component
import pathlib

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="snappymail",
	notices=[
		"SnappyMail is licensed under AGPL v3. As the server operator you must",
		"ensure users who interact with SnappyMail can access its source code.",
		"Source: https://github.com/the-djmaze/snappymail",
	],
	packages=[
		"php-cli",
		"php-fpm",
		"php-sqlite3",
		"php-json",
		"php-common",
		"php-xml",
		"php-mbstring",
		"php-curl",
		"php-zip",
		"php-gd",
		"ca-certificates",
		"unzip",
		# php-intl intentionally omitted: SnappyMail ships its own polyfill
		# (app/libraries/polyfill/intl.php) so it's optional, not a hard dep.
	],
	services=[],  # runs under PHP-FPM, no own service
	docker_services=[],
	enabled=lambda env: env.get("WEBMAIL_CLIENT", "rav") == "snappymail",
)

SNAPPYMAIL_VERSION = "2.38.2"
# SnappyMail doesn't publish a GitHub-computed digest for this asset, so the
# hash was computed directly from the release zip when this pin was added.
# Never trust a hash fetched from the same place as the archive at install time.
SNAPPYMAIL_SHA256 = "ad37235002520958094f69bfe97952aab773c5634d68d967db4fc2d439f26399"
SNAPPYMAIL_URL = f"https://github.com/the-djmaze/snappymail/releases/download/v{SNAPPYMAIL_VERSION}/snappymail-{SNAPPYMAIL_VERSION}.zip"

_SM_SRC = "/usr/local/src/snappymail"
_SM_TARGET = "/usr/local/share/snappymail"
_SM_STAMP = "/usr/local/share/snappymail.version"

# Lines to replace in DefaultDomain.php to fix the wildcard-domain fallback bug.
# See roundcube.sh comments for full explanation.
_BUGGY_LINE = r'$sName = \strtolower(\idn_to_ascii($sName));'
_FIXED_LINE = r'$sName = "*" === $sName ? $sName : \strtolower(\idn_to_ascii($sName));'
_DOMAIN_PHP = f"{_SM_SRC}/snappymail/v/{SNAPPYMAIL_VERSION}/app/libraries/RainLoop/Providers/Domain/DefaultDomain.php"


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	storage_root = env["STORAGE_ROOT"]
	sm_data = os.path.join(storage_root, "snappymail", "_data_", "_default_")
	sm_config_ini = os.path.join(sm_data, "configs", "config.ini")
	sm_domain_json = os.path.join(sm_data, "domains", "default.json")

	return [
		{
			"name": "fetch",
			# Stamp includes the script's own function bodies so a patch change
			# (e.g. wildcard-domain fix update) forces redeploy even when the
			# version string hasn't changed.
			"targets": [_SM_STAMP],
			"uptodate": [config_changed(f"{SNAPPYMAIL_VERSION}:{artifacts.fn_stamp(_fetch)}")],
			"actions": [(_fetch,)],
		},
		{
			"name": "dirs",
			"uptodate": [config_changed(f"{storage_root}:{artifacts.fn_stamp(_dirs)}")],
			"actions": [(_dirs, [storage_root])],
		},
		{
			"name": "config",
			"targets": [sm_config_ini],
			"uptodate": [config_changed(f"{storage_root}:{artifacts.fn_stamp(_config)}")],
			"task_dep": ["snappymail:dirs"],
			"actions": [(_config, [storage_root])],
		},
		{
			"name": "domain",
			"targets": [sm_domain_json],
			"uptodate": [config_changed(f"{storage_root}:{artifacts.fn_stamp(_domain)}")],
			"task_dep": ["snappymail:dirs"],
			"actions": [(_domain, [storage_root])],
		},
	]


# ── Action functions ──────────────────────────────────────────────────────────


def _fetch() -> None:
	"""Download, verify, apply upstream bug patch, and deploy SnappyMail.

	The wildcard-domain bug in DefaultDomain.php (present in 2.38.2) causes
	idn_to_ascii('*') to corrupt the domain name to an empty string before the
	'*' sentinel special-case runs, making default.json unreachable. Patched
	here idempotently on every run so boxes that already had this version
	downloaded before the patch was introduced pick it up on the next rerun.
	"""
	import shutil
	import tempfile

	tmp_fd, tmp = tempfile.mkstemp(suffix=".zip")
	os.close(tmp_fd)
	try:
		print(f"Downloading SnappyMail {SNAPPYMAIL_VERSION}...", flush=True)
		subprocess.run(["wget", "-q", "-O", tmp, SNAPPYMAIL_URL], check=True)
		result = subprocess.run(
			["sha256sum", "--check", "--strict"],
			input=f"{SNAPPYMAIL_SHA256}  {tmp}",
			text=True,
			capture_output=True,
			check=False,
		)
		if result.returncode != 0:
			msg = f"SnappyMail SHA256 mismatch: {result.stderr.strip()}"
			raise RuntimeError(msg)

		shutil.rmtree(_SM_SRC, ignore_errors=True)
		os.makedirs(_SM_SRC, exist_ok=True)
		# The release zip is not flat - it nests the real app under
		# snappymail/v/<version>/app/, which is SnappyMail's own multi-version
		# layout for its built-in updater. Extracting the whole tree as-is is
		# correct; index.php at the top level resolves the active version
		# through that nested path itself.
		subprocess.run(["unzip", "-q", "-o", tmp, "-d", _SM_SRC], check=True)
	finally:
		if os.path.exists(tmp):
			os.unlink(tmp)

	# Apply wildcard-domain bug patch idempotently.
	if not os.path.exists(_DOMAIN_PHP):
		print(
			"WARNING: DefaultDomain.php not found at expected path - cannot apply wildcard-domain bug patch.",
			flush=True,
		)
	else:
		content = pathlib.Path(_DOMAIN_PHP).read_text(encoding="utf-8")
		if _FIXED_LINE in content:
			pass  # already patched
		elif _BUGGY_LINE in content:
			pathlib.Path(_DOMAIN_PHP).write_text(content.replace(_BUGGY_LINE, _FIXED_LINE), encoding="utf-8")
			print("Patched SnappyMail wildcard-domain fallback bug (DefaultDomain.php).")
		else:
			print(
				"WARNING: SnappyMail wildcard-domain bug patch target not found - upstream may have already fixed or changed this. default.json fallback may not work; check manually.",
				flush=True,
			)

	os.makedirs(_SM_TARGET, exist_ok=True)
	subprocess.run(
		["rsync", "-a", "--delete", _SM_SRC + "/", _SM_TARGET + "/"],
		check=True,
		capture_output=True,
	)
	subprocess.run(["chown", "-R", "root:root", _SM_TARGET], check=True)
	subprocess.run(["chmod", "-R", "755", _SM_TARGET], check=True)

	pathlib.Path(_SM_STAMP).write_text(SNAPPYMAIL_VERSION, encoding="utf-8")


def _dirs(storage_root: str) -> None:
	"""Create SnappyMail data directories. chown -R only on first creation."""
	data_dir = os.path.join(storage_root, "snappymail")
	configs_dir = os.path.join(data_dir, "_data_", "_default_", "configs")
	domains_dir = os.path.join(data_dir, "_data_", "_default_", "domains")

	fresh = not os.path.isdir(data_dir)
	os.makedirs(configs_dir, exist_ok=True)
	os.makedirs(domains_dir, exist_ok=True)
	if fresh:
		subprocess.run(["chown", "-R", "www-data:www-data", data_dir], check=True)
		subprocess.run(["chmod", "-R", "750", data_dir], check=True)

	# Write the include.php redirect so SnappyMail uses the external data dir.
	# APP_INDEX_ROOT_PATH + 'include.php' is the only real hook - _include.php
	# (with underscore) is an unused example template that nothing ever loads.
	artifacts.write_file(
		f"{_SM_TARGET}/include.php",
		f"<?php\ndefine('APP_DATA_FOLDER_PATH', '{data_dir}/');\n",
	)


def _config(storage_root: str) -> None:
	"""Write config.ini: disable admin panel, enable fail2ban auth logging.

	allow_admin=Off: NAUST already has its own control panel. An enabled-by-default
	admin UI with an auto-generated password that's never surfaced to the admin is
	a needless attack surface for a feature nobody asked for.

	auth_logging=On writes a syslog entry (tag 'snappymail') on every failed login
	attempt. auth_logging_format is not set so only syslog fires, not an additional
	app-managed log file.
	"""
	data_dir = os.path.join(storage_root, "snappymail")
	config_ini = os.path.join(data_dir, "_data_", "_default_", "configs", "config.ini")

	artifacts.write_file(
		config_ini,
		"[security]\nallow_admin = Off\nforce_https = On\n\n[logs]\nauth_logging = On\n",
	)
	subprocess.run(["chown", "www-data:www-data", config_ini], check=True)


def _domain(storage_root: str) -> None:
	"""Write default.json: IMAP/SMTP connection settings for all domains.

	Schema must match RainLoop\\Model\\Domain::fromArray()'s legacy flat format
	exactly - camelCase keys, integer security-type codes. fromArray() checks for
	a nested IMAP/SMTP/Sieve object first; failing that, falls back to flat
	imapHost/imapPort/etc keys. Neither snake_case nor string-valued security
	types match, causing fromArray() to silently return null and log
	"Undefined array key imapHost" even after the wildcard bug is fixed.

	Security type codes (MailSo\\Net\\Enumerations\\ConnectionSecurityType):
	  NONE=0, SSL/TLS=1, STARTTLS=2.
	IMAP 143 is plaintext loopback (0); SMTP 587 is mandatory STARTTLS (2).
	"""
	data_dir = os.path.join(storage_root, "snappymail")
	domain_json = os.path.join(data_dir, "_data_", "_default_", "domains", "default.json")

	artifacts.write_file(
		domain_json,
		'{\n'
		'    "imapHost": "127.0.0.1",\n'
		'    "imapPort": 143,\n'
		'    "imapSecure": 0,\n'
		'    "imapShortLogin": false,\n'
		'    "useSieve": false,\n'
		'    "sieveHost": "127.0.0.1",\n'
		'    "sievePort": 4190,\n'
		'    "sieveSecure": 0,\n'
		'    "smtpHost": "127.0.0.1",\n'
		'    "smtpPort": 587,\n'
		'    "smtpSecure": 2,\n'
		'    "smtpShortLogin": false,\n'
		'    "smtpAuth": true,\n'
		'    "whiteList": ""\n'
		'}\n',
	)
	subprocess.run(["chown", "www-data:www-data", domain_json], check=True)
