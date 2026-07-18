"""
Cypht webmail.

Steps:
  fetch     - download, apply patches, run composer install, deploy to target
  dirs      - create STORAGE_ROOT/cypht/{users,attachments}
  auth-log  - create /var/log/cypht-auth.log with correct ownership for fail2ban
  logrotate - write logrotate config for auth log
  config    - write .env and run config_gen.php (every run)
"""

import os
import subprocess

from doit.tools import config_changed

from ... import artifacts, SETUP_DIR
from ...component import Component
import pathlib

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="cypht",
	packages=[
		"php-cli",
		"php-fpm",
		"php-curl",
		"php-mbstring",
		"php-zip",
		"php-json",
		"php-intl",
		"php-xml",
		"php-soap",
		"php-gd",
		"ca-certificates",
		"composer",
		"unzip",
	],
	services=[],  # runs under PHP-FPM, no own service
	docker_services=[],
	enabled=lambda env: env.get("WEBMAIL_CLIENT", "rav") == "cypht",
)

# Pinned to a commit rather than a release tag so merged upstream fixes land
# without waiting for a release. Update CYPHT_COMMIT + CYPHT_SHA256 together.
CYPHT_COMMIT = "0e8c64c01acb862e0271c14491166334245de279"
CYPHT_SHA256 = "9f4704482915e8467ef872bc953214477d89dd6950da7196980867fbf9caa7b0"
CYPHT_URL = f"https://github.com/cypht-org/cypht/archive/{CYPHT_COMMIT}.tar.gz"

_CYPHT_SRC = "/usr/local/src/cypht"
_CYPHT_TARGET = "/usr/local/share/cypht"
_CYPHT_STAMP = "/usr/local/share/cypht.version"

_BASE_MODULES = "core,contacts,local_contacts,feeds,imap,smtp,account,idle_timer,desktop_notifications,themes,nux,profiles,imap_folders,sievefilters,tags,history,scheduled_sends"

# PHP handler classes injected into the upstream sources by the patch
# functions below, plus the .env template. Whole file bodies live under
# setup/conf/, not inline.
_CARDDAV_HANDLER_SRC = os.path.join(SETUP_DIR, "conf", "cypht", "carddav-autofill.php")
_LOGIN_LOGGER_SRC = os.path.join(SETUP_DIR, "conf", "cypht", "failed-login-logger.php")
_ENV_TPL = os.path.join(SETUP_DIR, "conf", "cypht", "env")


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	storage_root = env["STORAGE_ROOT"]
	enable_radicale = env.get("ENABLE_RADICALE", "true").lower() != "false"

	return [
		{
			"name": "fetch",
			# Stamp includes fn_stamp of _fetch plus the injected handler
			# sources so patch changes force redeploy even when the commit
			# pin hasn't changed (fn_stamp cannot see template files).
			"targets": [_CYPHT_STAMP],
			"uptodate": [config_changed(f"{CYPHT_COMMIT}:{artifacts.hash_files(_CARDDAV_HANDLER_SRC, _LOGIN_LOGGER_SRC)}:{artifacts.fn_stamp(_fetch)}")],
			"actions": [(_fetch,)],
		},
		{
			"name": "dirs",
			"uptodate": [config_changed(f"{storage_root}:{artifacts.fn_stamp(_dirs)}")],
			"actions": [(_dirs, [storage_root])],
		},
		{
			"name": "auth-log",
			"uptodate": [config_changed(artifacts.fn_stamp(_auth_log))],
			"actions": [(_auth_log,)],
		},
		{
			"name": "logrotate",
			"uptodate": [config_changed(artifacts.fn_stamp(_logrotate))],
			"actions": [(_logrotate,)],
		},
		{
			"name": "config",
			"targets": [f"{_CYPHT_TARGET}/.env"],
			# Re-runs when env vars or module list changes - config_gen.php re-reads .env.
			"uptodate": [config_changed(f"{storage_root}:{enable_radicale}:{artifacts.hash_files(_ENV_TPL)}:{artifacts.fn_stamp(_config)}")],
			"task_dep": ["cypht:fetch", "cypht:dirs"],
			"actions": [(_config, [storage_root, enable_radicale])],
		},
	]


# ── Action functions ──────────────────────────────────────────────────────────


def _fetch() -> None:
	"""Download, verify, patch, composer install, and deploy Cypht.

	Patches applied (all idempotent guards so re-runs are safe):
	- index.php APP_PATH: blank -> absolute path (fixes .env loading under PHP-FPM)
	- carddav_contacts: auto-populate CardDAV creds on login (modules.php + setup.php)
	- carddav_contacts: hide credentials form in SINGLE_SERVER_MODE
	- core/imap/smtp/nux: hide server-adding wizard in SINGLE_SERVER_MODE
	- imap: hide EWS server config in SINGLE_SERVER_MODE
	- carddav_contacts: rename 'Add Carddav' button to 'Add Contact'
	- lib/environment.php: fall back to $_ENV for Symfony Dotenv 6.x compat
	- core: log failed logins with real client IP for fail2ban (handler_modules + setup)
	"""
	import re
	import shutil
	import tempfile

	tmp_fd, tmp = tempfile.mkstemp(suffix=".tar.gz")
	os.close(tmp_fd)
	try:
		print("Downloading Cypht...", flush=True)
		subprocess.run(["wget", "-q", "-O", tmp, CYPHT_URL], check=True)
		result = subprocess.run(
			["sha256sum", "--check", "--strict"],
			input=f"{CYPHT_SHA256}  {tmp}",
			text=True,
			capture_output=True,
			check=False,
		)
		if result.returncode != 0:
			msg = f"Cypht SHA256 mismatch: {result.stderr.strip()}"
			raise RuntimeError(msg)

		shutil.rmtree(_CYPHT_SRC, ignore_errors=True)
		os.makedirs(_CYPHT_SRC, exist_ok=True)
		subprocess.run(["tar", "-xzf", tmp, "--strip-components=1", "-C", _CYPHT_SRC], check=True)
	finally:
		if os.path.exists(tmp):
			os.unlink(tmp)

	# Install vendor dependencies.
	env_copy = os.environ.copy()
	env_copy["COMPOSER_ALLOW_SUPERUSER"] = "1"
	print("Installing Cypht dependencies via composer...", flush=True)
	subprocess.run(
		["composer", "install", "--no-dev", "--working-dir", _CYPHT_SRC],
		check=True,
		env=env_copy,
	)

	os.makedirs(_CYPHT_TARGET, exist_ok=True)
	subprocess.run(
		["rsync", "-a", "--delete", _CYPHT_SRC + "/", _CYPHT_TARGET + "/"],
		check=True,
		capture_output=True,
	)

	# Patch index.php: fix APP_PATH so PHP-FPM can find .env regardless of CWD.
	_patch_file(
		f"{_CYPHT_TARGET}/index.php",
		"define('APP_PATH', '');",
		"define('APP_PATH', dirname(__FILE__).'/');",
	)

	# Patch carddav_contacts: auto-populate credentials on login.
	_patch_carddav_autofill(
		f"{_CYPHT_TARGET}/modules/carddav_contacts/modules.php",
		f"{_CYPHT_TARGET}/modules/carddav_contacts/setup.php",
	)

	# Patch carddav_contacts: hide credentials form in single-server mode.
	_patch_single_server_carddav(f"{_CYPHT_TARGET}/modules/carddav_contacts/modules.php")

	# Patch server-adding wizard modules to check single_server_mode.
	_patch_single_server_wizard(_CYPHT_TARGET, re)

	# Patch EWS output module.
	_patch_single_server_ews(f"{_CYPHT_TARGET}/modules/imap/output_modules.php")

	# Rename 'Add Carddav' to 'Add Contact'.
	_patch_file(
		f"{_CYPHT_TARGET}/modules/carddav_contacts/modules.php",
		"trans('Add Carddav')",
		"trans('Add Contact')",
	)

	# Fix env() for Symfony Dotenv 6.x: fall back to $_ENV if getenv returns false.
	_patch_env_function(f"{_CYPHT_TARGET}/lib/environment.php", re)

	# Add failed-login logging handler for fail2ban (writes real client IP).
	_patch_failed_login_logger(
		f"{_CYPHT_TARGET}/modules/core/handler_modules.php",
		f"{_CYPHT_TARGET}/modules/core/setup.php",
	)

	subprocess.run(["chown", "-R", "root:root", _CYPHT_TARGET], check=True)

	pathlib.Path(_CYPHT_STAMP).write_text(CYPHT_COMMIT, encoding="utf-8")


def _patch_file(path: str, old: str, new: str) -> None:
	"""Replace old with new in path (once, idempotent)."""
	content = pathlib.Path(path).read_text(encoding="utf-8")
	if new in content:
		return
	if old not in content:
		return
	pathlib.Path(path).write_text(content.replace(old, new, 1), encoding="utf-8")


def _patch_carddav_autofill(modules_php: str, setup_php: str) -> None:
	"""Inject handler that auto-populates CardDAV credentials from login credentials."""
	handler = "\n" + artifacts.render_template(_CARDDAV_HANDLER_SRC)
	hook = "add_handler('home', 'auto_populate_carddav_credentials', true, 'carddav_contacts', 'load_user_data', 'after');"
	c = pathlib.Path(modules_php).read_text(encoding="utf-8")
	if "auto_populate_carddav_credentials" not in c:
		pathlib.Path(modules_php).write_text(c.rstrip() + "\n" + handler + "\n", encoding="utf-8")

	c = pathlib.Path(setup_php).read_text(encoding="utf-8")
	if "auto_populate_carddav_credentials" not in c:
		pathlib.Path(setup_php).write_text(c.replace("handler_source(", hook + "\n" + "handler_source(", 1), encoding="utf-8")


def _patch_single_server_carddav(modules_php: str) -> None:
	"""Hide CardDAV credentials form when SINGLE_SERVER_MODE is active."""
	needle = "protected function output() {\n        $settings = $this->get('carddav_settings'"
	guard = "protected function output() {\n        if (filter_var(env('SINGLE_SERVER_MODE', 'false'), FILTER_VALIDATE_BOOLEAN)) { return ''; }\n        $settings = $this->get('carddav_settings'"
	c = pathlib.Path(modules_php).read_text(encoding="utf-8")
	if needle in c and guard not in c:
		pathlib.Path(modules_php).write_text(c.replace(needle, guard, 1), encoding="utf-8")


def _patch_single_server_wizard(target: str, re) -> None:
	"""Inject single_server_mode guard into server-adding wizard output modules.

	The server-adding wizard (stepper) is split across many output modules: the
	container, form steps, end-parts, and the NUX 'Add a new server' button.
	Each module must independently check single_server_mode because the module
	system concatenates HTML strings - returning '' from the container but not
	the children leaves the child HTML orphaned on the page.
	"""
	guard_php = "if ($this->get('single_server_mode')) { return ''; }"
	patches = [
		(
			f"{target}/modules/core/output_modules.php",
			[
				"Hm_Output_server_config_stepper",
				"Hm_Output_server_config_stepper_end_part",
				"Hm_Output_server_config_stepper_accordion_end_part",
			],
		),
		(
			f"{target}/modules/imap/output_modules.php",
			[
				"Hm_Output_stepper_setup_server_jmap",
				"Hm_Output_stepper_setup_server_imap",
				"Hm_Output_stepper_setup_server_jmap_imap_common",
			],
		),
		(
			f"{target}/modules/smtp/modules.php",
			[
				"Hm_Output_stepper_setup_server_smtp",
			],
		),
		(
			f"{target}/modules/nux/modules.php",
			[
				"Hm_Output_quick_add_multiple_section",
			],
		),
	]
	for fpath, classes in patches:
		c = pathlib.Path(fpath).read_text(encoding="utf-8")
		for cls in classes:
			if guard_php not in c:
				pat = (
					r"(class " + re.escape(cls) + r"\s+extends\s+Hm_Output_Module\s*\{.*?"
					r"protected\s+function\s+output\s*\(\s*\)\s*\{)"
				)
				c = re.sub(
					pat,
					lambda m: m.group(0) + "\n        " + guard_php,
					c,
					flags=re.DOTALL,
					count=1,
				)
		pathlib.Path(fpath).write_text(c, encoding="utf-8")


def _patch_single_server_ews(output_modules_php: str) -> None:
	"""Hide EWS server config in single-server mode (upstream omits the check)."""
	needle = "class Hm_Output_server_config_ews extends Hm_Output_Module {\n    protected function output() {\n        $hasEWSActivated"
	guard = "class Hm_Output_server_config_ews extends Hm_Output_Module {\n    protected function output() {\n        if ($this->get('single_server_mode')) { return ''; }\n        $hasEWSActivated"
	c = pathlib.Path(output_modules_php).read_text(encoding="utf-8")
	if needle in c and guard not in c:
		pathlib.Path(output_modules_php).write_text(c.replace(needle, guard, 1), encoding="utf-8")


def _patch_env_function(environment_php: str, re) -> None:
	"""Make env() fall back to $_ENV for Symfony Dotenv 6.x compatibility.

	Dotenv 6.x deprecated putenv() - values land in $_ENV only. Cypht's env()
	uses getenv() which reads the process env and sees nothing without this fix.
	"""
	c = pathlib.Path(environment_php).read_text(encoding="utf-8")
	if "$_ENV" in c:
		return
	fixed = "    function env($key, $default = null) {\n        $v = getenv($key);\n        if ($v !== false) return $v;\n        return isset($_ENV[$key]) ? $_ENV[$key] : $default;\n    }"
	c = re.sub(
		r"function env\(\$key,\s*\$default\s*=\s*null\)\s*\{[^}]+\}",
		fixed.lstrip(),
		c,
	)
	pathlib.Path(environment_php).write_text(c, encoding="utf-8")


def _patch_failed_login_logger(handler_modules_php: str, setup_php: str) -> None:
	"""Add handler that logs failed logins with real client IP for fail2ban.

	Without this, Cypht's IMAP auth makes Dovecot see 127.0.0.1 as the source,
	which is whitelisted and never banned.
	"""
	handler = "\n" + artifacts.render_template(_LOGIN_LOGGER_SRC)
	hook = "add_handler('home', 'log_failed_login', false, 'core', 'login', 'after');"
	anchor = "add_handler('home', 'check_missing_passwords'"

	c = pathlib.Path(handler_modules_php).read_text(encoding="utf-8")
	if "log_failed_login" not in c:
		pathlib.Path(handler_modules_php).write_text(c.rstrip() + "\n" + handler + "\n", encoding="utf-8")

	c = pathlib.Path(setup_php).read_text(encoding="utf-8")
	if "log_failed_login" not in c:
		pathlib.Path(setup_php).write_text(c.replace(anchor, hook + "\n" + anchor, 1), encoding="utf-8")


def _dirs(storage_root: str) -> None:
	"""Create Cypht data directories. chown -R only on first creation."""
	data_dir = os.path.join(storage_root, "cypht")
	if not os.path.isdir(data_dir):
		os.makedirs(os.path.join(data_dir, "users"), exist_ok=True)
		os.makedirs(os.path.join(data_dir, "attachments"), exist_ok=True)
		subprocess.run(["chown", "-R", "www-data:www-data", data_dir], check=True)
		subprocess.run(["chmod", "750", data_dir], check=True)
	else:
		os.makedirs(os.path.join(data_dir, "users"), exist_ok=True)
		os.makedirs(os.path.join(data_dir, "attachments"), exist_ok=True)


def _auth_log() -> None:
	"""Create /var/log/cypht-auth.log with www-data:adm ownership for fail2ban."""
	log = "/var/log/cypht-auth.log"
	if not os.path.exists(log):
		open(log, "a", encoding="utf-8").close()
	subprocess.run(["chown", "www-data:adm", log], check=True)
	subprocess.run(["chmod", "640", log], check=True)


def _logrotate() -> None:
	"""Write logrotate config for the Cypht auth log."""
	artifacts.write_file(
		"/etc/logrotate.d/cypht-auth",
		"/var/log/cypht-auth.log {\n    daily\n    rotate 14\n    compress\n    delaycompress\n    missingok\n    notifempty\n    create 640 www-data adm\n}\n",
	)


def _config(storage_root: str, enable_radicale: bool) -> None:
	"""Write .env and run config_gen.php to produce config/dynamic.php.

	AUTH_TYPE=IMAP authenticates directly against Dovecot on 127.0.0.1:143 -
	no separate user database needed.
	SINGLE_SERVER_MODE prevents users from adding external accounts.
	The carddav_contacts module is included only when ENABLE_RADICALE=true;
	local_contacts is dropped to avoid two contact stores in that case.

	config_gen.php must run after every deploy and after .env changes since it
	reads .env and encodes the active module list into config/dynamic.php.
	"""
	data_dir = os.path.join(storage_root, "cypht")

	modules = _BASE_MODULES
	if enable_radicale:
		# Drop local_contacts (avoid two contact stores), add carddav_contacts.
		modules = modules.replace("local_contacts,", "")
		modules += ",carddav_contacts"

	artifacts.write_file(
		f"{_CYPHT_TARGET}/.env",
		artifacts.render_template(
			_ENV_TPL,
			{
				"DATA_DIR": data_dir,
				"MODULES": modules,
			},
		),
		mode=0o640,
	)
	subprocess.run(["chown", "root:www-data", f"{_CYPHT_TARGET}/.env"], check=True)

	result = subprocess.run(
		["php", f"{_CYPHT_TARGET}/scripts/config_gen.php"],
		check=False,
		capture_output=True,
		text=True,
	)
	if result.returncode != 0:
		msg = f"Cypht config_gen.php failed:\n{result.stdout}{result.stderr}"
		raise RuntimeError(msg)

	subprocess.run(["chown", "-R", "root:root", _CYPHT_TARGET], check=True)
	subprocess.run(
		["chown", "-R", "root:www-data", f"{_CYPHT_TARGET}/.env", f"{_CYPHT_TARGET}/config"],
		check=True,
	)
	subprocess.run(
		["chown", "-R", "www-data:www-data", f"{_CYPHT_TARGET}/assets"],
		check=True,
	)
	subprocess.run(["chmod", "-R", "755", _CYPHT_TARGET], check=True)
	subprocess.run(["chmod", "640", f"{_CYPHT_TARGET}/.env"], check=True)
	dynamic_php = f"{_CYPHT_TARGET}/config/dynamic.php"
	if os.path.exists(dynamic_php):
		subprocess.run(["chmod", "644", dynamic_php], check=True)
