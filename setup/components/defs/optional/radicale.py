"""
Radicale CardDAV/CalDAV server.

Replaces Z-Push (ActiveSync). Provides contacts and calendar sync to mobile
clients (DAVx5, iOS, Thunderbird) using the same mail credentials.

Steps:
  venv         - create Python venv at /usr/local/lib/radicale (skipped if exists)
  pip-install  - install radicale + passlib[bcrypt] into the venv
  plugin       - write radicale_naust/auth.py and storage.py plugin package
  config       - write /etc/radicale/config
  log          - create log file + logrotate config
  namespace    - detect mount-namespace support; write drop-in if not available
  systemd      - install and enable the systemd unit
"""

import os
import pathlib
import subprocess

from doit.tools import config_changed

from ... import artifacts, SETUP_DIR
from ...component import Component

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="radicale",
	packages=["python3-venv", "python3-pip"],
	services=["radicale"],
	docker_services=["radicale"],
	enabled=lambda env: env.get("ENABLE_RADICALE", "true").lower() != "false",
)

_VENV = "/usr/local/lib/radicale"
_PLUGIN_DIR = "/usr/local/lib/radicale-naust"

_PIP_PACKAGES = ["radicale>=3.1,<4", "passlib[bcrypt]"]

_CONF_DIR = os.path.join(SETUP_DIR, "conf", "systemd")

# ── Plugin sources ───────────────────────────────────────────────────────────
#
# auth.py validates credentials via managerd's /internal/auth/verify;
# storage.py bridges rav per-user SQLite databases to CardDAV/CalDAV.
# Installed verbatim from setup/conf/radicale/ (no substitutions).

_AUTH_SRC = os.path.join(SETUP_DIR, "conf", "radicale", "auth.py")
_STORAGE_SRC = os.path.join(SETUP_DIR, "conf", "radicale", "storage.py")
_CONFIG_TPL = os.path.join(SETUP_DIR, "conf", "radicale", "config")


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, runtime: str) -> list[dict]:
	storage_root = env["STORAGE_ROOT"]
	webmail = env.get("WEBMAIL_CLIENT", "rav")
	management_host = env.get("MANAGEMENT_HOST", "127.0.0.1")
	bind_host = "0.0.0.0" if runtime == "docker" else "127.0.0.1"

	return [
		{
			"name": "venv",
			"build": True,  # no env needed - safe to run at Docker build time
			# Only run if the venv directory is missing.
			"targets": [_VENV],
			"actions": [(_venv,)],
		},
		{
			"name": "pip-install",
			"build": True,  # no env needed - safe to run at Docker build time
			# Stamp on package list; re-runs when packages change.
			"uptodate": [config_changed(":".join(_PIP_PACKAGES))],
			"task_dep": ["radicale:venv"],
			"actions": [(_pip_install,)],
		},
		{
			"name": "plugin-auth",
			# Plugin source hash is part of the stamp - fn_stamp cannot see it.
			"uptodate": [config_changed(f"{artifacts.hash_files(_AUTH_SRC)}:{artifacts.fn_stamp(_write_plugin_auth)}")],
			"task_dep": ["radicale:pip-install"],
			"actions": [(_write_plugin_auth, [_AUTH_SRC])],
		},
		# Storage plugin bridges rav per-user SQLite to CardDAV/CalDAV.
		# Only needed when rav is the active webmail client.
		*(
			[
				{
					"name": "plugin-storage",
					"uptodate": [config_changed(f"{artifacts.hash_files(_STORAGE_SRC)}:{artifacts.fn_stamp(_write_plugin_storage)}")],
					"task_dep": ["radicale:pip-install"],
					"actions": [(_write_plugin_storage, [_STORAGE_SRC])],
				}
			]
			if webmail == "rav"
			else []
		),
		{
			"name": "config",
			# Stamp includes all values that affect the config output, plus
			# the template hash - fn_stamp cannot see the template file.
			"uptodate": [config_changed(f"{storage_root}:{webmail}:{management_host}:{bind_host}:{artifacts.hash_files(_CONFIG_TPL)}:{artifacts.fn_stamp(_write_config)}")],
			"task_dep": ["radicale:plugin-auth"],
			"actions": [(_write_config, [storage_root, webmail, management_host, bind_host])],
		},
		{
			"name": "log",
			"uptodate": [config_changed(artifacts.fn_stamp(_log))],
			"actions": [(_log,)],
		},
		{
			"name": "namespace",
			# Re-run whenever the function body changes (new directives, etc).
			"uptodate": [config_changed(artifacts.fn_stamp(_namespace_dropin))],
			"actions": [(_namespace_dropin,)],
		},
		{
			"name": "systemd",
			"targets": ["/lib/systemd/system/radicale.service"],
			"uptodate": [config_changed(f"{storage_root}:{_VENV}:{artifacts.fn_stamp(_systemd)}")],
			"task_dep": ["radicale:config"],
			"actions": [(_systemd, [storage_root])],
		},
	]


# ── Action functions ──────────────────────────────────────────────────────────


def _venv() -> None:
	"""Create the Radicale Python virtual environment."""
	print("Creating the Radicale venv...", flush=True)
	subprocess.run(
		["python3", "-m", "venv", _VENV],
		check=True,
		capture_output=True,
	)
	# Ensure pip is present in the venv regardless of how the system Python
	# was installed (some distros omit ensurepip from the base package).
	subprocess.run(
		[f"{_VENV}/bin/python3", "-m", "ensurepip", "--upgrade"],
		check=True,
		capture_output=True,
	)
	subprocess.run(
		[f"{_VENV}/bin/pip", "install", "--upgrade", "pip"],
		check=True,
		capture_output=True,
	)


def _pip_install() -> None:
	"""Install Radicale and passlib into the venv."""
	print("Installing Radicale into its venv...", flush=True)
	subprocess.run(
		[f"{_VENV}/bin/pip", "install", *_PIP_PACKAGES],
		check=True,
	)


def _write_plugin_auth(src: str) -> None:
	"""Install the radicale_naust auth plugin."""
	os.makedirs(f"{_PLUGIN_DIR}/radicale_naust", exist_ok=True)
	open(f"{_PLUGIN_DIR}/radicale_naust/__init__.py", "a", encoding="utf-8").close()
	artifacts.write_file(f"{_PLUGIN_DIR}/radicale_naust/auth.py", artifacts.render_template(src), mode=0o644)
	subprocess.run(["chown", "-R", "root:root", _PLUGIN_DIR], check=True)


def _write_plugin_storage(src: str) -> None:
	"""Install the radicale_naust rav SQLite storage plugin."""
	os.makedirs(f"{_PLUGIN_DIR}/radicale_naust", exist_ok=True)
	artifacts.write_file(f"{_PLUGIN_DIR}/radicale_naust/storage.py", artifacts.render_template(src), mode=0o644)
	subprocess.run(["chown", "-R", "root:root", _PLUGIN_DIR], check=True)


def _write_config(_storage_root: str, webmail: str, management_host: str = "127.0.0.1", bind_host: str = "127.0.0.1") -> None:
	"""Write /etc/radicale/config.

	When WEBMAIL=rav the custom plugin bridges per-user SQLite databases so
	contacts/calendar show up in both the web UI and DAV clients.
	For all other clients, Radicale's standard multifilesystem storage is used
	so contacts saved via DAV clients (DAVx5, iOS, Thunderbird) are persisted
	independently.

	/var/lib/radicale is used (not /home) so the path is outside home and
	compatible with ProtectHome=true in the systemd sandbox.
	"""
	os.makedirs("/etc/radicale", exist_ok=True)
	os.makedirs("/var/lib/radicale", exist_ok=True)

	if webmail == "rav":
		storage_block = "type = radicale_naust.storage"
	else:
		# /var/lib/radicale: outside /home, compatible with ProtectHome=true.
		collections_path = "/var/lib/radicale/collections"
		os.makedirs(collections_path, exist_ok=True)
		subprocess.run(["chown", "www-data:www-data", collections_path], check=True)
		storage_block = f"type = multifilesystem\nfilesystem_folder = {collections_path}"

	artifacts.write_file(
		"/etc/radicale/config",
		artifacts.render_template(
			_CONFIG_TPL,
			{
				"BIND_HOST": bind_host,
				"MANAGEMENT_HOST": management_host,
				"STORAGE_BLOCK": storage_block,
			},
		),
		mode=0o644,
	)


def _log() -> None:
	"""Create log file and write logrotate config."""
	log = "/var/log/radicale.log"
	if not os.path.exists(log):
		open(log, "a", encoding="utf-8").close()
	subprocess.run(["chown", "www-data:www-data", log], check=True)

	artifacts.write_file(
		"/etc/logrotate.d/radicale",
		"/var/log/radicale.log {\n    daily\n    missingok\n    rotate 14\n    compress\n    delaycompress\n    notifempty\n    copytruncate\n    su www-data www-data\n}\n",
	)


def _namespace_dropin() -> None:
	"""Write a sandbox drop-in for kernels that lack mount namespace support.

	Some VPS kernels (OpenVZ, LXC) don't support mount namespaces, causing
	PrivateTmp=true and ProtectSystem=strict to fail with 226/NAMESPACE.
	Detect this at install time and write a drop-in disabling only those directives.
	"""
	dropin_dir = "/etc/systemd/system/radicale.service.d"
	dropin = os.path.join(dropin_dir, "no-namespace.conf")
	os.makedirs(dropin_dir, exist_ok=True)

	result = subprocess.run(["unshare", "-m", "true"], check=False, capture_output=True)
	if result.returncode == 0:
		# Namespaces supported - remove any previously applied drop-in.
		if os.path.exists(dropin):
			os.unlink(dropin)
	else:
		print("  Note: kernel lacks mount namespace support - applying reduced sandbox configuration")
		artifacts.write_file(
			dropin,
			"[Service]\nPrivateTmp=false\nProtectSystem=false\nBindPaths=\nReadWritePaths=\n",
		)


def _systemd(storage_root: str) -> None:
	"""Install and enable the Radicale systemd unit."""
	unit_src = os.path.join(_CONF_DIR, "radicale.service")
	if os.path.exists(unit_src):
		unit_content = pathlib.Path(unit_src).read_text(encoding="utf-8").replace("${RADICALE_VENV}", _VENV).replace("${STORAGE_ROOT}", storage_root)
		artifacts.write_file("/lib/systemd/system/radicale.service", unit_content)

	subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)
	subprocess.run(["systemctl", "enable", "radicale"], check=True, capture_output=True)
