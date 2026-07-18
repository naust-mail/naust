"""
rav webmail client.

Fetches a pinned prebuilt release (binary + frontend assets). No compilation
on the box. The SHA256 is the stamp: updating RAV_SHA256 triggers
re-download.

Steps:
  user    - create rav system user (dedicated, not shared with www-data)
  fetch   - download and install the rav-server binary + static assets
  dirs    - create and chown STORAGE_ROOT/rav data directory
  config  - write /etc/rav/config.env runtime config + systemd unit
"""

import os
import pathlib
import pwd
import shutil
import subprocess
import tempfile

from doit.tools import config_changed

from ... import artifacts, SETUP_DIR
from ...component import Component
from ...task_names import SSL_CERT

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="rav",
	packages=["ca-certificates"],
	services=["rav"],
	docker_services=["rav"],
	enabled=lambda env: env.get("WEBMAIL_CLIENT", "rav") == "rav",
	naust_backup_groups=["rav"],
)

# Update RAV_VERSION / RAV_ASSET / RAV_SHA256 together
# when upgrading. The hash must be copied from the release's checksums.txt, not
# fetched at install time - fetching from the same place as the binary means a
# compromised release could ship a tampered binary and a matching tampered hash.
# The asset/binary filenames come from the rav repo's own release CI.
RAV_VERSION = "v0.2.4+7e153c3"
RAV_ASSET = "rav-email-server-linux-x86_64.tar.gz"
RAV_SHA256 = "5e9a36092460a0f2a9f484465e9d770bd2995cb6a940f2973f4242f93fb70edf"
RAV_URL = f"https://github.com/naust-mail/rav/releases/download/{RAV_VERSION.replace('+', '%2B')}/{RAV_ASSET}"

_WEBMAIL_STATIC_DIR = "/usr/local/share/rav/static"
_WEBMAIL_BINARY = "/usr/local/bin/rav-server"

_CONF_DIR = os.path.join(SETUP_DIR, "conf", "systemd")


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	storage_root = env["STORAGE_ROOT"]
	hostname = env.get("PRIMARY_HOSTNAME", "localhost")
	pgp_enabled = env.get("WEBMAIL_PGP", "false").lower() == "true"

	return [
		{
			"name": "user",
			"uptodate": [config_changed(artifacts.fn_stamp(_create_user))],
			"actions": [(_create_user,)],
		},
		{
			"name": "fetch",
			# Re-download when RAV_SHA256 changes (i.e. when the pinned version is bumped).
			"targets": [_WEBMAIL_BINARY],
			"uptodate": [config_changed(RAV_SHA256)],
			"actions": [(_fetch,)],
		},
		{
			"name": "dirs",
			"uptodate": [config_changed(f"{storage_root}:{artifacts.fn_stamp(_dirs)}")],
			"task_dep": ["rav:user"],
			"actions": [(_dirs, [storage_root])],
		},
		{
			"name": "config",
			"uptodate": [False],
			"task_dep": ["rav:user", "rav:fetch", SSL_CERT],
			"actions": [(_config, [storage_root, hostname, pgp_enabled])],
		},
	]


# ── Action functions ──────────────────────────────────────────────────────────


def _create_user() -> None:
	"""Dedicated system user for rav - not shared with www-data.

	Unlike the PHP webmail clients (roundcube/cypht/snappymail), which run
	inside the www-data-owned php-fpm pool, rav is a standalone binary with
	its own systemd unit. Sharing www-data would give it (and any bug in it)
	access to radicale's and filebrowser's files for no reason, and vice
	versa. ssl-cert access is still granted separately via SupplementaryGroups
	in rav.service.
	"""
	try:
		pwd.getpwnam("rav")
	except KeyError:
		subprocess.run(
			["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "rav"],
			check=True,
		)


def _fetch() -> None:
	"""Download, verify, and install the pinned rav-server release.

	The SHA256 is pinned in this file (not fetched alongside the binary) so a
	compromised release cannot ship a tampered binary and a matching tampered
	hash with nothing independent to catch it.
	"""
	tmp_fd, tmp = tempfile.mkstemp(suffix=".tar.gz")
	os.close(tmp_fd)
	try:
		print(f"Downloading rav-server {RAV_VERSION}...", flush=True)
		subprocess.run(["wget", "-q", "-O", tmp, RAV_URL], check=True)

		result = subprocess.run(
			["sha256sum", "--check", "--strict"],
			input=f"{RAV_SHA256}  {tmp}",
			text=True,
			capture_output=True,
			check=False,
		)
		if result.returncode != 0:
			msg = f"rav SHA256 mismatch: {result.stderr.strip()}"
			raise RuntimeError(msg)

		extract_dir = tempfile.mkdtemp()
		try:
			subprocess.run(["tar", "-xzf", tmp, "-C", extract_dir], check=True)

			subprocess.run(
				["cp", "--remove-destination", os.path.join(extract_dir, "rav-email-server"), _WEBMAIL_BINARY],
				check=True,
			)
			os.chmod(_WEBMAIL_BINARY, 0o755)
			subprocess.run(["chown", "root:root", _WEBMAIL_BINARY], check=True)

			os.makedirs(_WEBMAIL_STATIC_DIR, exist_ok=True)
			subprocess.run(
				["rsync", "-a", "--delete", os.path.join(extract_dir, "static") + "/", _WEBMAIL_STATIC_DIR + "/"],
				check=True,
				capture_output=True,
			)
			subprocess.run(["chown", "-R", "root:root", _WEBMAIL_STATIC_DIR], check=True)
			subprocess.run(["chmod", "-R", "755", _WEBMAIL_STATIC_DIR], check=True)
		finally:
			shutil.rmtree(extract_dir, ignore_errors=True)
	finally:
		if os.path.exists(tmp):
			os.unlink(tmp)

	# Remove legacy cargo.sh profile if present from a source-build era.
	cargo_sh = "/etc/profile.d/cargo.sh"
	if os.path.exists(cargo_sh):
		os.unlink(cargo_sh)


def _dirs(storage_root: str) -> None:
	"""Create and permission the rav data directory (per-user SQLite + search indexes).

	-R matters on upgrade: an existing box may already have files here
	(including .mfa_key) owned by the old www-data user. A non-recursive
	chown would leave them stuck as www-data, which the dedicated rav user
	(no longer in that group) couldn't read.
	"""
	webmail_dir = os.path.join(storage_root, "rav")
	os.makedirs(webmail_dir, exist_ok=True)
	subprocess.run(["chown", "-R", "rav:rav", webmail_dir], check=True)
	subprocess.run(["chmod", "750", webmail_dir], check=True)


def _config(storage_root: str, hostname: str, pgp_enabled: bool) -> None:
	"""Write rav runtime config and install the systemd unit.

	IMAP_HOST / SMTP_HOST are the primary hostname, used for TLS SNI and Message-ID.
	IMAP_CONNECT_HOST / SMTP_CONNECT_HOST are set to 127.0.0.1 so TCP connections go
	via loopback, avoiding hairpin NAT issues on VPS providers where the server cannot
	reach its own public IP from inside.
	TLS_CA_CERT_PATH points rav directly at the server certificate. The cert
	file is owned by the ssl-cert group (set by ssl:cert), and rav gets
	ssl-cert via SupplementaryGroups in its systemd unit - no copy needed.
	"""
	os.makedirs("/etc/rav", exist_ok=True)

	# IMAP_HOST / SMTP_HOST: primary hostname for TLS SNI and Message-ID.
	# IMAP_CONNECT_HOST / SMTP_CONNECT_HOST: loopback for TCP - avoids hairpin
	# NAT on VPS providers where the server cannot reach its own public IP.
	config_lines = [
		"HOST=127.0.0.1",
		"PORT=3001",
		f"IMAP_HOST={hostname}",
		"IMAP_PORT=993",
		"IMAP_CONNECT_HOST=127.0.0.1",
		"TLS_ENABLED=true",
		f"SMTP_HOST={hostname}",
		"SMTP_PORT=587",
		"SMTP_CONNECT_HOST=127.0.0.1",
		"ALLOW_CUSTOM_MAIL_SERVERS=false",
		f"DATA_DIR={storage_root}/rav",
		f"STATIC_DIR={_WEBMAIL_STATIC_DIR}",
		"RUST_LOG=info,tantivy=warn,async_imap=warn",
		"SESSION_TIMEOUT_HOURS=24",
		f"TLS_CA_CERT_PATH={storage_root}/ssl/ssl_certificate.pem",
		f"PGP_ENABLED={'true' if pgp_enabled else 'false'}",
	]

	artifacts.write_file("/etc/rav/config.env", "\n".join(config_lines) + "\n")
	os.chmod("/etc/rav/config.env", 0o640)
	subprocess.run(["chown", "root:rav", "/etc/rav/config.env"], check=True)

	# Install systemd unit (substitutes STORAGE_ROOT via envsubst in bash;
	# we read the template and substitute directly).
	unit_src = os.path.join(_CONF_DIR, "rav.service")
	if os.path.exists(unit_src):
		unit_content = pathlib.Path(unit_src).read_text(encoding="utf-8").replace("${STORAGE_ROOT}", storage_root)
		artifacts.write_file("/lib/systemd/system/rav.service", unit_content)

	subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)
	subprocess.run(["systemctl", "enable", "rav"], check=True, capture_output=True)
