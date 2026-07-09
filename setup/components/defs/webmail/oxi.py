"""
Oxi.email webmail.

Fetches a pinned prebuilt release (binary + frontend assets). No compilation
on the box. The SHA256 is the stamp: updating OXI_SHA256 triggers re-download.

Steps:
  fetch   - download and install the oxi-email-server binary + static assets
  dirs    - create and chown STORAGE_ROOT/oxi data directory
  config  - write /etc/oxi/config.env runtime config + systemd unit
"""

import os
import shutil
import subprocess
import tempfile

from doit.tools import config_changed

from ... import artifacts, SETUP_DIR
from ...component import Component

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="oxi",
	packages=["ca-certificates"],
	services=["oxi-email"],
	docker_services=["oxi-email"],
	enabled=lambda env: env.get("WEBMAIL_CLIENT", "oxi") == "oxi",
)

# Update OXI_VERSION / OXI_ASSET / OXI_SHA256 together when upgrading.
# The hash must be copied from the release's checksums.txt, not fetched at
# install time - fetching from the same place as the binary means a compromised
# release could ship a tampered binary and a matching tampered hash.
OXI_VERSION = "v0.2.0+edbc93d"
OXI_ASSET = "oxi-email-server-linux-x86_64.tar.gz"
OXI_SHA256 = "0187d8ef8c49dc47c6f1476551ac5697ef516cbf0685c3b78a5b5e9ec71681b1"
OXI_URL = f"https://github.com/boomboompower/oxi-miab/releases/download/{OXI_VERSION.replace('+', '%2B')}/{OXI_ASSET}"

_OXI_STATIC_DIR = "/usr/local/share/oxi-email/static"
_OXI_BINARY = "/usr/local/bin/oxi-email-server"

_CONF_DIR = os.path.join(SETUP_DIR, "conf", "systemd")


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, runtime: str) -> list[dict]:
	storage_root = env["STORAGE_ROOT"]
	hostname = env.get("PRIMARY_HOSTNAME", "localhost")
	pgp_enabled = env.get("WEBMAIL_PGP", "false").lower() == "true"

	return [
		{
			"name": "fetch",
			# Re-download when OXI_SHA256 changes (i.e. when the pinned version is bumped).
			"targets": [_OXI_BINARY],
			"uptodate": [config_changed(OXI_SHA256)],
			"actions": [(_fetch,)],
		},
		{
			"name": "dirs",
			"uptodate": [config_changed(f"{storage_root}:{artifacts.fn_stamp(_dirs)}")],
			"actions": [(_dirs, [storage_root])],
		},
		{
			"name": "config",
			"uptodate": [False],
			"task_dep": ["oxi:fetch", "ssl:cert"],
			"actions": [(_config, [storage_root, hostname, pgp_enabled])],
		},
	]


# ── Action functions ──────────────────────────────────────────────────────────


def _fetch() -> None:
	"""Download, verify, and install the pinned oxi-email-server release.

	The SHA256 is pinned in this file (not fetched alongside the binary) so a
	compromised release cannot ship a tampered binary and a matching tampered
	hash with nothing independent to catch it.
	"""
	tmp = "/tmp/oxi-email-server.tar.gz"
	try:
		subprocess.run(["wget", "-q", "-O", tmp, OXI_URL], check=True)

		result = subprocess.run(
			["sha256sum", "--check", "--strict"],
			input=f"{OXI_SHA256}  {tmp}",
			text=True,
			capture_output=True,
			check=False,
		)
		if result.returncode != 0:
			raise RuntimeError(f"oxi SHA256 mismatch: {result.stderr.strip()}")

		extract_dir = tempfile.mkdtemp()
		try:
			subprocess.run(["tar", "-xzf", tmp, "-C", extract_dir], check=True)

			subprocess.run(
				["cp", "--remove-destination", os.path.join(extract_dir, "oxi-email-server"), _OXI_BINARY],
				check=True,
			)
			os.chmod(_OXI_BINARY, 0o755)
			subprocess.run(["chown", "root:root", _OXI_BINARY], check=True)

			os.makedirs(_OXI_STATIC_DIR, exist_ok=True)
			subprocess.run(
				["rsync", "-a", "--delete", os.path.join(extract_dir, "static") + "/", _OXI_STATIC_DIR + "/"],
				check=True,
				capture_output=True,
			)
			subprocess.run(["chown", "-R", "root:root", _OXI_STATIC_DIR], check=True)
			subprocess.run(["chmod", "-R", "755", _OXI_STATIC_DIR], check=True)
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
	"""Create and permission the oxi data directory (per-user SQLite + search indexes)."""
	oxi_dir = os.path.join(storage_root, "oxi")
	os.makedirs(oxi_dir, exist_ok=True)
	subprocess.run(["chown", "www-data:www-data", oxi_dir], check=True)
	subprocess.run(["chmod", "750", oxi_dir], check=True)


def _config(storage_root: str, hostname: str, pgp_enabled: bool) -> None:
	"""Write oxi runtime config and install the systemd unit.

	IMAP_HOST / SMTP_HOST are the primary hostname, used for TLS SNI and Message-ID.
	IMAP_CONNECT_HOST / SMTP_CONNECT_HOST are set to 127.0.0.1 so TCP connections go
	via loopback, avoiding hairpin NAT issues on VPS providers where the server cannot
	reach its own public IP from inside.
	TLS_CA_CERT_PATH points oxi directly at the server certificate. The cert file is
	owned by the ssl-cert group (set by ssl:cert), and oxi gets ssl-cert via
	SupplementaryGroups in its systemd unit - no copy needed.
	"""
	os.makedirs("/etc/oxi", exist_ok=True)

	# IMAP_HOST / SMTP_HOST: primary hostname for TLS SNI and Message-ID.
	# IMAP_CONNECT_HOST / SMTP_CONNECT_HOST: loopback for TCP - avoids hairpin
	# NAT on VPS providers where the server cannot reach its own public IP.
	config_lines = [
		"HOST=127.0.0.1",
		"PORT=3001",
		f"IMAP_HOST={hostname}",
		"IMAP_PORT=993",
		f"IMAP_CONNECT_HOST=127.0.0.1",
		"TLS_ENABLED=true",
		f"SMTP_HOST={hostname}",
		"SMTP_PORT=587",
		f"SMTP_CONNECT_HOST=127.0.0.1",
		"ALLOW_CUSTOM_MAIL_SERVERS=false",
		f"DATA_DIR={storage_root}/oxi",
		f"STATIC_DIR={_OXI_STATIC_DIR}",
		"RUST_LOG=info,tantivy=warn,async_imap=warn",
		"SESSION_TIMEOUT_HOURS=24",
		f"TLS_CA_CERT_PATH={storage_root}/ssl/ssl_certificate.pem",
		f"PGP_ENABLED={'true' if pgp_enabled else 'false'}",
	]

	artifacts.write_file("/etc/oxi/config.env", "\n".join(config_lines) + "\n")
	os.chmod("/etc/oxi/config.env", 0o640)
	subprocess.run(["chown", "root:www-data", "/etc/oxi/config.env"], check=True)

	# Install systemd unit (substitutes STORAGE_ROOT via envsubst in bash;
	# we read the template and substitute directly).
	unit_src = os.path.join(_CONF_DIR, "oxi-email.service")
	if os.path.exists(unit_src):
		with open(unit_src) as fh:
			unit_content = fh.read().replace("${STORAGE_ROOT}", storage_root)
		artifacts.write_file("/lib/systemd/system/oxi-email.service", unit_content)

	subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)
	subprocess.run(["systemctl", "enable", "oxi-email"], check=True, capture_output=True)
