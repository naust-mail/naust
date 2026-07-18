"""
Beszel system monitoring (hub + agent).

Steps:
  user    - create beszel system user
  install - download and install hub + agent binaries
  systemd - install and enable systemd units
  keygen  - generate Ed25519 keypair for hub->agent SSH auth (runs once, never clobbered)

Hub listens on 127.0.0.1:8090. nginx proxies /admin/beszel/ with
TRUSTED_AUTH_HEADER so users never see a Beszel login screen.
The pre-seeded hub.env user is the only account; USER_CREATION is intentionally off.
"""

import hashlib
import os
import pwd
import subprocess
import tarfile
import tempfile
import urllib.request

from doit.tools import config_changed

from ... import artifacts, SETUP_DIR
from ...component import Component, DOCKER
import pathlib

# ── Pin ───────────────────────────────────────────────────────────────────────

_BESZEL_VERSION = "0.18.7"
# SHA256 of beszel_linux_amd64.tar.gz for v0.18.7.
# Update both constants together when upgrading.
_BESZEL_HUB_SHA256 = "b75c52a82af5c9721f08a7a9cb0c16df27e81967a3855cef7c77dbad9fb43524"
_BESZEL_AGENT_SHA256 = "4ae327aac5ad5a231845b0ef613066d555bbe52f7ecb2f28a53d07c04e689aff"

_BASE_URL = f"https://github.com/henrygd/beszel/releases/download/v{_BESZEL_VERSION}"
_HUB_URL = f"{_BASE_URL}/beszel_linux_amd64.tar.gz"
_AGENT_URL = f"{_BASE_URL}/beszel-agent_linux_amd64.tar.gz"

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="beszel",
	packages=[],
	services=["beszel-hub", "beszel-agent"],
	docker_services=["beszel-hub", "beszel-agent"],
	enabled=lambda env: env.get("MONITORING_TOOL", "none") == "beszel",
	naust_backup_groups=["beszel"],
)

_SYSTEMD_DIR = os.path.join(SETUP_DIR, "conf", "systemd")


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, runtime: str) -> list[dict]:
	storage_root = env["STORAGE_ROOT"]

	return [
		{
			"name": "user",
			"uptodate": [config_changed(artifacts.fn_stamp(_create_user))],
			"actions": [(_create_user,)],
		},
		{
			"name": "install",
			"targets": ["/usr/local/bin/beszel", "/usr/local/bin/beszel-agent"],
			"uptodate": [config_changed(f"{_BESZEL_VERSION}:{artifacts.fn_stamp(_install_binaries)}")],
			"actions": [(_install_binaries,)],
		},
		{
			"name": "hub-keys",
			"targets": [os.path.join(storage_root, "beszel", "id_ed25519")],
			"uptodate": [config_changed(artifacts.fn_stamp(_generate_keypair))],
			"actions": [(_generate_keypair, [storage_root, env["PRIMARY_HOSTNAME"], runtime])],
		},
		{
			"name": "systemd",
			"uptodate": [config_changed(f"{storage_root}:{env['PRIMARY_HOSTNAME']}:{artifacts.fn_stamp(_install_units)}")],
			"actions": [(_install_units, [storage_root, env["PRIMARY_HOSTNAME"]])],
		},
	]


# ── Action functions ──────────────────────────────────────────────────────────


def _create_user() -> None:
	try:
		pwd.getpwnam("beszel")
	except KeyError:
		subprocess.run(
			["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "beszel"],
			check=True,
		)


def _fetch_and_verify(url: str, expected_sha256: str, dest: str) -> None:
	with tempfile.NamedTemporaryFile(delete=False) as tmp:
		tmp_path = tmp.name

	try:
		print(f"Downloading {url}...", flush=True)
		urllib.request.urlretrieve(url, tmp_path)

		if expected_sha256:
			digest = hashlib.sha256(pathlib.Path(tmp_path).read_bytes()).hexdigest()
			if digest != expected_sha256:
				msg = f"SHA256 mismatch for {url}: got {digest}"
				raise ValueError(msg)

		with tarfile.open(tmp_path, "r:gz") as tar:
			for member in tar.getmembers():
				if member.name in {"beszel", "beszel-agent"} and "/" not in member.name:
					member.name = os.path.basename(dest)
					tar.extract(member, path=os.path.dirname(dest))
					break
		os.chmod(dest, 0o755)
	finally:
		os.unlink(tmp_path)


def _install_binaries() -> None:
	_fetch_and_verify(_HUB_URL, _BESZEL_HUB_SHA256, "/usr/local/bin/beszel")
	_fetch_and_verify(_AGENT_URL, _BESZEL_AGENT_SHA256, "/usr/local/bin/beszel-agent")


def _install_units(storage_root: str, primary_hostname: str) -> None:
	for unit in ("beszel-hub.service", "beszel-agent.service"):
		src = os.path.join(_SYSTEMD_DIR, unit)
		dst = f"/lib/systemd/system/{unit}"
		content = pathlib.Path(src).read_text(encoding="utf-8").replace("${STORAGE_ROOT}", storage_root).replace("${PRIMARY_HOSTNAME}", primary_hostname)
		pathlib.Path(dst).write_text(content, encoding="utf-8")

	subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)
	for unit in ("beszel-hub", "beszel-agent"):
		subprocess.run(["systemctl", "enable", unit], check=True, capture_output=True)


def _generate_keypair(storage_root: str, primary_hostname: str, runtime: str) -> None:
	import uuid

	data_dir = os.path.join(storage_root, "beszel")
	key_path = os.path.join(data_dir, "id_ed25519")
	agent_env_path = os.path.join(data_dir, "agent.env")
	hub_env_path = os.path.join(data_dir, "hub.env")
	config_path = os.path.join(data_dir, "config.yml")
	user_file = os.path.join(data_dir, "beszel-user")

	# Never clobber an existing keypair - this guard holds even under --force.
	if os.path.isfile(key_path):
		return

	os.makedirs(data_dir, exist_ok=True)
	print("Generating the beszel hub SSH keypair...", flush=True)
	subprocess.run(
		["ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", "", "-C", "beszel-hub"],
		check=True,
		capture_output=True,
	)

	pub_key = pathlib.Path(f"{key_path}.pub").read_text(encoding="utf-8").strip()

	# Token shared between agent.env and config.yml.
	# Hub reads config.yml on startup and creates the system + fingerprint record.
	# Agent uses the same token to connect. Users field omitted - hub defaults to first user.
	token = str(uuid.uuid4())

	# KEY holds a full "ssh-ed25519 AAAA... comment" line, which contains
	# spaces - quoted so a shell `source` of this file (the Docker agent
	# entrypoint) parses it as one value, not a command line. systemd's
	# EnvironmentFile= (bare metal) parses lines literally either way.
	pathlib.Path(agent_env_path).write_text(f'KEY="{pub_key}"\nTOKEN={token}\n', encoding="utf-8")

	# hub.env: consumed by the initial migration on first DB creation only.
	# USER_EMAIL is a random internal identity, not guessable from public info.
	# USER_PASSWORD is random; DISABLE_PASSWORD_AUTH=true means it can never be used.
	hub_email = f"beszel-{os.urandom(12).hex()}@beszel.local"
	hub_password = os.urandom(24).hex()
	pathlib.Path(hub_env_path).write_text(f"USER_EMAIL={hub_email}\nUSER_PASSWORD={hub_password}\n", encoding="utf-8")

	# config.yml: read by hub on startup to provision the local agent as a
	# system. On bare metal hub and agent are co-located (127.0.0.1); in
	# Docker the agent runs in a separate container reached by service name.
	agent_host = "beszel-agent" if runtime == DOCKER else "127.0.0.1"
	pathlib.Path(config_path).write_text(f"systems:\n  - name: {primary_hostname}\n    host: {agent_host}\n    port: 45876\n    token: {token}\n", encoding="utf-8")

	# beszel-user: read by web_update.py for nginx config generation (root-only).
	pathlib.Path(user_file).write_text(hub_email, encoding="utf-8")
	os.chmod(user_file, 0o600)

	subprocess.run(
		["chown", "beszel:beszel", key_path, f"{key_path}.pub", agent_env_path, hub_env_path, config_path],
		check=True,
	)
	os.chmod(key_path, 0o600)
	os.chmod(agent_env_path, 0o640)
	os.chmod(hub_env_path, 0o640)
	os.chmod(config_path, 0o640)
