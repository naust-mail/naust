"""
Management daemon (gunicorn/Flask API) and admin UI (Vue frontend).

PARKED (2026-07-12): retired by the managerd cutover. This component installs
nothing (enabled=lambda env: False) - managerd serves the API, defs/panel.py
installs the admin frontend, and defs/boxctl.py installs the CLI. The file and
its actions are kept in place until the source-tree cleanup pass deletes the
Flask stack (management/, this file, naust.service, the :10222 nginx confs,
dns_update/web_update, deploy/docker/management). Do not re-enable.

Steps:
  virtualenv    - create Python venv (skipped if already exists)
  pip-install   - install Python dependencies
  start-script  - write the gunicorn start script and install the systemd unit
  cron          - write nightly cron job (baremetal only; Docker ships its own)
  frontend      - build or fetch the Vue admin frontend
  install-files - rsync management/, frontend/dist, nginx templates to FHS paths
  boxctl        - write the boxctl CLI wrapper script

Backup tool installation (restic binary / duplicity pip packages) and backup
key generation live in defs/backup/.
"""

import json
import os
import random
import secrets
import shutil
import subprocess
import tempfile

from doit.tools import config_changed

from .. import artifacts, SETUP_DIR
from ..component import Component, BAREMETAL, DOCKER
import pathlib

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="management",
	packages=[
		# virtualenv: creates the management venv; python3-pip bootstraps pip inside it
		"python3-pip",
		"virtualenv",
		# certbot: TLS certificate provisioning and renewal
		"certbot",
		# rsync: used to deploy management files and sync backups
		"rsync",
		# libxml2-dev + libxslt1-dev: lxml compile-time headers (pip uses --prefer-binary,
		# but kept here as a fallback for arches without prebuilt wheels)
		"libxml2-dev",
		"libxslt1-dev",
		# cron: runs daily_tasks.py for backups, certificate renewal, and status checks
		"cron",
		# ldnsutils: provides ldns-signzone, called by dns_update.py to sign DNSSEC zones
		"ldnsutils",
		# python3-idna: imported at module level by mailconfig.py for domain name handling
		"python3-idna",
	],
	services=["naust"],
	# In Docker, gunicorn is exec'd directly by the entrypoint - no supervisord.
	# The entrypoint restarts the container to pick up changes, so no in-process
	# restart is needed here.
	docker_services=[],
	# PARKED: the Flask stack is retired by the managerd cutover. Never runs;
	# its tasks (venv, gunicorn, naust.service, api.key, cron, rsync) install
	# nothing. Kept until the source-tree cleanup pass. See module docstring.
	enabled=lambda _env: False,
)

_INST_DIR = "/usr/local/lib/naust"
_SHARE_DIR = "/usr/local/share/naust"
_VENV = os.path.join(_INST_DIR, "env")

_PIP_PACKAGES = [
	"rtyaml",
	"email_validator>=1.0.0",
	"flask",
	"dnspython",
	"python-dateutil",
	"expiringdict",
	"gunicorn",
	"qrcode[pil]",
	"pyotp",
	"fido2>=1.0",
	"idna>=2.0.0",
	"cryptography>=41.0.0",
	"psutil",
	"postfix-mta-sts-resolver",
	"passlib[bcrypt]",
	"bcrypt<4",
]


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, runtime: str) -> list[dict]:
	repo_root = os.path.dirname(SETUP_DIR)
	frontend_src = os.path.join(repo_root, "frontend")
	frontend_dist = os.path.join(frontend_src, "dist")
	management_src = os.path.join(repo_root, "management")
	nginx_conf_src = os.path.join(repo_root, "setup", "conf", "nginx")
	boxctl_src = os.path.join(repo_root, "setup", "boxctl")
	setup_src = os.path.join(repo_root, "setup")

	tasks = [
		{
			"name": "virtualenv",
			"build": True,  # no env needed - safe to run at Docker build time
			# Run only if the venv directory is missing.
			"targets": [_VENV],
			"actions": [(_virtualenv,)],
		},
		{
			"name": "pip-install",
			"build": True,  # no env needed - safe to run at Docker build time
			"uptodate": [config_changed(":".join(_PIP_PACKAGES))],
			"task_dep": ["management:virtualenv"],
			"actions": [(_pip_install,)],
		},
		{
			"name": "start-script",
			"uptodate": [config_changed(f"{runtime}:{artifacts.fn_stamp(_start_script)}")],
			"task_dep": ["management:virtualenv"],
			"actions": [(_start_script, [repo_root, runtime])],
		},
		{
			"name": "boxctl",
			"uptodate": [config_changed(f"{runtime}:{artifacts.fn_stamp(_boxctl)}")],
			"actions": [(_boxctl, [runtime])],
		},
	]

	# Baremetal only: nightly cron is baked into the Docker image, and
	# frontend/install-files are already built into the Docker image at build time.
	if runtime == BAREMETAL:
		tasks += [
			{
				"name": "frontend",
				# Re-runs when frontend source files change. The content hash is the same
				# key CI uses to publish prebuilt artifacts, so a box never needs to build
				# from source when an identical artifact was already built by CI.
				# When source is absent (VPS install), fall back to dist hash so the
				# task doesn't re-run just because the source hash changed between
				# the build machine and the target box.
				"uptodate": [config_changed(artifacts.hash_files(frontend_src) if os.path.isdir(frontend_src) else artifacts.hash_files(f"{_SHARE_DIR}/frontend/dist") if os.path.isdir(f"{_SHARE_DIR}/frontend/dist") else "")],
				"actions": [(_frontend, [frontend_src, frontend_dist])],
			},
			{
				"name": "install-files",
				# Re-runs when any source file under management/, nginx/, frontend/dist, or
				# boxctl/ changes. Dep on frontend ensures dist/ is built before rsync.
				"uptodate": [
					config_changed(
						"|".join([
							artifacts.hash_files(management_src) if os.path.isdir(management_src) else "",
							artifacts.hash_files(nginx_conf_src) if os.path.isdir(nginx_conf_src) else "",
							artifacts.hash_files(frontend_dist) if os.path.isdir(frontend_dist) else "",
							artifacts.hash_files(boxctl_src) if os.path.isdir(boxctl_src) else "",
							env.get("PRIMARY_HOSTNAME", ""),
						])
					)
				],
				"task_dep": ["management:frontend"],
				"actions": [
					(
						_install_files,
						[
							management_src,
							nginx_conf_src,
							frontend_dist,
							boxctl_src,
							setup_src,
							repo_root,
							env.get("PRIMARY_HOSTNAME", ""),
						],
					)
				],
			},
			{
				"name": "cron",
				"uptodate": [config_changed(f"{env.get('PRIMARY_HOSTNAME', '')}:{artifacts.fn_stamp(_cron)}")],
				"actions": [
					(
						_cron,
						[
							# Stable per-box, unique across boxes - seeds from hostname.
							random.Random(env.get("PRIMARY_HOSTNAME", "")).randint(0, 59),  # noqa: S311 -- cron jitter, not security-sensitive
						],
					)
				],
			},
		]

	return tasks


# ── Action functions ──────────────────────────────────────────────────────────


def _virtualenv() -> None:
	"""Create the management daemon Python virtualenv.

	DEB_PYTHON_INSTALL_LAYOUT=deb works around a virtualenv bug on Ubuntu 22.04
	/ Python 3.10 that causes the venv layout to be incorrect (see #2335).
	"""
	os.makedirs(_INST_DIR, exist_ok=True)
	env = os.environ.copy()
	env["DEB_PYTHON_INSTALL_LAYOUT"] = "deb"
	print("Creating the management venv...", flush=True)
	subprocess.run(
		["virtualenv", "-ppython3", _VENV],
		env=env,
		check=True,
		capture_output=True,
	)


def _pip_install() -> None:
	"""Install Python packages for the management daemon into the virtualenv.

	Upgrading pip first because the Ubuntu-packaged version is often too old.
	All packages use --prefer-binary to avoid C compiler requirements on new
	Python versions where wheels haven't been built yet.
	"""
	pip = os.path.join(_VENV, "bin", "pip")
	print("Installing Python packages into the management venv...", flush=True)
	subprocess.run([pip, "install", "--upgrade", "pip"], check=True)
	subprocess.run(
		[pip, "install", "--upgrade", "--prefer-binary", *_PIP_PACKAGES],
		check=True,
	)


def _start_script(repo_root: str, runtime: str = BAREMETAL) -> None:
	"""Write the gunicorn start script and install the systemd unit.

	Generates API key at setup time (used by dns_update/web_update) rather than
	daemon startup time. The API key is static across daemon restarts - it's only
	regenerated on full setup. Authentication breaks with >1 gunicorn worker
	because sessions are in-memory, so we pin to 1 worker.
	"""
	api_key_path = "/var/lib/naust/api.key"
	os.makedirs(os.path.dirname(api_key_path), exist_ok=True)

	# Generate API key on first setup. Keep it stable across daemon restarts so
	# dns_update and web_update don't fail when called before daemon starts.
	if not os.path.exists(api_key_path):
		pathlib.Path(api_key_path).write_text(secrets.token_hex(16), encoding="utf-8")
		os.chmod(api_key_path, 0o640)

	# In Docker, nginx runs in a separate container so gunicorn must bind on all
	# interfaces. On bare metal it listens on loopback only (nginx is local).
	bind_addr = "0.0.0.0" if runtime == DOCKER else "127.0.0.1"

	start_path = os.path.join(_INST_DIR, "start")
	artifacts.write_file(
		start_path,
		f"#!/bin/bash\nexport LANGUAGE=en_US.UTF-8\nexport LC_ALL=en_US.UTF-8\nexport LANG=en_US.UTF-8\nexport LC_TYPE=en_US.UTF-8\n\nsource {_VENV}/bin/activate\nexport PYTHONPATH={_INST_DIR}/management\nexec gunicorn -b {bind_addr}:10222 -w 1 --timeout 630 core.wsgi:app\n",
		mode=0o755,
	)

	# Look for the unit file in the repo source first (pre-install-files),
	# then fall back to the installed location (re-runs after install-files).
	unit_src_candidates = [
		os.path.join(repo_root, "setup", "conf", "systemd", "naust.service"),
		os.path.join(_INST_DIR, "setup", "conf", "systemd", "naust.service"),
	]
	for src in unit_src_candidates:
		if os.path.exists(src):
			shutil.copy2(src, "/lib/systemd/system/naust.service")
			break

	subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)
	subprocess.run(["systemctl", "enable", "naust.service"], check=True, capture_output=True)


def _cron(minute: int) -> None:
	"""Write the nightly cron job for backups and status checks.

	The minute is seeded from the hostname so each box gets a stable but
	unique offset - avoids thundering-herd on external services (GitHub API,
	RBL checks, etc.) when many boxes run at the same time.
	"""
	artifacts.write_file(
		"/etc/cron.d/naust-nightly",
		f"# Naust --- Do not edit / will be overwritten on update.\n# Run nightly tasks: backup, status checks.\n{minute} 1 * * *\troot\t(cd {_INST_DIR} && management/scripts/daily_tasks.py)\n",
	)


def _frontend(frontend_src: str, frontend_dist: str) -> None:
	"""Build or fetch the Vue admin frontend.

	The content hash of frontend/ matches what CI uses as the artifact tag, so
	a box can almost always fetch a prebuilt artifact. Builds from source only
	when no prebuilt exists (local dev, unmerged changes).
	"""
	fe_hash = artifacts.hash_files(frontend_src)
	fe_tag = f"frontend-{fe_hash}"
	# URL constructed from the project's github repo release endpoint.
	fe_url = f"https://github.com/naust-mail/naust/releases/download/{fe_tag}/frontend-dist.tar.gz"

	fetched = False
	# Try the prebuilt artifact. The sha256 sidecar is fetched from the same
	# host as the tarball (unlike the pinned-hash pattern used for third-party
	# tools like restic) - that's intentional: this artifact is published by our
	# own CI from our own source, so same-source is fine. It verifies transit
	# integrity, not provenance independent of the publisher.
	tmp_dir = tempfile.mkdtemp(prefix="naust-frontend-")
	tmp_tarball = os.path.join(tmp_dir, "frontend-dist.tar.gz")
	tmp_sha = os.path.join(tmp_dir, "frontend-dist.tar.gz.sha256")
	try:
		sha_url = f"{fe_url}.sha256"
		sha_result = subprocess.run(
			["curl", "-fsSL", "-o", tmp_sha, sha_url],
			check=False,
			capture_output=True,
		)
		if sha_result.returncode == 0:
			print("Downloading the prebuilt admin frontend...", flush=True)
			dl = subprocess.run(
				["wget", "-q", "-O", tmp_tarball, fe_url],
				check=False,
				capture_output=True,
			)
			if dl.returncode == 0:
				expected = pathlib.Path(tmp_sha).read_text(encoding="utf-8").strip()
				result = subprocess.run(
					["sha256sum", "--check", "--strict"],
					input=f"{expected}  {tmp_tarball}",
					text=True,
					capture_output=True,
					check=False,
				)
				if result.returncode == 0:
					shutil.rmtree(frontend_dist, ignore_errors=True)
					os.makedirs(frontend_dist, exist_ok=True)
					subprocess.run(
						["tar", "-xzf", tmp_tarball, "-C", frontend_dist],
						check=True,
					)
					fetched = True
	finally:
		shutil.rmtree(tmp_dir, ignore_errors=True)

	if not fetched:
		if not os.path.isdir(frontend_src):
			installed_dist = f"{_SHARE_DIR}/frontend/dist"
			if os.path.isdir(installed_dist) and os.listdir(installed_dist):
				# Already installed to system path, no source to rebuild from - skip.
				return
			msg = f"No prebuilt admin frontend found for this build and frontend source directory does not exist ({frontend_src}). Push to CI to publish a release artifact, or run setup from the repo root."
			raise RuntimeError(msg)
		print("No prebuilt admin frontend found - building from source...")
		# Download bun to a scratch dir, use it, then delete it.
		# Avoids touching system packages or apt sources.
		bun_install = tempfile.mkdtemp(prefix="naust-bun-")
		bun_bin = f"{bun_install}/bin/bun"
		try:
			subprocess.run(  # noqa: S602 - hardcoded, non-interpolated command; no injection surface
				"curl -fsSL https://bun.sh/install | bash",
				shell=True,
				check=True,
				env={**os.environ, "BUN_INSTALL": bun_install},
			)

			subprocess.run([bun_bin, "install", "--frozen-lockfile"], cwd=frontend_src, check=True)
			# vite only empties its own outDir subtree; clear the whole dist/
			# so output from an older layout never ships in the rsync.
			shutil.rmtree(frontend_dist, ignore_errors=True)
			subprocess.run([bun_bin, "x", "vite", "build"], cwd=frontend_src, check=True)
		finally:
			shutil.rmtree(bun_install, ignore_errors=True)


def _install_files(
	management_src: str,
	nginx_conf_src: str,
	frontend_dist: str,
	boxctl_src: str,
	setup_src: str,
	repo_root: str,
	primary_hostname: str,
) -> None:
	"""Rsync source files to FHS system paths so the daemon runs without the repo.

	After setup completes, the repo can be deleted. The daemon, web_update, and
	boxctl all operate from /usr/local/lib/naust/ and /usr/local/share/naust/.
	"""
	os.makedirs(f"{_SHARE_DIR}/frontend/dist", exist_ok=True)
	os.makedirs(f"{_SHARE_DIR}/nginx-templates", exist_ok=True)
	os.makedirs(_INST_DIR, exist_ok=True)

	def rsync(src: str, dest: str) -> None:
		if os.path.isdir(src):
			subprocess.run(
				["rsync", "-a", "--delete", f"{src}/", dest],
				check=True,
				capture_output=True,
			)

	rsync(frontend_dist, f"{_SHARE_DIR}/frontend/dist/")
	rsync(nginx_conf_src, f"{_SHARE_DIR}/nginx-templates/")

	# Stamp the box hostname into the panel's boot loader so first paint
	# never waits on the API. dist/ ships a placeholder boot.js; the real
	# file must be written here, after the rsync, because --delete would
	# otherwise restore the placeholder on every re-install.
	if primary_hostname:
		artifacts.write_file(
			f"{_SHARE_DIR}/frontend/dist/admin/boot.js",
			f"window.__BOX__ = {{ hostname: {json.dumps(primary_hostname)} }}\ndocument.title = window.__BOX__.hostname\n",
		)
	rsync(management_src, f"{_INST_DIR}/management/")
	rsync(boxctl_src, f"{_INST_DIR}/boxctl/")
	rsync(setup_src, f"{_INST_DIR}/setup/")

	# Install commit SHA for the version check in status_checks/utils.py.
	# get_latest_naust_version() fetches the latest SHA from GitHub main branch,
	# so the installed version must also be a full commit SHA for the comparison to work.
	version_dest = os.path.join(_SHARE_DIR, "version")
	result = subprocess.run(
		["git", "-C", repo_root, "rev-parse", "HEAD"],
		capture_output=True,
		text=True,
		check=False,
	)
	if result.returncode == 0:
		artifacts.write_file(version_dest, result.stdout.strip() + "\n")


def _boxctl(runtime: str = BAREMETAL) -> None:
	"""Write the boxctl CLI wrapper that invokes the installed Python module.

	On bare metal, boxctl is rsynced to _INST_DIR by install-files.
	In Docker, install-files doesn't run, so point PYTHONPATH at the repo instead.
	"""
	pythonpath = "/opt/naust/setup" if runtime == DOCKER else _INST_DIR
	artifacts.write_file(
		"/usr/local/bin/boxctl",
		f'#!/bin/bash\nexport PYTHONPATH={pythonpath}\nexec {_VENV}/bin/python3 -m boxctl "$@"\n',
		mode=0o755,
	)
	# 'naust' is an alias for backward compatibility.
	naust_bin = "/usr/local/bin/naust"
	if not os.path.exists(naust_bin):
		os.symlink("/usr/local/bin/boxctl", naust_bin)
