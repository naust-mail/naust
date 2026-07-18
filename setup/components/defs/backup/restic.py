"""
Restic backup backend.

Active when BACKUP_TOOL=restic (the default). Restic is a Go binary - no pip
packages needed. Installation tries apt first; if apt doesn't carry restic for
this Ubuntu release, falls back to downloading a pinned GitHub release.

Steps:
  backup-key  - generate backup encryption key (skipped if exists)
  restic      - install restic binary if not available via apt [conditional]
"""

import os
import shutil
import subprocess
import tempfile

from doit.tools import config_changed

from ...component import Component
from . import backup_key_task, ssh_key_task

# ── Component declaration ─────────────────────────────────────────────────────


def _restic_packages() -> list[str]:
	# Use apt's restic if available (Ubuntu 22.04+), otherwise just bzip2 for
	# the fallback binary download in make_tasks().
	apt_result = subprocess.run(["apt-cache", "show", "restic"], check=False, capture_output=True)
	if apt_result.returncode == 0:
		return ["restic"]
	return ["bzip2"]


COMPONENT = Component(
	name="restic",
	packages=_restic_packages(),
	services=[],
	docker_services=[],
	enabled=lambda env: env.get("BACKUP_TOOL", "restic") == "restic",
)

# Pinned fallback: only used when apt-cache show restic fails.
# Update both together when bumping.
_RESTIC_VERSION = "0.19.1"
_RESTIC_SHA256 = "f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c"


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	tasks = [backup_key_task(env["STORAGE_ROOT"]), ssh_key_task(env["STORAGE_ROOT"])]

	# Only needed when apt doesn't carry restic - the batched apt install in the
	# runner handles the apt case via COMPONENT.packages.
	if not shutil.which("restic"):
		apt_result = subprocess.run(["apt-cache", "show", "restic"], check=False, capture_output=True)
		if apt_result.returncode != 0:
			tasks.append({
				"name": "restic",
				"build": True,
				"targets": ["/usr/local/bin/restic"],
				"uptodate": [config_changed(_RESTIC_SHA256)],
				"actions": [(_install_restic,)],
			})

	return tasks


# ── Action functions ──────────────────────────────────────────────────────────


def _install_restic() -> None:
	"""Download and install a pinned restic release when apt doesn't have it.

	The SHA256 is cross-checked against the GitHub-published digest for this
	asset. Update both _RESTIC_VERSION and _RESTIC_SHA256 together when bumping.
	"""
	url = f"https://github.com/restic/restic/releases/download/v{_RESTIC_VERSION}/restic_{_RESTIC_VERSION}_linux_amd64.bz2"
	bz2_fd, bz2_path = tempfile.mkstemp(suffix=".bz2")
	os.close(bz2_fd)
	try:
		print(f"Downloading restic {_RESTIC_VERSION}...", flush=True)
		subprocess.run(["wget", "-q", "-O", bz2_path, url], check=True)

		# Verify SHA256.
		result = subprocess.run(
			["sha256sum", "--check", "--strict"],
			input=f"{_RESTIC_SHA256}  {bz2_path}",
			text=True,
			capture_output=True,
			check=False,
		)
		if result.returncode != 0:
			msg = f"restic SHA256 mismatch: {result.stderr.strip()}"
			raise RuntimeError(msg)

		# Decompress and install.
		with open(bz2_path, "rb") as src, tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
			subprocess.run(["bzip2", "-d", "-c"], stdin=src, stdout=tmp, check=True)
			tmp_path = tmp.name

		shutil.move(tmp_path, "/usr/local/bin/restic")
		os.chmod("/usr/local/bin/restic", 0o755)
	finally:
		if os.path.exists(bz2_path):
			os.unlink(bz2_path)
