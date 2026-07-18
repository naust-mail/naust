"""
Duplicity backup backend.

Active when BACKUP_TOOL=duplicity. Duplicity and its cloud backend SDKs are
installed into a dedicated venv this component owns (not system pip - Ubuntu
24.04 blocks system pip installs via PEP 668). The venv is self-contained: it
exists only when this backend is selected and has no tie to the retired Flask
management stack.

Steps:
  backup-key   - generate backup encryption key (skipped if exists)
  virtualenv   - create the dedicated backup venv (skipped if it exists)
  pip-install  - install duplicity and its backend deps into the backup venv
"""

import os
import subprocess

from doit.tools import config_changed

from ...component import Component
from . import backup_key_task, ssh_key_task

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="duplicity",
	# python3-pip bootstraps pip inside the venv; virtualenv creates it.
	packages=["virtualenv", "python3-pip"],
	services=[],
	docker_services=[],
	enabled=lambda env: env.get("BACKUP_TOOL", "restic") == "duplicity",
)

_VENV = "/usr/local/lib/naust/backup-venv"

# duplicity's own packaging hard-requires every cloud backend SDK it supports
# (azure-storage-blob, boxsdk, dropbox, jottalib, megatools, pyrax,
# python-swiftclient, google-api-python-client, lxml, etc.) - none are optional
# extras, they're unconditional requires_dist, even though we only ever use
# file/rsync/s3/b2. Two of those unused deps (lxml, and netifaces transitively
# via pyrax) need a C compiler to build from source when no prebuilt wheel
# exists. Rather than install a compiler just to build packages we'll never
# import, use --no-deps and supply only what our backends actually need:
# fasteners + python-gettext unconditionally, boto3/b2sdk only for s3/b2 status
# listing in backup/status.py (restic's Go binary talks to S3/B2 natively -
# no Python SDK involved there).
_DUPLICITY_PACKAGES = [
	"fasteners",
	"python-gettext",
	"b2sdk",
	"boto3",
]


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	return [
		backup_key_task(env["STORAGE_ROOT"]),
		ssh_key_task(env["STORAGE_ROOT"]),
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
			"uptodate": [config_changed(":".join(_DUPLICITY_PACKAGES))],
			# The backup venv must exist before we can pip install into it.
			"task_dep": ["duplicity:virtualenv"],
			"actions": [(_pip_install,)],
		},
	]


# ── Action functions ──────────────────────────────────────────────────────────


def _virtualenv() -> None:
	"""Create the dedicated backup venv.

	DEB_PYTHON_INSTALL_LAYOUT=deb works around a virtualenv bug on Ubuntu 22.04
	/ Python 3.10 that causes the venv layout to be incorrect (see #2335).
	"""
	os.makedirs(os.path.dirname(_VENV), exist_ok=True)
	env = os.environ.copy()
	env["DEB_PYTHON_INSTALL_LAYOUT"] = "deb"
	print("Creating the backup venv...", flush=True)
	subprocess.run(
		["virtualenv", "-ppython3", _VENV],
		env=env,
		check=True,
		capture_output=True,
	)


def _pip_install() -> None:
	"""Install duplicity and its backend deps into the backup venv."""
	pip = os.path.join(_VENV, "bin", "pip")
	print("Installing duplicity into the backup venv...", flush=True)
	subprocess.run([pip, "install", "--upgrade", "pip"], check=True)
	subprocess.run(
		[pip, "install", "--upgrade", "--prefer-binary", *_DUPLICITY_PACKAGES],
		check=True,
	)
	subprocess.run(
		[pip, "install", "--upgrade", "--prefer-binary", "--no-deps", "duplicity>=1.0"],
		check=True,
	)
