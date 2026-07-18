"""
boxctl operator CLI (Go binary).

The Go rewrite of the operator CLI: `boxctl doctor`, `boxctl status`, and the
`boxctl recover` break-glass surface. Built from daemon/cmd/boxctl and installed
to /usr/local/bin/boxctl (with a backward-compatible `naust` alias). Like the
other Go daemons it is fetched from the versioned release or built from source
(see gobuild.py).

Steps:
  boxctl - install the operator CLI binary on PATH

Bare metal only: Docker images ship their binaries at image build time.

This component no longer persists the Python installer sources on disk. Re-running
setup fetches the current release; offline re-setup returns when the installer
itself is rewritten in Go.
"""

import os

from doit.tools import config_changed

from .. import artifacts, SETUP_DIR
from ..component import Component
from ..gobuild import fetch_or_build

COMPONENT = Component(
	name="boxctl",
	packages=[],
	services=[],
	docker_services=[],
	skip_on=["docker"],
)

_BIN = "/usr/local/bin/boxctl"


def make_tasks(_env: dict, _runtime: str) -> list[dict]:
	repo_root = os.path.dirname(SETUP_DIR)
	daemon_src = os.path.join(repo_root, "daemon")

	return [
		{
			"name": "boxctl",
			# Re-runs when any Go source changes. When the repo is gone (re-run
			# after install), fall back to the installed binary's hash so the task
			# does not re-run spuriously.
			"uptodate": [config_changed(artifacts.hash_files(daemon_src) if os.path.isdir(daemon_src) else artifacts.file_hash(_BIN) if os.path.exists(_BIN) else "")],
			"targets": [_BIN],
			"actions": [(_binary, [daemon_src]), (_alias,)],
		},
	]


def _binary(daemon_src: str) -> None:
	if not os.path.isdir(daemon_src):
		if os.path.exists(_BIN):
			return
		msg = f"boxctl binary is not installed and daemon source directory does not exist ({daemon_src}). Run setup from the repo root."
		raise RuntimeError(msg)
	fetch_or_build(daemon_src, "./cmd/boxctl", _BIN)


def _alias() -> None:
	"""`naust` is a backward-compatible alias for boxctl."""
	naust_bin = "/usr/local/bin/naust"
	if not os.path.exists(naust_bin):
		os.symlink(_BIN, naust_bin)
