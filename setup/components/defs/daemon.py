"""
Go daemon binaries (helperd, muninweb).

One component owns installing everything daemon/ builds to - the
binaries are one artifact set, built together by CI and attached to
the versioned project release (see gobuild.py for the fetch-or-build
mechanics). Each binary is its own step so a box only installs what
its configuration uses; components that run one of these binaries
(helper, munin) install their systemd units and depend on the
matching step via task_names.py.

Steps:
  helperd  - install the privileged helper daemon binary
  managerd - install the management daemon binary
  muninweb - install the munin web frontend binary (only when munin is the monitoring tool)

Bare metal only: Docker images ship their binaries at image build time.
"""

import os

from doit.tools import config_changed

from .. import artifacts, SETUP_DIR
from ..component import Component
from ..gobuild import fetch_or_build

COMPONENT = Component(
	name="daemon",
	packages=[],
	services=[],
	docker_services=[],
	skip_on=["docker"],
)

_INST_DIR = "/usr/local/lib/naust"


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	repo_root = os.path.dirname(SETUP_DIR)
	daemon_src = os.path.join(repo_root, "daemon")

	def binary_task(name: str) -> dict:
		out = os.path.join(_INST_DIR, name)
		return {
			"name": name,
			# Re-runs when any Go source changes. When the repo is gone
			# (re-run after install), fall back to the installed binary's
			# hash so the task doesn't re-run spuriously.
			"uptodate": [config_changed(artifacts.hash_files(daemon_src) if os.path.isdir(daemon_src) else artifacts.file_hash(out) if os.path.exists(out) else "")],
			"targets": [out],
			"actions": [(_binary, [daemon_src, name, out])],
		}

	tasks = [binary_task("helperd"), binary_task("managerd")]
	# Same gate as the munin component's enabled lambda: no monitoring
	# choice recorded means a legacy munin box.
	if env.get("MONITORING_TOOL", "munin") == "munin":
		tasks.append(binary_task("muninweb"))
	return tasks


def _binary(daemon_src: str, name: str, out: str) -> None:
	if not os.path.isdir(daemon_src):
		if os.path.exists(out):
			return
		msg = f"{name} binary is not installed and daemon source directory does not exist ({daemon_src}). Run setup from the repo root."
		raise RuntimeError(msg)
	fetch_or_build(daemon_src, f"./cmd/{name}", out)
