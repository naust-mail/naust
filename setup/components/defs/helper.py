"""
Privileged helper daemon (helperd, Go).

Executes the fixed menu of privileged operations (service lifecycle,
allowlisted postfix/config writes, apt, reboot) over
/run/naust/helper.sock so the management daemon can run without root.
The management daemon delegates automatically when the socket exists.

Steps:
  group - create the 'naust' system group that may connect to the socket
  unit  - install and enable the systemd unit

The helperd binary itself is installed by the daemon component
(defs/daemon.py), which owns all Go daemon binaries as one artifact set.

Bare metal only: in Docker, per-container control sockets already fill the
helper role and the management container holds no host privileges.
"""

import grp
import os
import subprocess

from doit.tools import config_changed

from .. import artifacts, SETUP_DIR
from ..component import Component
from ..task_names import DAEMON_HELPERD

COMPONENT = Component(
	name="helper",
	packages=[],
	services=["naust-helper"],
	docker_services=[],
	skip_on=["docker"],
)

_UNIT_DEST = "/lib/systemd/system/naust-helper.service"
_SOCKET_GROUP = "naust"


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	repo_root = os.path.dirname(SETUP_DIR)
	daemon_src = os.path.join(repo_root, "daemon")
	unit_src = os.path.join(daemon_src, "systemd", "naust-helper.service")
	storage_root = env["STORAGE_ROOT"]

	return [
		{
			"name": "group",
			"uptodate": [config_changed(artifacts.fn_stamp(_group))],
			"actions": [(_group,)],
		},
		{
			"name": "unit",
			"uptodate": [config_changed((artifacts.hash_files(unit_src) if os.path.exists(unit_src) else artifacts.hash_files(_UNIT_DEST) if os.path.exists(_UNIT_DEST) else "") + f":{storage_root}:" + artifacts.fn_stamp(_unit))],
			"task_dep": ["helper:group", DAEMON_HELPERD],
			"actions": [(_unit, [unit_src, storage_root])],
		},
	]


def _group() -> None:
	"""Create the system group whose members may connect to the helper socket.

	The management daemon's user joins this group when the web process is
	de-rooted; until then the socket is simply root-connectable.
	"""
	try:
		grp.getgrnam(_SOCKET_GROUP)
	except KeyError:
		subprocess.run(["groupadd", "--system", _SOCKET_GROUP], check=True, capture_output=True)


def _unit(unit_src: str, storage_root: str) -> None:
	"""Install and enable the helper systemd unit.

	The unit file at /lib/systemd/system/ is the durable copy; the repo
	source is only needed the first time (or when the unit changes). The
	unit is a ${STORAGE_ROOT} template: ReadWritePaths must name the real
	path, matching the pattern managerd's own unit install uses.
	"""
	if os.path.exists(unit_src):
		artifacts.write_file(_UNIT_DEST, artifacts.render_template(unit_src, {"STORAGE_ROOT": storage_root}))
	elif not os.path.exists(_UNIT_DEST):
		msg = f"helper unit file not found at {unit_src} or {_UNIT_DEST}"
		raise RuntimeError(msg)
	subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)
	subprocess.run(["systemctl", "enable", "naust-helper.service"], check=True, capture_output=True)
