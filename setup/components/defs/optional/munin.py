"""
Munin system monitoring (node + master).

Steps:
  config          - write /etc/munin/munin.conf
  node-config     - configure munin-node.conf (hostname, log_level, IPv4 bind)
  plugin-config   - autoconfigure munin plugins, remove NTP + down-interface plugins
  systemd         - install munin.service and enable it
  log-perms       - fix www-data-owned log file permissions
  muninweb-unit   - install and enable the muninweb systemd unit (baremetal only)

Munin has no web server of its own: muninweb serves the cron-rendered
site plus the graph CGI on loopback (port 4948), so nginx can front
munin behind auth_request like every other monitoring backend. The
muninweb binary itself is installed by the daemon component
(defs/daemon.py), which owns all Go daemon binaries as one artifact set.
"""

import os
import shlex
import shutil
import subprocess

from doit.tools import config_changed

from ... import artifacts, SETUP_DIR
from ...component import Component, BAREMETAL
from ...task_names import DAEMON_MUNINWEB
import pathlib

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="munin",
	packages=[
		"munin",
		"munin-node",
		"libcgi-fast-perl",  # needed by /usr/lib/munin/cgi/munin-cgi-graph
		"procps",  # provides ps/free/top for CPU/memory/process plugins
		"sudo",  # supervisord runs munin-cron as the munin user via sudo
	],
	services=["munin", "munin-node", "naust-muninweb"],
	docker_services=["munin", "munin-node"],
	enabled=lambda env: env.get("MONITORING_TOOL", "munin") == "munin",
)

_CONF_DIR = os.path.join(SETUP_DIR, "conf", "systemd")
_MUNINWEB_UNIT = "/lib/systemd/system/naust-muninweb.service"


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, runtime: str) -> list[dict]:
	hostname = env.get("PRIMARY_HOSTNAME", "localhost")
	repo_root = os.path.dirname(SETUP_DIR)
	daemon_src = os.path.join(repo_root, "daemon")
	unit_src = os.path.join(daemon_src, "systemd", "naust-muninweb.service")

	tasks = [
		{
			"name": "config",
			"targets": ["/etc/munin/munin.conf"],
			"uptodate": [config_changed(f"{hostname}:{artifacts.fn_stamp(_config)}")],
			"actions": [(_config, [hostname])],
		},
		{
			"name": "node-config",
			"uptodate": [config_changed(f"{hostname}:{artifacts.fn_stamp(_node_config)}")],
			"actions": [(_node_config, [hostname])],
		},
		{
			"name": "plugin-config",
			# Runs munin's autoconfiguration to activate appropriate plugins.
			# Re-runs if the function body changes (new cleanup rule added, etc.).
			"uptodate": [config_changed(artifacts.fn_stamp(_plugin_config))],
			"actions": [(_plugin_config,)],
		},
		{
			"name": "systemd",
			"targets": ["/lib/systemd/system/munin.service"],
			"uptodate": [config_changed(artifacts.fn_stamp(_systemd))],
			"actions": [(_systemd,)],
		},
		{
			"name": "log-perms",
			# Debian's munin postinst chowns these to www-data; munin itself
			# needs to own them to write CGI output.
			"uptodate": [config_changed(artifacts.fn_stamp(_log_perms))],
			"actions": [(_log_perms,)],
		},
	]

	# Baremetal only: the Docker munin image must ship muninweb itself.
	if runtime == BAREMETAL:
		tasks += [
			{
				"name": "muninweb-unit",
				"uptodate": [config_changed((artifacts.hash_files(unit_src) if os.path.exists(unit_src) else artifacts.hash_files(_MUNINWEB_UNIT) if os.path.exists(_MUNINWEB_UNIT) else "") + ":" + artifacts.fn_stamp(_muninweb_unit))],
				"task_dep": [DAEMON_MUNINWEB],
				"actions": [(_muninweb_unit, [unit_src])],
			},
		]

	return tasks


# ── Action functions ──────────────────────────────────────────────────────────


def _config(hostname: str) -> None:
	"""Write munin master config with alert email to the admin address."""
	artifacts.write_file(
		"/etc/munin/munin.conf",
		"dbdir /var/lib/munin\n"
		"htmldir /var/cache/munin/www\n"
		"logdir /var/log/munin\n"
		"rundir /var/run/munin\n"
		"tmpldir /etc/munin/templates\n"
		"\n"
		"includedir /etc/munin/munin-conf.d\n"
		"\n"
		"# path dynazoom uses for requests\n"
		"cgiurl_graph /admin/munin/cgi-graph\n"
		"\n"
		"# a simple host tree\n"
		f"[{hostname}]\n"
		"address 127.0.0.1\n"
		"\n"
		"# send alerts to the following address\n"
		"contacts admin\n"
		f'contact.admin.command mail -s "Munin notification ${{var:host}}" administrator@{hostname}\n'
		"contact.admin.always_send warning critical\n",
	)


def _node_config(hostname: str) -> None:
	"""Configure munin-node: set hostname, reduce log verbosity, bind loopback only."""
	artifacts.editconf(
		"/etc/munin/munin-node.conf",
		f"host_name={hostname}",
		"log_level=1",
		space_delim=True,
	)

	# Bind to loopback only - munin-master is on the same host.
	# Explicit allow directive rather than relying on package defaults.
	content = pathlib.Path("/etc/munin/munin-node.conf").read_text(encoding="utf-8")

	if "^host " in content or "\nhost " in content:
		subprocess.run(
			["sed", "-i", r"s/^host .*/host 127.0.0.1/", "/etc/munin/munin-node.conf"],
			check=True,
		)
	else:
		with open("/etc/munin/munin-node.conf", "a", encoding="utf-8") as fh:
			fh.write("host 127.0.0.1\n")

	if "allow " not in content and "cidr_allow " not in content:
		with open("/etc/munin/munin-node.conf", "a", encoding="utf-8") as fh:
			fh.write("allow ^127\\.0\\.0\\.1$\n")


def _plugin_config() -> None:
	"""Run munin's autoconfiguration and remove unwanted plugins.

	Removes NTP peer plugins (addresses change, causing chart churn) and
	network interface plugins for interfaces that aren't up.
	"""
	os.makedirs("/var/lib/munin-node/plugin-state/", exist_ok=True)

	# Autoconfigure: the shell output is a series of ln -sf and rm commands.
	result = subprocess.run(
		["munin-node-configure", "--shell", "--remove-also"],
		capture_output=True,
		text=True,
		check=False,
	)
	for raw_line in result.stdout.splitlines():
		line = raw_line.strip()
		if line:
			subprocess.run(shlex.split(line), check=False)

	# Remove NTP peer plugins (no one wants to monitor random NTP peers).
	result = subprocess.run(
		["find", "/etc/munin/plugins/", "-lname", "/usr/share/munin/plugins/ntp_", "-print0"],
		capture_output=True,
		check=False,
	)
	if result.stdout:
		subprocess.run(
			["xargs", "-0", "rm", "-f"],
			input=result.stdout,
			check=False,
		)

	# Remove plugins for network interfaces that are not up.
	result = subprocess.run(
		["find", "/etc/munin/plugins/", "-lname", "/usr/share/munin/plugins/if_", "-o", "-lname", "/usr/share/munin/plugins/if_err_", "-o", "-lname", "/usr/share/munin/plugins/bonding_err_"],
		capture_output=True,
		text=True,
		check=False,
	)
	for plugin_path in result.stdout.splitlines():
		# Extract interface name from the plugin symlink name (e.g. if_eth0 → eth0).
		iface = plugin_path.rsplit("_", 1)[-1]
		operstate = f"/sys/class/net/{iface}/operstate"
		if not os.path.exists(operstate):
			continue
		if pathlib.Path(operstate).read_text(encoding="utf-8").strip() != "up":
			os.unlink(plugin_path)


def _systemd() -> None:
	"""Install the munin systemd unit and enable it."""
	unit_src = os.path.join(_CONF_DIR, "munin.service")
	if os.path.exists(unit_src):
		subprocess.run(
			["cp", "--remove-destination", unit_src, "/lib/systemd/system/munin.service"],
			check=True,
		)
	subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)
	subprocess.run(["systemctl", "unmask", "munin.service"], check=False, capture_output=True)
	subprocess.run(["systemctl", "enable", "munin.service"], check=True, capture_output=True)


def _muninweb_unit(unit_src: str) -> None:
	"""Install and enable the muninweb systemd unit.

	The unit runs as the munin user with ProtectSystem=strict, so the
	CGI graph cache directory must exist and be writable before start.
	"""
	os.makedirs("/var/lib/munin/cgi-tmp", exist_ok=True)
	subprocess.run(["chown", "munin:munin", "/var/lib/munin/cgi-tmp"], check=True, capture_output=True)

	if os.path.exists(unit_src):
		shutil.copy2(unit_src, _MUNINWEB_UNIT)
	elif not os.path.exists(_MUNINWEB_UNIT):
		msg = f"muninweb unit file not found at {unit_src} or {_MUNINWEB_UNIT}"
		raise RuntimeError(msg)
	subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)
	subprocess.run(["systemctl", "enable", "naust-muninweb.service"], check=True, capture_output=True)


def _log_perms() -> None:
	"""Fix log file ownership: Debian postinst chowns them to www-data:adm for
	use with spawn-fcgi, but munin itself needs to own them to write CGI output."""
	for log in [
		"/var/log/munin/munin-cgi-html.log",
		"/var/log/munin/munin-cgi-graph.log",
	]:
		if not os.path.exists(log):
			open(log, "a", encoding="utf-8").close()
		subprocess.run(["chown", "munin", log], check=False)
