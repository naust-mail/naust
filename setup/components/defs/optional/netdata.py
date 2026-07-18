"""
Netdata real-time system monitoring.

Steps:
  install  - download and run the official kickstart script (skipped if already installed)
  config   - write /etc/netdata/netdata.conf (loopback-only, disable telemetry)
  systemd  - enable netdata service
"""

import hashlib
import os
import subprocess
import tempfile

from doit.tools import config_changed

from ... import artifacts
from ...component import Component

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="netdata",
	packages=[],
	services=["netdata"],
	docker_services=[],
	skip_on=["docker"],
	enabled=lambda env: env.get("MONITORING_TOOL", "none") == "netdata",
)

_NETDATA_VERSION = "1.47.5"
_NETDATA_SHA256 = "337139e899257c76c14881e76987cefa409075da07e232bddf7fcd1bd4416159"
_NETDATA_URL = f"https://github.com/netdata/netdata/releases/download/v{_NETDATA_VERSION}/netdata-x86_64-v{_NETDATA_VERSION}.gz.run"
_NETDATA_BIN = "/opt/netdata/bin/netdata"
_NETDATA_CONF = "/opt/netdata/etc/netdata/netdata.conf"


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	hostname = env.get("PRIMARY_HOSTNAME", "localhost")

	return [
		{
			"name": "install",
			"uptodate": [config_changed(_NETDATA_VERSION), lambda: os.path.isfile(_NETDATA_BIN)],
			"actions": [_install],
		},
		{
			"name": "config",
			"targets": [_NETDATA_CONF],
			"task_dep": ["netdata:install"],
			"uptodate": [config_changed(f"{hostname}:{artifacts.fn_stamp(_config)}")],
			"actions": [(_config, [hostname])],
		},
		{
			"name": "systemd",
			"task_dep": ["netdata:install"],
			"uptodate": [config_changed(artifacts.fn_stamp(_systemd))],
			"actions": [(_systemd,)],
		},
	]


# ── Action functions ──────────────────────────────────────────────────────────


def _install() -> None:
	"""Download, verify, and run the pinned netdata installer."""
	fd, tmp = tempfile.mkstemp(suffix=".gz.run")
	os.close(fd)
	try:
		subprocess.run(["wget", "--https-only", "-O", tmp, _NETDATA_URL], check=True)
		h = hashlib.sha256()
		with open(tmp, "rb") as f:
			for chunk in iter(lambda: f.read(65536), b""):
				h.update(chunk)
		actual = h.hexdigest()
		if actual != _NETDATA_SHA256:
			msg = f"netdata installer SHA256 mismatch\n  expected: {_NETDATA_SHA256}\n  got:      {actual}"
			raise RuntimeError(msg)
		subprocess.run(
			["sh", tmp, "--accept", "--", "--dont-start-it", "--disable-telemetry"],
			check=True,
		)
	finally:
		os.unlink(tmp)


def _config(hostname: str) -> None:
	"""Bind to loopback (nginx proxies /admin/netdata/), set hostname, disable telemetry."""
	artifacts.write_file(
		_NETDATA_CONF,
		"[global]\n"
		f"\thostname = {hostname}\n"
		"\t# Loopback only - nginx proxies /admin/netdata/ externally.\n"
		"\tbind socket to IP = 127.0.0.1\n"
		"\t# Disable anonymous usage stats sent upstream.\n"
		"\tanonymous statistics = no\n"
		"\n"
		"[db]\n"
		"\tmode = dbengine\n"
		"\tstorage tiers = 1\n"
		"\tdbengine multihost disk space MB = 64\n"
		"\n"
		"[cloud]\n"
		"\tenabled = no\n",
	)


def _systemd() -> None:
	subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)
	subprocess.run(["systemctl", "enable", "netdata"], check=True, capture_output=True)
