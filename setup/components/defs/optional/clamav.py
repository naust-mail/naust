"""
ClamAV antivirus (optional).

On bare metal: installs clamav-milter so Postfix scans mail directly as a milter.
Rspamd also connects to clamd via the unix socket for in-process scanning.
In Docker: the naust-clamav sidecar provides clamav-milter over TCP; only
the base ClamAV packages are needed here.

Steps:
  config          - configure clamd.conf socket path and logging
  rspamd-wiring   - write rspamd antivirus.conf (only when SPAM_FILTER=rspamd)
  milter-config   - write clamav-milter.conf and add milter to postfix (baremetal only)
  freshclam       - download initial signature database (skipped if already present)
"""

import os
import subprocess

from doit.tools import config_changed

from ... import artifacts
from ... import packages as pkg
from ...component import Component, BAREMETAL
from ...task_names import RSPAMD_POSTFIX_MILTERS, DKIM_POSTFIX_MILTERS

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="clamav",
	packages=[],  # runtime-conditional; installed by the "packages" task action
	services=["clamav-daemon", "clamav-freshclam"],
	docker_services=["clamav-daemon", "clamav-freshclam"],
	enabled=lambda env: env.get("ENABLE_CLAMAV", "false").lower() == "true",
)


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, runtime: str) -> list[dict]:
	spam_filter = env.get("SPAM_FILTER", "rspamd")

	tasks = [
		{
			"name": "packages",
			# Re-runs when runtime changes (baremetal adds clamav-milter, docker does not).
			# mask+install order is enforced inside the action.
			"uptodate": [config_changed(f"clamav-pkgs:{runtime}")],
			"actions": [(_install_packages, [runtime])],
		},
		{
			"name": "config",
			"uptodate": [config_changed(artifacts.fn_stamp(_config))],
			"task_dep": ["clamav:packages"],
			"actions": [(_config,)],
		},
		{
			"name": "freshclam",
			# Only download if the signature database is completely absent.
			# On re-runs the running clamav-freshclam service keeps them current.
			"uptodate": [lambda _task, _values: os.path.exists("/var/lib/clamav/main.cvd") or os.path.exists("/var/lib/clamav/main.cld")],
			"task_dep": ["clamav:packages"],
			"actions": [(_freshclam,)],
		},
	]

	if spam_filter == "rspamd":
		tasks.append({
			"name": "rspamd-wiring",
			# Write antivirus.conf so rspamd passes mail through clamd for scanning.
			"targets": ["/etc/rspamd/local.d/antivirus.conf"],
			"uptodate": [config_changed(artifacts.fn_stamp(_rspamd_wiring))],
			"task_dep": ["clamav:packages"],
			"actions": [(_rspamd_wiring,)],
		})

	if runtime == BAREMETAL:
		# Dep on the spam filter's milter task, not just postfix:spam-filter directly.
		# rspamd/dkim both assign smtpd_milters= in main.cf; clamav appends to it.
		# Without this dep, doit may run clamav:milter-config before the milter
		# assignment lands, leaving clamav as the only milter instead of appending.
		milter_dep = RSPAMD_POSTFIX_MILTERS if spam_filter == "rspamd" else DKIM_POSTFIX_MILTERS
		tasks.append({
			"name": "milter-config",
			# Configure clamav-milter and wire it into Postfix on bare metal.
			"targets": ["/etc/clamav/clamav-milter.conf"],
			"uptodate": [config_changed(artifacts.fn_stamp(_milter_config))],
			"task_dep": [milter_dep],
			"actions": [(_milter_config,)],
		})

	return tasks


# ── Action functions ──────────────────────────────────────────────────────────


def _install_packages(runtime: str) -> None:
	"""Install ClamAV packages. On baremetal, mask clamav-milter before install so
	postinst doesn't try to start the milter before clamd is running."""
	if runtime == BAREMETAL:
		subprocess.run(["systemctl", "mask", "clamav-milter"], check=False, capture_output=True)
		pkg.ensure_installed(["clamav", "clamav-daemon", "clamav-milter"])
	else:
		pkg.ensure_installed(["clamav", "clamav-daemon"])


def _config() -> None:
	"""Configure clamd to use the unix socket path rspamd's antivirus module expects."""
	artifacts.editconf(
		"/etc/clamav/clamd.conf",
		"LocalSocket=/run/clamav/clamd.ctl",
		"LocalSocketMode=666",
		"LogSyslog=true",
		"LogFacility=LOG_MAIL",
		space_delim=True,
	)


def _freshclam() -> None:
	"""Download the ClamAV virus signature database on first install.

	Stops the freshclam service to avoid concurrent database writes, then
	runs freshclam directly. If the download fails (no network in CI), we
	warn but don't abort - the running service will retry on schedule.
	"""
	subprocess.run(
		["systemctl", "stop", "clamav-freshclam"],
		check=False,
		capture_output=True,
	)
	print("Downloading the ClamAV signature database...", flush=True)
	result = subprocess.run(["freshclam"], check=False, capture_output=True)
	if result.returncode != 0:
		print("WARNING: freshclam could not update signatures - check network connectivity.")


def _rspamd_wiring() -> None:
	"""Wire rspamd's antivirus module to scan through the clamd socket."""
	os.makedirs("/etc/rspamd/local.d", exist_ok=True)
	artifacts.write_file(
		"/etc/rspamd/local.d/antivirus.conf",
		'clamav {\n    action = "reject";\n    symbol = "CLAM_VIRUS";\n    type = "clamav";\n    log_clean = false;\n    servers = "/run/clamav/clamd.ctl";\n    scan_mime_parts = true;\n    scan_text_mime = false;\n    scan_image_mime = false;\n    max_size = 20971520; # 20MB\n}\n',
	)


def _milter_config() -> None:
	"""Write clamav-milter.conf and add the milter socket to Postfix.

	The milter connects to clamd.ctl, so clamd must be started before the
	milter. The runner restarts clamav-daemon first (it appears before
	clamav-milter in COMPONENT.services ordering).
	"""
	artifacts.write_file(
		"/etc/clamav/clamav-milter.conf",
		'MilterSocket unix:/run/clamav/clamav-milter.sock\nMilterSocketMode 660\nPidFile /run/clamav/clamav-milter.pid\nClamdSocket unix:/run/clamav/clamd.ctl\nOnInfected Reject\nRejectMsg "Message rejected: virus detected"\nAddHeader Replace\nLogSyslog true\nLogFacility LOG_MAIL\n',
	)

	# Append the milter to smtpd_milters in main.cf (idempotent).
	# postconf returns the current value; we append only if not already present.
	result = subprocess.run(
		["postconf", "-h", "smtpd_milters"],
		capture_output=True,
		text=True,
		check=False,
	)
	current = result.stdout.strip()
	if current.startswith("$"):
		current = ""
	milter = "unix:/run/clamav/clamav-milter.sock"
	if milter not in current.split():
		new_val = f"{current} {milter}".strip() if current else milter
		artifacts.editconf("/etc/postfix/main.cf", f"smtpd_milters={new_val}")
		artifacts.editconf(
			"/etc/postfix/main.cf",
			r"non_smtpd_milters=$smtpd_milters",
		)

	# Unmask so systemctl can start the milter after clamd is up.
	subprocess.run(["systemctl", "unmask", "clamav-milter"], check=False, capture_output=True)
