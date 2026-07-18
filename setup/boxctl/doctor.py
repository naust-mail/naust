"""
boxctl doctor - live status check and service management for a running box.

Scans all services, shows health status, lets you manage each one.
Navigate with up/down, Enter to open a service, Esc to quit.
Exits non-zero if any service is degraded.
"""

import os
import sys
import subprocess
import datetime
import tarfile
import re
import threading
import time
from typing import NamedTuple
from collections.abc import Callable
from .ui import (
	bold,
	gray_desc,
	lavender,
	white_b,
	red,
	green,
	Raw,
	read_key,
	clear,
	_term_width,
)
from .checks import (
	OK,
	WARN,
	ERR,
	OFF,
	_port_open,
	check_mail,
	check_spam,
	check_webmail,
	check_dns,
	check_certs,
	check_radicale,
	check_filebrowser,
	check_nginx,
	check_unbound,
	check_clamav,
	check_monitoring,
	check_system,
	check_management,
	check_backup,
	check_relay,
)
import pathlib
from .questions import step_webmail, step_monitoring

BARE_METAL_CONF = "/etc/naust.conf"
# Parent of the boxctl/ package - either setup/ (dev) or /usr/local/lib/naust/ (installed).
# components/ lives at the same level, so this is the correct cwd for python3 -m components.runner.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_ANSI_RE = re.compile(r'\x1b(?:\[[0-9;?]*[A-Za-z]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|[@-_][0-?]*[ -/]*[@-~]|[0-?])')

# -- Backup + apply helpers -----------------------------------------------------

_BACKUP_PATHS = {
	"WEBMAIL_CLIENT:roundcube": ["roundcube"],
	"WEBMAIL_CLIENT:snappymail": ["snappymail"],
	"WEBMAIL_CLIENT:cypht": ["cypht"],
	"SPAM_FILTER:spamassassin": ["mail/spamassassin"],
	"ENABLE_RADICALE:true": ["mail/radicale"],
	"ENABLE_FILEBROWSER:true": ["filebrowser"],
	"MONITORING_TOOL:beszel": ["beszel"],
	"MONITORING_TOOL:munin": ["munin"],
}

_STOP_SERVICES = {
	"WEBMAIL_CLIENT:rav": ["rav"],
	"WEBMAIL_CLIENT:roundcube": [],
	"WEBMAIL_CLIENT:snappymail": [],
	"WEBMAIL_CLIENT:cypht": [],
	"WEBMAIL_CLIENT:none": [],
	"SPAM_FILTER:spamassassin": ["spampd", "opendkim", "opendmarc", "postgrey"],
	"SPAM_FILTER:rspamd": ["rspamd", "redis-server"],
	"ENABLE_RADICALE:true": ["radicale"],
	"ENABLE_FILEBROWSER:true": ["filebrowser"],
	"ENABLE_CLAMAV:true": ["clamav-daemon", "clamav-freshclam"],
	"MONITORING_TOOL:beszel": ["beszel-hub", "beszel-agent"],
	"MONITORING_TOOL:netdata": ["netdata"],
	"MONITORING_TOOL:munin": ["munin", "munin-node"],
}


def _backup(storage_root, conf_key):
	paths = _BACKUP_PATHS.get(conf_key, [])
	existing = [os.path.join(storage_root, p) for p in paths if os.path.exists(os.path.join(storage_root, p))]
	if not existing:
		return None
	backup_dir = os.path.join(storage_root, "backups", "doctor")
	os.makedirs(backup_dir, exist_ok=True)
	ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
	label = conf_key.replace(":", "-").replace("_", "").lower()
	archive = os.path.join(backup_dir, f"{ts}-{label}.tar.gz")
	with tarfile.open(archive, "w:gz") as tar:
		for path in existing:
			tar.add(path, arcname=os.path.relpath(path, storage_root))
	return archive


def _stop(conf_key):
	for svc in _STOP_SERVICES.get(conf_key, []):
		subprocess.run(["systemctl", "stop", svc], capture_output=True)
		subprocess.run(["systemctl", "disable", svc], capture_output=True)


def _start(conf_key) -> list[str]:
	"""Re-enable and start services for a conf_key. Returns list of services that failed to start."""
	failed = []
	for svc in _STOP_SERVICES.get(conf_key, []):
		subprocess.run(["systemctl", "enable", svc], capture_output=True)
		r = subprocess.run(["systemctl", "start", svc], capture_output=True)
		if r.returncode != 0:
			failed.append(svc)
	return failed


# -- Runner helpers -------------------------------------------------------------


def _redraw_log(buf, log_lines):
	"""Redraw the rolling log panel in place (must have reserved log_lines blank lines first)."""
	width = _term_width() - 6
	visible = buf[-log_lines:]
	sys.stdout.write(f"\033[{log_lines}A")
	for i in range(log_lines):
		if i < len(visible):
			sys.stdout.write(f"  {gray_desc(visible[i][:width])}\033[K\n")
		else:
			sys.stdout.write("\033[K\n")
	sys.stdout.flush()


def _run_component(names: list[str], log_buf=None, log_lines=10, force=False) -> bool:
	"""Run one or more components via the component runner. Returns True on success.

	force: if True, run with --force flag to skip cache checks.
	"""
	if not names:
		return True
	cmd = ["python3", "-m", "components.runner", *names]
	if force:
		cmd.append("--force")
	proc = subprocess.Popen(
		cmd,
		cwd=PROJECT_ROOT,
		env={**os.environ, "PYTHONUNBUFFERED": "1", "TERM": "dumb"},
		stdin=subprocess.DEVNULL,
		stdout=subprocess.PIPE if log_buf is not None else None,
		stderr=subprocess.STDOUT if log_buf is not None else None,
	)
	if log_buf is not None:

		def _reader():
			for raw in proc.stdout:
				# apt uses \r to overwrite progress lines; take the last segment
				parts = raw.split(b"\r")
				text = _ANSI_RE.sub("", parts[-1].decode("utf-8", errors="replace")).rstrip()
				if text:
					log_buf.append(text)
					_redraw_log(log_buf, log_lines)

		t = threading.Thread(target=_reader, daemon=True)
		t.start()
	try:
		proc.wait(timeout=300)
	except subprocess.TimeoutExpired:
		proc.kill()
		proc.wait()
		if log_buf is not None:
			t.join(timeout=2)
			log_buf.append("[timed out after 5 minutes]")
			_redraw_log(log_buf, log_lines)
		else:
			print(f"\n  Component runner timed out: {' '.join(names)}")
		return False
	if log_buf is not None:
		t.join()
	return proc.returncode == 0


def _run_all_enabled(log_buf=None, log_lines=10, force=False) -> bool:
	"""Run all enabled components. Stamps ensure only changed tasks actually execute."""
	cmd = ["python3", "-m", "components.runner"]
	if force:
		cmd.append("--force")
	proc = subprocess.Popen(
		cmd,
		cwd=PROJECT_ROOT,
		env={**os.environ, "PYTHONUNBUFFERED": "1", "TERM": "dumb"},
		stdin=subprocess.DEVNULL,
		stdout=subprocess.PIPE if log_buf is not None else None,
		stderr=subprocess.STDOUT if log_buf is not None else None,
	)
	if log_buf is not None:

		def _reader():
			for raw in proc.stdout:
				parts = raw.split(b"\r")
				text = _ANSI_RE.sub("", parts[-1].decode("utf-8", errors="replace")).rstrip()
				if text:
					log_buf.append(text)
					_redraw_log(log_buf, log_lines)

		t = threading.Thread(target=_reader, daemon=True)
		t.start()
	try:
		proc.wait(timeout=300)
	except subprocess.TimeoutExpired:
		proc.kill()
		proc.wait()
		if log_buf is not None:
			t.join(timeout=2)
			log_buf.append("[timed out after 5 minutes]")
			_redraw_log(log_buf, log_lines)
		else:
			print("  Component runner timed out")
		return False
	if log_buf is not None:
		t.join()
	return proc.returncode == 0


def _write_conf_key(key, value):
	lines = []
	found = False
	with open(BARE_METAL_CONF, encoding="utf-8") as f:
		for line in f:
			if line.strip().startswith(key + "=") and not line.strip().startswith("#"):
				lines.append(f"{key}={value}\n")
				found = True
			else:
				lines.append(line)
	if not found:
		lines.append(f"{key}={value}\n")
	# Write to a tempfile on the same filesystem then atomically replace.
	# A plain open(..., "w") truncates the file before writing; a kill mid-write
	# would destroy the entire config.
	import tempfile

	dir_ = os.path.dirname(BARE_METAL_CONF)
	fd, tmp = tempfile.mkstemp(dir=dir_, prefix=".naust-conf-")
	try:
		with os.fdopen(fd, "w", encoding="utf-8") as f:
			f.writelines(lines)
		os.replace(tmp, BARE_METAL_CONF)
	except Exception:
		os.unlink(tmp)
		raise


def _regenerate(_conf, reload_daemon=False):  # noqa: ARG001 - reload_daemon kept for call-site clarity; every call restarts managerd regardless (see comment below)
	# managerd converges nginx sites and nsd zones on startup, so a
	# restart IS the regeneration (and re-reads /etc/naust.conf, which
	# is why service enable/disable needs this).
	subprocess.run(["systemctl", "restart", "naust-managerd"], capture_output=True)
	for _ in range(30):
		if _port_open("127.0.0.1", 10223, timeout=1):
			return True
		time.sleep(1)
	return False


# -- UI rendering ---------------------------------------------------------------

_STATUS_ICON = {
	OK: "\033[38;2;95;255;135m✓\033[0m",
	WARN: "\033[38;2;255;215;0m!\033[0m",
	ERR: "\033[38;2;255;85;85m✗\033[0m",
	OFF: "\033[38;2;103;105;114m-\033[0m",
}


def _icon(status):
	return _STATUS_ICON.get(status, "-")


def _press_enter_to_return():
	"""Wait for Enter/Esc in raw mode (safe to call while already in Raw())."""
	print(f"\n  {gray_desc('Press Enter to return...')}", end="", flush=True)
	while True:
		k = read_key()
		if k in {'enter', 'esc', 'ctrl_c'}:
			break
	print()


def _render_list(services, results, sel, first=False):
	if first:
		print("\033[s", end="", flush=True)
	else:
		print("\033[u\033[J", end="", flush=True)

	out = []
	label_w = max(len(svc.label) for svc in services) + 2
	for i, svc in enumerate(services):
		status, msg = results.get(svc.key, (OFF, "checking..."))
		icon = _icon(status)
		pad = " " * (label_w - len(svc.label))
		arrow = lavender("❯") if i == sel else " "
		lbl = lavender(svc.label, bold=True) if i == sel else white_b(svc.label)
		out.append(f"  {arrow} {icon}  {lbl}{pad}{gray_desc(msg)}")

	out.extend(["", f"  {gray_desc('↑↓ navigate  ·  Enter to manage  ·  r recheck all  ·  q quit')}"])

	text = "\n".join(out)
	print(text, end="\n", flush=True)


def _render_detail(_label, status, msg, actions, sel, first=False):
	if first:
		print("\033[s", end="", flush=True)
	else:
		print("\033[u\033[J", end="", flush=True)

	out = [f"  {_icon(status)}  {gray_desc(msg)}", ""]

	for i, (action_label, _) in enumerate(actions):
		arrow = lavender("❯") if i == sel else " "
		lbl = lavender(action_label, bold=True) if i == sel else white_b(action_label)
		out.append(f"  {arrow} {lbl}")

	out.extend(["", f"  {gray_desc('↑↓ navigate  ·  Enter to select  ·  r recheck  ·  Esc to go back')}"])

	text = "\n".join(out)
	print(text, end="\n", flush=True)


def _warn_screen(lines, confirm_label="Yes, proceed", cancel_label="Cancel", title=None, context=None):
	"""Show a warning prompt and return True if user confirms, False if cancelled."""
	if title is None:
		title = lines[0] if lines else "Confirm"
	subtitle = f"{red('!')}  {title}"
	_page_header(context=context, subtitle=subtitle)
	sel = 1  # default to Cancel
	choices = [(confirm_label, True), (cancel_label, False)]

	def render(first=False):
		if first:
			print("\033[s", end="", flush=True)
		else:
			print("\033[u\033[J", end="", flush=True)
		out = [f"  {line}" for line in lines[1:]]
		out.append("")
		for i, (label, _) in enumerate(choices):
			if i == sel:
				out.append(f"  {lavender('❯', bold=True)} {lavender(label, bold=True)}")
			else:
				out.append(f"    {white_b(label)}")
		out.extend(["", f"  {gray_desc('↑↓ navigate  ·  Enter to confirm  ·  Esc to cancel')}"])
		text = "\n".join(out)
		print(text, end="\n", flush=True)

	print("\033[?25l", end="", flush=True)
	try:
		render(first=True)
		with Raw():
			while True:
				k = read_key()
				if k in {"up", "shift_tab"}:
					sel = (sel - 1) % len(choices)
				elif k in {"down", "tab"}:
					sel = (sel + 1) % len(choices)
				elif k == "enter":
					return choices[sel][1]
				elif k in {"esc", "ctrl_c"}:
					return False
				render()
	finally:
		print("\033[?25h", end="", flush=True)


def _page_header(context=None, subtitle=None):
	"""Print the standard boxctl doctor page header.

	context: shown on title line after "boxctl doctor -" (grey)
	subtitle: shown below separator on its own line
	"""
	clear()
	title = f"boxctl doctor  {gray_desc('-')}  {gray_desc(context)}" if context else "boxctl doctor"
	print(f"\n  {bold(title)}")
	print(f"  {gray_desc('─' * (_term_width() - 4))}")
	if subtitle:
		print()
		print(f"  {subtitle}")
	print()


def _run_logged_screen(title, run_fn):
	"""TUI page: header, title, 10-line rolling log, result footer.
	run_fn(log_buf, log_lines) -> bool."""
	LOG_LINES = 10
	_page_header(title)
	print()
	for _ in range(LOG_LINES):
		print()
	log_buf = []
	ok = run_fn(log_buf, LOG_LINES)
	print()
	if ok:
		print(f"  {green('✓')} {bold('Done.')}")
	else:
		print(f"  {red('✗')} {bold('Failed.')}  {gray_desc('Run sudo setup/install.sh to restore a known-good state.')}")
	_press_enter_to_return()
	return ok


def _run_with_output(conf_key, _conf, storage_root, action_verb="Installing"):
	"""Back up, stop old services, run scripts, regenerate. Prints progress."""
	LOG_LINES = 10
	_page_header(f"{action_verb}...")

	sys.stdout.write("  → Backing up...  ")
	sys.stdout.flush()
	archive = _backup(storage_root, conf_key.replace("new:", "old:"))
	bname = os.path.basename(archive) if archive else None
	print(f"{green('✓')}  {gray_desc(bname) if bname else gray_desc('nothing to back up')}")

	sys.stdout.write("  → Stopping old services...  ")
	sys.stdout.flush()
	_stop(conf_key.replace("new:", "old:"))
	print(green('✓'))

	print(f"  → {action_verb}...")
	print()
	for _ in range(LOG_LINES):
		print()

	log_buf = []
	ok = _run_all_enabled(log_buf, LOG_LINES)
	print()

	if not ok:
		print(f"  {red('✗')} Script failed - check output above.\n")
		return False

	sys.stdout.write("  → Reloading daemon (regenerates nginx + DNS)...  ")
	sys.stdout.flush()
	regen_ok = _regenerate(_conf)
	if regen_ok:
		print(green('✓'))
	else:
		print(f"{red('✗')}  {gray_desc('daemon unreachable - check journalctl -u naust-managerd')}")

	if regen_ok:
		print(f"\n  {green('✓')} {bold('Done.')}\n")
	else:
		print(f"\n  {bold('Installed.')} {gray_desc('daemon restart failed - services are running but may not be reachable. Check journalctl -u naust-managerd.')}\n")
	return True


# -- Action builders ------------------------------------------------------------


def _make_reinstall(title, run_fn, regen=False, conf=None):
	"""Return [(label, handler)] for Reinstall and Reinstall (force) menu items.

	run_fn: callable(log_buf, log_lines, force) -> bool
	regen:  if True, call _regenerate(conf) after a successful run
	"""

	def _do(force):
		def run(log_buf, log_lines):
			ok = run_fn(log_buf, log_lines, force)
			if ok and regen:
				_regenerate(conf)
			return ok

		_run_logged_screen(f"{title}{' (force)' if force else ''}", run)

	def reinstall():
		_do(False)

	def reinstall_force():
		_do(True)

	return [("Reinstall", reinstall), ("Reinstall (force)", reinstall_force)]


def _no_actions(_key, _label, _status, _msg, _conf, _storage_root):
	return []


def _view_logs_action(*units):
	"""Return a (label, handler) tuple that shows the last 40 lines of systemd journal logs."""

	def handler():
		_page_header("Logs: " + " + ".join(units))
		args = ["journalctl", "--no-pager", "-n", "40"]
		for u in units:
			args += ["-u", u]
		r = subprocess.run(args, capture_output=True, text=True)
		width = _term_width() - 4
		for line in r.stdout.splitlines():
			clean = _ANSI_RE.sub("", line)
			print(f"  {gray_desc(clean[:width])}")
		print()
		_press_enter_to_return()

	return ("View logs", handler)


def _mail_actions(_key, _label, _status, msg, _conf, _storage_root):
	result = _make_reinstall(
		"Reinstalling mail services",
		lambda lb, ll, f: _run_component(["postfix", "dovecot"], lb, ll, f),
	)
	if "deferred" in msg:

		def flush_queue():
			_page_header("Flush deferred queue")
			r = subprocess.run(["postqueue", "-f"], capture_output=True, text=True)
			remaining = subprocess.run(
				["find", "/var/spool/postfix/deferred", "-type", "f"],
				capture_output=True,
				text=True,
			)
			count = len(remaining.stdout.splitlines()) if remaining.returncode == 0 else "?"
			if r.returncode == 0:
				print(f"\n  {green('✓')} Flush requested. {count} messages still deferred.")
			else:
				print(f"\n  {red('✗')} postqueue -f failed.")
			_press_enter_to_return()

		result.append(("Flush deferred queue", flush_queue))
	result.append(_view_logs_action("postfix", "dovecot"))
	return result


def _nginx_actions(_key, _label, _status, _msg, _conf, _storage_root):
	return [_view_logs_action("nginx")]


def _management_actions(_key, _label, _status, _msg, _conf, _storage_root):
	return [_view_logs_action("naust-managerd")]


def _spam_actions(_key, _label, _status, _msg, conf, storage_root):
	current = conf.get("SPAM_FILTER", "rspamd")
	other = "spamassassin" if current == "rspamd" else "rspamd"
	other_label = "SpamAssassin" if other == "spamassassin" else "Rspamd"

	def switch_spam():
		clear()
		confirmed = _warn_screen(
			[
				f"Switching from {current} to {other_label}.",
				"",
				"Spam learning history (Bayes database) will be backed up",
				"but the new filter starts fresh with no trained data.",
				"",
				f"Backup location: {storage_root}/backups/doctor/",
			],
			confirm_label=f"Switch to {other_label}",
			cancel_label="Cancel",
			context="Spam Filter",
		)
		if not confirmed:
			return
		_backup(storage_root, f"SPAM_FILTER:{current}")
		_stop(f"SPAM_FILTER:{current}")
		_write_conf_key("SPAM_FILTER", other)
		conf["SPAM_FILTER"] = other
		ok = _run_with_output(f"SPAM_FILTER:{other}", conf, storage_root, f"Installing {other_label}")
		if not ok:
			sys.stdout.write(f"  → Rolling back to {current}...  ")
			sys.stdout.flush()
			_write_conf_key("SPAM_FILTER", current)
			conf["SPAM_FILTER"] = current
			failed = _start(f"SPAM_FILTER:{current}")
			if failed:
				svcs = ", ".join(failed)
				print(red('✗') + f"  {gray_desc(f'Could not restart: {svcs}. Verify manually.')}")
			else:
				print(green('✓') + f"  {gray_desc(f'{current} restored.')}")
		_press_enter_to_return()

	return [
		(f"Switch to {other_label}", switch_spam),
		*_make_reinstall(f"Reinstalling {current}", _run_all_enabled),
	]


def _webmail_actions(_key, _label, status, _msg, conf, storage_root):
	current = conf.get("WEBMAIL_CLIENT", "rav")
	clients = [
		("rav", "rav"),
		("Roundcube", "roundcube"),
		("SnappyMail", "snappymail"),
		("Cypht", "cypht"),
		("None", "none"),
	]
	current_label = next((lbl for lbl, v in clients if v == current), current)

	def switch_webmail():
		_page_header("Select Webmail Client")

		class _FakeArgs:
			pass

		new_client = step_webmail(_FakeArgs(), dict(conf))
		if not new_client or new_client == current:
			return
		new_label = next((lbl for lbl, v in clients if v == new_client), new_client)
		clear()
		warn_lines = [f"Switching webmail from {current_label} to {new_label}.", ""]
		backup_paths = _BACKUP_PATHS.get(f"WEBMAIL_CLIENT:{current}", [])
		if backup_paths:
			warn_lines += ["The following will be backed up but NOT migrated:"]
			for p in backup_paths:
				warn_lines.append(f"  · {storage_root}/{p}")
			warn_lines += ["", "Contacts synced via Radicale (CardDAV) are unaffected."]
		confirmed = _warn_screen(warn_lines, confirm_label=f"Switch to {new_label}", cancel_label="Cancel", context="Webmail")
		if not confirmed:
			return
		_backup(storage_root, f"WEBMAIL_CLIENT:{current}")
		_stop(f"WEBMAIL_CLIENT:{current}")
		_write_conf_key("WEBMAIL_CLIENT", new_client)
		conf["WEBMAIL_CLIENT"] = new_client
		ok = _run_with_output(f"WEBMAIL_CLIENT:{new_client}", conf, storage_root, f"Installing {new_label}")
		if not ok:
			sys.stdout.write(f"  → Rolling back to {current_label}...  ")
			sys.stdout.flush()
			_write_conf_key("WEBMAIL_CLIENT", current)
			conf["WEBMAIL_CLIENT"] = current
			failed = _start(f"WEBMAIL_CLIENT:{current}")
			if failed:
				svcs = ", ".join(failed)
				print(red('✗') + f"  {gray_desc(f'Could not restart: {svcs}. Verify manually.')}")
			else:
				print(green('✓') + f"  {gray_desc(f'{current_label} restored.')}")
		_press_enter_to_return()

	result = [("Switch to a different client", switch_webmail)]
	if status != OFF:
		result += _make_reinstall(f"Reinstalling {current_label}", _run_all_enabled, regen=True, conf=conf)
	return result


def _monitoring_actions(_key, _label, status, _msg, conf, storage_root):
	current = conf.get("MONITORING_TOOL", "none")
	tools = [
		("None", "none"),
		("Beszel", "beszel"),
		("Netdata", "netdata"),
		("Munin", "munin"),
	]
	current_label = next((lbl for lbl, v in tools if v == current), current)

	def switch_monitoring():
		_page_header("Select Monitoring Tool")

		class _FakeArgs:
			pass

		new_tool = step_monitoring(_FakeArgs(), dict(conf))
		if not new_tool or new_tool == current:
			return
		new_label = next((lbl for lbl, v in tools if v == new_tool), new_tool)
		clear()
		warn_lines = [f"Switching monitoring from {current_label} to {new_label}."]
		backup_paths = _BACKUP_PATHS.get(f"MONITORING_TOOL:{current}", [])
		if backup_paths:
			warn_lines += ["", "Monitoring history will be backed up but not migrated:"]
			for p in backup_paths:
				warn_lines.append(f"  · {storage_root}/{p}")
		confirmed = _warn_screen(
			warn_lines,
			confirm_label=f"Switch to {new_label}",
			cancel_label="Cancel",
			context="Monitoring",
		)
		if not confirmed:
			return
		_backup(storage_root, f"MONITORING_TOOL:{current}")
		_stop(f"MONITORING_TOOL:{current}")
		_write_conf_key("MONITORING_TOOL", new_tool)
		conf["MONITORING_TOOL"] = new_tool
		ok = _run_with_output(f"MONITORING_TOOL:{new_tool}", conf, storage_root, f"Installing {new_label}")
		if not ok:
			sys.stdout.write(f"  → Rolling back to {current_label}...  ")
			sys.stdout.flush()
			_write_conf_key("MONITORING_TOOL", current)
			conf["MONITORING_TOOL"] = current
			failed = _start(f"MONITORING_TOOL:{current}")
			if failed:
				svcs = ", ".join(failed)
				print(red('✗') + f"  {gray_desc(f'Could not restart: {svcs}. Verify manually.')}")
			else:
				print(green('✓') + f"  {gray_desc(f'{current_label} restored.')}")
		_press_enter_to_return()

	result = [("Switch to a different tool", switch_monitoring)]
	if status != OFF:
		result += _make_reinstall(f"Reinstalling {current_label}", _run_all_enabled)
	return result


def _optional_svc_actions(key, label, _status, msg, conf, storage_root):
	ck = {"radicale": "ENABLE_RADICALE", "filebrowser": "ENABLE_FILEBROWSER", "clamav": "ENABLE_CLAMAV"}[key]
	enabled = conf.get(ck, "false") == "true"
	result = []

	if key == "radicale" and "226/NAMESPACE" in msg:

		def fix_namespace():
			_page_header("Fix Radicale sandbox")
			dropin_dir = "/etc/systemd/system/radicale.service.d"
			dropin = os.path.join(dropin_dir, "no-namespace.conf")
			os.makedirs(dropin_dir, exist_ok=True)
			pathlib.Path(dropin).write_text("[Service]\nPrivateTmp=false\nProtectSystem=false\nBindPaths=\nReadWritePaths=\n", encoding="utf-8")
			subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
			subprocess.run(["systemctl", "restart", "radicale"], capture_output=True)
			print(f"\n  {green('✓')} Drop-in written, Radicale restarted.")
			_press_enter_to_return()

		result.append(("Fix sandbox (no namespace support)", fix_namespace))

	if enabled:
		result += _make_reinstall(f"Reinstalling {label}", _run_all_enabled, regen=True, conf=conf)

		def disable_svc(ck=ck):
			clear()
			backup_paths = _BACKUP_PATHS.get(f"{ck}:true", [])
			warn_lines = [f"Disable {label}?", ""]
			if backup_paths:
				warn_lines += ["Data will be backed up and kept on disk:"]
				for p in backup_paths:
					warn_lines.append(f"  · {storage_root}/{p}")
			else:
				warn_lines.append("No data will be lost.")
			confirmed = _warn_screen(warn_lines, confirm_label=f"Disable {label}", cancel_label="Cancel", context=label)
			if not confirmed:
				return
			_backup(storage_root, f"{ck}:true")
			_stop(f"{ck}:true")
			_write_conf_key(ck, "false")
			conf[ck] = "false"
			_regenerate(conf, reload_daemon=True)
			print(f"\n  {green('✓')} {label} disabled.")
			_press_enter_to_return()

		result.append((f"Disable {label}", disable_svc))
	else:

		def enable_svc(ck=ck):
			_write_conf_key(ck, "true")
			conf[ck] = "true"

			def run(log_buf, log_lines):
				ok = _run_all_enabled(log_buf, log_lines)
				if ok:
					_regenerate(conf, reload_daemon=True)
				return ok

			ok = _run_logged_screen(f"Installing {label}", run)
			if not ok:
				# Revert config so the service shows as disabled in the menu
				_write_conf_key(ck, "false")
				conf[ck] = "false"

		result.append((f"Enable {label}", enable_svc))

	return result


def _infra_actions(key, label, _status, _msg, _conf, _storage_root):
	comp = {"dns": "dns", "certs": "ssl"}[key]
	return _make_reinstall(
		f"Reinstalling {label}",
		lambda lb, ll, f: _run_component([comp], lb, ll, f),
	)


# -- Service registry -----------------------------------------------------------


class _Svc(NamedTuple):
	key: str
	label: str
	check_fn: Callable
	actions_fn: Callable


SERVICES: list[_Svc] = [
	_Svc("system", "System", check_system, _no_actions),
	_Svc("backup", "Backup", check_backup, _no_actions),
	_Svc("nginx", "nginx", check_nginx, _nginx_actions),
	_Svc("management", "Management", check_management, _management_actions),
	_Svc("mail", "Mail", check_mail, _mail_actions),
	_Svc("spam", "Spam", check_spam, _spam_actions),
	_Svc("dns", "DNS", check_dns, _infra_actions),
	_Svc("unbound", "Unbound", check_unbound, _no_actions),
	_Svc("certs", "Certificates", check_certs, _infra_actions),
	_Svc("webmail", "Webmail", check_webmail, _webmail_actions),
	_Svc("radicale", "Radicale", check_radicale, _optional_svc_actions),
	_Svc("filebrowser", "FileBrowser", check_filebrowser, _optional_svc_actions),
	_Svc("clamav", "ClamAV", check_clamav, _optional_svc_actions),
	_Svc("relay", "SMTP Relay", check_relay, _no_actions),
	_Svc("monitoring", "Monitoring", check_monitoring, _monitoring_actions),
]


def _actions_for(key, label, status, msg, conf):
	"""Return list of (action_label, handler) for a service."""
	storage_root = conf.get("STORAGE_ROOT", "/home/user-data")
	svc = next(s for s in SERVICES if s.key == key)
	return [("Recheck status", "recheck"), *svc.actions_fn(key, label, status, msg, conf, storage_root)]


# -- Detail loop ----------------------------------------------------------------


def run_detail(key, label, conf, results):

	status, msg = results.get(key, (OFF, "unknown"))
	actions = _actions_for(key, label, status, msg, conf)
	sel = 0

	print("\033[?25l", end="", flush=True)
	try:
		_page_header(context=label)
		_render_detail(label, status, msg, actions, sel, first=True)

		def _do_recheck():
			nonlocal status, msg, actions, sel
			sys.stdout.write("\033[u\033[J  ↻  Checking...\n")
			sys.stdout.flush()
			service_check = next(s.check_fn for s in SERVICES if s.key == key)
			new_status, new_msg = service_check(conf)
			results[key] = (new_status, new_msg)
			status, msg = new_status, new_msg
			actions = _actions_for(key, label, status, msg, conf)
			sel = min(sel, len(actions) - 1)

		with Raw():
			while True:
				k = read_key()
				if k in {"up", "shift_tab"}:
					sel = (sel - 1) % len(actions)
				elif k in {"down", "tab"}:
					sel = (sel + 1) % len(actions)
				elif k == "r":
					_do_recheck()
				elif k == "enter":
					_, handler = actions[sel]
					if handler == "recheck":
						_do_recheck()
					else:
						print("\033[?25h", end="", flush=True)
						clear()
						handler()
						# Recheck after any action
						service_check = next(s.check_fn for s in SERVICES if s.key == key)
						results[key] = service_check(conf)
						status, msg = results[key]
						actions = _actions_for(key, label, status, msg, conf)
						sel = 0
						clear()
						print("\033[?25l", end="", flush=True)
						# Screen was cleared - reprint static header and reset save position
						_page_header(context=label)
						_render_detail(label, status, msg, actions, sel, first=True)
						continue
				elif k in {"esc", "ctrl_c", "q"}:
					return
				_render_detail(label, status, msg, actions, sel)
	finally:
		print("\033[?25h", end="", flush=True)


# -- Main list loop -------------------------------------------------------------


def _is_docker():
	return os.path.exists("/.dockerenv") or os.path.exists("/run/supervisor.sock") or os.environ.get("RUNTIME") == "docker"


def _load_conf():
	conf = {}
	try:
		with open(BARE_METAL_CONF, encoding="utf-8") as f:
			for raw in f:
				line = raw.strip()
				if not line or line.startswith("#") or "=" not in line:
					continue
				k, _, v = line.partition("=")
				conf[k.strip()] = v.strip().strip("'\"")
	except FileNotFoundError:
		pass
	return conf


def _run_check(conf):
	"""Non-interactive check mode: print status table and exit."""
	label_w = max(len(svc.label) for svc in SERVICES) + 2
	results = {}
	for svc in SERVICES:
		results[svc.key] = svc.check_fn(conf)

	for svc in SERVICES:
		status, msg = results[svc.key]
		pad = " " * (label_w - len(svc.label))
		print(f"  {_icon(status)}  {svc.label}{pad}{msg}")

	degraded = any(s in {WARN, ERR} for s, _ in results.values())
	sys.exit(1 if degraded else 0)


def run(check=False):

	conf = _load_conf()

	if check:
		if not conf:
			print("  error: no /etc/naust.conf found")
			sys.exit(2)
		_run_check(conf)
		return

	clear()

	if _is_docker():
		print(f"\n  {red('boxctl doctor does not run inside Docker.')}")
		print(f"  {gray_desc('Edit deploy/docker/.env and re-run docker compose to reconfigure.')}\n")
		sys.exit(1)

	if os.geteuid() != 0:
		print(f"\n  {red('doctor must be run as root.')}")
		print(f"  {gray_desc('Try: sudo python3 setup/boxctl doctor')}\n")
		sys.exit(1)

	if not conf:
		print(f"\n  {red('No /etc/naust.conf found.')}")
		print(f"  {gray_desc('Run sudo setup/install.sh first.')}\n")
		sys.exit(1)

	# Run all checks
	print(f"\n  {bold('boxctl doctor')}  {gray_desc('scanning...')}", flush=True)
	results = {}
	for svc in SERVICES:
		results[svc.key] = svc.check_fn(conf)

	sel = 0

	print("\033[?25l", end="", flush=True)
	try:
		clear()
		_page_header()
		_render_list(SERVICES, results, sel, first=True)

		with Raw():
			while True:
				k = read_key()
				if k in {"up", "shift_tab"}:
					sel = (sel - 1) % len(SERVICES)
				elif k in {"down", "tab"}:
					sel = (sel + 1) % len(SERVICES)
				elif k == "r":
					sys.stdout.write("\033[u\033[J")
					sys.stdout.flush()
					print(f"\n  {bold('boxctl doctor')}  {gray_desc('rechecking...')}", flush=True)
					for svc in SERVICES:
						results[svc.key] = svc.check_fn(conf)
					clear()
					_page_header()
					_render_list(SERVICES, results, sel, first=True)
					continue
				elif k == "enter":
					svc = SERVICES[sel]
					print("\033[?25h", end="", flush=True)
					clear()
					run_detail(svc.key, svc.label, conf, results)
					clear()
					print("\033[?25l", end="", flush=True)
					# Screen was cleared - reprint static header and reset save position
					_page_header()
					_render_list(SERVICES, results, sel, first=True)
					continue
				elif k in {"esc", "ctrl_c", "q"}:
					break
				_render_list(SERVICES, results, sel)
	finally:
		print("\033[?25h", end="", flush=True)
		clear()

	# Exit non-zero if anything is degraded
	degraded = any(s in {WARN, ERR} for s, _ in results.values())
	sys.exit(1 if degraded else 0)
