"""
Naust installer - called by setup/install.sh.

Flow:
  1. Preflight (RAM / disk)
  2. Questions wizard  ->  writes /etc/naust.conf
  3. System packages (apt-get, rolling log)
  4. Components (one doit run, rolling log with active-component tracking)
  5. boxctl bootstrap --install  (admin URL + TLS fingerprint)
"""

import contextlib
import glob
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import termios
import threading
import time
import urllib.request
import ipaddress
from collections import deque
from datetime import datetime

# ── sys.path: add setup/ so boxctl.* and components.* are importable ─────────

_HERE = os.path.dirname(os.path.abspath(__file__))  # setup/boxctl/
_SETUP = os.path.dirname(_HERE)  # setup/
_REPO = os.path.dirname(_SETUP)  # repo root

for _p in (_SETUP, _REPO):
	if _p not in sys.path:
		sys.path.insert(0, _p)

from boxctl.ui import (  # noqa: E402 - must follow the sys.path insert above
	bold,
	gray_desc,
	gray_num,
	white_b,
	green,
	red,
	clear,
	_term_width,
)
from boxctl.questions import STEPS, VALUE_DISPLAY, PROFILES  # noqa: E402 - must follow the sys.path insert above
from boxctl.runner import run_questions, write_output, load_conf  # noqa: E402 - must follow the sys.path insert above

CONF_PATH = "/etc/naust.conf"

# Strip ANSI escape sequences from subprocess output before displaying.
# apt and dpkg emit \033[K (erase-to-EOL), \033[Nm (colors) etc. which corrupt
# our cursor-based rendering if re-emitted inside it.
_ANSI_RE = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')

# Progress rendering: running accent (soft blue), no-output observation (amber),
# braille spinner at 10Hz. Times/counts right-align to one fixed edge so state
# changes never shift columns.
_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_NO_OUTPUT_AFTER = 20  # seconds of silence before the observation appears
_DURATIONS_PATH = "/usr/local/lib/naust/setup-durations.json"


def _accent(s: str) -> str:
	return f"\033[38;2;97;175;239m{s}\033[0m"


def _amber(s: str) -> str:
	return f"\033[38;2;255;184;108m{s}\033[0m"


def _plain_len(s: str) -> int:
	return len(_ANSI_RE.sub("", s))


def _edge() -> int:
	w = _term_width()
	if w < 40:  # size unknown/absurd (some pseudo-terminals report 0)
		w = 80
	return min(w - 2, 76)


def _rrow(left: str, right: str) -> str:
	"""Compose a row with `right` ending at the fixed right edge."""
	pad = _edge() - _plain_len(left) - _plain_len(right)
	return left + " " * max(1, pad) + right


def _fmt_mmss(sec: float) -> str:
	m, s = divmod(int(max(0, sec)), 60)
	return f"{m}:{s:02d}"


LOG_PATH = "/tmp/naust-setup.log"  # noqa: S108 - fixed path so it survives across re-runs and is discoverable for support
_logfile: "open | None" = None


def _log(line: str) -> None:
	"""Write a line to the log file. No-op until _open_log() is called."""
	if _logfile is not None:
		_logfile.write(line + "\n")
		_logfile.flush()


def _open_log() -> None:
	global _logfile  # noqa: PLW0603 - module-level log handle, set once at startup and read by _log() throughout
	# Rotate: preserve the previous run as .prev so failure context survives a re-run,
	# but truncate the current log so it never grows unboundedly.
	if os.path.exists(LOG_PATH):
		os.replace(LOG_PATH, LOG_PATH + ".prev")
	_logfile = open(LOG_PATH, "w", encoding="utf-8")  # noqa: SIM115 - kept open for the process lifetime, closed implicitly on exit
	width = 72
	ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	_log("=" * width)
	_log("  Naust - Setup Log")
	_log(f"  Started: {ts}")
	_log("=" * width)


# ── Rendering helpers ─────────────────────────────────────────────────────────


def _header(subtitle: str | None = None) -> None:
	clear()
	suffix = f"  {gray_desc('-')}  {gray_desc(subtitle)}" if subtitle else ""
	print(f"\n  {bold('Naust')}{suffix}")
	print(f"  {gray_desc('─' * (_term_width() - 4))}")
	print()


# ── Subprocess output reader (shared by both phase renderers) ────────────────


def _spawn(cmd: list[str], cwd: str | None, on_line) -> subprocess.Popen:
	"""Start cmd and a reader thread that calls on_line(str) per output line.

	Handles \\r-overwritten progress lines (apt) by keeping only what a
	terminal would show, and strips ANSI. The reader thread is stored on the
	returned proc as proc._reader for joining.
	"""
	proc = subprocess.Popen(
		cmd,
		stdout=subprocess.PIPE,
		stderr=subprocess.STDOUT,
		stdin=subprocess.DEVNULL,  # prevent apt from sniffing the terminal via stdin
		text=False,  # binary - we handle \r ourselves
		bufsize=0,
		cwd=cwd or _REPO,
		env={**os.environ, "PYTHONUNBUFFERED": "1", "TERM": "dumb"},
	)

	def _reader() -> None:
		partial = b""
		while True:
			chunk = proc.stdout.read(512)
			if not chunk:
				break
			data = partial + chunk
			*segments, partial = data.split(b"\n")
			for seg in segments:
				# \r within a segment: apt progress lines overwrite in place.
				# Take the last non-empty piece - that's what the terminal shows.
				cr_parts = [p for p in seg.split(b"\r") if p]
				if not cr_parts:
					continue
				line = _ANSI_RE.sub("", cr_parts[-1].decode("utf-8", errors="replace")).rstrip()
				if line:
					on_line(line)
		if partial:
			line = _ANSI_RE.sub("", partial.split(b"\r")[-1].decode("utf-8", errors="replace")).rstrip()
			if line:
				on_line(line)

	t = threading.Thread(target=_reader, daemon=True)
	t.start()
	proc._reader = t  # type: ignore[attr-defined]  # noqa: SLF001 - our own attribute, stashed on Popen to smuggle the reader thread handle to the caller
	return proc


# ── Phase runner (single-command phases: apt, pip) ────────────────────────────


def _run_phase(
	label: str,
	cmd: list[str],
	timeout: int = 1800,
	cwd: str | None = None,
) -> bool:
	"""Run cmd showing one live row: spinner, label, elapsed clock, and the
	last output line beneath it. Collapses to a ✓/✗ row on completion; on
	failure the last few output lines stay visible."""
	_log(f"\n=== {label} ===")
	started = time.monotonic()
	ring: deque = deque(maxlen=6)
	tail = [""]
	last_out = [started]

	def _on_line(line: str) -> None:
		_log(line)
		tail[0] = line
		ring.append(line)
		last_out[0] = time.monotonic()

	proc = _spawn(cmd, cwd, _on_line)
	plain = not sys.stdout.isatty()
	drawn = [0]

	def _draw(final_icon: str | None = None, note: str = "") -> None:
		if plain:
			return
		el = time.monotonic() - started
		lines = []
		if final_icon is None:
			sp = _accent(_SPIN[int(el * 10) % 10])
			quiet = time.monotonic() - last_out[0]
			obs = f"  {_amber(f'[no output for {int(quiet)}s]')}" if quiet >= _NO_OUTPUT_AFTER else ""
			lines.extend((_rrow(f"  {sp}  {white_b(label)}{obs}", gray_desc(_fmt_mmss(el))), f"     {gray_desc(tail[0][: _edge() - 6])}" if tail[0] else ""))
		else:
			suffix = f"  {gray_desc(note)}" if note else ""
			lines.append(_rrow(f"  {final_icon}  {bold(label)}{suffix}", gray_desc(_fmt_mmss(el))))
		buf = (f"\033[{drawn[0]}A" if drawn[0] else "") + "".join(ln + "\033[K\n" for ln in lines) + "\033[J"
		sys.stdout.write(buf)
		sys.stdout.flush()
		drawn[0] = len(lines)

	timed_out = False
	try:
		while proc.poll() is None:
			if time.monotonic() - started > timeout:
				proc.kill()
				proc.wait()
				timed_out = True
				break
			_draw()
			time.sleep(0.1)
	except (KeyboardInterrupt, SystemExit):
		proc.kill()
		proc.wait()
		_draw(final_icon=red("✗"), note="(cancelled)")
		raise
	proc.wait()
	proc._reader.join()  # type: ignore[attr-defined]  # noqa: SLF001 - our own attribute, see _spawn()

	ok = proc.returncode == 0 and not timed_out
	if timed_out:
		_log(f"[timed out after {timeout // 60} minutes]")
		ring.append(f"[timed out after {timeout // 60} minutes]")
	_log(f"=== {label} {'ok' if ok else 'FAILED'} ===")
	if plain:
		print(f"  {label}: {'ok' if ok else 'FAILED'} ({_fmt_mmss(time.monotonic() - started)})")
		if not ok:
			for line in list(ring)[-4:]:
				print(f"     {line}")
		return ok
	_draw(final_icon=green("✓") if ok else red("✗"))
	if not ok:
		width = _edge() - 6
		for line in list(ring)[-4:]:
			sys.stdout.write(f"     {gray_desc(line[:width])}\033[K\n")
		sys.stdout.write("\033[J")
		sys.stdout.flush()
	return ok


# ── Components phase: event-driven checklist renderer ─────────────────────────


def _run_components(timeout: int = 2700) -> bool:
	"""Run the component runner, rendering a live checklist from its @@ event
	lines: every component visible with state (queued / running / done /
	failed), live output tail and elapsed clock per running component, honest
	step counter, and a no-output observation on quiet steps. Failures stay
	expanded with their own last output lines; nothing scrolls away."""
	cmd = [sys.executable, "-m", "components.runner"]
	_log("\n=== Components ===")
	started = time.monotonic()
	lock = threading.Lock()

	order: list[str] = []
	comps: dict[str, dict] = {}
	steps = {"done": 0, "total": 0}
	current: list[str | None] = [None]  # component owning raw output lines
	pre_tail = [""]  # raw output before the plan arrives (component apt installs)
	restarts = {"active": False, "current": "", "failed": []}

	try:
		with open(_DURATIONS_PATH, encoding="utf-8") as f:
			hist = json.load(f)
	except (OSError, ValueError):
		hist = {}

	def _on_line(line: str) -> None:
		_log(line)
		with lock:
			if line.startswith("@@plan "):
				parts = line.split()
				if len(parts) >= 3:
					name = parts[1]
					comps[name] = {
						"tasks": len(parts) - 2,
						"done": 0,
						"state": "pending",
						"current": "",
						"started": None,
						"ended": None,
						"tail": "",
						"ring": deque(maxlen=6),
						"fail_lines": [],
						"failed_task": "",
						"last_out": 0.0,
					}
					order.append(name)
					steps["total"] += len(parts) - 2
				return
			if line.startswith("@@ev "):
				parts = line.split()
				kind = parts[1] if len(parts) > 1 else ""
				if kind in {"start", "done", "cached", "fail"} and len(parts) > 2 and ":" in parts[2]:
					comp, task = parts[2].split(":", 1)
					c = comps.get(comp)
					if c is None:
						return
					now = time.monotonic()
					if kind == "start":
						if c["state"] != "failed":
							c["state"] = "running"
						c["current"] = task
						if c["started"] is None:
							c["started"] = now
						c["last_out"] = now
						current[0] = comp
					else:
						steps["done"] += 1  # attempted - keeps the bar honest
						if kind == "fail":
							c["state"] = "failed"
							c["failed_task"] = task
							c["fail_lines"] = list(c["ring"])[-4:]
							c["ended"] = now
						else:
							c["done"] += 1
							if c["done"] >= c["tasks"] and c["state"] != "failed":
								c["state"] = "done"
								c["ended"] = now
				elif kind == "phase" and len(parts) > 2 and parts[2] == "restarts":
					restarts["active"] = True
					current[0] = None
				elif kind == "restart-start" and len(parts) > 2:
					restarts["current"] = parts[2]
				elif kind == "restart-fail" and len(parts) > 2:
					restarts["failed"].append(parts[2])
				return
			# Raw output line: attach to whichever component is running.
			c = comps.get(current[0]) if current[0] else None
			if c is not None and c["state"] == "running":
				c["tail"] = line
				c["ring"].append(line)
				c["last_out"] = time.monotonic()
			elif not order:
				pre_tail[0] = line

	proc = _spawn(cmd, _SETUP, _on_line)
	plain = not sys.stdout.isatty()
	drawn = [0]

	def _eta_text() -> str:
		known = [n for n in order if n in hist]
		if not order or steps["total"] == 0 or len(known) < 0.6 * len(order):
			return ""
		avg = sum(hist[n] for n in known) / len(known)
		remaining = sum(hist.get(n, avg) for n in order if comps[n]["state"] not in {"done", "failed"})
		if remaining >= 90:
			return f"about {int(remaining // 60) + 1} min remaining"
		if remaining >= 5:
			return "under a minute remaining"
		return ""

	def _rows(final: bool) -> list[str]:
		now = time.monotonic()
		el = now - started
		spin = _accent(_SPIN[int(el * 10) % 10])
		total = steps["total"]
		done_n = steps["done"]
		pct = int(done_n * 100 / total) if total else 0
		barw = 40
		fill = int(barw * pct / 100)
		bar = _accent("█" * fill) + gray_num("░" * (barw - fill))
		lines = [
			_rrow(f"  {bar}", f"{white_b(f'{pct:3d}%')}   {gray_desc(f'{done_n} / {total} steps')}"),
			_rrow(f"  {gray_desc(_eta_text())}", gray_desc(f"elapsed {_fmt_mmss(el)}")),
			"",
		]
		if not order:
			# Runner is still installing component packages - plan not emitted yet.
			lines.append(_rrow(f"  {spin}  {white_b('Component packages')}", gray_desc(_fmt_mmss(el))))
			if pre_tail[0]:
				lines.append(f"     {gray_desc(pre_tail[0][: _edge() - 6])}")
			return lines
		for name in order:
			c = comps[name]
			if c["state"] == "pending":
				label = "not run" if final else "queued"
				lines.append(_rrow(f"  {gray_num('□')}  {gray_desc(name)}", gray_desc(label)))
			elif c["state"] == "running":
				celapsed = _fmt_mmss(now - c["started"]) if c["started"] else ""
				quiet = now - c["last_out"] if c["last_out"] else 0
				left = f"  {_amber('!')}  {white_b(name)}  {gray_desc(c['current'])}  {_amber(f'[no output for {int(quiet)}s]')}" if quiet >= _NO_OUTPUT_AFTER else f"  {spin}  {white_b(name)}  {gray_desc(c['current'])}"
				lines.append(_rrow(left, gray_desc(celapsed)))
				if c["tail"]:
					lines.append(f"        {gray_desc('│ ' + c['tail'][: _edge() - 10])}")
			elif c["state"] == "done":
				dur = _fmt_mmss(c["ended"] - c["started"]) if c["started"] and c["ended"] else "cached"
				lines.append(_rrow(f"  {green('✓')}  {name}", gray_desc(f"{c['done']}/{c['tasks']}   {dur}")))
			else:  # failed
				lines.append(_rrow(f"  {red('✗')}  {white_b(name)}  {gray_desc(c['failed_task'])}", gray_desc(f"{c['done']}/{c['tasks']}")))
				lines.extend(f"        {red('│')} {gray_desc(fl[: _edge() - 10])}" for fl in c["fail_lines"])
				lines.append(f"        {gray_desc(f'(full output: {LOG_PATH})')}")
		if restarts["active"]:
			if restarts["failed"]:
				lines.append(_rrow(f"  {red('✗')}  Service restarts", red(", ".join(restarts["failed"]))))
			elif final:
				lines.append(_rrow(f"  {green('✓')}  Service restarts", ""))
			else:
				lines.append(_rrow(f"  {spin}  {white_b('Service restarts')}  {gray_desc(restarts['current'])}", ""))
		return lines

	def _draw(final: bool = False) -> None:
		if plain:
			return
		with lock:
			lines = _rows(final)
		# Collapse leading done components into one row if the block would
		# outgrow the terminal.
		try:
			avail = os.get_terminal_size().lines - 4
		except OSError:
			avail = 40
		if avail <= 4:  # size unknown/absurd (some pseudo-terminals report 0)
			avail = 40
		if len(lines) > avail:
			done_names = [n for n in order if comps[n]["state"] == "done"]
			if done_names:
				head, rest = lines[:3], lines[3:]
				kept = [ln for ln in rest if not any(f"  {name}" in _ANSI_RE.sub("", ln) and "✓" in ln for name in done_names)]
				summary = _rrow(f"  {green('✓')}  {len(done_names)} components installed", "")
				lines = [*head, summary, *kept]
		buf = (f"\033[{drawn[0]}A" if drawn[0] else "") + "".join(ln + "\033[K\n" for ln in lines) + "\033[J"
		sys.stdout.write(buf)
		sys.stdout.flush()
		drawn[0] = len(lines)

	timed_out = False
	try:
		while proc.poll() is None:
			if time.monotonic() - started > timeout:
				proc.kill()
				proc.wait()
				timed_out = True
				break
			_draw()
			time.sleep(0.1)
	except (KeyboardInterrupt, SystemExit):
		proc.kill()
		proc.wait()
		_draw(final=True)
		sys.stdout.write(f"  {red('✗')}  {bold('Components')}  {gray_desc('(cancelled)')}\033[K\n")
		sys.stdout.flush()
		raise
	proc.wait()
	proc._reader.join()  # type: ignore[attr-defined]  # noqa: SLF001 - our own attribute, see _spawn()

	ok = proc.returncode == 0 and not timed_out
	if timed_out:
		_log(f"[timed out after {timeout // 60} minutes]")
	_log(f"=== Components {'ok' if ok else 'FAILED'} ===")
	if plain:
		with lock:
			for name in order:
				c = comps[name]
				print(f"  {name}: {c['state']} ({c['done']}/{c['tasks']})")
				if c["state"] == "failed":
					for fl in c["fail_lines"]:
						print(f"     {fl}")
		print(f"  Components: {'ok' if ok else 'FAILED'} ({_fmt_mmss(time.monotonic() - started)})")
		return ok
	# Final frame stays on screen - the history is the summary.
	_draw(final=True)
	return ok


# ── IP detection ──────────────────────────────────────────────────────────────


def _detect_public_ip(version: int) -> str:
	"""Try to determine the public IPv4 or IPv6 via external HTTP services."""
	services_v4 = [
		"https://ipv4.icanhazip.com",
		"https://ifconfig.me/ip",
		"https://api.ipify.org",
		"https://api4.my-ip.io/ip",
	]
	services_v6 = [
		"https://ipv6.icanhazip.com",
		"https://api6.ipify.org",
		"https://api6.my-ip.io/ip",
	]
	services = services_v6 if version == 6 else services_v4
	for url in services:
		with contextlib.suppress(Exception), urllib.request.urlopen(url, timeout=3) as r:
			ip = r.read().decode().strip()
			parsed = ipaddress.ip_address(ip)

			if parsed.version == version:
				return ip
	return ""


def _detect_private_ip(version: int) -> str:
	"""Return the local interface address used to reach the internet."""
	try:
		family = socket.AF_INET6 if version == 6 else socket.AF_INET
		target = ("2001:4860:4860::8888", 80) if version == 6 else ("8.8.8.8", 80)
		with socket.socket(family, socket.SOCK_DGRAM) as s:
			s.connect(target)
			return s.getsockname()[0]
	except Exception:  # noqa: BLE001 - best-effort network probe, empty string means "couldn't detect"
		return ""


# ── Preflight ─────────────────────────────────────────────────────────────────


def _preflight() -> bool:

	OK, WARN, ERR = "ok", "warn", "err"
	checks: list[tuple[str, str, str]] = []

	with contextlib.suppress(Exception), open("/proc/meminfo", encoding="utf-8") as f:
		for line in f:
			if line.startswith("MemTotal:"):
				mb = int(line.split()[1]) // 1024
				if mb < 256:
					checks.append((ERR, "RAM", f"{mb} MB - 512 MB minimum required"))
				elif mb < 512:
					checks.append((WARN, "RAM", f"{mb} MB - 512 MB recommended"))
				else:
					checks.append((OK, "RAM", f"{mb} MB available"))
				break

	with contextlib.suppress(Exception):
		# Check the partitions that actually receive install artifacts.
		low: list[str] = []
		warn: list[str] = []
		for mount in ("/", "/home", "/var", "/tmp"):  # noqa: S108 - checking free space on the mount, not writing a file
			with contextlib.suppress(Exception):
				free_mb = shutil.disk_usage(mount).free // (1024**2)
				if free_mb < 500:
					low.append(f"{mount} ({free_mb} MB)")
				elif free_mb < 1024:
					warn.append(f"{mount} ({free_mb} MB)")
		if low:
			checks.append((ERR, "Disk", f"< 500 MB free on: {', '.join(low)} - 1 GB recommended"))
		elif warn:
			checks.append((WARN, "Disk", f"< 1 GB free on: {', '.join(warn)}"))
		else:
			checks.append((OK, "Disk", "sufficient free space on all partitions"))

	if not checks:
		return True

	ICON = {
		OK: "\033[38;2;95;255;135m✓\033[0m",
		WARN: "\033[38;2;255;215;0m!\033[0m",
		ERR: "\033[38;2;255;85;85m✗\033[0m",
	}
	any_err = any(s == ERR for s, _, _ in checks)
	any_warn = any(s == WARN for s, _, _ in checks)

	if any_err or any_warn:
		label_w = max(len(lbl) for _, lbl, _ in checks) + 2
		print(f"  {bold('Pre-flight')}")
		print(f"  {gray_desc('─' * (_term_width() - 4))}")
		for status, lbl, msg in checks:
			pad = " " * (label_w - len(lbl))
			print(f"  {ICON[status]}  {lbl}{pad}{gray_desc(msg)}")
		print()

	if any_err:
		print(f"  {red('Setup cannot continue. Resolve the issues above first.')}\n")
		return False

	return True


# ── Main ──────────────────────────────────────────────────────────────────────


def _choose_profile() -> str:
	"""Show the install profile selection screen. Returns 'recommended', 'original', or 'custom'."""
	from boxctl.ui import select_prompt

	_header("Installation profile")
	return select_prompt(
		"Which installation profile would you like to use?",
		"Recommended and Original pre-fill all settings. You can still adjust anything before confirming.",
		[
			("Recommended", "Modern stack: rav, rspamd, restic, Beszel, external DNS, Radicale.", "recommended"),
			("Original", "Classic stack: Roundcube, SpamAssassin, duplicity, Munin, self-hosted DNS, Radicale, FileBrowser.", "original"),
			("Custom", "Step through every option and choose yourself.", "custom"),
		],
		"recommended",
		False,
	)


def _resolve_auto(value: str, auto_value: str) -> str:
	"""Return auto_value if value is 'auto' or empty, otherwise value."""
	v = value.strip()
	return auto_value if (not v or v == "auto") else v


def main() -> None:
	if os.geteuid() != 0:
		print(f"\n  {red('install.py must be run as root.')}\n")
		sys.exit(1)

	noninteractive = os.environ.get("NONINTERACTIVE", "").strip() == "1"

	if not noninteractive and not sys.stdin.isatty():
		sys.exit("Interactive terminal required.")

	if not noninteractive:
		saved = termios.tcgetattr(sys.stdin.fileno())

		def _restore(_sig, _frame):
			with contextlib.suppress(Exception):
				termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, saved)
			print("\033[?25h", end="", flush=True)
			sys.exit(1)

		signal.signal(signal.SIGTERM, _restore)
		signal.signal(signal.SIGINT, _restore)

	# Ensure UTF-8 locale so Python reads/writes files consistently.
	subprocess.run(["locale-gen", "en_US.UTF-8"], capture_output=True)
	os.environ.update({
		"LANGUAGE": "en_US.UTF-8",
		"LC_ALL": "en_US.UTF-8",
		"LANG": "en_US.UTF-8",
		"LC_TYPE": "en_US.UTF-8",
		"NCURSES_NO_UTF8_ACS": "1",
	})

	import fcntl

	install_lockfile = open("/tmp/naust-install.lock", "w", encoding="utf-8")  # noqa: S108, SIM115 - fixed path so concurrent runs can find and flock it; held for the process lifetime
	try:
		fcntl.flock(install_lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
	except BlockingIOError:
		sys.exit("Another setup run is already in progress.")

	_open_log()

	# ── Preflight ─────────────────────────────────────────────────────────────
	if not noninteractive:
		_header()
	if not _preflight():
		sys.exit(1)

	# ── Migrations (re-run only) ───────────────────────────────────────────────
	if os.path.exists(CONF_PATH):
		migrate = os.path.join(_SETUP, "migrate.py")
		if os.path.exists(migrate):
			r = subprocess.run(
				[sys.executable, migrate, "--migrate"],
				capture_output=True,
				text=True,
			)
			if r.returncode != 0:
				print(f"  {red('Migration failed:')}\n{(r.stdout + r.stderr).strip()}\n")
				sys.exit(1)

	# ── Detect IPs (best-effort, shown as defaults in the wizard) ────────────
	initial = load_conf(CONF_PATH)

	guessed_v4 = _detect_public_ip(4)
	guessed_v6 = _detect_public_ip(6)
	private_v4 = _detect_private_ip(4)
	private_v6 = _detect_private_ip(6)

	class _Args:
		default_hostname = initial.get("PRIMARY_HOSTNAME", "")
		guessed_ipv4 = guessed_v4
		default_ipv4 = initial.get("PUBLIC_IP", guessed_v4)
		guessed_ipv6 = guessed_v6
		default_ipv6 = initial.get("PUBLIC_IPV6", guessed_v6)

	# ── Wizard / non-interactive conf resolution ──────────────────────────────
	if noninteractive:
		e = os.environ
		answers: dict[str, str] = {
			"PRIMARY_HOSTNAME": _resolve_auto(e.get("PRIMARY_HOSTNAME", ""), socket.getfqdn()),
			"PUBLIC_IP": _resolve_auto(e.get("PUBLIC_IP", ""), guessed_v4),
			"PUBLIC_IPV6": _resolve_auto(e.get("PUBLIC_IPV6", ""), guessed_v6),
			"ENABLE_FILEBROWSER": e.get("ENABLE_FILEBROWSER", initial.get("ENABLE_FILEBROWSER", "true")),
			"ENABLE_RADICALE": e.get("ENABLE_RADICALE", initial.get("ENABLE_RADICALE", "true")),
			"ENABLE_CLAMAV": e.get("ENABLE_CLAMAV", initial.get("ENABLE_CLAMAV", "false")),
			"WEBMAIL_CLIENT": e.get("WEBMAIL_CLIENT", initial.get("WEBMAIL_CLIENT", "rav")),
			"SPAM_FILTER": e.get("SPAM_FILTER", initial.get("SPAM_FILTER", "rspamd")),
			"DNS_MODE": e.get("DNS_MODE", initial.get("DNS_MODE", "self")),
			"BACKUP_TOOL": e.get("BACKUP_TOOL", initial.get("BACKUP_TOOL", "restic")),
			"MONITORING_TOOL": e.get("MONITORING_TOOL", initial.get("MONITORING_TOOL", "none")),
			"TIMEZONE": e.get("TIMEZONE", initial.get("TIMEZONE", "")),
		}
		from .questions import validate_hostname, validate_ipv4

		hostname_err = validate_hostname(answers["PRIMARY_HOSTNAME"])
		ip_err = validate_ipv4(answers["PUBLIC_IP"])
		if hostname_err is not True:
			print(f"ERROR: PRIMARY_HOSTNAME is invalid: {hostname_err}")
			sys.exit(1)
		if ip_err is not True:
			print(f"ERROR: PUBLIC_IP is invalid: {ip_err}")
			sys.exit(1)
		print(f"Non-interactive install: PRIMARY_HOSTNAME={answers['PRIMARY_HOSTNAME']} PUBLIC_IP={answers['PUBLIC_IP']}")
	else:
		try:
			profile = _choose_profile()
			all_steps = [(key, label, fn) for _, key, label, fn in STEPS]

			if profile in PROFILES:
				# Merge preset values - existing conf values win on re-installs.
				for k, v in PROFILES[profile].items():
					if k not in initial:
						initial[k] = v
				# Seed auto-detected IPs so they appear on the confirm screen.
				initial.setdefault("PUBLIC_IP", guessed_v4)
				initial.setdefault("PUBLIC_IPV6", guessed_v6)
				# Populate the optionals synthetic key for confirm display.
				initial["__optionals__"] = {
					"ENABLE_RADICALE": initial.get("ENABLE_RADICALE", "false"),
					"ENABLE_CLAMAV": initial.get("ENABLE_CLAMAV", "false"),
				}
				# Only ask hostname interactively; everything else is pre-filled.
				hostname_step = [(key, label, fn) for _, key, label, fn in STEPS if key == "PRIMARY_HOSTNAME"]
				answers = run_questions(hostname_step, _Args(), VALUE_DISPLAY, initial=initial, all_steps=all_steps, all_editable=True)
			else:
				# Custom: walk through every step.
				answers = run_questions(all_steps, _Args(), VALUE_DISPLAY, initial=initial, all_steps=all_steps)

		except KeyboardInterrupt:
			clear()
			print("\n  Setup cancelled.\n")
			sys.exit(0)

	# ── Build and write /etc/naust.conf ──────────────────────────────────
	storage_user = initial.get("STORAGE_USER", "user-data")
	storage_root = initial.get("STORAGE_ROOT", f"/home/{storage_user}")

	conf: dict[str, str] = {
		"STORAGE_USER": storage_user,
		"STORAGE_ROOT": storage_root,
		"PRIMARY_HOSTNAME": answers.get("PRIMARY_HOSTNAME", ""),
		"PUBLIC_IP": answers.get("PUBLIC_IP", guessed_v4),
		"PUBLIC_IPV6": answers.get("PUBLIC_IPV6", guessed_v6),
		"PRIVATE_IP": initial.get("PRIVATE_IP", private_v4),
		"PRIVATE_IPV6": initial.get("PRIVATE_IPV6", private_v6),
		"MTA_STS_MODE": initial.get("MTA_STS_MODE", "enforce"),
		"ENABLE_FILEBROWSER": answers.get("ENABLE_FILEBROWSER", initial.get("ENABLE_FILEBROWSER", "true")),
		"ENABLE_RADICALE": answers.get("ENABLE_RADICALE", initial.get("ENABLE_RADICALE", "true")),
		"ENABLE_CLAMAV": answers.get("ENABLE_CLAMAV", initial.get("ENABLE_CLAMAV", "false")),
		"WEBMAIL_CLIENT": answers.get("WEBMAIL_CLIENT", initial.get("WEBMAIL_CLIENT", "rav")),
		"SPAM_FILTER": answers.get("SPAM_FILTER", initial.get("SPAM_FILTER", "rspamd")),
		"DNS_MODE": answers.get("DNS_MODE", initial.get("DNS_MODE", "self")),
		"BACKUP_TOOL": answers.get("BACKUP_TOOL", initial.get("BACKUP_TOOL", "restic")),
		"MONITORING_TOOL": answers.get("MONITORING_TOOL", initial.get("MONITORING_TOOL", "none")),
		"TIMEZONE": answers.get("TIMEZONE", initial.get("TIMEZONE", "")),
	}

	write_output(CONF_PATH, conf)

	# Ensure STORAGE_ROOT exists with the right ownership.
	if not os.path.isdir(storage_root):
		os.makedirs(storage_root, exist_ok=True)
	# Create system user for storage if not already present.
	r = subprocess.run(["id", "-u", storage_user], capture_output=True)
	if r.returncode != 0:
		subprocess.run(
			["useradd", "-r", "-m", "-d", storage_root, storage_user],
			check=True,
		)
	# World-readable up the directory chain (mirrors start.sh behaviour).
	d = storage_root
	while d != "/":
		os.chmod(d, 0o755)
		d = os.path.dirname(d)
	# Stamp migration number on first install.
	ver_file = os.path.join(storage_root, "naust.version")
	if not os.path.exists(ver_file):
		migrate = os.path.join(_SETUP, "migrate.py")
		if os.path.exists(migrate):
			r = subprocess.run(
				[sys.executable, migrate, "--current"],
				capture_output=True,
				text=True,
			)
			if r.returncode == 0 and r.stdout.strip():
				pathlib.Path(ver_file).write_text(r.stdout.strip() + "\n", encoding="utf-8")
				subprocess.run(
					["chown", f"{storage_user}:{storage_user}", ver_file],
					capture_output=True,
				)

	# boxctl (the operator CLI) is a Go binary put on PATH by the boxctl
	# component below, which also creates the `naust` alias. The Python installer
	# is no longer persisted to /usr/local/lib/naust: re-running setup fetches the
	# current release (`python3 setup/boxctl update`) until the installer itself
	# is rewritten in Go.

	# ── Install screen ────────────────────────────────────────────────────────
	if not noninteractive:
		_header("Installing...")

	errors: list[str] = []

	# Repair any interrupted dpkg state before touching apt. This is a no-op
	# on a clean system but recovers from a previous interrupted install.
	subprocess.run(
		["dpkg", "--configure", "-a"],
		env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
		capture_output=True,
	)

	# System packages: python3-venv, doit, exclusiveprocess, email_validator -
	# the minimum needed before the component runner can import itself.
	base_packages = [
		"python3",
		"python3-venv",
		"python3-pip",
		"apt-utils",
		"lsb-release",
		"git",
		"wget",
		"curl",
		"ca-certificates",
	]
	if not _run_phase(
		"System packages",
		[
			"apt-get",
			"install",
			"-y",
			"--no-install-recommends",
			"-o",
			"Dpkg::Options::=--force-confdef",
			"-o",
			"Dpkg::Options::=--force-confnew",
			"-o",
			"DPkg::Lock::Timeout=300",
			*base_packages,
		],
	):
		errors.append("packages")

	if not errors:
		# Ensure doit is available in system Python. --break-system-packages
		# (PEP 668) only exists on Ubuntu 23.04+ pip; 22.04's pip exits on
		# the unknown flag, so pass it only where the environment is
		# externally managed.
		pip_install = [sys.executable, "-m", "pip", "install"]
		if glob.glob("/usr/lib/python3*/EXTERNALLY-MANAGED"):
			pip_install.append("--break-system-packages")
		if not _run_phase(
			"Python dependencies",
			[*pip_install, "-q", "doit"],
		):
			errors.append("python-deps")

	# Run as a module so relative imports inside runner.py work.
	# cwd=_SETUP (set in _run_components) makes `components` importable.
	if not errors and not _run_components(timeout=2700):  # 45 min for first install
		errors.append("components")

	# No dns_update/web_update poke here: nginx sites and nsd zones
	# converge inside naust-managerd on startup, and the legacy tools
	# would overwrite them with the retired Flask stack's config
	# (duplicate nginx server names, stomped zone files).

	# ── Result ────────────────────────────────────────────────────────────────
	if errors:
		print(f"\n  {red('Setup finished with errors:')} {', '.join(errors)}")
		print(f"  {gray_desc('Run sudo setup/install.sh to retry.')}\n")
		sys.exit(1)

	ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	width = 72
	_log("\n" + "=" * width)
	_log("  Naust - Setup Complete")
	_log(f"  Finished: {ts}")
	_log("  Next step: sudo boxctl bootstrap")
	_log("=" * width)
	print(f"\n  {green('✓')}  {bold('Setup complete.')}\n")

	# Show admin URL, setup code, and TLS fingerprint via the installed operator
	# binary - the sole owner of the setup-code token, so there is one code path
	# whether setup mints it or an operator re-mints it later. Not logged: the
	# setup code is a credential. Inherits our stdout so the panel renders in place.
	try:
		subprocess.run(
			["/usr/local/bin/boxctl", "bootstrap", "--install", "--show-cert"],
			check=True,
		)
	except Exception:  # noqa: BLE001 - bootstrap can fail many ways; user gets a clear manual fallback either way
		# Bootstrap can fail if managerd isn't up yet. Give the user a clear
		# next step rather than silent nothing.
		print(f"  {gray_desc('─' * (_term_width() - 4))}")
		print(f"  To finish setup, run:  {bold('sudo boxctl bootstrap')}")
		print(f"  {gray_desc('─' * (_term_width() - 4))}")
		print()


if __name__ == "__main__":
	main()
