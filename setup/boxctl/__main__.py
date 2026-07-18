"""Entry point: python3 setup/boxctl [docker|questions|bootstrap|doctor]"""

import argparse
import contextlib
import os
import pathlib
import signal
import sys
import termios

# When run as `python3 setup/boxctl`, __package__ is '' and relative imports fail.
# Add the setup/ directory to sys.path so `import boxctl` works as an absolute import.
if __package__ in {None, ''}:
	sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
	from boxctl.questions import STEPS, VALUE_DISPLAY
	from boxctl.runner import run_questions, write_output, load_conf
	from boxctl.ui import select_prompt, clear, bold, gray_desc, red, _term_width
else:
	from .questions import STEPS, VALUE_DISPLAY
	from .runner import run_questions, write_output, load_conf
	from .ui import select_prompt, clear, bold, gray_desc, red, _term_width

BARE_METAL_CONF = "/etc/naust.conf"
DOCKER_ENV_DEFAULT = "deploy/docker/.env"


def _landing():
	"""Interactive landing screen shown when no subcommand is given."""
	clear()
	print(f"\n  {bold('boxctl')}  {gray_desc('-')}  {gray_desc('Naust management CLI')}")
	width = _term_width() - 4
	print(f"  {gray_desc('─' * width)}\n")
	options = [
		("Docker", "Configure a Docker Compose deployment. Generates a .env file and compose command.", "docker"),
		("Bare metal", "Install directly on an Ubuntu machine via the guided installer.", "baremetal"),
		("Manage services", "Check service health and swap services on a running box.", "doctor"),
	]
	return select_prompt(
		"What would you like to do?",
		"Run with a subcommand to skip this screen.",
		options,
		None,
		False,
	)


def _preflight():
	"""Check RAM and disk space before starting setup. Prints warnings, returns False if critical."""
	import shutil

	OK, WARN, ERR = "ok", "warn", "err"
	checks = []

	with contextlib.suppress(Exception), open("/proc/meminfo", encoding='utf-8') as f:
		for line in f:
			if line.startswith("MemTotal:"):
				mb = int(line.split()[1]) // 1024
				if mb < 256:
					checks.append((ERR, "RAM", f"{mb} MB available - 512 MB minimum required"))
				elif mb < 512:
					checks.append((WARN, "RAM", f"{mb} MB available - 512 MB recommended"))
				else:
					checks.append((OK, "RAM", f"{mb} MB available"))
				break

	with contextlib.suppress(Exception):
		free_gb = shutil.disk_usage("/home").free // (1024**3)
		if free_gb < 2:
			checks.append((ERR, "Disk", f"{free_gb} GB free at /home - 5 GB recommended"))
		elif free_gb < 5:
			checks.append((WARN, "Disk", f"{free_gb} GB free at /home"))
		else:
			checks.append((OK, "Disk", f"{free_gb} GB free at /home"))

	if not checks:
		return True

	ICON = {OK: "\033[38;2;95;255;135m✓\033[0m", WARN: "\033[38;2;255;215;0m!\033[0m", ERR: "\033[38;2;255;85;85m✗\033[0m"}
	width = _term_width() - 2
	label_w = max(len(label) for _, label, _ in checks) + 2
	any_err = any(s == ERR for s, _, _ in checks)
	any_warn = any(s == WARN for s, _, _ in checks)

	if any_err or any_warn:
		print(f"\n  {bold('Pre-flight checks')}")
		print(f"  {gray_desc('─' * (width - 2))}")
		for status, label, msg in checks:
			pad = " " * (label_w - len(label))
			print(f"  {ICON[status]}  {label}{pad}{gray_desc(msg)}")
		print()

	if any_err:
		print(f"  {red('Setup cannot continue. Resolve the issues above first.')}\n")
		return False

	return True


def _run_update():
	import os
	import subprocess
	import sys
	import tarfile
	import tempfile
	import urllib.request

	# Docker users update by pulling a new image, not by running setup.
	if os.path.exists("/.dockerenv") or os.environ.get("container") == "docker":  # noqa: SIM112 - "container" is the actual lowercase env var systemd/Docker set, not ours to capitalize
		print("boxctl update is only available on bare metal installs.")
		print("To update a Docker deployment, pull a new image and restart your containers.")
		sys.exit(1)

	if os.geteuid() != 0:
		print("boxctl update must be run as root (sudo boxctl update).")
		sys.exit(1)

	# /releases/latest excludes prereleases, so frontend hash builds never appear here.
	api_url = "https://api.github.com/repos/naust-mail/naust/releases/latest"
	print("Fetching latest release info...")
	try:
		with urllib.request.urlopen(api_url, timeout=15) as r:
			import json

			release = json.loads(r.read())
	except Exception as e:  # noqa: BLE001 - network/JSON fetch, any failure becomes a user-facing CLI message
		print(f"Failed to fetch release info: {e}")
		sys.exit(1)

	version = release.get("tag_name", "unknown")
	tarball_url = release.get("tarball_url")
	if not tarball_url:
		print("No versioned release found. Check https://github.com/naust-mail/naust/releases")
		sys.exit(1)

	current_version = ""
	version_file = "/usr/local/share/naust/version"
	if os.path.exists(version_file):
		current_version = pathlib.Path(version_file).read_text(encoding='utf-8').strip()

	if current_version == version:
		print(f"Already on the latest version ({version}).")
		answer = input("Re-run setup anyway? [y/N] ").strip().lower()
		if answer != "y":
			sys.exit(0)
	else:
		print(f"Updating from {current_version or 'unknown'} to {version}...")

	with tempfile.TemporaryDirectory(prefix="naust-update-") as tmp:
		tarball = os.path.join(tmp, "release.tar.gz")
		print("Downloading...")
		try:
			urllib.request.urlretrieve(tarball_url, tarball)
		except Exception as e:  # noqa: BLE001 - network fetch, any failure becomes a user-facing CLI message
			print(f"Download failed: {e}")
			sys.exit(1)

		print("Extracting...")
		with tarfile.open(tarball, "r:gz") as tf:
			tf.extractall(tmp, filter="data")

		# GitHub tarballs extract to a single top-level directory.
		subdirs = [d for d in os.listdir(tmp) if os.path.isdir(os.path.join(tmp, d)) and d != "__MACOSX"]
		if len(subdirs) != 1:
			print("Unexpected tarball structure.")
			sys.exit(1)
		repo_dir = os.path.join(tmp, subdirs[0])

		print(f"Running setup from {version}...")
		result = subprocess.run(["bash", "setup/install.sh"], cwd=repo_dir)
		sys.exit(result.returncode)


def main():
	# bootstrap, update, and doctor --check don't need an interactive terminal.
	# Exempt them before the TTY check so they work from scripts and monitoring.
	if len(sys.argv) > 1 and sys.argv[1] in {'bootstrap', 'update'}:
		p = argparse.ArgumentParser(add_help=False)
		p.add_argument('command')
		p.add_argument('--show-cert', action='store_true')
		p.add_argument('--install', action='store_true')
		quick, _ = p.parse_known_args()
		if quick.command == 'bootstrap':
			if __package__ in {None, ''}:
				from boxctl.bootstrap import run as run_bootstrap
			else:
				from .bootstrap import run as run_bootstrap
			run_bootstrap(show_cert=quick.show_cert, install=quick.install)
		elif quick.command == 'update':
			_run_update()
		return

	if len(sys.argv) > 1 and sys.argv[1] == 'doctor' and '--check' in sys.argv:
		if __package__ in {None, ''}:
			from boxctl.doctor import run as run_doctor
		else:
			from .doctor import run as run_doctor
		run_doctor(check=True)
		return

	if not sys.stdin.isatty():
		sys.exit("Interactive terminal required")

	saved = termios.tcgetattr(sys.stdin.fileno())

	def _on_sigterm(_sig, _frame):
		with contextlib.suppress(Exception):
			termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, saved)
		print("\033[?25h", end="", flush=True)
		sys.exit(1)

	signal.signal(signal.SIGTERM, _on_sigterm)

	p = argparse.ArgumentParser(
		description="boxctl - Naust management CLI. Run with no subcommand for an interactive menu.",
		epilog="Run without a subcommand to choose interactively.",
	)
	sub = p.add_subparsers(dest="command", required=False, title="subcommands", description="Pass one of the following, or omit to get the interactive menu.")

	# ── bare metal: questions ──────────────────────────────────────────────────
	pq = sub.add_parser("questions", help="collect bare metal install answers interactively")
	pq.add_argument("--output", required=True, help="file to write answers to")
	pq.add_argument("--default-hostname", default="", help="suggested hostname")
	pq.add_argument("--guessed-ipv4", default="", help="auto-detected public IPv4")
	pq.add_argument("--default-ipv4", default="", help="previously configured IPv4")
	pq.add_argument("--guessed-ipv6", default="", help="auto-detected public IPv6")
	pq.add_argument("--default-ipv6", default="", help="previously configured IPv6")
	pq.add_argument("--ask-email", action="store_true", help="ask for admin email address")
	pq.add_argument("--ask-hostname", action="store_true", help="ask for server hostname")
	pq.add_argument("--ask-ipv4", action="store_true", help="ask for public IPv4")
	pq.add_argument("--ask-ipv6", action="store_true", help="ask for public IPv6")
	pq.add_argument("--ask-filebrowser", action="store_true", help="ask whether to install FileBrowser")
	pq.add_argument("--ask-optionals", action="store_true", help="ask which optional features to install (Radicale, ClamAV)")
	pq.add_argument("--ask-spam-filter", action="store_true", help="ask which spam filter to use (rspamd or spamassassin)")
	pq.add_argument("--ask-webmail", action="store_true", help="ask which webmail client to install")
	pq.add_argument("--ask-dns-mode", action="store_true", help="ask how DNS is managed")
	pq.add_argument("--ask-backup-tool", action="store_true", help="ask which backup tool to use (restic or duplicity)")
	pq.add_argument("--ask-monitoring", action="store_true", help="ask which monitoring tool to install")
	pq.add_argument("--ask-timezone", action="store_true", help="ask for the server timezone")

	# ── docker wizard ──────────────────────────────────────────────────────────
	pd = sub.add_parser("docker", help="interactive Docker Compose setup - writes .env and prints the compose command")
	pd.add_argument("--env", default="deploy/docker/.env", help="path to write the Docker .env file (default: deploy/docker/.env)")

	# ── doctor ─────────────────────────────────────────────────────────────────
	pd2 = sub.add_parser("doctor", help="check service health and swap services on a running box")
	pd2.add_argument("--check", action="store_true", help="non-interactive: print service status and exit (non-zero if any degraded)")

	# ── bootstrap ──────────────────────────────────────────────────────────────
	pb = sub.add_parser("bootstrap", help="generate a one-time setup code to create the first admin account via the web UI")
	pb.add_argument("--show-cert", action="store_true", help="also print the TLS certificate fingerprint (useful when DNS is not yet resolving)")
	pb.add_argument("--install", action="store_true", help="called from the installer: show a completion message if an admin already exists instead of an error")

	# ── update (bare metal only) ───────────────────────────────────────────────
	sub.add_parser("update", help="fetch the latest release from GitHub and re-run setup (bare metal only)")

	args = p.parse_args()

	try:
		if args.command is None:
			mode = _landing()
			if mode is None:
				sys.exit(0)
			elif mode == "docker":
				if __package__ in {None, ''}:
					from boxctl.docker import run as run_docker
				else:
					from .docker import run as run_docker
				run_docker(DOCKER_ENV_DEFAULT)
			elif mode == "baremetal":
				clear()
				print(f"\n  {bold('Bare metal setup')}\n")
				print("  Run the installer on your Ubuntu machine:\n")
				print("    sudo setup/install.sh\n")
				print(f"  {gray_desc('boxctl runs automatically during installation.')}\n")
			elif mode == "doctor":
				if __package__ in {None, ''}:
					from boxctl.doctor import run as run_doctor
				else:
					from .doctor import run as run_doctor
				run_doctor()
			return

		if args.command == "questions":
			if not _preflight():
				sys.exit(1)
			active = [(key, label, fn) for flag, key, label, fn in STEPS if getattr(args, flag.replace("-", "_"), False)]
			all_steps = [(key, label, fn) for _, key, label, fn in STEPS]
			initial = load_conf(BARE_METAL_CONF)
			results = run_questions(active, args, VALUE_DISPLAY, initial=initial, all_steps=all_steps)
			write_output(args.output, results)

		elif args.command == "docker":
			if __package__ in {None, ''}:
				from boxctl.docker import run as run_docker
			else:
				from .docker import run as run_docker
			run_docker(args.env)

		elif args.command == "doctor":
			if __package__ in {None, ''}:
				from boxctl.doctor import run as run_doctor
			else:
				from .doctor import run as run_doctor
			run_doctor(check=getattr(args, "check", False))

		elif args.command == "bootstrap":
			if __package__ in {None, ''}:
				from boxctl.bootstrap import run as run_bootstrap
			else:
				from .bootstrap import run as run_bootstrap
			run_bootstrap(show_cert=getattr(args, 'show_cert', False), install=getattr(args, 'install', False))

		elif args.command == "update":
			_run_update()

	except KeyboardInterrupt:
		print("\n\n  Setup cancelled.\n")
		sys.exit(1)


if __name__ == "__main__":
	main()
