"""
Component runner. Discovers all modules under defs/ (including subdirectories),
installs packages, runs doit for build steps, then restarts services.

Each defs module must expose:
  COMPONENT: Component
  make_tasks(env: dict, runtime: str) -> list[dict]  # doit task dicts

Modules without both attributes (e.g. shared __init__.py helpers) are silently
skipped - they are not components.

Task names within make_tasks() should be short step names ('keys', 'configure').
The runner groups them under the component name so doit sees 'dns:keys' etc.

uptodate conventions:
  [config_changed(VERSION)]  - versioned artifact (re-run when version changes)
  [run_once]                 - generate once, never re-run (e.g. DNSSEC keys)
  targets=['/path']          - re-run if output file is missing
  [False]                    - always run (configure steps)
"""

import grp
import importlib
import json
import logging
import os
import pkgutil
import pwd
import sqlite3
import subprocess
import sys
import time
import types
from collections import defaultdict
from collections.abc import Callable

import fcntl

from .component import Component, BAREMETAL, DOCKER
from . import packages as pkg

log = logging.getLogger(__name__)

STATE_DB = "/usr/local/lib/naust/setup-state.db"
# Per-component wall-clock times from previous runs, used by install.py to
# show an honest "about X remaining" on re-runs (first installs get none).
DURATIONS_PATH = "/usr/local/lib/naust/setup-durations.json"


def _emit(*parts: str) -> None:
	"""Print a machine-readable progress event line.

	install.py renders progress from these instead of scraping doit's human
	output. Anything not starting with @@ is treated as raw log text there.
	"""
	print("@@ev", *parts, flush=True)


# Keys doit recognises in task dicts. Used to strip our own metadata (e.g.
# "build") before passing tasks to doit, which rejects unknown fields.
_DOIT_KEYS = frozenset([
	"name",
	"actions",
	"file_dep",
	"task_dep",
	"targets",
	"uptodate",
	"verbosity",
	"title",
	"doc",
	"clean",
	"teardown",
	"setup",
	"calc_dep",
	"getargs",
	"watch",
	"pos_arg",
])


def _grant_naust_backup_groups(groups: list[str]) -> None:
	"""Add the naust user to each group, once, after every component's own
	tasks (including whatever task creates that group) have finished.

	Runs as plain sequential code, not a doit task: naust_backup_groups is
	only ever populated by optional components whose group-creation is a
	task, not a package, so nothing here can assume doit's task graph has
	already ordered it correctly. Tolerant of a missing naust user (managerd
	not installed) or a missing group (component disabled without the field
	being consulted, or usermod already covered by managerd's own package-
	derived group list) - both are silently skipped, not errors.
	"""
	try:
		pwd.getpwnam("naust")
	except KeyError:
		return
	for group in groups:
		try:
			grp.getgrnam(group)
		except KeyError:
			continue
		subprocess.run(["usermod", "-aG", group, "naust"], check=True, capture_output=True)


# ── Discovery ─────────────────────────────────────────────────────────────────


def _discover(errors_out: list[tuple[str, str]] | None = None) -> list[tuple[Component, Callable]]:
	"""Import every module under defs/ (recursive) and collect (COMPONENT, make_tasks) pairs.

	Modules missing COMPONENT or make_tasks are silently skipped - they are
	shared helpers, not components (e.g. backup/__init__.py).

	Import errors: raises unless errors_out is given, in which case
	(modname, error) pairs are appended there and the caller decides which are
	fatal (run() skips broken modules for components you are not installing).
	"""
	from . import defs as defs_pkg

	result = []
	errors = []
	for _, modname, ispkg in pkgutil.walk_packages(defs_pkg.__path__, defs_pkg.__name__ + "."):
		if ispkg:
			# Sub-packages (webmail/, filter/, etc.) are namespace containers,
			# not components themselves - skip and let walk_packages descend into them.
			continue
		try:
			mod = importlib.import_module(modname)
		except Exception as e:  # noqa: BLE001 - any single broken component module is collected, not fatal to the scan
			errors.append((modname, str(e)))
			continue
		if not hasattr(mod, "COMPONENT") or not hasattr(mod, "make_tasks"):
			# Shared helper module (e.g. backup/__init__.py) - not a component.
			continue
		result.append((mod.COMPONENT, mod.make_tasks))
	if errors:
		if errors_out is None:
			raise ImportError("Component modules failed to load:\n" + "\n".join(f"{m}: {e}" for m, e in errors))
		errors_out.extend(errors)
	result.sort(key=lambda pair: (pair[0].port_order, pair[0].name))
	return result


def _import_error_fatal(modname: str, env: dict, component_names: list[str] | None) -> bool:
	"""Decide whether a broken defs module aborts the run.

	Relies on the module basename matching COMPONENT.name (true for every defs
	file today; a broken module cannot tell us its component name). Choice-based
	subdirectories map to their selecting env var; anything top-level is core
	and always fatal.
	"""
	parts = modname.split(".")
	basename = parts[-1]
	parent = parts[-2] if len(parts) >= 2 else ""
	if component_names is not None:
		return basename in component_names
	if parent == "webmail":
		return env.get("WEBMAIL_CLIENT") == basename
	if parent == "filter":
		return env.get("SPAM_FILTER") == basename
	if parent == "backup":
		return env.get("BACKUP_TOOL") == basename
	if parent == "optional":
		return env.get(f"ENABLE_{basename.upper()}") == "true" or env.get("MONITORING_TOOL") == basename
	return True


# ── Doit integration ──────────────────────────────────────────────────────────


def _make_reporter_class(ran: set[str], comp_times: dict[str, tuple[float, float]]) -> type:
	"""Return a ConsoleReporter subclass that records which components ran tasks,
	emits @@ev progress events for install.py, and tracks per-component wall time."""
	from doit.reporter import ConsoleReporter

	def _touch(comp: str) -> None:
		now = time.monotonic()
		first, _ = comp_times.get(comp, (now, now))
		comp_times[comp] = (first, now)

	class _Reporter(ConsoleReporter):
		def execute_task(self, task):
			super().execute_task(task)
			if ":" in task.name:
				_emit("start", task.name)
				_touch(task.name.split(":")[0])

		def add_success(self, task):
			super().add_success(task)
			# Only subtasks have ":" in their name. The parent group task (the
			# generator itself) always calls add_success once all subtasks finish,
			# even when every subtask was up-to-date. Tracking only subtasks gives
			# the correct semantics: "component had at least one task actually run".
			if ":" in task.name:
				ran.add(task.name.split(":")[0])
				_emit("done", task.name)
				_touch(task.name.split(":")[0])

		def add_failure(self, task, fail):
			super().add_failure(task, fail)
			if ":" in task.name:
				_emit("fail", task.name)
				_touch(task.name.split(":")[0])

		def skip_uptodate(self, task):
			super().skip_uptodate(task)
			if ":" in task.name:
				_emit("cached", task.name)
				_touch(task.name.split(":")[0])

	return _Reporter


def _run_doit(component_tasks: dict[str, list[dict]], force: bool = False, parallel: int = 0) -> set[str]:
	"""Run doit with the given component→tasks mapping.
	Returns set of component names that had at least one task execute.

	force: if True, use --always-execute to skip cache checks.
	parallel: if > 0, run up to that many tasks concurrently (threads, so task
	dicts need no pickling). Correctness relies on complete task_dep chains for
	shared-file writes - hence opt-in.
	"""
	from doit.doit_cmd import DoitMain
	from doit.cmd_base import ModuleTaskLoader

	ran: set[str] = set()
	comp_times: dict[str, tuple[float, float]] = {}

	# Emit the full plan before running so the UI knows every step up front.
	for comp_name, task_list in component_tasks.items():
		print(f"@@plan {comp_name} {' '.join(t['name'] for t in task_list)}", flush=True)

	mod = types.ModuleType("_naust_tasks")
	mod.DOIT_CONFIG = {  # type: ignore[attr-defined]
		"backend": "sqlite3",
		"dep_file": STATE_DB,
		"reporter": _make_reporter_class(ran, comp_times),
		"verbosity": 2,
	}
	if parallel > 0:
		mod.DOIT_CONFIG["num_process"] = parallel
		mod.DOIT_CONFIG["par_type"] = "thread"

	def _strip(task: dict) -> dict:
		return {k: v for k, v in task.items() if k in _DOIT_KEYS}

	for comp_name, task_list in component_tasks.items():
		# doit discovers task_* generator functions; yield creates comp:step subtasks.
		def _make_gen(tasks: list[dict]) -> Callable:
			def _gen():
				yield from (_strip(t) for t in tasks)

			return _gen

		gen = _make_gen(task_list)
		gen.__name__ = f"task_{comp_name}"
		setattr(mod, f"task_{comp_name}", gen)

	os.makedirs(os.path.dirname(STATE_DB), exist_ok=True)
	if os.path.exists(STATE_DB):
		try:
			with sqlite3.connect(STATE_DB) as con:
				ok = con.execute("PRAGMA integrity_check").fetchone()[0]
			if ok != "ok":
				msg = f"integrity_check returned: {ok}"
				raise sqlite3.DatabaseError(msg)
		except sqlite3.DatabaseError as e:
			log.warning("Doit state DB is corrupt (%s) - removing and starting fresh", e)
			os.unlink(STATE_DB)
	doit_cmd = ["run", "--continue"]
	if force:
		doit_cmd.append("--always-execute")
	doit_result = DoitMain(ModuleTaskLoader(mod)).run(doit_cmd)
	# Record per-component wall times (merged over previous runs) before any
	# failure exit - partial timings are still useful for re-run estimates.
	if comp_times:
		durations: dict[str, float] = {}
		try:
			with open(DURATIONS_PATH, encoding="utf-8") as f:
				durations = json.load(f)
		except (OSError, ValueError):
			pass
		for comp, (t0, t1) in comp_times.items():
			durations[comp] = round(t1 - t0, 2)
		try:
			os.makedirs(os.path.dirname(DURATIONS_PATH), exist_ok=True)
			with open(DURATIONS_PATH + ".tmp", "w", encoding="utf-8") as f:
				json.dump(durations, f)
			os.replace(DURATIONS_PATH + ".tmp", DURATIONS_PATH)
		except OSError:
			pass
	if doit_result != 0:
		# One or more tasks failed. --continue means unrelated tasks still ran;
		# propagate failure so install.py reports "components" as failed.
		sys.exit(doit_result)
	return ran


# ── Service restart ───────────────────────────────────────────────────────────


def _restart(svc: str, runtime: str) -> None:
	if runtime == DOCKER:
		# On first-time container setup this runs before supervisord has started
		# (no /run/supervisor.sock yet); the service will start fresh under
		# supervisord at the end of the entrypoint anyway, so skip the restart
		# rather than treating the missing socket as a failure.
		if not os.path.exists("/run/supervisor.sock"):
			return
		subprocess.run(["supervisorctl", "restart", svc], check=True)
	else:
		subprocess.run(["systemctl", "restart", svc], check=True)


# ── Main entry point ──────────────────────────────────────────────────────────


def run(env: dict, component_names: list[str] | None = None, force: bool = False, parallel: int = 0) -> None:
	"""Discover, install packages, run doit tasks, restart services.

	env: parsed /etc/naust.conf.
	component_names: explicit list to run, or None for all enabled.
	force: if True, run all tasks even if up-to-date (skip cache checks).
	parallel: if > 0, run up to that many tasks concurrently (opt-in).
	"""
	runner_lockfile = open("/tmp/naust-runner.lock", "w", encoding="utf-8")  # noqa: S108, SIM115 - fixed path so concurrent runs can find and flock it; held for the process lifetime
	try:
		fcntl.flock(runner_lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
	except BlockingIOError:
		sys.exit("Another setup run is already in progress.")

	# Fail once, clearly, instead of 26 scattered env["KEY"] crashes mid-install.
	required = ("STORAGE_USER", "STORAGE_ROOT", "PRIMARY_HOSTNAME", "PUBLIC_IP")
	missing = [k for k in required if not env.get(k)]
	if missing:
		sys.exit(f"/etc/naust.conf is missing required settings: {', '.join(missing)} - re-run sudo setup/install.sh")

	runtime = os.environ.get("RUNTIME", BAREMETAL)
	import_errors: list[tuple[str, str]] = []
	all_defs = _discover(import_errors)
	fatal_imports = []
	for modname, err in import_errors:
		if _import_error_fatal(modname, env, component_names):
			fatal_imports.append(f"{modname}: {err}")
		else:
			log.warning("WARNING: skipping component module %s (not selected) - it failed to load: %s", modname, err)
	if fatal_imports:
		raise ImportError("Component modules failed to load:\n" + "\n".join(fatal_imports))

	if component_names is not None:
		known = {comp.name for comp, _ in all_defs}
		missing = [n for n in component_names if n not in known]
		if missing:
			msg = f"Unknown components: {missing}"
			raise ValueError(msg)
		defs = [(c, fn) for c, fn in all_defs if c.name in component_names]
	else:
		defs = all_defs

	enabled = [(c, fn) for c, fn in defs if runtime not in c.skip_on and (c.enabled is None or c.enabled(env))]

	if not enabled:
		log.info("No components to run.")
		return

	# One batched apt install for all enabled components.
	all_packages = sorted({p for c, _ in enabled for p in c.packages})
	if all_packages:
		log.info("Installing packages: %s", " ".join(all_packages))
		pkg.ensure_installed(all_packages)

	# Build per-component task lists. Components with no tasks (configure-only)
	# are still restarted below but don't participate in doit.
	component_tasks: dict[str, list[dict]] = {}
	for comp, fn in enabled:
		tasks = fn(env, runtime)
		if tasks:
			component_tasks[comp.name] = tasks

	ran = _run_doit(component_tasks, force=force, parallel=parallel) if component_tasks else set()

	# Grant naust read access to any group an optional component created for
	# its own service files, now that every component's tasks (including
	# group creation) have run. See Component.naust_backup_groups.
	all_naust_groups = sorted({g for c, _ in enabled for g in c.naust_backup_groups})
	if all_naust_groups:
		_grant_naust_backup_groups(all_naust_groups)

	# Restart services only when at least one task actually ran for that component.
	# Because all tasks are stamped (none use uptodate=[False]), `ran` accurately
	# reflects what changed this invocation - no need to restart postfix just
	# because we ran setup with nothing changed.
	_emit("phase", "restarts")
	restart_failures: list[str] = []
	for comp, _ in enabled:
		if comp.name not in ran:
			log.info("Skipping restart for %s (all tasks cached)", comp.name)
			continue
		targets = comp.docker_services if runtime == DOCKER else comp.services
		for svc in targets:
			log.info("Restarting %s", svc)
			_emit("restart-start", svc)
			try:
				_restart(svc, runtime)
				_emit("restart-done", svc)
			except FileNotFoundError:
				# supervisorctl/systemctl not present - non-fatal (e.g. Docker entrypoint-managed).
				log.warning("WARNING: failed to restart %s - systemctl/supervisorctl not found", svc)
				_emit("restart-done", svc)
			except subprocess.CalledProcessError:
				log.exception("ERROR: failed to restart %s - service may be broken, check logs", svc)
				_emit("restart-fail", svc)
				restart_failures.append(svc)

	# Every declared service must survive a reboot, regardless of whether its
	# package's own postinst enabled it. Relying on package defaults left
	# fail2ban permanently disabled after a single startup failure (it crashed
	# once on a config race, systemd correctly declined to loop-restart it,
	# and it was never enabled in the first place - so a later reboot never
	# brought it back). Enabling here is idempotent and makes the runner, not
	# each component author, the one source of truth for this invariant.
	#
	# This also catches the case where an earlier setup run executed a
	# component's tasks but died before this restart phase: the rerun sees
	# the tasks cached, skips the restart, and a freshly installed unit stays
	# dead forever. Start anything left enabled-but-inactive.
	if runtime != DOCKER:
		for comp, _ in enabled:
			for svc in comp.services:
				enable_result = subprocess.run(["systemctl", "enable", svc], check=False, capture_output=True)
				if enable_result.returncode != 0:
					log.warning("WARNING: failed to enable %s - %s", svc, enable_result.stderr.decode().strip())
				is_active = subprocess.run(["systemctl", "is-active", "--quiet", svc], check=False)
				if is_active.returncode != 0:
					log.info("Starting %s (not running)", svc)
					try:
						subprocess.run(["systemctl", "start", svc], check=True)
					except subprocess.CalledProcessError:
						log.exception("ERROR: failed to start %s - check its logs", svc)
						restart_failures.append(svc)

	if restart_failures:
		sys.exit(f"Services failed to restart: {', '.join(restart_failures)}")

	all_notices = [n for comp, _ in enabled for n in comp.notices]
	if all_notices:
		print("\n" + "=" * 60)
		print("POST-INSTALL NOTICES")
		print("=" * 60)
		for notice in all_notices:
			print(f"  * {notice}")
		print("=" * 60 + "\n")


# ── Build mode ───────────────────────────────────────────────────────────────


def build(component_names: list[str], skip_packages: bool = False) -> None:
	"""Install packages and run build-safe tasks for use in Dockerfiles.

	Runs at Docker image build time - no /etc/naust.conf exists yet.
	Only tasks tagged with "build": True are executed. Config-writing tasks
	that need real env vars are skipped and run at container startup instead.

	RUNTIME must be unset when calling this so ensure_installed() runs apt
	normally (at runtime RUNTIME=docker makes it a no-op).

	skip_packages: skip the apt install step and run tasks only. Used by the
	venv-builder Docker stage which pre-installs compile deps manually and only
	needs the venv/pip tasks, not the full COMPONENT.packages list.
	"""
	all_defs = _discover()

	known = {comp.name for comp, _ in all_defs}
	missing = [n for n in component_names if n not in known]
	if missing:
		msg = f"Unknown components: {missing}"
		raise ValueError(msg)

	defs = [(c, fn) for c, fn in all_defs if c.name in component_names]

	if not skip_packages:
		# Batched apt install for all named components.
		all_packages = sorted({p for c, _ in defs for p in c.packages})
		if all_packages:
			log.info("Installing packages: %s", " ".join(all_packages))
			pkg.ensure_installed(all_packages)

	# Use a defaultdict so env["ANY_KEY"] returns "" instead of KeyError.
	# make_tasks() may construct task dicts that reference env keys at call
	# time; those values are never used since we filter to build-safe tasks only.
	env: dict = defaultdict(str)

	component_tasks: dict[str, list[dict]] = {}
	for comp, fn in defs:
		all_tasks = fn(env, BAREMETAL)
		build_tasks = [t for t in all_tasks if t.get("build") is True]
		if build_tasks:
			component_tasks[comp.name] = build_tasks

	if component_tasks:
		_run_doit(component_tasks)
	else:
		log.info("No build-time tasks to run.")


# ── CLI / conf helpers ────────────────────────────────────────────────────────


def load_conf(path: str = "/etc/naust.conf") -> dict:
	conf = {}
	try:
		with open(path, encoding="utf-8") as f:
			for raw_line in f:
				line = raw_line.strip()
				if not line or line.startswith("#") or "=" not in line:
					continue
				k, _, v = line.partition("=")
				conf[k.strip()] = v.strip().strip("'\"")
	except FileNotFoundError:
		pass
	if os.environ.get("RUNTIME") == "docker":
		# docker-compose's `environment:` block is the complete, intentional
		# set of overrides for this container - mirrors boxconf.Load (the Go
		# side), where real process env already wins over the file. Bare
		# metal stays file-only: /etc/naust.conf is the operator's
		# deliberately curated source of truth there, and a stray shell var
		# should not silently override it.
		conf.update(os.environ)
	return conf


if __name__ == "__main__":
	import argparse

	logging.basicConfig(level=logging.INFO, format="%(message)s")
	parser = argparse.ArgumentParser(description="Run NAUST component runner")
	parser.add_argument("components", nargs="*", help="Components to run (default: all)")
	parser.add_argument("--force", action="store_true", help="Always execute tasks, skip cache checks")
	parser.add_argument("--parallel", type=int, default=0, metavar="N", help="Experimental: run up to N tasks concurrently. Relies on complete task_dep chains for shared-file writes.")
	parser.add_argument("--build-mode", action="store_true", help="Docker build time: install packages and run build-safe tasks only. No /etc/naust.conf needed. RUNTIME must be unset.")
	parser.add_argument("--skip-packages", action="store_true", help="--build-mode only: skip apt install and run tasks only. Used by the venv-builder Docker stage.")
	args = parser.parse_args()
	if args.build_mode:
		if not args.components:
			parser.error("--build-mode requires at least one component name")
		build(args.components, skip_packages=args.skip_packages)
	else:
		env = load_conf()
		if not env:
			if os.path.exists("/etc/naust.conf"):
				log.error("ERROR: /etc/naust.conf exists but is empty or unreadable - re-run setup")
			else:
				log.error("ERROR: /etc/naust.conf not found - run setup first")
			sys.exit(1)
		run(env, component_names=args.components or None, force=args.force, parallel=args.parallel)
