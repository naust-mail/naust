import os
import sys

from core.utils import load_environment, shell


def _atomic_json_write(path, data):
	"""Write data as JSON to path atomically (temp-file + os.replace) with 0o600 permissions."""
	import json
	import tempfile

	dir_ = os.path.dirname(path)
	os.makedirs(dir_, exist_ok=True)
	fd, tmp = tempfile.mkstemp(dir=dir_, suffix=".tmp")
	try:
		with os.fdopen(fd, "w", encoding="utf-8") as f:
			json.dump(data, f)
		os.chmod(tmp, 0o600)
		os.replace(tmp, path)
	except Exception:
		try:
			os.unlink(tmp)
		except OSError:
			pass
		raise


def _email_administrator(subject, body):
	# email_administrator.py is a script, not an importable module - it reads
	# sys.argv/stdin and runs top-level code unconditionally, so it must be
	# invoked as a subprocess (matching how daily_tasks.py already pipes other
	# backup output into it), never imported directly.
	script = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'mail', 'email_administrator.py')
	shell('check_output', [script, subject], input=body.encode())


def perform_backup(full_backup):
	"""Dispatches to the active backend. Callers never branch on BACKUP_TOOL -
	this is the one place that decision is made."""
	from .config import get_backup_config

	env = load_environment()

	from core.utils import acquire_process_lock

	_backup_lock = acquire_process_lock("/tmp/naust-backup.lock")

	config = get_backup_config(env)
	if config["target"] == "off":
		return

	if env.get("BACKUP_TOOL", "duplicity") == "restic":
		_perform_backup_restic(env, config)
	else:
		_perform_backup_duplicity(env, config, full_backup)


def _checkpoint_sqlite_databases(storage_root):
	# Flush WAL logs for every SQLite database under storage_root so that
	# a plain file copy (duplicity, or restic's own file scan) sees a fully
	# consistent database file. All databases are opened with WAL mode via
	# initialize_database().
	import sqlite3
	import pathlib

	for db_path in pathlib.Path(storage_root).rglob('*.sqlite'):
		try:
			conn = sqlite3.connect(str(db_path), timeout=10)
			conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
			conn.close()
		except Exception as e:
			print(f"WARNING: WAL checkpoint failed for {db_path}: {e}", file=sys.stderr)


def _run_pre_script(env, backup_root, config):
	# Execute a pre-backup script that copies files outside the homedir.
	# Run as the STORAGE_USER user, not as root. Pass our settings in
	# environment variables so the script has access to STORAGE_ROOT.
	# The backup target URL is available to the script as $BACKUP_TARGET.
	# (Passing it as a positional arg via 'su -c cmd arg' makes it $0, not $1.)
	pre_script = os.path.join(backup_root, 'before-backup')
	if os.path.exists(pre_script):
		shell('check_call', ['su', env['STORAGE_USER'], '-c', pre_script], env={**env, 'BACKUP_TARGET': config["target"]})


def _run_post_script(env, backup_root, config):
	post_script = os.path.join(backup_root, 'after-backup')
	if os.path.exists(post_script):
		shell('check_call', ['su', env['STORAGE_USER'], '-c', post_script], env={**env, 'BACKUP_TARGET': config["target"]})


def _perform_backup_duplicity(env, config, full_backup):
	from .duplicity_args import DUPLICITY, get_duplicity_additional_args, get_duplicity_env_vars, get_duplicity_target_url
	from .status import should_force_full, _backup_cache_dir
	from .config import get_target_type

	backup_root = os.path.join(env["STORAGE_ROOT"], 'backup')
	backup_cache_dir = _backup_cache_dir(env)
	backup_dir = os.path.join(backup_root, 'encrypted')

	# On the first run, always do a full backup. Incremental
	# will fail. Otherwise do a full backup when the size of
	# the increments since the most recent full backup are
	# large.
	try:
		full_backup = full_backup or should_force_full(config, env)
	except Exception as e:
		# This was the first call to duplicity, and there might
		# be an error already.
		print(e)
		sys.exit(1)

	# Checkpoint all SQLite databases in STORAGE_ROOT before backup.
	_checkpoint_sqlite_databases(env["STORAGE_ROOT"])

	_run_pre_script(env, backup_root, config)

	# Run a backup of STORAGE_ROOT (but excluding the backups themselves!).
	# --allow-source-mismatch is needed in case the box's hostname is changed
	# after the first backup. See #396.
	shell(
		'check_call',
		[
			DUPLICITY,
			"full" if full_backup else "incr",
			"--verbosity",
			"warning",
			"--no-print-statistics",
			"--archive-dir",
			backup_cache_dir,
			"--exclude",
			backup_root,
			"--exclude",
			os.path.join(env["STORAGE_ROOT"], "owncloud-backup"),
			"--volsize",
			"250",
			"--gpg-options",
			"'--cipher-algo=AES256'",
			"--allow-source-mismatch",
			*get_duplicity_additional_args(env),
			env["STORAGE_ROOT"],
			get_duplicity_target_url(config),
		],
		get_duplicity_env_vars(env),
	)

	# Remove old backups. This deletes all backup data no longer needed
	# from more than 3 days ago.
	shell('check_call', [DUPLICITY, "remove-older-than", "%dD" % config["min_age_in_days"], "--verbosity", "error", "--archive-dir", backup_cache_dir, "--force", *get_duplicity_additional_args(env), get_duplicity_target_url(config)], get_duplicity_env_vars(env))

	# From duplicity's manual:
	# "This should only be necessary after a duplicity session fails or is
	# aborted prematurely."
	# That may be unlikely here but we may as well ensure we tidy up if
	# that does happen - it might just have been a poorly timed reboot.
	shell('check_call', [DUPLICITY, "cleanup", "--verbosity", "error", "--archive-dir", backup_cache_dir, "--force", *get_duplicity_additional_args(env), get_duplicity_target_url(config)], get_duplicity_env_vars(env))

	# Change ownership of backups to the user-data user, so that the after-bcakup
	# script can access them.
	if get_target_type(config) == 'file':
		shell('check_call', ["/bin/chown", "-R", env["STORAGE_USER"], backup_dir])

	if config.get("check_after_backup", True):
		_verify_duplicity(env, config, backup_cache_dir)

	_run_post_script(env, backup_root, config)


def _restic_repo_exists(repo, extra_args, restic_env):
	from .restic_args import RESTIC

	code, output = shell('check_output', [RESTIC, "-r", repo, "snapshots", "--json", *extra_args], restic_env, trap=True, capture_stderr=True)
	if code == 0:
		return True
	# restic's specific "repository does not exist yet" signature - this is the
	# expected first-run condition, not a failure. Anything else (auth, network,
	# wrong password) must not be masked as "needs init."
	if "Is there a repository at the following location" in output or "unable to open config file" in output:
		return False
	raise Exception("Something is wrong with the backup: " + output)


def _perform_backup_restic(env, config):
	from .restic_args import RESTIC, get_restic_repository, get_restic_extra_args, get_restic_env_vars

	backup_root = os.path.join(env["STORAGE_ROOT"], 'backup')
	repo = get_restic_repository(env, config)
	extra_args = get_restic_extra_args(env, config)
	restic_env = get_restic_env_vars(env, config)

	# restic init is atomic by restic's own design (the config object is
	# written last) - an interrupted init simply isn't "initialized" yet and
	# the next run's existence check correctly retries it. No custom
	# partial-init recovery is needed.
	if not _restic_repo_exists(repo, extra_args, restic_env):
		shell('check_call', [RESTIC, "-r", repo, "init", *extra_args], restic_env)

	_checkpoint_sqlite_databases(env["STORAGE_ROOT"])

	_run_pre_script(env, backup_root, config)

	# Back up STORAGE_ROOT, excluding the backup directories themselves.
	# --json emits a final summary line with snapshot_id, data_added,
	# total_bytes_processed, and total_files_processed - captured for the
	# stats cache so the status page never needs extra restic calls.
	code, backup_output = shell(
		'check_output',
		[
			RESTIC,
			"-r",
			repo,
			"backup",
			"--json",
			"--exclude",
			backup_root,
			"--exclude",
			os.path.join(env["STORAGE_ROOT"], "owncloud-backup"),
			*extra_args,
			env["STORAGE_ROOT"],
		],
		restic_env,
		trap=True,
		capture_stderr=False,
	)
	if code != 0:
		raise Exception("restic backup failed:\n" + backup_output)
	_cache_restic_snapshot_stats(env, backup_output)

	# Pruning lifecycle guarantee: forget --keep-within {N}d --prune always
	# runs immediately after a successful backup. It is never skipped. If it
	# fails (e.g. a stale lock from a previous crashed run), retry once after
	# unlocking. If it still fails, the backup itself is NOT marked as failed -
	# a dirty retention window doesn't invalidate data that was just safely
	# taken - but the failure must surface as a non-fatal operational error
	# through both logging and email_administrator.py, never silently swallowed.
	_prune_restic(repo, extra_args, restic_env, config)
	if config.get("check_after_backup", True):
		_verify_restic(repo, extra_args, restic_env, env)

	_run_post_script(env, backup_root, config)


def _cache_restic_snapshot_stats(env, backup_output):
	import json

	# The backup --json output is multiple JSON lines. The last line with
	# message_type "summary" has everything we need.
	summary = None
	for line in backup_output.splitlines():
		line = line.strip()
		if not line:
			continue
		try:
			obj = json.loads(line)
			if obj.get("message_type") == "summary":
				summary = obj
		except (ValueError, KeyError):
			pass
	if not summary or not summary.get("snapshot_id"):
		print("WARNING: restic backup produced no summary line - snapshot stats will not be cached", file=sys.stderr)
		return

	cache_path = _restic_stats_cache_path(env)
	try:
		with open(cache_path, encoding="utf-8") as f:
			cache = json.load(f)
	except (FileNotFoundError, ValueError):
		cache = {}
	if "snapshots" not in cache:
		# Migrate old format where snapshot IDs were top-level keys
		cache = {"snapshots": {k: v for k, v in cache.items() if k != "last_check"}}

	# status.py looks up stats by short_id (first 8 chars), so key by that.
	short_id = summary["snapshot_id"][:8]
	cache["snapshots"][short_id] = {
		"restore_size": summary.get("total_bytes_processed", 0),
		"data_added": summary.get("data_added", 0),
		"file_count": summary.get("total_files_processed", 0),
	}

	_atomic_json_write(cache_path, cache)


def _restic_stats_cache_path(env):
	return os.path.join(env["STORAGE_ROOT"], "backup", "cache", "restic-snapshot-stats.json")


def _restic_check_cache_path(env):
	return os.path.join(env["STORAGE_ROOT"], "backup", "cache", "restic-check.json")


def _duplicity_check_cache_path(env):
	return os.path.join(env["STORAGE_ROOT"], "backup", "cache", "duplicity-check.json")


def _verify_duplicity(env, config, backup_cache_dir):
	import datetime
	import subprocess
	from .duplicity_args import DUPLICITY, get_duplicity_additional_args, get_duplicity_env_vars, get_duplicity_target_url

	# collection-status verifies the backup chain is intact without downloading data.
	# Timeout prevents a hung check from blocking future backups. Default 10 min; override
	# with check_timeout_seconds in custom.yaml.
	timeout = int(config.get("check_timeout_seconds", 600))
	dup_env = {**get_duplicity_env_vars(env), "PATH": "/sbin:/bin:/usr/sbin:/usr/bin"}
	try:
		result = subprocess.run(
			[
				DUPLICITY,
				"collection-status",
				"--archive-dir",
				backup_cache_dir,
				"--gpg-options",
				"'--cipher-algo=AES256'",
				"--log-fd",
				"1",
				*get_duplicity_additional_args(env),
				get_duplicity_target_url(config),
			],
			env=dup_env,
			stdout=subprocess.PIPE,
			stderr=subprocess.STDOUT,
			timeout=1800,
		)
		passed = result.returncode == 0
		output = result.stdout.decode(errors="replace").strip()
	except subprocess.TimeoutExpired:
		passed = False
		output = f"duplicity collection-status timed out after {timeout // 60} minutes"

	_atomic_json_write(
		_duplicity_check_cache_path(env),
		{
			"passed": passed,
			"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
			"output": output if not passed else "",
		},
	)

	if not passed:
		warning = f"duplicity collection-status failed after backup - your backup chain may have integrity issues:\n\n{output}"
		print(f"WARNING: {warning}", file=sys.stderr)
		try:
			_email_administrator("Backup Integrity Check Failed", warning)
		except Exception as e:
			print(f"WARNING: could not send admin email: {e}", file=sys.stderr)


def _verify_restic(repo, extra_args, restic_env, env):
	import datetime
	import subprocess
	from .restic_args import RESTIC
	from .config import get_backup_config as _get_cfg

	# Timeout prevents a hung check from holding the process lock and blocking future backups.
	# Default is 10 minutes; override with check_timeout_seconds in custom.yaml.
	cfg = _get_cfg(env)
	timeout = int(cfg.get("check_timeout_seconds", 600))
	try:
		result = subprocess.run(
			[RESTIC, "-r", repo, "check", *extra_args],
			env={**restic_env, "PATH": "/sbin:/bin:/usr/sbin:/usr/bin"},
			stdout=subprocess.PIPE,
			stderr=subprocess.STDOUT,
			timeout=timeout,
		)
		passed = result.returncode == 0
		output = result.stdout.decode(errors="replace").strip()
	except subprocess.TimeoutExpired:
		passed = False
		output = f"restic check timed out after {timeout // 60} minutes"

	_atomic_json_write(
		_restic_check_cache_path(env),
		{
			"passed": passed,
			"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
			"output": output if not passed else "",
		},
	)

	if not passed:
		warning = f"restic check failed after backup - your repository may have integrity issues:\n\n{output}"
		print(f"WARNING: {warning}", file=sys.stderr)
		try:
			_email_administrator("Backup Integrity Check Failed", warning)
		except Exception as e:
			print(f"WARNING: could not send admin email: {e}", file=sys.stderr)


def _prune_restic(repo, extra_args, restic_env, config):
	from .restic_args import RESTIC

	forget_cmd = [RESTIC, "-r", repo, "forget", "--keep-within", f"{config['min_age_in_days']}d", "--prune", *extra_args]
	code, output = shell('check_output', forget_cmd, restic_env, trap=True, capture_stderr=True)
	if code == 0:
		return

	if "unable to create lock" in output or "already locked" in output:
		shell('check_call', [RESTIC, "-r", repo, "unlock", *extra_args], restic_env)
		code, output = shell('check_output', forget_cmd, restic_env, trap=True, capture_stderr=True)
		if code == 0:
			return

	# Still failing after one retry - report, don't fail the backup. Both
	# channels, every time: this must never go unreported, and it must never
	# be conflated with the backup itself having failed.
	warning = f"restic forget --prune failed and did not recover after one retry:\n\n{output}"
	print(f"WARNING: {warning}", file=sys.stderr)
	try:
		_email_administrator("Backup Retention Warning", warning)
	except Exception as e:
		print(f"WARNING: could not send admin email: {e}", file=sys.stderr)


def run_duplicity_verification():
	from .config import get_backup_config
	from .duplicity_args import DUPLICITY, get_duplicity_additional_args, get_duplicity_env_vars, get_duplicity_target_url
	from .status import _backup_cache_dir

	env = load_environment()
	backup_root = os.path.join(env["STORAGE_ROOT"], 'backup')
	config = get_backup_config(env)
	backup_cache_dir = _backup_cache_dir(env)

	shell(
		'check_call',
		[
			DUPLICITY,
			"--verbosity",
			"info",
			"verify",
			"--compare-data",
			"--archive-dir",
			backup_cache_dir,
			"--exclude",
			backup_root,
			"--exclude",
			os.path.join(env["STORAGE_ROOT"], "owncloud-backup"),
			*get_duplicity_additional_args(env),
			get_duplicity_target_url(config),
			env["STORAGE_ROOT"],
		],
		get_duplicity_env_vars(env),
	)


def run_duplicity_restore(args):
	from .config import get_backup_config
	from .duplicity_args import DUPLICITY, get_duplicity_additional_args, get_duplicity_env_vars, get_duplicity_target_url
	from .status import _backup_cache_dir

	env = load_environment()
	config = get_backup_config(env)
	backup_cache_dir = _backup_cache_dir(env)
	shell('check_call', [DUPLICITY, "restore", "--archive-dir", backup_cache_dir, *get_duplicity_additional_args(env), get_duplicity_target_url(config), *args], get_duplicity_env_vars(env))


def verify_backup():
	"""Unified, backend-agnostic entry point. Callers must never branch on
	BACKUP_TOOL themselves - this dispatcher is the only place that happens."""
	env = load_environment()
	from .config import get_backup_config

	config = get_backup_config(env)

	if env.get("BACKUP_TOOL", "duplicity") == "restic":
		from .restic_args import RESTIC, get_restic_repository, get_restic_extra_args, get_restic_env_vars

		repo = get_restic_repository(env, config)
		extra_args = get_restic_extra_args(env, config)
		restic_env = get_restic_env_vars(env, config)
		# --read-data downloads and verifies every data blob - this is the full check,
		# distinct from the lightweight post-backup check which omits this flag.
		shell('check_call', [RESTIC, "-r", repo, "check", "--read-data", *extra_args], restic_env)
	else:
		run_duplicity_verification()


def restore_backup(snapshot, target_dir):
	"""Unified, backend-agnostic entry point.

	`snapshot` is backend-specific by contract:
	  - restic: a snapshot ID (the `id`/`short_id` field from /backup/status entries)
	  - duplicity: a time specifier (ISO date, or a duplicity relative-time
	    string like "3D"), matching the `date` field from /backup/status entries

	Callers must never branch on BACKUP_TOOL themselves - this dispatcher is
	the only place that happens.
	"""
	env = load_environment()
	from .config import get_backup_config

	config = get_backup_config(env)

	if env.get("BACKUP_TOOL", "duplicity") == "restic":
		from .restic_args import RESTIC, get_restic_repository, get_restic_extra_args, get_restic_env_vars

		repo = get_restic_repository(env, config)
		extra_args = get_restic_extra_args(env, config)
		restic_env = get_restic_env_vars(env, config)
		shell('check_call', [RESTIC, "-r", repo, "restore", snapshot, "--target", target_dir, *extra_args], restic_env)
	else:
		run_duplicity_restore(["--time", snapshot, target_dir])


def print_duplicity_command():
	import shlex
	from .config import get_backup_config
	from .duplicity_args import get_duplicity_additional_args, get_duplicity_env_vars, get_duplicity_target_url
	from .status import _backup_cache_dir

	env = load_environment()
	config = get_backup_config(env)
	backup_cache_dir = _backup_cache_dir(env)
	for k, v in get_duplicity_env_vars(env).items():
		print(f"export {k}={shlex.quote(v)}")
	print("duplicity", "{command}", shlex.join(["--archive-dir", backup_cache_dir, *get_duplicity_additional_args(env), get_duplicity_target_url(config)]))
