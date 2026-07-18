import datetime
import json
import os
import threading

from flask import Blueprint, request

from core import utils
from core.app_context import env
from core.auth_decorators import require_admin, read_scope
from core.web_helpers import json_response, sanitize_error_message

bp = Blueprint("system", __name__, url_prefix="/system")
bp.before_request(require_admin)

# ---------------------------------------------------------------------------
# System status check infrastructure
# ---------------------------------------------------------------------------

# Shared on-disk cache path - same file the nightly cron writes, so GET /system/status
# is instant on first visit after the cron has run.
_STATUS_CACHE_FILE = "/var/cache/naust/status_checks.json"


def _load_cache_from_disk():
	"""Read the on-disk cache (serialized CheckResults, legacy-rendered).
	Returns (items, checked_at_iso) or (None, None) if unavailable."""
	if not os.path.exists(_STATUS_CACHE_FILE):
		return None, None
	try:
		mtime = os.path.getmtime(_STATUS_CACHE_FILE)
		with open(_STATUS_CACHE_FILE, encoding="utf-8") as f:
			items = json.load(f)
		if not isinstance(items, list):
			return None, None
		checked_at = datetime.datetime.fromtimestamp(mtime).astimezone().isoformat()
		return items, checked_at
	except Exception:
		return None, None


def _write_cache_to_disk(items: list) -> None:
	try:
		os.makedirs(os.path.dirname(_STATUS_CACHE_FILE), exist_ok=True)
		with open(_STATUS_CACHE_FILE, "w", encoding="utf-8") as f:
			json.dump(items, f)
	except Exception:
		pass


# In-memory job state shared across all requests.
_status_job: dict = {
	"running": False,
	"lock": threading.Lock(),
	"items": None,  # list[StatusCheckItem] | None
	"checked_at": None,  # ISO 8601 string | None
	"source": None,  # 'cron' | 'manual' | None
}


def _ensure_disk_cache_loaded() -> None:
	"""Lazy-load the nightly cron's cache on first access so GET is instant."""
	if _status_job["items"] is not None:
		return
	items, checked_at = _load_cache_from_disk()
	if items is not None:
		_status_job["items"] = items
		_status_job["checked_at"] = checked_at
		_status_job["source"] = "cron"


def _run_status_check_thread() -> None:
	"""Background thread body. Runs checks, updates state, releases lock.

	on_progress fires after each individual check finishes, not just at the
	end - the dashboard already polls every 8s while a run is in progress
	(see system_status_get below), so this means a long check no longer looks
	frozen: whatever has completed so far is what the next poll sees."""
	from services.status_checks import run_checks
	from services.status_checks.legacy_render import to_legacy_items

	try:
		partial_results = {}

		def on_progress(key, result):
			partial_results[key] = result
			_status_job["items"] = to_legacy_items(partial_results)

		results = run_checks(env, on_progress=on_progress)
		items = to_legacy_items(results)

		# Persist to the shared disk cache (same format as the nightly cron).
		_write_cache_to_disk(items)

		_status_job["items"] = items
		_status_job["checked_at"] = datetime.datetime.now().astimezone().isoformat()
		_status_job["source"] = "manual"
	except Exception:
		pass
	finally:
		_status_job["running"] = False
		_status_job["lock"].release()


@bp.route('/version', methods=["GET"])
@read_scope
def system_version():
	from services.status_checks import what_version_is_this

	try:
		return what_version_is_this(env)
	except Exception as e:
		return (sanitize_error_message(str(e)), 500)


@bp.route('/latest-upstream-version', methods=["POST"])
def system_latest_upstream_version():
	from services.status_checks import get_latest_naust_version

	try:
		return get_latest_naust_version()
	except Exception as e:
		return (sanitize_error_message(str(e)), 500)


@bp.route('/status', methods=["GET"])
@read_scope
def system_status_get():
	_ensure_disk_cache_loaded()
	return json_response({
		"status": "running" if _status_job["running"] else ("done" if _status_job["items"] is not None else "idle"),
		"items": _status_job["items"],
		"checked_at": _status_job["checked_at"],
		"source": _status_job["source"],
	})


@bp.route('/status', methods=["POST"])
def system_status_post():
	_ensure_disk_cache_loaded()
	acquired = _status_job["lock"].acquire(blocking=False)
	if not acquired:
		# A check is already running - return current state without starting another.
		return json_response({
			"status": "running",
			"items": _status_job["items"],
			"checked_at": _status_job["checked_at"],
			"source": _status_job["source"],
		}), 202
	# Lock acquired - mark as running and kick off the background thread.
	_status_job["running"] = True
	t = threading.Thread(target=_run_status_check_thread, daemon=True)
	try:
		t.start()
	except Exception:
		_status_job["running"] = False
		_status_job["lock"].release()
		raise
	return json_response({
		"status": "running",
		"items": _status_job["items"],
		"checked_at": _status_job["checked_at"],
		"source": _status_job["source"],
	}), 202


@bp.route('/updates')
@read_scope
def show_updates():
	from services.status_checks import list_apt_updates

	return "".join("{} ({})\n".format(p["package"], p["version"]) for p in list_apt_updates())


@bp.route('/update-packages', methods=["POST"])
def do_updates():
	import shutil

	if not shutil.which("apt-get"):
		return ("Package management is not available in this environment.", 501)
	from services.control_plane import apt_update, apt_upgrade

	apt_update()
	return apt_upgrade()


@bp.route('/reboot', methods=["GET"])
@read_scope
def needs_reboot():
	from services.status_checks import is_reboot_needed_due_to_package_installation

	if is_reboot_needed_due_to_package_installation():
		return json_response(True)
	return json_response(False)


@bp.route('/reboot', methods=["POST"])
def do_reboot():
	import shutil

	if not shutil.which("shutdown"):
		return ("Reboot is not available in this environment.", 501)
	# To keep the attack surface low, we don't allow a remote reboot if one isn't necessary.
	from services.status_checks import is_reboot_needed_due_to_package_installation

	if is_reboot_needed_due_to_package_installation():
		from services.control_plane import host_reboot

		return host_reboot()
	return "No reboot is required, so it is not allowed."


@bp.route('/backup/status')
@read_scope
def backup_status():
	from services.backup import backup_status as get_backup_status

	try:
		return json_response(get_backup_status(env))
	except Exception as e:
		return json_response({"error": sanitize_error_message(str(e))})


@bp.route('/backup/config', methods=["GET"])
@read_scope
def backup_get_custom():
	from services.backup import get_backup_config

	return json_response(get_backup_config(env, for_ui=True))


@bp.route('/backup/config', methods=["POST"])
def backup_set_custom():
	from services.backup import backup_set_custom

	_cab_raw = request.form.get('check_after_backup')
	check_after_backup = _cab_raw.lower() in ('true', '1', 'on', 'yes') if _cab_raw is not None else True
	return json_response(
		backup_set_custom(
			env,
			request.form.get('target', ''),
			request.form.get('target_user', ''),
			request.form.get('target_pass', ''),
			request.form.get('min_age', ''),
			check_after_backup,
		)
	)


@bp.route('/privacy', methods=["GET"])
@read_scope
def privacy_status_get():
	config = utils.load_settings(env)
	return json_response(config.get("privacy", True))


@bp.route('/privacy', methods=["POST"])
def privacy_status_set():
	config = utils.load_settings(env)
	config["privacy"] = request.form.get('value') == "private"
	utils.write_settings(config, env)
	return "OK"
