import datetime
import operator
import re

import dateutil.parser
import dateutil.relativedelta
import dateutil.tz

from core.utils import shell


def reldate(date, ref, clip):
	if ref < date:
		return clip
	rd = dateutil.relativedelta.relativedelta(ref, date)
	if rd.years > 1:
		return "%d years, %d months" % (rd.years, rd.months)
	if rd.years == 1:
		return "%d year, %d months" % (rd.years, rd.months)
	if rd.months > 1:
		return "%d months, %d days" % (rd.months, rd.days)
	if rd.months == 1:
		return "%d month, %d days" % (rd.months, rd.days)
	if rd.days >= 7:
		return "%d days" % rd.days
	if rd.days > 1:
		return "%d days, %d hours" % (rd.days, rd.hours)
	if rd.days == 1:
		return "%d day, %d hours" % (rd.days, rd.hours)
	return "%d hours, %d minutes" % (rd.hours, rd.minutes)


def backup_status(env):
	"""Dispatches to the active backend's status builder. This is the only
	function outside this module that callers should use - never branch on
	BACKUP_TOOL outside of this dispatcher."""
	from .config import get_backup_config

	config = get_backup_config(env)
	if config["target"] == "off":
		return {}

	if env.get("BACKUP_TOOL", "duplicity") == "restic":
		return _restic_backup_status(env, config)
	return _duplicity_backup_status(env, config)


def _ensure_local_backup_dirs(env, config):
	"""Create backup cache and local target directories if they don't exist yet.
	Duplicity and the file-listing code both require these to exist before first use."""
	import os
	import urllib.parse

	os.makedirs(_backup_cache_dir(env), exist_ok=True)
	target = urllib.parse.urlparse(config["target"])
	if target.scheme == "file":
		os.makedirs(target.path, exist_ok=True)


def _duplicity_backup_status(env, config):
	from .duplicity_args import DUPLICITY, get_duplicity_additional_args, get_duplicity_env_vars, get_duplicity_target_url

	_ensure_local_backup_dirs(env, config)

	# Query duplicity to get a list of all full and incremental
	# backups available.

	backups = {}
	now = datetime.datetime.now(dateutil.tz.tzlocal())
	backup_cache_dir = _backup_cache_dir(env)

	# Get duplicity collection status and parse for a list of backups.
	def parse_line(line):
		keys = line.strip().split()
		date = dateutil.parser.parse(keys[1]).astimezone(dateutil.tz.tzlocal())
		return {
			"date": keys[1],
			"date_str": date.strftime("%Y-%m-%d %X") + " " + now.tzname(),
			"date_delta": reldate(date, now, "the future?"),
			"full": keys[0] == "full",
			"size": 0,  # collection-status doesn't give us the size
			"volumes": int(keys[2]),  # number of archive volumes for this backup (not really helpful)
		}

	code, collection_status = shell('check_output', [DUPLICITY, "collection-status", "--archive-dir", backup_cache_dir, "--gpg-options", "'--cipher-algo=AES256'", "--log-fd", "1", *get_duplicity_additional_args(env), get_duplicity_target_url(config)], get_duplicity_env_vars(env), trap=True)
	if code != 0:
		if code == 127:
			raise Exception("duplicity is not installed - check that BACKUP_TOOL=duplicity is set and the image was built with duplicity support")
		raise Exception("Something is wrong with the backup: " + collection_status)
	for line in collection_status.split('\n'):
		if line.startswith((" full", " inc")):
			backup = parse_line(line)
			backups[backup["date"]] = backup

	# Look at the target directly to get the sizes of each of the backups. There is more than one file per backup.
	# Starting with duplicity in Ubuntu 18.04, "signatures" files have dates in their
	# filenames that are a few seconds off the backup date and so don't line up
	# with the list of backups we have. Track unmatched files so we know how much other
	# space is used for those.
	unmatched_file_size = 0
	for fn, size in list_target_files(config):
		m = re.match(r"duplicity-(full|full-signatures|(inc|new-signatures)\.(?P<incbase>\d+T\d+Z)\.to)\.(?P<date>\d+T\d+Z)\.", fn)
		if not m:
			continue  # not a part of a current backup chain
		key = m.group("date")
		if key in backups:
			backups[key]["size"] += size
		else:
			unmatched_file_size += size

	# Ensure the rows are sorted reverse chronologically.
	# This is relied on by should_force_full() and the next step.
	backups = sorted(backups.values(), key=operator.itemgetter("date"), reverse=True)

	# Get the average size of incremental backups, the size of the
	# most recent full backup, and the date of the most recent
	# backup and the most recent full backup.
	incremental_count = 0
	incremental_size = 0
	first_date = None
	first_full_size = None
	first_full_date = None
	for bak in backups:
		if first_date is None:
			first_date = dateutil.parser.parse(bak["date"])
		if bak["full"]:
			first_full_size = bak["size"]
			first_full_date = dateutil.parser.parse(bak["date"])
			break
		incremental_count += 1
		incremental_size += bak["size"]

	# When will the most recent backup be deleted? It won't be deleted if the next
	# backup is incremental, because the increments rely on all past increments.
	# So first guess how many more incremental backups will occur until the next
	# full backup. That full backup frees up this one to be deleted. But, the backup
	# must also be at least min_age_in_days old too.
	deleted_in = None
	if incremental_count > 0 and incremental_size > 0 and first_full_size is not None:
		# How many days until the next incremental backup? First, the part of
		# the algorithm based on increment sizes:
		est_days_to_next_full = (0.5 * first_full_size - incremental_size) / (incremental_size / incremental_count)
		est_time_of_next_full = first_date + datetime.timedelta(days=est_days_to_next_full)

		# ...And then the part of the algorithm based on full backup age:
		est_time_of_next_full = min(est_time_of_next_full, first_full_date + datetime.timedelta(days=config["min_age_in_days"] * 10 + 1))

		# It still can't be deleted until it's old enough.
		est_deleted_on = max(est_time_of_next_full, first_date + datetime.timedelta(days=config["min_age_in_days"]))

		deleted_in = "approx. %d days" % round((est_deleted_on - now).total_seconds() / 60 / 60 / 24 + 0.5)

	# When will a backup be deleted? Set the deleted_in field of each backup.
	saw_full = False
	for bak in backups:
		if deleted_in:
			# The most recent increment in a chain and all of the previous backups
			# it relies on are deleted at the same time.
			bak["deleted_in"] = deleted_in
		if bak["full"]:
			# Reset when we get to a full backup. A new chain start *next*.
			saw_full = True
			deleted_in = None
		elif saw_full and not deleted_in:
			# We're now on backups prior to the most recent full backup. These are
			# free to be deleted as soon as they are min_age_in_days old.
			deleted_in = reldate(now, dateutil.parser.parse(bak["date"]) + datetime.timedelta(days=config["min_age_in_days"]), "on next daily backup")
			bak["deleted_in"] = deleted_in

	from .actions import _duplicity_check_cache_path
	import json as _json

	last_check = None
	try:
		with open(_duplicity_check_cache_path(env), encoding="utf-8") as f:
			last_check = _json.load(f)
	except (FileNotFoundError, ValueError):
		pass

	return {
		"backend": "duplicity",
		"backups": backups,
		"unmatched_file_size": unmatched_file_size,
		"last_check": last_check,
	}


def _restic_backup_status(env, config):
	import json
	from .restic_args import RESTIC, get_restic_repository, get_restic_extra_args, get_restic_env_vars

	repo = get_restic_repository(env, config)
	extra_args = get_restic_extra_args(env, config)
	restic_env = get_restic_env_vars(env, config)
	now = datetime.datetime.now(dateutil.tz.tzlocal())

	code, snapshots_json = shell(
		'check_output',
		[
			RESTIC,
			"-r",
			repo,
			"snapshots",
			"--json",
			*extra_args,
		],
		restic_env,
		trap=True,
		capture_stderr=True,
	)
	if code != 0:
		if code == 127:
			raise Exception("restic is not installed - check that BACKUP_TOOL=restic is set and the image was built with restic support")
		if code == 11:
			raise Exception("restic repository is locked by another process - run 'restic unlock' to clear it")
		if code == 12:
			raise Exception("restic repository password is wrong - secret_key.txt may have changed after the repository was initialized, making existing backups inaccessible")
		if "Is there a repository at the following location" in snapshots_json or "unable to open config file" in snapshots_json:
			return {"backend": "restic", "backups": [], "unmatched_file_size": 0}
		raise Exception("Something is wrong with the backup: " + snapshots_json)

	snapshots = json.loads(snapshots_json) if snapshots_json.strip() else []

	min_age = config.get("min_age_in_days", 3)

	# Load per-snapshot stats cache written by the backup run itself.
	# Prune entries for snapshots that no longer exist and rewrite the cache
	# so it never grows beyond the current snapshot count.
	from .actions import _restic_stats_cache_path, _restic_check_cache_path, _atomic_json_write
	import json as _json

	cache_path = _restic_stats_cache_path(env)
	try:
		with open(cache_path, encoding="utf-8") as f:
			cache = _json.load(f)
	except (FileNotFoundError, ValueError):
		cache = {}
	if "snapshots" not in cache:
		# Migrate old format where snapshot IDs were top-level keys
		cache = {"snapshots": {k: v for k, v in cache.items() if k != "last_check"}}
	live_ids = {s.get("short_id", s.get("id")) for s in snapshots}
	pruned_snapshots = {k: v for k, v in cache["snapshots"].items() if k in live_ids}
	if pruned_snapshots != cache["snapshots"]:
		try:
			cache["snapshots"] = pruned_snapshots
			_atomic_json_write(cache_path, cache)
		except Exception as e:
			import sys

			print(f"WARNING: could not prune backup stats cache: {e}", file=sys.stderr)
	stats_cache = pruned_snapshots

	# Load the integrity check result from its own file (written by _verify_restic).
	last_check = None
	try:
		with open(_restic_check_cache_path(env), encoding="utf-8") as f:
			last_check = _json.load(f)
	except (FileNotFoundError, ValueError):
		pass

	backups = []
	for snap in snapshots:
		date = dateutil.parser.parse(snap["time"]).astimezone(dateutil.tz.tzlocal())
		expires_on = date + datetime.timedelta(days=min_age)
		if expires_on <= now:
			deleted_in = "on next backup run"
		else:
			deleted_in = reldate(now, expires_on, "on next backup run")
		snap_id = snap.get("short_id", snap.get("id"))
		cached = stats_cache.get(snap_id, {})
		backups.append({
			"date": snap["time"],
			"date_str": date.strftime("%Y-%m-%d %X") + " " + now.tzname(),
			"date_delta": reldate(date, now, "the future?"),
			"full": True,
			"size": cached.get("restore_size", 0),
			"volumes": 0,
			"id": snap_id,
			"deleted_in": deleted_in,
			"data_added": cached.get("data_added", 0),
			"file_count": cached.get("file_count", 0),
		})
	backups.sort(key=operator.itemgetter("date"), reverse=True)

	# Total repository size is reported once, at the repository level, never
	# attributed to any individual snapshot.
	unmatched_file_size = 0
	code, stats_json = shell(
		'check_output',
		[
			RESTIC,
			"-r",
			repo,
			"stats",
			"--mode",
			"raw-data",
			"--json",
			*extra_args,
		],
		restic_env,
		trap=True,
	)
	if code == 0 and stats_json.strip():
		try:
			unmatched_file_size = json.loads(stats_json).get("total_size", 0)
		except (ValueError, KeyError):
			pass

	return {
		"backend": "restic",
		"backups": backups,
		"unmatched_file_size": unmatched_file_size,
		"last_check": last_check,
	}


def should_force_full(config, env):
	# Force a full backup when the total size of the increments
	# since the last full backup is greater than half the size
	# of that full backup.
	#
	# duplicity-only: restic has no full/incremental distinction, so this
	# concept simply does not apply to the restic backend.
	from datetime import date

	inc_size = 0
	# Check if day of week is a weekend day
	weekend = date.today().weekday() >= 5
	for bak in backup_status(env)["backups"]:
		if not bak["full"]:
			# Scan through the incremental backups cumulating
			# size...
			inc_size += bak["size"]
		else:
			# ...until we reach the most recent full backup.
			# Return if we should to a full backup, which is based
			# on whether it is a weekend day, the size of the
			# increments relative to the full backup, as well as
			# the age of the full backup.
			if weekend:
				if inc_size > 0.5 * bak["size"]:
					return True
				if dateutil.parser.parse(bak["date"]) + datetime.timedelta(days=config["min_age_in_days"] * 10 + 1) < datetime.datetime.now(dateutil.tz.tzlocal()):
					return True
			return False
	# If we got here there are no (full) backups, so make one.
	return True


def list_target_files(config):
	# duplicity-only: used to validate connectivity/credentials when saving a
	# target (backup_set_custom) and to compute per-file sizes for collection-status.
	import urllib.parse

	try:
		target = urllib.parse.urlparse(config["target"])
	except ValueError:
		return "invalid target"

	if target.scheme == "file":
		import os

		if not os.path.isdir(target.path):
			return []
		return [(fn, os.path.getsize(os.path.join(target.path, fn))) for fn in os.listdir(target.path)]

	if target.scheme == "rsync":
		rsync_fn_size_re = re.compile(r'.*    ([^ ]*) [^ ]* [^ ]* (.*)')
		rsync_target = '{host}:{path}'

		# Strip off any trailing port specifier because it's not valid in rsync's
		# DEST syntax.  Explicitly set the port number for the ssh transport.
		user_host, *_ = target.netloc.rsplit(':', 1)
		try:
			port = target.port
		except ValueError:
			port = 22
		if port is None:
			port = 22

		target_path = target.path
		if not target_path.endswith('/'):
			target_path += '/'
		target_path = target_path.removeprefix('/')

		rsync_command = ['rsync', '-e', f'/usr/bin/ssh -i /root/.ssh/id_rsa_naust -oStrictHostKeyChecking=no -oBatchMode=yes -p {port}', '--list-only', '-r', rsync_target.format(host=user_host, path=target_path)]

		code, listing = shell('check_output', rsync_command, trap=True, capture_stderr=True)
		if code == 0:
			ret = []
			for l in listing.split('\n'):
				match = rsync_fn_size_re.match(l)
				if match:
					ret.append((match.groups()[1], int(match.groups()[0].replace(',', ''))))
			return ret
		if 'Permission denied (publickey).' in listing:
			reason = "Invalid user or check you correctly copied the SSH key."
		elif 'No such file or directory' in listing:
			reason = f"Provided path {target_path} is invalid."
		elif 'Network is unreachable' in listing:
			reason = f"The IP address {target.hostname} is unreachable."
		elif 'Could not resolve hostname' in listing:
			reason = f"The hostname {target.hostname} cannot be resolved."
		else:
			reason = "Unknown error. Please check running 'management/services/backup --verify' from naust sources to debug the issue."
		msg = f"Connection to rsync host failed: {reason}"
		raise ValueError(msg)

	if target.scheme == "s3":
		import boto3.s3
		from botocore.exceptions import ClientError

		# separate bucket from path in target
		bucket_path = target.path.lstrip('/')
		bucket, _, path = bucket_path.partition('/')
		if path and not path.endswith('/'):
			path += '/'

		if bucket == "":
			msg = "Enter an S3 bucket name."
			raise ValueError(msg)

		# connect to the region & bucket
		try:
			if config['target_user'] == "" and config['target_pass'] == "":
				s3 = boto3.client('s3', endpoint_url=f'https://{target.hostname}')
			else:
				s3 = boto3.client('s3', endpoint_url=f'https://{target.hostname}', aws_access_key_id=config['target_user'], aws_secret_access_key=config['target_pass'])
			response = s3.list_objects_v2(Bucket=bucket, Prefix=path)
			bucket_objects = response.get('Contents', [])
			backup_list = [(key['Key'][len(path) :], key['Size']) for key in bucket_objects]
		except ClientError as e:
			raise ValueError(e)
		return backup_list
	if target.scheme == 'b2':
		from b2sdk.v1 import InMemoryAccountInfo, B2Api
		from b2sdk.v1.exception import NonExistentBucket

		info = InMemoryAccountInfo()
		b2_api = B2Api(info)

		# Extract information from target
		b2_application_keyid = target.netloc[: target.netloc.index(':')]
		b2_application_key = urllib.parse.unquote(target.netloc[target.netloc.index(':') + 1 : target.netloc.index('@')])
		b2_bucket = target.netloc[target.netloc.index('@') + 1 :]

		try:
			b2_api.authorize_account("production", b2_application_keyid, b2_application_key)
			bucket = b2_api.get_bucket_by_name(b2_bucket)
		except NonExistentBucket:
			msg = "B2 Bucket does not exist. Please double check your information!"
			raise ValueError(msg)
		return [(key.file_name, key.size) for key, _ in bucket.ls()]

	raise ValueError(config["target"])


def _backup_cache_dir(env):
	import os

	return os.path.join(env["STORAGE_ROOT"], 'backup', 'cache')
