# restic lives at /usr/bin/restic (apt) or /usr/local/bin/restic (pinned
# static binary fallback). shell() restricts PATH to /sbin:/bin:/usr/sbin:/usr/bin,
# so /usr/local/bin is not searched.
# Resolve the absolute path at import time so the subprocess call always works.

import os
import shutil

RESTIC = shutil.which("restic") or "/usr/local/bin/restic"


def get_restic_repository_dir(env):
	# Local restic repo and its metadata cache live in their own subdirectories,
	# distinct from duplicity's backup/encrypted + backup/cache - the two
	# backends' on-disk formats are incompatible and must never collide.
	return os.path.join(env["STORAGE_ROOT"], 'backup', 'restic-repo')


def get_restic_cache_dir(env):
	return os.path.join(env["STORAGE_ROOT"], 'backup', 'restic-cache')


def _restic_target_type(config):
	# get_backup_config() always expands the "local" sentinel into a full
	# file:// URL before any caller sees it (duplicity needs that form), so
	# the raw string "local" can never actually appear here - it shows up as
	# scheme "file" instead. Treat "file" the same as the "local"/"off"
	# sentinels so this dispatch doesn't fall through to "unsupported" for
	# the single most common case: a fresh box's default target.
	from .config import get_target_type

	target_type = get_target_type(config) if config["target"] not in {"off", "local"} else "local"
	if target_type == "file":
		target_type = "local"
	return target_type


def get_restic_repository(env, config):
	target_type = _restic_target_type(config)

	if target_type == "local":
		return get_restic_repository_dir(env)

	if target_type == "rsync":
		# Stored as rsync://user@host[:port]/path - restic's sftp backend uses
		# a different scheme (sftp:user@host:/path), built from the same parts.
		from urllib.parse import urlsplit

		target = urlsplit(config["target"])
		path = target.path.lstrip('/')
		return f"sftp:{target.username}@{target.hostname}:/{path}"

	if target_type == "s3":
		# Stored as s3://[region@]host/bucket/path - restic accepts the bucket
		# (and an optional path prefix within it) appended directly to the
		# endpoint URL, so no bucket/path split is needed here unlike duplicity.
		from urllib.parse import urlsplit

		target = urlsplit(config["target"])
		path = target.path.lstrip('/')
		return f"s3:https://{target.hostname}/{path}"

	if target_type == "b2":
		# Stored as b2://keyid:key@bucket (same format list_target_files already parses).
		from urllib.parse import urlsplit

		target = urlsplit(config["target"])
		bucket = target.netloc[target.netloc.index('@') + 1 :]
		return f"b2:{bucket}:"

	msg = f"Unsupported backup target for restic: {config['target']}"
	raise ValueError(msg)


def get_restic_extra_args(env, config):
	args = ["--cache-dir", get_restic_cache_dir(env)]

	target_type = _restic_target_type(config)
	if target_type == "rsync":
		from urllib.parse import urlsplit

		target = urlsplit(config["target"])
		try:
			port = target.port
		except ValueError:
			port = 22
		if port is None:
			port = 22
		args += ["-o", f"sftp.command=ssh -i /root/.ssh/id_rsa_naust -p {port} -oStrictHostKeyChecking=no -oBatchMode=yes {target.username}@{target.hostname} -s sftp"]

	return args


def get_restic_env_vars(env, config):
	from .config import get_passphrase

	restic_env = {"RESTIC_PASSWORD": get_passphrase(env)}

	target_type = _restic_target_type(config)

	if target_type == "s3":
		restic_env["AWS_ACCESS_KEY_ID"] = config["target_user"]
		restic_env["AWS_SECRET_ACCESS_KEY"] = config["target_pass"]
		from urllib.parse import urlsplit

		target = urlsplit(config["target"])
		if target.username:  # region name is stuffed here, same convention as duplicity_args.py
			restic_env["AWS_DEFAULT_REGION"] = target.username

	if target_type == "b2":
		from urllib.parse import urlsplit
		import urllib.parse

		target = urlsplit(config["target"])
		b2_application_keyid = target.netloc[: target.netloc.index(':')]
		b2_application_key = urllib.parse.unquote(target.netloc[target.netloc.index(':') + 1 : target.netloc.index('@')])
		restic_env["B2_ACCOUNT_ID"] = b2_application_keyid
		restic_env["B2_ACCOUNT_KEY"] = b2_application_key

	return restic_env
