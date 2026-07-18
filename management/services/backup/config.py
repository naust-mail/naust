import os

import rtyaml


def get_backup_config(env, for_save=False, for_ui=False):
	backup_root = os.path.join(env["STORAGE_ROOT"], 'backup')

	# Defaults.
	config = {
		"min_age_in_days": 3,
		"target": "local",
		"check_after_backup": True,
	}

	# Merge in anything written to custom.yaml.
	try:
		with open(os.path.join(backup_root, 'custom.yaml'), encoding="utf-8") as f:
			custom_config = rtyaml.load(f)
		if not isinstance(custom_config, dict):
			raise ValueError("custom.yaml did not parse as a mapping")
		config.update(custom_config)
	except FileNotFoundError:
		pass  # first run - no custom config yet
	except Exception as e:
		import sys

		print(f"WARNING: backup config could not be read ({e}), using defaults", file=sys.stderr)

	# When updating config.yaml, don't do any further processing on what we find.
	if for_save:
		return config

	# Coerce typed fields so callers always get the right types regardless of
	# whether the value came from the API (already validated) or hand-edited YAML.
	try:
		config["min_age_in_days"] = max(1, int(config["min_age_in_days"]))
	except (TypeError, ValueError):
		config["min_age_in_days"] = 3
	config["check_after_backup"] = bool(config.get("check_after_backup", True))

	# When passing this back to the admin to show the current settings, do not include
	# authentication details. The user will have to re-enter it.
	if for_ui:
		for field in ("target_user", "target_pass"):
			config.pop(field, None)

	# helper fields for the admin
	config["file_target_directory"] = os.path.join(backup_root, 'encrypted')
	config["enc_pw_file"] = os.path.join(backup_root, 'secret_key.txt')
	if config["target"] == "local":
		# Expand to the full URL.
		config["target"] = "file://" + config["file_target_directory"]
	ssh_pub_key = os.path.join('/root', '.ssh', 'id_rsa_naust.pub')
	if os.path.exists(ssh_pub_key):
		with open(ssh_pub_key, encoding="utf-8") as f:
			config["ssh_pub_key"] = f.read()

	return config


def write_backup_config(env, newconfig):
	import tempfile

	backup_root = os.path.join(env["STORAGE_ROOT"], 'backup')
	target = os.path.join(backup_root, 'custom.yaml')
	# Atomic write: truncate only happens on os.replace, so a crash mid-write
	# leaves the previous config intact. 0o600 because the file holds credentials.
	fd, tmp = tempfile.mkstemp(dir=backup_root, suffix=".tmp")
	try:
		with os.fdopen(fd, "w", encoding="utf-8") as f:
			f.write(rtyaml.dump(newconfig))
		os.chmod(tmp, 0o600)
		os.replace(tmp, target)
	except Exception:
		try:
			os.unlink(tmp)
		except OSError:
			pass
		raise


def backup_set_custom(env, target, target_user, target_pass, min_age, check_after_backup=True):
	from .status import list_target_files

	config = get_backup_config(env, for_save=True)

	try:
		min_age = max(1, int(min_age))
	except (TypeError, ValueError):
		return "Minimum backup age must be a positive integer."

	config["target"] = target
	config["target_user"] = target_user
	config["target_pass"] = target_pass
	config["min_age_in_days"] = min_age
	config["check_after_backup"] = bool(check_after_backup)

	# Validate connectivity. list_target_files is duplicity-only; restic validates
	# connectivity itself on first backup/init, so skip the probe for restic targets.
	try:
		if config["target"] not in {"off", "local"} and env.get("BACKUP_TOOL", "duplicity") != "restic":
			list_target_files(config)
	except ValueError as e:
		return str(e)

	write_backup_config(env, config)

	return "OK"


def get_passphrase(env):
	# Get the encryption passphrase. secret_key.txt is 2048 random
	# bits base64-encoded and with line breaks every 65 characters.
	# gpg will only take the first line of text, so sanity check that
	# that line is long enough to be a reasonable passphrase. It
	# only needs to be 43 base64-characters to match AES256's key
	# length of 32 bytes.
	#
	# This same file is also used as RESTIC_PASSWORD for the restic backend
	# (see restic_args.py) - it becomes that repository's permanent password.
	# Losing or changing this file makes a restic repository permanently
	# unreadable, exactly as it already makes duplicity's GPG-encrypted
	# backups unreadable today.
	backup_root = os.path.join(env["STORAGE_ROOT"], 'backup')
	if not os.path.exists(os.path.join(backup_root, 'secret_key.txt')):
		raise FileNotFoundError("secret_key.txt is missing. This file is required to read your backups. Please restore it from a backup if you have lost it.")
	with open(os.path.join(backup_root, 'secret_key.txt'), encoding="utf-8") as f:
		passphrase = f.readline().strip()
	if len(passphrase) < 43:
		raise Exception("secret_key.txt's first line is too short!")

	return passphrase


def get_target_type(config):
	return config["target"].split(":")[0]
