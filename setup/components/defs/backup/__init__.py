"""
Shared helpers for backup component defs (restic, duplicity).
"""

import os
import subprocess

from ... import artifacts


def backup_key_task(storage_root: str) -> dict:
	"""Return a doit task dict that generates the backup encryption key."""
	return {
		"name": "backup-key",
		# targets= only skips the normal case; --force (doit
		# --always-execute) bypasses it. The action's own existence
		# check is the never-rotate guarantee.
		"targets": [os.path.join(storage_root, "backup", "secret_key.txt")],
		"actions": [(_backup_key, [storage_root])],
	}


def _backup_key(storage_root: str) -> None:
	"""Generate a random backup encryption key.

	This key doubles as RESTIC_PASSWORD for restic repositories. Losing or
	replacing this file makes all existing backups permanently unreadable.
	Written with umask 077 so only root can read it.
	"""
	backup_dir = os.path.join(storage_root, "backup")
	key_path = os.path.join(backup_dir, "secret_key.txt")
	os.makedirs(backup_dir, exist_ok=True)
	if os.path.exists(key_path):
		print(f"Backup key already exists at {key_path} - skipping generation.")
		return

	old_umask = os.umask(0o077)
	try:
		result = subprocess.run(
			["openssl", "rand", "-base64", "2048"],
			check=True,
			capture_output=True,
		)
		artifacts.write_file(key_path, result.stdout.decode())
	finally:
		os.umask(old_umask)
	os.chmod(key_path, 0o600)


def ssh_key_task(storage_root: str) -> dict:
	"""Return a doit task dict that provisions the rsync/sftp backup ssh key."""
	return {
		"name": "ssh-key",
		# targets= only skips the normal case; --force (doit
		# --always-execute) bypasses it. The action's own existence
		# check is the never-rotate guarantee.
		"targets": [os.path.join(storage_root, "backup", "ssh", "id_rsa")],
		"actions": [(_ssh_key, [storage_root])],
	}


def _ssh_key(storage_root: str) -> None:
	"""Generate the ssh identity for rsync/sftp backup targets.

	Lives under STORAGE_ROOT so the backup engine can use it without
	root and so it travels with the box's data. The filename is id_rsa
	but the key type is ed25519 - the name is just the path the engine
	expects. Created once, never rotated.
	"""
	ssh_dir = os.path.join(storage_root, "backup", "ssh")
	key = os.path.join(ssh_dir, "id_rsa")
	if os.path.exists(key):
		return
	os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
	print("Generating the backup SSH key...", flush=True)
	subprocess.run(
		["ssh-keygen", "-t", "ed25519", "-f", key, "-N", "", "-q"],
		check=True,
	)
	os.chmod(key, 0o600)
	if os.path.exists(key + ".pub"):
		os.chmod(key + ".pub", 0o644)
