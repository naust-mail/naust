"""
Verify that one-time generator tasks refuse to overwrite existing artifacts.

Each test pre-creates a sentinel file at the artifact path, invokes the
action function directly, then asserts the file bytes are unchanged.
"""

import os
from unittest.mock import patch, MagicMock
import pathlib

_DOVECOT_FAKE = MagicMock(stdout="2.3.21 (abc)", returncode=0)
_SENTINEL = b"SENTINEL_DO_NOT_OVERWRITE"


def _extract_action(tasks: list[dict], task_name: str):
	"""Pull the first (callable, args) pair from a named task's actions list."""
	for t in tasks:
		if t["name"] == task_name:
			entry = t["actions"][0]
			if isinstance(entry, tuple):
				fn, args = entry[0], entry[1] if len(entry) > 1 else []
			else:
				fn, args = entry, []
			return fn, args
	msg = f"Task {task_name!r} not found"
	raise KeyError(msg)


def _call_action(fn, args):
	with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout="", stderr="")):
		fn(*args)


# ── DNSSEC key generators ─────────────────────────────────────────────────────


def test_dnssec_rsasha256_is_idempotent(tmp_path):
	"""DNSSEC RSASHA256 key generator must not overwrite an existing .conf file."""
	storage_root = str(tmp_path / "storage")
	dnssec_dir = os.path.join(storage_root, "dns", "dnssec")
	os.makedirs(dnssec_dir, exist_ok=True)
	conf_file = os.path.join(dnssec_dir, "RSASHA256.conf")
	pathlib.Path(conf_file).write_bytes(_SENTINEL)

	from components.defs import dns

	env = {"STORAGE_ROOT": storage_root, "PRIVATE_IP": "", "PRIVATE_IPV6": ""}
	with patch("subprocess.run", return_value=_DOVECOT_FAKE):
		tasks = dns.make_tasks(env, "baremetal")
	fn, args = _extract_action(tasks, "dnssec-keys-rsasha256")
	_call_action(fn, args)

	assert pathlib.Path(conf_file).read_bytes() == _SENTINEL


def test_dnssec_ecdsap256sha256_is_idempotent(tmp_path):
	"""DNSSEC ECDSAP256SHA256 key generator must not overwrite an existing .conf file."""
	storage_root = str(tmp_path / "storage")
	dnssec_dir = os.path.join(storage_root, "dns", "dnssec")
	os.makedirs(dnssec_dir, exist_ok=True)
	conf_file = os.path.join(dnssec_dir, "ECDSAP256SHA256.conf")
	pathlib.Path(conf_file).write_bytes(_SENTINEL)

	from components.defs import dns

	env = {"STORAGE_ROOT": storage_root, "PRIVATE_IP": "", "PRIVATE_IPV6": ""}
	with patch("subprocess.run", return_value=_DOVECOT_FAKE):
		tasks = dns.make_tasks(env, "baremetal")
	fn, args = _extract_action(tasks, "dnssec-keys-ecdsap256sha256")
	_call_action(fn, args)

	assert pathlib.Path(conf_file).read_bytes() == _SENTINEL


# ── SSL key generator ─────────────────────────────────────────────────────────


def test_ssl_key_is_idempotent(tmp_path):
	"""SSL RSA key generator must not overwrite an existing key file."""
	storage_root = str(tmp_path / "storage")
	ssl_dir = os.path.join(storage_root, "ssl")
	os.makedirs(ssl_dir, exist_ok=True)
	key_file = os.path.join(ssl_dir, "ssl_private_key.pem")
	pathlib.Path(key_file).write_bytes(_SENTINEL)

	from components.defs import ssl

	env = {
		"STORAGE_ROOT": storage_root,
		"PRIMARY_HOSTNAME": "box.example.com",
	}
	tasks = ssl.make_tasks(env, "baremetal")
	fn, args = _extract_action(tasks, "key")
	# targets= means doit skips when file exists; the action itself must also gate.
	_call_action(fn, args)

	assert pathlib.Path(key_file).read_bytes() == _SENTINEL


# ── DKIM key generator (dkim component / spamassassin path) ──────────────────


def test_dkim_key_is_idempotent(tmp_path):
	"""DKIM key generator (opendkim path) must not overwrite an existing key file."""
	storage_root = str(tmp_path / "storage")
	dkim_dir = os.path.join(storage_root, "mail", "dkim")
	os.makedirs(dkim_dir, exist_ok=True)
	key_file = os.path.join(dkim_dir, "mail.private")
	pathlib.Path(key_file).write_bytes(_SENTINEL)

	from components.defs import dkim

	env = {"STORAGE_ROOT": storage_root, "SPAM_FILTER": "spamassassin"}
	tasks = dkim.make_tasks(env, "baremetal")
	fn, args = _extract_action(tasks, "dkim-key")
	_call_action(fn, args)

	assert pathlib.Path(key_file).read_bytes() == _SENTINEL


# ── Roundcube DES key ─────────────────────────────────────────────────────────


def test_roundcube_des_key_is_idempotent(tmp_path):
	"""Roundcube DES key generator must not overwrite an existing key file."""
	storage_root = str(tmp_path / "storage")
	rc_dir = os.path.join(storage_root, "roundcube")
	os.makedirs(rc_dir, exist_ok=True)
	des_key_file = os.path.join(rc_dir, "des_key.txt")
	pathlib.Path(des_key_file).write_bytes(_SENTINEL)

	from components.defs.webmail import roundcube

	env = {
		"STORAGE_ROOT": storage_root,
		"PRIMARY_HOSTNAME": "box.example.com",
		"WEBMAIL_CLIENT": "roundcube",
		"ENABLE_RADICALE": "false",
	}
	with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout="", stderr="")):
		tasks = roundcube.make_tasks(env, "baremetal")
	fn, args = _extract_action(tasks, "des-key")
	_call_action(fn, args)

	assert pathlib.Path(des_key_file).read_bytes() == _SENTINEL


# ── Management backup key ─────────────────────────────────────────────────────


def test_backup_key_is_idempotent(tmp_path):
	"""Backup key generator must not overwrite an existing key file."""
	storage_root = str(tmp_path / "storage")
	backup_dir = os.path.join(storage_root, "backup")
	os.makedirs(backup_dir, exist_ok=True)
	key_file = os.path.join(backup_dir, "secret_key.txt")
	pathlib.Path(key_file).write_bytes(_SENTINEL)

	from components.defs.backup import restic

	env = {"STORAGE_ROOT": storage_root}
	with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout="", stderr="")), patch("shutil.which", return_value="/usr/bin/restic"):
		tasks = restic.make_tasks(env, "baremetal")
	fn, args = _extract_action(tasks, "backup-key")
	_call_action(fn, args)

	assert pathlib.Path(key_file).read_bytes() == _SENTINEL


def test_backup_key_created_when_absent(tmp_path):
	"""Backup key generator must create the key file when it does not exist."""
	storage_root = str(tmp_path / "storage")
	backup_dir = os.path.join(storage_root, "backup")
	os.makedirs(backup_dir, exist_ok=True)
	key_file = os.path.join(backup_dir, "secret_key.txt")
	assert not os.path.exists(key_file)

	# Feed fake openssl output so the action doesn't need the real binary.
	# subprocess.run with capture_output=True returns stdout as bytes.
	fake_openssl = MagicMock(returncode=0, stdout=b"FAKEKEY==\n", stderr=b"")
	from components.defs.backup import restic

	env = {"STORAGE_ROOT": storage_root}
	with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout="", stderr="")), patch("shutil.which", return_value="/usr/bin/restic"):
		tasks = restic.make_tasks(env, "baremetal")
	fn, args = _extract_action(tasks, "backup-key")
	with patch("subprocess.run", return_value=fake_openssl):
		fn(*args)

	assert os.path.exists(key_file), "backup key file must be created when absent"
	content = pathlib.Path(key_file).read_text(encoding="utf-8")
	assert len(content) > 0, "backup key file must not be empty"


def test_backup_key_task_structure(tmp_path):
	"""backup_key_task() must return a dict with the required doit keys."""
	from components.defs.backup import backup_key_task

	storage_root = str(tmp_path / "storage")
	task = backup_key_task(storage_root)

	assert task["name"] == "backup-key"
	assert isinstance(task["targets"], list) and len(task["targets"]) == 1
	assert task["targets"][0].endswith("secret_key.txt")
	assert "actions" in task
	# Must NOT have "build": True - this task needs STORAGE_ROOT at action time.
	assert not task.get("build"), "backup-key is not build-safe; it needs STORAGE_ROOT"
