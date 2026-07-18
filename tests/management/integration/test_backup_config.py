"""Integration tests for services/backup/config.py.

All tests use the test_db fixture which provides a STORAGE_ROOT under tmp_path.
The backup/ subdirectory is created by each test that needs it.
"""

import os

import pytest
import rtyaml
import pathlib


def _backup_root(env):
	return os.path.join(env["STORAGE_ROOT"], "backup")


def _ensure_backup_dir(env):
	os.makedirs(_backup_root(env), exist_ok=True)


# ---------------------------------------------------------------------------
# get_backup_config - defaults
# ---------------------------------------------------------------------------


def test_get_backup_config_no_custom_yaml_returns_defaults(test_db):
	_ensure_backup_dir(test_db)
	from services.backup.config import get_backup_config

	config = get_backup_config(test_db)
	assert "min_age_in_days" in config
	assert "check_after_backup" in config
	# Default target is "local" but expanded to file:// path after processing.
	assert "target" in config


def test_get_backup_config_default_min_age_is_int(test_db):
	_ensure_backup_dir(test_db)
	from services.backup.config import get_backup_config

	config = get_backup_config(test_db)
	assert isinstance(config["min_age_in_days"], int)
	assert config["min_age_in_days"] >= 1


def test_get_backup_config_default_check_after_backup_is_bool(test_db):
	_ensure_backup_dir(test_db)
	from services.backup.config import get_backup_config

	config = get_backup_config(test_db)
	assert isinstance(config["check_after_backup"], bool)


def test_get_backup_config_default_target_local_expanded(test_db):
	_ensure_backup_dir(test_db)
	from services.backup.config import get_backup_config

	config = get_backup_config(test_db)
	# "local" should be expanded to a file:// URL.
	assert config["target"].startswith("file://")


# ---------------------------------------------------------------------------
# get_backup_config - custom YAML
# ---------------------------------------------------------------------------


def _write_custom_yaml(env, data):
	_ensure_backup_dir(env)
	yaml_path = os.path.join(_backup_root(env), "custom.yaml")
	with open(yaml_path, "w", encoding="utf-8") as f:
		rtyaml.dump(data, f)


def test_get_backup_config_reads_custom_yaml(test_db):
	_write_custom_yaml(test_db, {"min_age_in_days": 7, "target": "s3://mybucket", "check_after_backup": False})
	from services.backup.config import get_backup_config

	config = get_backup_config(test_db)
	assert config["min_age_in_days"] == 7
	assert config["check_after_backup"] is False


def test_get_backup_config_min_age_coerced_from_string(test_db):
	# YAML might deliver this as a string if hand-edited.
	_write_custom_yaml(test_db, {"min_age_in_days": "5"})
	from services.backup.config import get_backup_config

	config = get_backup_config(test_db)
	assert config["min_age_in_days"] == 5
	assert isinstance(config["min_age_in_days"], int)


def test_get_backup_config_check_after_backup_coerced_to_bool(test_db):
	_write_custom_yaml(test_db, {"check_after_backup": 1})
	from services.backup.config import get_backup_config

	config = get_backup_config(test_db)
	assert isinstance(config["check_after_backup"], bool)


# ---------------------------------------------------------------------------
# get_backup_config - for_ui strips credentials
# ---------------------------------------------------------------------------


def test_get_backup_config_for_ui_strips_credential_fields(test_db):
	_write_custom_yaml(
		test_db,
		{
			"target": "s3://bucket",
			"target_user": "myuser",
			"target_pass": "mysecret",
		},
	)
	from services.backup.config import get_backup_config

	config = get_backup_config(test_db, for_ui=True)
	assert "target_user" not in config
	assert "target_pass" not in config


def test_get_backup_config_not_for_ui_includes_credentials(test_db):
	_write_custom_yaml(
		test_db,
		{
			"target": "s3://bucket",
			"target_user": "myuser",
			"target_pass": "mysecret",
		},
	)
	from services.backup.config import get_backup_config

	config = get_backup_config(test_db, for_ui=False)
	assert "target_user" in config
	assert "target_pass" in config


# ---------------------------------------------------------------------------
# write_backup_config
# ---------------------------------------------------------------------------


def test_write_backup_config_creates_file(test_db):
	_ensure_backup_dir(test_db)
	from services.backup.config import write_backup_config

	write_backup_config(test_db, {"target": "local", "min_age_in_days": 3})
	yaml_path = os.path.join(_backup_root(test_db), "custom.yaml")
	assert os.path.exists(yaml_path)


def test_write_backup_config_file_has_0600_permissions(test_db):
	_ensure_backup_dir(test_db)
	from services.backup.config import write_backup_config

	write_backup_config(test_db, {"target": "local", "min_age_in_days": 3})
	yaml_path = os.path.join(_backup_root(test_db), "custom.yaml")
	perms = os.stat(yaml_path).st_mode & 0o777
	assert perms == 0o600, f"Expected 0600, got {oct(perms)}"


def test_write_backup_config_produces_valid_yaml(test_db):
	_ensure_backup_dir(test_db)
	from services.backup.config import write_backup_config

	cfg = {"target": "s3://testbucket", "min_age_in_days": 14, "check_after_backup": True}
	write_backup_config(test_db, cfg)
	yaml_path = os.path.join(_backup_root(test_db), "custom.yaml")
	with open(yaml_path, encoding="utf-8") as f:
		parsed = rtyaml.load(f)
	assert parsed["min_age_in_days"] == 14
	assert parsed["target"] == "s3://testbucket"


# ---------------------------------------------------------------------------
# get_passphrase
# ---------------------------------------------------------------------------


def _write_passphrase(env, content):
	_ensure_backup_dir(env)
	path = os.path.join(_backup_root(env), "secret_key.txt")
	pathlib.Path(path).write_text(content + "\n", encoding="utf-8")
	return path


def test_get_passphrase_returns_first_line(test_db):
	passphrase = "A" * 43
	_write_passphrase(test_db, passphrase)
	from services.backup.config import get_passphrase

	result = get_passphrase(test_db)
	assert result == passphrase


def test_get_passphrase_short_content_raises(test_db):
	_write_passphrase(test_db, "short")
	from services.backup.config import get_passphrase

	with pytest.raises(Exception, match="too short"):
		get_passphrase(test_db)


def test_get_passphrase_missing_file_raises(test_db):
	_ensure_backup_dir(test_db)
	# Ensure the file does not exist.
	path = os.path.join(_backup_root(test_db), "secret_key.txt")
	if os.path.exists(path):
		os.unlink(path)
	from services.backup.config import get_passphrase

	with pytest.raises((FileNotFoundError, OSError)):
		get_passphrase(test_db)


# ---------------------------------------------------------------------------
# backup_set_custom
# ---------------------------------------------------------------------------


def test_backup_set_custom_returns_ok_for_local_target(test_db):
	_ensure_backup_dir(test_db)
	from services.backup.config import backup_set_custom

	result = backup_set_custom(test_db, "local", "", "", 3)
	assert result == "OK"


def test_backup_set_custom_writes_config(test_db):
	_ensure_backup_dir(test_db)
	from services.backup.config import backup_set_custom, get_backup_config

	backup_set_custom(test_db, "local", "", "", 7)
	config = get_backup_config(test_db, for_save=True)
	assert config["min_age_in_days"] == 7


def test_backup_set_custom_invalid_min_age_returns_error(test_db):
	_ensure_backup_dir(test_db)
	from services.backup.config import backup_set_custom

	result = backup_set_custom(test_db, "local", "", "", "notanumber")
	assert result != "OK"
	assert "integer" in result.lower()


def test_backup_set_custom_min_age_coerced_to_int(test_db):
	_ensure_backup_dir(test_db)
	from services.backup.config import backup_set_custom, get_backup_config

	backup_set_custom(test_db, "local", "", "", "5")
	config = get_backup_config(test_db, for_save=True)
	assert config["min_age_in_days"] == 5


def test_backup_set_custom_min_age_floor_is_one(test_db):
	_ensure_backup_dir(test_db)
	from services.backup.config import backup_set_custom, get_backup_config

	backup_set_custom(test_db, "local", "", "", 0)
	config = get_backup_config(test_db, for_save=True)
	assert config["min_age_in_days"] >= 1


def test_backup_set_custom_check_after_backup_stored(test_db):
	_ensure_backup_dir(test_db)
	from services.backup.config import backup_set_custom, get_backup_config

	backup_set_custom(test_db, "local", "", "", 3, check_after_backup=False)
	config = get_backup_config(test_db, for_save=True)
	assert config["check_after_backup"] is False


def test_backup_set_custom_skips_connectivity_probe_for_local(test_db):
	# local and off targets must never call list_target_files (no network needed).
	_ensure_backup_dir(test_db)
	from unittest.mock import patch
	from services.backup.config import backup_set_custom

	with patch("services.backup.status.list_target_files") as mock_probe:
		backup_set_custom(test_db, "local", "", "", 3)
	mock_probe.assert_not_called()


def test_backup_set_custom_skips_connectivity_probe_for_restic(test_db):
	_ensure_backup_dir(test_db)
	from unittest.mock import patch
	from services.backup.config import backup_set_custom

	env = {**test_db, "BACKUP_TOOL": "restic"}
	with patch("services.backup.status.list_target_files") as mock_probe:
		backup_set_custom(env, "s3://mybucket", "key", "secret", 3)
	mock_probe.assert_not_called()


def test_backup_set_custom_connectivity_error_returns_message(test_db):
	_ensure_backup_dir(test_db)
	from unittest.mock import patch
	from services.backup.config import backup_set_custom

	with patch("services.backup.status.list_target_files", side_effect=ValueError("cannot reach target")):
		result = backup_set_custom(test_db, "s3://mybucket", "key", "secret", 3)
	assert result != "OK"
	assert "cannot reach target" in result


# ---------------------------------------------------------------------------
# get_target_type
# ---------------------------------------------------------------------------


def test_get_target_type_s3(test_db):
	from services.backup.config import get_target_type

	assert get_target_type({"target": "s3://mybucket"}) == "s3"


def test_get_target_type_local(test_db):
	from services.backup.config import get_target_type

	assert get_target_type({"target": "local"}) == "local"


def test_get_target_type_rsync(test_db):
	from services.backup.config import get_target_type

	assert get_target_type({"target": "rsync://user@host/path"}) == "rsync"


def test_get_target_type_file(test_db):
	from services.backup.config import get_target_type

	assert get_target_type({"target": "file:///some/path"}) == "file"
