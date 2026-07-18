import json
import time
import auth.bootstrap as bootstrap_module
from auth.bootstrap import token_file_path, validate_code, consume_token
import pathlib


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _env(tmp_path):
	return {"STORAGE_ROOT": str(tmp_path)}


def _write_token(tmp_path, uuid="test-uuid-1234", code="ABCD1234", expires_delta=900):
	"""Write a token file directly for tests that bypass generate_token."""
	path = token_file_path(_env(tmp_path))
	data = {
		"uuid": uuid,
		"code": code,
		"expires": int(time.time()) + expires_delta,
	}
	with open(path, "w") as f:
		json.dump(data, f)
	return data


def _reset_module_state(uuid=None):
	bootstrap_module._current_uuid = uuid
	bootstrap_module._attempt_count = 0


# ---------------------------------------------------------------------------
# token_file_path
# ---------------------------------------------------------------------------


class TestTokenFilePath:
	def test_path_is_under_storage_root(self, tmp_path):
		env = _env(tmp_path)
		path = token_file_path(env)
		assert path.startswith(str(tmp_path))

	def test_path_ends_with_bootstrap_token(self, tmp_path):
		env = _env(tmp_path)
		path = token_file_path(env)
		assert path.endswith("bootstrap.token")


# ---------------------------------------------------------------------------
# _load_token
# ---------------------------------------------------------------------------


class TestLoadToken:
	def test_valid_json_returns_dict(self, tmp_path):
		_write_token(tmp_path)
		result = bootstrap_module._load_token(_env(tmp_path))
		assert isinstance(result, dict)
		assert "code" in result

	def test_missing_file_returns_none(self, tmp_path):
		result = bootstrap_module._load_token(_env(tmp_path))
		assert result is None

	def test_malformed_json_returns_none(self, tmp_path):
		path = token_file_path(_env(tmp_path))
		pathlib.Path(path).write_text("{this is not valid json")
		result = bootstrap_module._load_token(_env(tmp_path))
		assert result is None


# ---------------------------------------------------------------------------
# validate_code
# ---------------------------------------------------------------------------


class TestValidateCode:
	def setup_method(self):
		_reset_module_state()

	def test_correct_code_returns_true(self, tmp_path):
		_write_token(tmp_path, uuid="u1", code="ABCD1234")
		_reset_module_state("u1")
		ok, err = validate_code("ABCD1234", _env(tmp_path))
		assert ok is True
		assert err == ""

	def test_wrong_code_returns_false(self, tmp_path):
		_write_token(tmp_path, uuid="u1", code="ABCD1234")
		_reset_module_state("u1")
		ok, err = validate_code("WRONGCOD", _env(tmp_path))
		assert ok is False
		assert err.startswith("invalid:")

	def test_wrong_code_increments_remaining_count(self, tmp_path):
		_write_token(tmp_path, uuid="u1", code="ABCD1234")
		_reset_module_state("u1")
		_, err = validate_code("WRONGCOD", _env(tmp_path))
		remaining = int(err.split(":")[1])
		assert remaining == 4

	def test_five_wrong_attempts_locks(self, tmp_path):
		_write_token(tmp_path, uuid="u1", code="ABCD1234")
		_reset_module_state("u1")
		for _ in range(5):
			ok, err = validate_code("WRONGCOD", _env(tmp_path))
		assert ok is False
		# After 5 failures the token file is deleted and lockout is returned
		assert err == "locked"

	def test_no_token_file_returns_not_found(self, tmp_path):
		ok, err = validate_code("ABCD1234", _env(tmp_path))
		assert ok is False
		assert err == "not_found"

	def test_expired_token_returns_expired(self, tmp_path):
		_write_token(tmp_path, uuid="u1", code="ABCD1234", expires_delta=-1)
		_reset_module_state("u1")
		ok, err = validate_code("ABCD1234", _env(tmp_path))
		assert ok is False
		assert err == "expired"

	def test_new_uuid_resets_attempt_counter(self, tmp_path):
		# Simulate 3 failed attempts against an old token
		_reset_module_state("old-uuid")
		bootstrap_module._attempt_count = 3

		# Write a brand-new token with a different UUID
		_write_token(tmp_path, uuid="new-uuid", code="NEWCODE1")
		ok, err = validate_code("NEWCODE1", _env(tmp_path))
		assert ok is True

	def test_case_insensitive_comparison(self, tmp_path):
		_write_token(tmp_path, uuid="u1", code="ABCD1234")
		_reset_module_state("u1")
		ok, err = validate_code("abcd1234", _env(tmp_path))
		assert ok is True

	def test_strips_whitespace_before_compare(self, tmp_path):
		_write_token(tmp_path, uuid="u1", code="ABCD1234")
		_reset_module_state("u1")
		ok, err = validate_code("  ABCD1234  ", _env(tmp_path))
		assert ok is True


# ---------------------------------------------------------------------------
# consume_token
# ---------------------------------------------------------------------------


class TestConsumeToken:
	def setup_method(self):
		_reset_module_state()

	def test_deletes_token_file(self, tmp_path):
		import os

		_write_token(tmp_path)
		path = token_file_path(_env(tmp_path))
		assert os.path.exists(path)
		consume_token(_env(tmp_path))
		assert not os.path.exists(path)

	def test_no_error_when_file_missing(self, tmp_path):
		consume_token(_env(tmp_path))

	def test_resets_module_state(self, tmp_path):
		bootstrap_module._current_uuid = "some-uuid"
		bootstrap_module._attempt_count = 3
		consume_token(_env(tmp_path))
		assert bootstrap_module._current_uuid is None
		assert bootstrap_module._attempt_count == 0
