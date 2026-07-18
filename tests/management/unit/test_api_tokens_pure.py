import auth.api_tokens as api_tokens_module
from auth.api_tokens import _hash_secret, _server_key, verify_token


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _env_with_key(key="test-server-key-abc123"):
	"""Return an env dict with SECRET_KEY set, bypassing file I/O in _server_key."""
	return {"SECRET_KEY": key, "STORAGE_ROOT": "/nonexistent"}


def _reset_server_key_cache():
	api_tokens_module._server_key_cache = None


# ---------------------------------------------------------------------------
# _server_key
# ---------------------------------------------------------------------------


class TestServerKey:
	def setup_method(self):
		_reset_server_key_cache()

	def teardown_method(self):
		_reset_server_key_cache()

	def test_returns_key_from_env_secret_key(self):
		env = _env_with_key("my-pepper")
		key = _server_key(env)
		assert key == b"my-pepper"

	def test_cached_after_first_call(self):
		env = _env_with_key("my-pepper")
		k1 = _server_key(env)
		k2 = _server_key(env)
		assert k1 is k2


# ---------------------------------------------------------------------------
# _hash_secret
# ---------------------------------------------------------------------------


class TestHashSecret:
	def setup_method(self):
		_reset_server_key_cache()

	def teardown_method(self):
		_reset_server_key_cache()

	def test_deterministic_same_input(self):
		env = _env_with_key()
		h1 = _hash_secret("mysecret", env)
		h2 = _hash_secret("mysecret", env)
		assert h1 == h2

	def test_different_secrets_produce_different_hashes(self):
		env = _env_with_key()
		h1 = _hash_secret("secret-one", env)
		h2 = _hash_secret("secret-two", env)
		assert h1 != h2

	def test_hash_is_hex_string(self):
		env = _env_with_key()
		h = _hash_secret("mysecret", env)
		assert isinstance(h, str)
		int(h, 16)  # raises ValueError if not valid hex

	def test_hash_is_sha256_length(self):
		env = _env_with_key()
		h = _hash_secret("mysecret", env)
		assert len(h) == 64

	def test_different_server_keys_produce_different_hashes(self):
		_reset_server_key_cache()
		env_a = _env_with_key("key-a")
		h_a = _hash_secret("mysecret", env_a)

		_reset_server_key_cache()
		env_b = _env_with_key("key-b")
		h_b = _hash_secret("mysecret", env_b)

		assert h_a != h_b


# ---------------------------------------------------------------------------
# verify_token - prefix and format checks (no DB)
# ---------------------------------------------------------------------------


class TestVerifyTokenPrefixValidation:
	def setup_method(self):
		_reset_server_key_cache()

	def teardown_method(self):
		_reset_server_key_cache()

	def test_missing_naust_prefix_returns_none(self):
		from unittest.mock import patch

		env = _env_with_key()
		# Patch open_database so the function never reaches DB code
		with patch('auth.api_tokens.open_database') as mock_db:
			result = verify_token("nosecretprefix", env)
		assert result is None
		mock_db.assert_not_called()

	def test_only_prefix_no_secret_returns_none(self):
		from unittest.mock import patch

		env = _env_with_key()
		with patch('auth.api_tokens.open_database') as mock_db:
			result = verify_token("naust_", env)
		assert result is None
		mock_db.assert_not_called()

	def test_empty_string_returns_none(self):
		from unittest.mock import patch

		env = _env_with_key()
		with patch('auth.api_tokens.open_database') as mock_db:
			result = verify_token("", env)
		assert result is None
		mock_db.assert_not_called()
