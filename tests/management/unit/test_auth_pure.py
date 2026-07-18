import base64

from auth.auth import parse_http_authorization_basic as _parse_basic


class TestParseHttpAuthorizationBasic:
	def _encode(self, username, password):
		raw = f"{username}:{password}".encode('ascii')
		return "Basic " + base64.b64encode(raw).decode('ascii')

	def test_valid_credentials_decoded(self):
		header = self._encode("user", "pass")
		u, p = _parse_basic(header)
		assert u == "user"
		assert p == "pass"

	def test_password_with_colon_preserved(self):
		header = self._encode("user", "p:a:s:s")
		u, p = _parse_basic(header)
		assert u == "user"
		assert p == "p:a:s:s"

	def test_bearer_scheme_returns_none(self):
		header = "Bearer sometoken"
		u, p = _parse_basic(header)
		assert u is None
		assert p is None

	def test_no_space_returns_none(self):
		u, p = _parse_basic("invalidheader")
		assert u is None
		assert p is None

	def test_empty_header_returns_none(self):
		u, p = _parse_basic("")
		assert u is None
		assert p is None

	def test_no_colon_in_decoded_returns_none(self):
		# Encode a string with no colon so credentials.split(':') yields nothing useful
		raw = base64.b64encode(b"nocolon").decode('ascii')
		header = f"Basic {raw}"
		u, p = _parse_basic(header)
		assert u is None
		assert p is None


# ---------------------------------------------------------------------------
# _get_dummy_hash
# ---------------------------------------------------------------------------


class TestGetDummyHash:
	def test_returns_blf_crypt_prefixed_string(self):
		# Import lazily to avoid AuthService.__init__ triggering key file read
		from auth.auth import _get_dummy_hash

		h = _get_dummy_hash()
		assert isinstance(h, str)
		assert h.startswith("{BLF-CRYPT}")

	def test_subsequent_calls_return_same_value(self):
		from auth.auth import _get_dummy_hash

		h1 = _get_dummy_hash()
		h2 = _get_dummy_hash()
		assert h1 == h2

	def test_hash_is_long_enough_to_be_bcrypt(self):
		from auth.auth import _get_dummy_hash

		h = _get_dummy_hash()
		# Strip the {BLF-CRYPT} prefix; the bcrypt hash body should be 60 chars
		body = h[len("{BLF-CRYPT}") :]
		assert len(body) >= 60
