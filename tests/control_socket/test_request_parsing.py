"""Tests for the request parsing logic from control-socket-server.py.

The server does:
    data = conn.recv(256).decode().strip().split("\\n")
    if len(data) < 2 or not data[0] or not data[1]:
        conn.sendall(b"ERROR: malformed request\\n")

We replicate that logic in parse_request() and test it in isolation.
"""


def parse_request(raw_bytes: bytes) -> tuple[str | None, str | None, str | None]:
	"""Replicate the server's parsing logic for testing.

	Returns (service, action, error). error is None on success.
	"""
	try:
		data = raw_bytes.decode().strip().split("\n")
	except UnicodeDecodeError:
		return None, None, "decode_error"
	if len(data) < 2 or not data[0] or not data[1]:
		return None, None, "invalid_format"
	service = data[0].strip()
	action = data[1].strip()
	return service, action, None


class TestValidRequests:
	def test_basic_request(self):
		service, action, err = parse_request(b"service\naction\n")
		assert err is None
		assert service == "service"
		assert action == "action"

	def test_extra_lines_ignored(self):
		service, action, err = parse_request(b"service\naction\nextra\n")
		assert err is None
		assert service == "service"
		assert action == "action"

	def test_no_trailing_newline(self):
		service, action, err = parse_request(b"service\naction")
		assert err is None
		assert service == "service"
		assert action == "action"

	def test_service_and_action_stripped(self):
		service, action, err = parse_request(b"  service  \n  action  \n")
		assert err is None
		assert service == "service"
		assert action == "action"


class TestInvalidRequests:
	def test_empty_bytes(self):
		_, _, err = parse_request(b"")
		assert err == "invalid_format"

	def test_only_one_field(self):
		_, _, err = parse_request(b"service\n")
		assert err == "invalid_format"

	def test_empty_service(self):
		_, _, err = parse_request(b"\naction\n")
		assert err == "invalid_format"

	def test_empty_action(self):
		_, _, err = parse_request(b"service\n\n")
		assert err == "invalid_format"

	def test_whitespace_only_after_strip(self):
		# strip() turns "  \n  \n" into "" which then splits into [""] - too short.
		_, _, err = parse_request(b"  \n  \n")
		assert err == "invalid_format"

	def test_only_newlines(self):
		_, _, err = parse_request(b"\n\n\n")
		assert err == "invalid_format"


class TestDecodeErrors:
	def test_invalid_utf8_returns_decode_error(self):
		# The server's bare except Exception catches UnicodeDecodeError and sends ERROR.
		# Our helper replicates this by catching UnicodeDecodeError explicitly.
		_, _, err = parse_request(b"\xff\xfe")
		assert err == "decode_error"
