"""Tests for the service name validation regex used in control-socket-server.py."""

import re

# Regex taken directly from deploy/docker/control-socket-server.py line 59.
_SERVICE_RE = r"[A-Za-z0-9._-]+"


def matches(name: str) -> bool:
	return re.fullmatch(_SERVICE_RE, name) is not None


class TestValidServiceNames:
	def test_plain_word(self):
		assert matches("mail")

	def test_hyphen(self):
		assert matches("postfix-test")

	def test_dot(self):
		assert matches("my.service")

	def test_alphanumeric(self):
		assert matches("svc-123")

	def test_mixed_case(self):
		assert matches("MyService")

	def test_digits_only(self):
		assert matches("123")

	def test_single_char(self):
		assert matches("a")

	def test_underscore_allowed(self):
		# The regex is [A-Za-z0-9._-] - underscore appears as a literal in the class.
		assert matches("abc_def")


class TestInvalidServiceNames:
	def test_path_traversal(self):
		assert not matches("../etc/passwd")

	def test_command_injection_semicolon(self):
		assert not matches("mail;rm -rf /")

	def test_command_injection_subshell(self):
		assert not matches("mail$(whoami)")

	def test_double_quotes(self):
		assert not matches('"mail"')

	def test_newline_in_name(self):
		assert not matches("mail\nrestart")

	def test_space_in_name(self):
		assert not matches("svc with space")

	def test_empty_string(self):
		assert not matches("")

	def test_unicode_outside_ascii(self):
		assert not matches("日本語")

	def test_null_byte(self):
		assert not matches("svc\x00null")

	def test_slash(self):
		assert not matches("some/path")

	def test_at_sign(self):
		assert not matches("svc@host")


class TestFullmatchSemantics:
	def test_fullmatch_rejects_trailing_newline(self):
		# re.fullmatch must match the entire string; "mail\n" must not match even
		# though "mail" alone would.
		assert not matches("mail\n")

	def test_fullmatch_rejects_leading_space(self):
		assert not matches(" mail")

	def test_fullmatch_rejects_trailing_space(self):
		assert not matches("mail ")
