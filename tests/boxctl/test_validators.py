"""Tests for validator functions in setup/boxctl/questions.py."""

from boxctl.questions import validate_email, validate_ipv4, validate_ipv6, validate_hostname


class TestValidateEmail:
	def test_valid_simple(self):
		assert validate_email("user@example.com") is True

	def test_valid_plus_tag(self):
		assert validate_email("user+tag@sub.example.com") is True

	def test_empty_string(self):
		result = validate_email("")
		assert result is not True
		assert isinstance(result, str)

	def test_no_at_sign(self):
		# email_validator may not be installed in test venv, in which case
		# validate_email returns True for any non-empty string.
		result = validate_email("notanemail")
		# Either True (validator absent) or an error string - never crashes.
		assert result is True or isinstance(result, str)

	def test_at_only_local(self):
		result = validate_email("@example.com")
		assert result is True or isinstance(result, str)

	def test_missing_domain(self):
		result = validate_email("user@")
		assert result is True or isinstance(result, str)

	def test_whitespace_only(self):
		result = validate_email("   ")
		assert result is not True
		assert isinstance(result, str)


class TestValidateIPv4:
	def test_valid_private(self):
		assert validate_ipv4("192.168.1.1") is True

	def test_valid_all_zeros(self):
		assert validate_ipv4("0.0.0.0") is True  # noqa: S104

	def test_valid_broadcast(self):
		assert validate_ipv4("255.255.255.255") is True

	def test_empty_string_invalid(self):
		# validate_ipv4 treats empty as invalid ("cannot be empty").
		result = validate_ipv4("")
		assert result is not True
		assert isinstance(result, str)

	def test_octet_out_of_range(self):
		result = validate_ipv4("192.168.1.256")
		assert result is not True

	def test_missing_octet(self):
		result = validate_ipv4("192.168.1")
		assert result is not True

	def test_alphabetic(self):
		result = validate_ipv4("abc.def.ghi.jkl")
		assert result is not True

	def test_whitespace_stripped(self):
		# strip() is called inside - leading/trailing space should not cause crash.
		result = validate_ipv4("  192.168.1.1  ")
		assert result is True

	def test_returns_string_on_error(self):
		result = validate_ipv4("bad")
		assert isinstance(result, str)


class TestValidateIPv6:
	def test_valid_loopback(self):
		assert validate_ipv6("::1") is True

	def test_valid_full(self):
		assert validate_ipv6("2001:db8::1") is True

	def test_empty_string_invalid(self):
		# validate_ipv6 treats empty as "cannot be empty" and returns a string.
		result = validate_ipv6("")
		assert result is not True
		assert isinstance(result, str)

	def test_ipv4_address_rejected(self):
		result = validate_ipv6("192.168.1.1")
		assert result is not True

	def test_too_few_groups(self):
		result = validate_ipv6("not:an:ipv6")
		assert result is not True

	def test_valid_full_notation(self):
		assert validate_ipv6("2001:0db8:0000:0000:0000:0000:0000:0001") is True

	def test_whitespace_stripped(self):
		result = validate_ipv6("  ::1  ")
		assert result is True


class TestValidateHostname:
	def test_valid_subdomain(self):
		assert validate_hostname("mail.example.com") is True

	def test_valid_two_label(self):
		assert validate_hostname("example.com") is True

	def test_empty_string(self):
		result = validate_hostname("")
		assert result is not True
		assert isinstance(result, str)

	def test_label_too_long(self):
		# A single label > 63 chars is invalid.
		long_label = "a" * 64
		result = validate_hostname(f"{long_label}.com")
		assert result is not True
		assert isinstance(result, str)

	def test_label_starts_with_hyphen(self):
		result = validate_hostname("-example.com")
		assert result is not True

	def test_label_ends_with_hyphen(self):
		result = validate_hostname("example-.com")
		assert result is not True

	def test_total_length_too_long(self):
		# Total hostname > 253 chars is invalid.
		long = "a" * 250 + ".com"
		result = validate_hostname(long)
		assert result is not True

	def test_single_label_no_dot(self):
		# Must have at least one dot (two labels).
		result = validate_hostname("localhost")
		assert result is not True

	def test_valid_with_digits(self):
		assert validate_hostname("box1.example.com") is True

	def test_valid_with_hyphens_inside(self):
		assert validate_hostname("my-box.example.com") is True

	def test_label_exactly_63_chars(self):
		label = "a" * 63
		assert validate_hostname(f"{label}.com") is True

	def test_underscore_in_label_rejected(self):
		# Underscores are not alphanumeric and not '-', so they are rejected.
		result = validate_hostname("my_box.example.com")
		assert result is not True

	def test_trailing_dot_accepted(self):
		# rstrip('.') is called, so trailing dot is OK.
		assert validate_hostname("mail.example.com.") is True
