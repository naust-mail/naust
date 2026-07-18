import pytest
from flask import Flask
from core.web_helpers import sanitize_error_message, validate_email, validate_csrf


# ---------------------------------------------------------------------------
# validate_csrf
#
# validate_csrf() reads Flask's request proxy, so each test runs inside a
# real Flask test request context to avoid LocalProxy errors.
# ---------------------------------------------------------------------------


def _app():
	app = Flask(__name__)
	app.config['TESTING'] = True
	return app


class TestValidateCsrf:
	def test_get_method_passes(self):
		app = _app()
		with app.test_request_context('/', method='GET'):
			assert validate_csrf() is True

	def test_post_with_correct_header_passes(self):
		app = _app()
		with app.test_request_context('/', method='POST', headers={'X-Requested-With': 'XMLHttpRequest'}):
			assert validate_csrf() is True

	def test_post_without_header_fails(self):
		app = _app()
		with app.test_request_context('/', method='POST'):
			assert validate_csrf() is False

	def test_put_without_header_fails(self):
		app = _app()
		with app.test_request_context('/', method='PUT'):
			assert validate_csrf() is False

	def test_delete_without_header_fails(self):
		app = _app()
		with app.test_request_context('/', method='DELETE'):
			assert validate_csrf() is False

	def test_post_with_wrong_header_value_fails(self):
		app = _app()
		with app.test_request_context('/', method='POST', headers={'X-Requested-With': 'fetch'}):
			assert validate_csrf() is False


# ---------------------------------------------------------------------------
# sanitize_error_message
# ---------------------------------------------------------------------------


class TestSanitizeErrorMessage:
	def test_redacts_py_file_path(self):
		msg = "Error in /home/user/project/app.py somewhere"
		result = sanitize_error_message(msg)
		assert "/home/user/project/app.py" not in result
		assert "[file]" in result

	def test_redacts_storage_root_path(self):
		msg = "Could not open /var/lib/naust/mail/users.db"
		result = sanitize_error_message(msg)
		assert "/var/lib/naust/mail/users.db" not in result
		assert "[storage]" in result

	def test_redacts_home_path(self):
		msg = "Access denied: /home/adminuser/secrets.txt"
		result = sanitize_error_message(msg)
		assert "/home/adminuser/secrets.txt" not in result
		assert "[home]" in result

	def test_redacts_line_number(self):
		msg = "Exception at line 42 in code"
		result = sanitize_error_message(msg)
		assert "line 42" not in result
		assert "line [redacted]" in result

	def test_traceback_string_replaced_entirely(self):
		msg = "Traceback (most recent call last):\n  File 'app.py', line 10"
		result = sanitize_error_message(msg)
		assert result == "An internal error occurred. Please contact your administrator."

	def test_file_quote_string_replaced_entirely(self):
		msg = 'File "app.py", line 5, in main'
		result = sanitize_error_message(msg)
		assert result == "An internal error occurred. Please contact your administrator."

	def test_non_string_input_coerced(self):
		result = sanitize_error_message(Exception("boom"))
		assert isinstance(result, str)

	def test_plain_message_unchanged(self):
		msg = "Invalid email address provided."
		assert sanitize_error_message(msg) == msg

	def test_strips_url_credentials(self):
		msg = "Cannot connect to s3://myuser:mysecret@s3.amazonaws.com/bucket"
		result = sanitize_error_message(msg)
		assert "mysecret" not in result
		assert "***" in result

	def test_strips_url_credentials_other_schemes(self):
		msg = "sftp://backup:password123@host.example.com failed"
		result = sanitize_error_message(msg)
		assert "password123" not in result


# ---------------------------------------------------------------------------
# validate_hostname (injection-focused)
# ---------------------------------------------------------------------------


class TestValidateHostname:
	def test_valid_hostname_returned(self):
		from core.web_helpers import validate_hostname

		assert validate_hostname("smtp.example.com") == "smtp.example.com"

	def test_rejects_space(self):
		from core.web_helpers import validate_hostname

		with pytest.raises(ValueError):
			validate_hostname("smtp example.com")

	def test_rejects_semicolon(self):
		from core.web_helpers import validate_hostname

		with pytest.raises(ValueError):
			validate_hostname("smtp;evil.com")

	def test_rejects_pipe(self):
		from core.web_helpers import validate_hostname

		with pytest.raises(ValueError):
			validate_hostname("smtp|evil.com")

	def test_rejects_slash(self):
		from core.web_helpers import validate_hostname

		with pytest.raises(ValueError):
			validate_hostname("smtp.com/path")

	def test_rejects_label_starting_with_hyphen(self):
		from core.web_helpers import validate_hostname

		with pytest.raises(ValueError):
			validate_hostname("-smtp.example.com")

	def test_rejects_missing_tld(self):
		from core.web_helpers import validate_hostname

		with pytest.raises(ValueError):
			validate_hostname("localhost")

	def test_rejects_empty(self):
		from core.web_helpers import validate_hostname

		with pytest.raises(ValueError):
			validate_hostname("")

	def test_strips_whitespace(self):
		from core.web_helpers import validate_hostname

		assert validate_hostname("  smtp.example.com  ") == "smtp.example.com"


# ---------------------------------------------------------------------------
# validate_email (web_helpers version - injection-focused)
# ---------------------------------------------------------------------------


class TestWebHelpersValidateEmail:
	def test_valid_email_returned(self):
		assert validate_email("user@example.com") == "user@example.com"

	def test_rejects_semicolon(self):
		with pytest.raises(ValueError):
			validate_email("user;bad@example.com")

	def test_rejects_pipe(self):
		with pytest.raises(ValueError):
			validate_email("user|bad@example.com")

	def test_rejects_ampersand(self):
		with pytest.raises(ValueError):
			validate_email("user&bad@example.com")

	def test_rejects_backtick(self):
		with pytest.raises(ValueError):
			validate_email("user`bad@example.com")

	def test_rejects_newline(self):
		with pytest.raises(ValueError):
			validate_email("user\nbad@example.com")

	def test_rejects_null_byte(self):
		with pytest.raises(ValueError):
			validate_email("user\x00bad@example.com")

	def test_rejects_missing_at(self):
		with pytest.raises(ValueError):
			validate_email("userexample.com")

	def test_rejects_empty_string(self):
		with pytest.raises(ValueError):
			validate_email("")

	def test_strips_whitespace(self):
		assert validate_email("  user@example.com  ") == "user@example.com"
