"""Tests for handler execution logic from control-socket-server.py.

Tests cover: valid handler, non-zero exit, non-executable file, directory at
handler path, timeout, and action string passthrough.
"""

import os
import subprocess  # noqa: S404
import pytest
from unittest.mock import patch


@pytest.fixture
def handlers_dir(tmp_path):
	d = tmp_path / "handlers"
	d.mkdir()
	return d


def make_handler(
	handlers_dir,
	name: str,
	content: str = "#!/bin/sh\necho OK\n",
	executable: bool = True,
):
	h = handlers_dir / name
	h.write_text(content)
	if executable:
		h.chmod(0o755)
	return h


def run_handler(handler_path: str, action: str) -> tuple[str, str]:
	"""Replicate the server's subprocess dispatch and response logic.

	Returns (response_line, stderr_text).
	"""
	if not os.path.isfile(handler_path) or not os.access(handler_path, os.X_OK):
		return f"ERROR: no handler for service '{os.path.basename(handler_path)}'", ""

	try:
		result = subprocess.run(  # noqa: S603
			[handler_path, action],
			capture_output=True,
			timeout=30,
			check=False,
		)
	except subprocess.TimeoutExpired:
		return "ERROR: handler timed out after 30s", ""

	if result.returncode == 0:
		return "OK", ""

	msg = result.stderr.decode().strip() or result.stdout.decode().strip() or f"exited {result.returncode}"
	service = os.path.basename(handler_path)
	return f"ERROR: {service} {action} failed: {msg}", msg


class TestHandlerExecution:
	def test_valid_handler_exits_zero(self, handlers_dir):
		handler = make_handler(handlers_dir, "myservice")
		response, _ = run_handler(str(handler), "restart")
		assert response == "OK"

	def test_handler_exits_nonzero_returns_error(self, handlers_dir):
		handler = make_handler(
			handlers_dir,
			"failing",
			content="#!/bin/sh\necho 'something broke' >&2\nexit 1\n",
		)
		response, _ = run_handler(str(handler), "restart")
		assert response.startswith("ERROR:")
		assert "failing" in response

	def test_non_executable_handler_not_run(self, handlers_dir):
		handler = make_handler(handlers_dir, "locked", executable=False)
		assert not os.access(str(handler), os.X_OK)
		response, _ = run_handler(str(handler), "restart")
		assert response.startswith("ERROR:")

	def test_directory_at_handler_path_returns_error(self, handlers_dir):
		d = handlers_dir / "adir"
		d.mkdir()
		response, _ = run_handler(str(d), "restart")
		assert response.startswith("ERROR:")

	def test_missing_handler_returns_error(self, handlers_dir):
		path = str(handlers_dir / "noexist")
		response, _ = run_handler(path, "restart")
		assert response.startswith("ERROR:")

	def test_action_passed_as_argument(self, handlers_dir):
		# Handler echoes its first argument to stdout; verify it receives the action.
		handler = make_handler(
			handlers_dir,
			"echo_action",
			content='#!/bin/sh\necho "got:$1"\n',
		)
		result = subprocess.run(  # noqa: S603
			[str(handler), "reload"],
			capture_output=True,
			text=True,
			check=False,
		)
		assert "got:reload" in result.stdout

	def test_timeout_returns_error(self, handlers_dir):
		handler = make_handler(handlers_dir, "slow")

		def fake_run(*args, **kwargs):
			raise subprocess.TimeoutExpired(cmd=args[0], timeout=30)

		with patch("subprocess.run", side_effect=fake_run):
			response, _ = run_handler(str(handler), "restart")
		assert "timed out" in response

	def test_handler_stderr_included_in_error(self, handlers_dir):
		handler = make_handler(
			handlers_dir,
			"noisyfail",
			content="#!/bin/sh\necho 'specific error message' >&2\nexit 2\n",
		)
		response, _ = run_handler(str(handler), "start")
		assert "specific error message" in response

	def test_handler_stdout_used_when_no_stderr(self, handlers_dir):
		handler = make_handler(
			handlers_dir,
			"stdoutfail",
			content="#!/bin/sh\necho 'stdout only error'\nexit 3\n",
		)
		response, _ = run_handler(str(handler), "start")
		assert "stdout only error" in response

	def test_exit_code_in_message_when_no_output(self, handlers_dir):
		handler = make_handler(
			handlers_dir,
			"silentexit",
			content="#!/bin/sh\nexit 42\n",
		)
		response, _ = run_handler(str(handler), "start")
		assert "42" in response
