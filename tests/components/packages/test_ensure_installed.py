"""
Tests for components.packages.ensure_installed().

ensure_installed() has three code paths:
  1. Empty list          -> return immediately, no subprocess call
  2. RUNTIME=docker      -> return immediately, no subprocess call
  3. Otherwise           -> call apt-get with the right flags

All three must be tested because path 2 is the primary guarantee that Docker
containers don't try to install packages at startup (packages are pre-baked
into the image via --build-mode).
"""

import os
from unittest.mock import patch


def _run(packages, env_overrides=None):
	"""Call ensure_installed with optional RUNTIME override."""
	env = {k: v for k, v in os.environ.items() if k != "RUNTIME"}
	if env_overrides:
		env.update(env_overrides)
	with patch.dict(os.environ, env, clear=True):
		from components.packages import ensure_installed

		with patch("subprocess.run") as mock_run:
			ensure_installed(packages)
			return mock_run


def test_empty_list_does_not_call_subprocess():
	mock_run = _run([])
	mock_run.assert_not_called()


def test_docker_runtime_does_not_call_subprocess():
	mock_run = _run(["nginx"], env_overrides={"RUNTIME": "docker"})
	mock_run.assert_not_called()


def test_baremetal_calls_apt_get():
	mock_run = _run(["nginx", "curl"])
	# apt-get update is called first, then apt-get install - two calls total.
	assert mock_run.call_count == 2
	cmd = mock_run.call_args[0][0]  # last call is the install
	assert cmd[0] == "apt-get"
	assert "install" in cmd
	assert "nginx" in cmd
	assert "curl" in cmd


def test_no_install_recommends_flag_is_present():
	mock_run = _run(["nginx"])
	cmd = mock_run.call_args[0][0]
	assert "--no-install-recommends" in cmd


def test_noninteractive_env_is_set():
	mock_run = _run(["nginx"])
	env_passed = mock_run.call_args[1].get("env") or mock_run.call_args.kwargs.get("env")
	assert env_passed is not None
	assert env_passed.get("DEBIAN_FRONTEND") == "noninteractive"


def test_needrestart_suspended():
	"""NEEDRESTART_SUSPEND prevents interactive prompts on kernel updates."""
	mock_run = _run(["nginx"])
	env_passed = mock_run.call_args[1].get("env") or mock_run.call_args.kwargs.get("env")
	assert env_passed.get("NEEDRESTART_SUSPEND") == "1"


def test_check_is_true():
	"""apt-get failure must propagate as an exception, not be silently ignored."""
	mock_run = _run(["nginx"])
	assert mock_run.call_args[1].get("check") is True


def test_unset_runtime_calls_apt_get():
	"""When RUNTIME is absent entirely, apt-get must be called (bare metal path)."""
	mock_run = _run(["vim"])
	assert mock_run.call_count == 2  # apt-get update + apt-get install
