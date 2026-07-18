"""
Regression: make_tasks() must be a pure function - no apt installs, no systemctl
calls, no writes - during graph construction.

If pkg.ensure_installed() or a write-side-effect subprocess.run() fires during
make_tasks(), these tests fail regardless of what the function is named.
"""

import pytest
from unittest.mock import patch, MagicMock

from components.runner import _discover  # noqa: PLC2701
from tests.components._helpers import _subprocess_dispatch


# ── Helpers ──────────────────────────────────────────────────────────────────

_BASE_ENV = {
	"STORAGE_ROOT": "/tmp/test-storage",  # noqa: S108
	"PRIMARY_HOSTNAME": "box.example.com",
	"PRIVATE_IP": "10.0.0.1",
	"PRIVATE_IPV6": "",
	"PUBLIC_IP": "1.2.3.4",
	"EMAIL_ADDR": "admin@example.com",
	"SPAM_FILTER": "rspamd",
	"WEBMAIL_CLIENT": "rav",
	"ENABLE_RADICALE": "false",
	"ENABLE_FILEBROWSER": "false",
	"ENABLE_CLAMAV": "false",
}

_SPAMASSASSIN_ENV = {**_BASE_ENV, "SPAM_FILTER": "spamassassin"}

_RUNTIMES = ["baremetal", "docker"]


def _all_make_tasks():
	"""Return list of (component_name, make_tasks_fn) for all discovered components."""
	with patch("subprocess.run", side_effect=_subprocess_dispatch):
		defs = _discover()
	return [(comp.name, fn) for comp, fn in defs]


# ── Tests ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("runtime", _RUNTIMES)
@pytest.mark.parametrize("comp_name,make_tasks_fn", _all_make_tasks())
def test_make_tasks_does_not_call_ensure_installed(comp_name, make_tasks_fn, runtime):
	"""make_tasks() must not call pkg.ensure_installed() during graph construction.

	Package installation belongs in task actions, not in the function that builds
	the task graph. Violating this means apt runs on every setup invocation even
	when all tasks are stamped up-to-date.
	"""
	env = _SPAMASSASSIN_ENV if comp_name in {"spamassassin", "dkim"} else _BASE_ENV
	installed_calls = []

	def _capture_install(pkgs):
		installed_calls.append(pkgs)

	with patch("subprocess.run", side_effect=_subprocess_dispatch), patch("components.packages.ensure_installed", side_effect=_capture_install):
		make_tasks_fn(env, runtime)

	assert installed_calls == [], f"{comp_name}.make_tasks({runtime!r}) called pkg.ensure_installed{installed_calls}; move package installation into a task action"


@pytest.mark.parametrize("runtime", _RUNTIMES)
@pytest.mark.parametrize("comp_name,make_tasks_fn", _all_make_tasks())
def test_make_tasks_does_not_call_systemctl(comp_name, make_tasks_fn, runtime):
	"""make_tasks() must not invoke systemctl during graph construction.

	systemctl calls (mask, stop, disable) are write-side-effects that must live
	inside task actions, not in the graph-building phase.
	"""
	env = _SPAMASSASSIN_ENV if comp_name in {"spamassassin", "dkim"} else _BASE_ENV
	systemctl_calls = []

	def _dispatch(cmd, **kwargs):
		if isinstance(cmd, list) and cmd and cmd[0] == "systemctl":
			systemctl_calls.append(cmd)
			return MagicMock(returncode=0, stdout="", stderr="")
		return _subprocess_dispatch(cmd, **kwargs)

	with patch("subprocess.run", side_effect=_dispatch), patch("components.packages.ensure_installed"):
		make_tasks_fn(env, runtime)

	assert systemctl_calls == [], f"{comp_name}.make_tasks({runtime!r}) called systemctl{systemctl_calls}; move service management into a task action"
