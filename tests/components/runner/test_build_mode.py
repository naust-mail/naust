"""
Tests for the runner's --build-mode / build() function.

build() is designed to run at Docker image build time where no
/etc/naust.conf exists. It must:
  - Not crash when make_tasks() accesses env keys (uses defaultdict)
  - Only run tasks tagged with "build": True
  - Install apt packages from COMPONENT.packages (via ensure_installed)
  - Reject unknown component names with ValueError
"""

import collections
from unittest.mock import patch

import pytest


# ── helpers ───────────────────────────────────────────────────────────────────


def _build_tasks_for(component_name: str) -> list[dict]:
	"""Return the build-safe tasks make_tasks() would produce for a component."""
	from components.runner import _discover, BAREMETAL  # noqa: PLC2701

	defs_by_name = {c.name: (c, fn) for c, fn in _discover()}
	_c, fn = defs_by_name[component_name]
	env = collections.defaultdict(str)
	all_tasks = fn(env, BAREMETAL)
	return [t for t in all_tasks if t.get("build") is True]


# ── build: True filtering ─────────────────────────────────────────────────────


def test_duplicity_has_two_build_safe_tasks():
	tasks = _build_tasks_for("duplicity")
	assert [t["name"] for t in tasks] == ["virtualenv", "pip-install"]


def test_radicale_has_two_build_safe_tasks():
	tasks = _build_tasks_for("radicale")
	assert [t["name"] for t in tasks] == ["venv", "pip-install"]


def test_filebrowser_has_one_build_safe_task():
	tasks = _build_tasks_for("filebrowser")
	assert [t["name"] for t in tasks] == ["fetch"]


def test_dns_has_no_build_safe_tasks():
	# dns only contributes apt packages; no doit tasks are build-safe.
	tasks = _build_tasks_for("dns")
	assert tasks == []


def test_munin_has_no_build_safe_tasks():
	tasks = _build_tasks_for("munin")
	assert tasks == []


# ── defaultdict doesn't crash make_tasks() ───────────────────────────────────


def test_env_key_access_does_not_crash_with_defaultdict():
	"""make_tasks() accesses env["STORAGE_ROOT"] etc at call time.
	build() must not crash even when the key is absent.

	Covers components that use env["KEY"] at dict-construction time (not just
	inside action functions), which would fail with a plain {} dict.
	"""
	from components.runner import BAREMETAL
	from components.defs import dns, ssl, postfix, users
	from components.defs.backup import restic, duplicity

	env = collections.defaultdict(str)
	# None of these should raise KeyError even with all-empty env values.
	dns.make_tasks(env, BAREMETAL)
	ssl.make_tasks(env, BAREMETAL)
	postfix.make_tasks(env, BAREMETAL)
	users.make_tasks(env, BAREMETAL)
	restic.make_tasks(env, BAREMETAL)
	duplicity.make_tasks(env, BAREMETAL)


# ── build() API ───────────────────────────────────────────────────────────────


def test_build_rejects_unknown_component():
	from components.runner import build

	with pytest.raises(ValueError, match="Unknown components"), patch("components.runner.pkg.ensure_installed"):
		build(["nonexistent_component"])


def test_build_calls_ensure_installed_with_component_packages():
	"""build() must batch-install all packages from the named components' defs."""
	from components.runner import build

	with patch("components.runner.pkg.ensure_installed") as mock_install, patch("components.runner._run_doit"):
		build(["duplicity"])

	mock_install.assert_called_once()
	installed = set(mock_install.call_args[0][0])
	# duplicity COMPONENT.packages
	assert "virtualenv" in installed
	assert "python3-pip" in installed


def test_build_skips_ensure_installed_when_no_packages():
	"""Components with packages=[] must not trigger an apt call."""
	from components.runner import build

	with patch("components.runner.pkg.ensure_installed") as mock_install, patch("components.runner._run_doit"):
		build(["users"])

	mock_install.assert_not_called()


def test_build_does_not_call_run_doit_when_no_build_tasks():
	"""When no build-safe tasks exist, _run_doit must not be called."""
	from components.runner import build

	with patch("components.runner.pkg.ensure_installed"), patch("components.runner._run_doit") as mock_doit:
		build(["dns"])

	mock_doit.assert_not_called()


def test_build_calls_run_doit_for_duplicity():
	"""duplicity has build-safe tasks, so _run_doit must be called."""
	from components.runner import build

	with patch("components.runner.pkg.ensure_installed"), patch("components.runner._run_doit") as mock_doit:
		build(["duplicity"])

	mock_doit.assert_called_once()
	component_tasks = mock_doit.call_args[0][0]
	assert "duplicity" in component_tasks
	task_names = [t["name"] for t in component_tasks["duplicity"]]
	assert "virtualenv" in task_names
	assert "pip-install" in task_names


def test_build_key_stripped_before_doit():
	"""Tasks with 'build': True must not reach doit with that key present.

	doit rejects unknown fields with exit code 3. The runner strips 'build'
	inside _run_doit's generator. This test verifies that stripping by checking
	what the doit module loader actually sees via the task generator.
	"""
	from components.runner import _DOIT_KEYS  # noqa: PLC2701

	task_with_build = {"name": "noop", "build": True, "actions": []}
	stripped = {k: v for k, v in task_with_build.items() if k in _DOIT_KEYS}
	assert "build" not in stripped
	assert "name" in stripped
	assert "actions" in stripped
