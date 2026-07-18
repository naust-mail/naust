"""
Smoke-test every component's make_tasks() function.

Calling make_tasks() is cheap - it builds doit task dicts but executes nothing.
These tests catch module-level errors (bad imports, broken path constants) and
malformed task structure before any of it reaches a real machine.

subprocess.run is mocked because a few components (dovecot, spamassassin) probe
the installed Dovecot version at task-build time. That's valid at runtime since
packages are installed before make_tasks() is called, but the binaries don't
exist in the test environment.
"""

from collections import defaultdict
from unittest.mock import MagicMock, patch

import pytest

from components.component import BAREMETAL
from components.runner import _discover  # noqa: PLC2701

_ALL_DEFS = _discover()
_ENV = defaultdict(str)


def _fake_run(args, **_kwargs):
	"""Return plausible stdout for the system probes make_tasks() calls."""
	cmd = args[0] if args else ""
	if cmd == "dovecot":
		stdout = "2.4.0\n"
	elif cmd == "free":
		# Matches the format free -tm produces; last line is "Total: <mb> ..."
		stdout = "              total\nMem:           1024\nTotal:         1024\n"
	else:
		stdout = ""
	return MagicMock(returncode=0, stdout=stdout, stderr="")


@pytest.mark.parametrize("comp,fn", _ALL_DEFS, ids=[c.name for c, _ in _ALL_DEFS])
def test_make_tasks_returns_list(comp, fn):
	with patch("subprocess.run", side_effect=_fake_run):
		result = fn(_ENV, BAREMETAL)
	assert isinstance(result, list), f"{comp.name}.make_tasks() did not return a list"
	assert result, f"{comp.name}.make_tasks() returned an empty list"


@pytest.mark.parametrize("comp,fn", _ALL_DEFS, ids=[c.name for c, _ in _ALL_DEFS])
def test_make_tasks_all_have_name(comp, fn):
	with patch("subprocess.run", side_effect=_fake_run):
		result = fn(_ENV, BAREMETAL)
	bad = [t for t in result if not isinstance(t.get("name"), str) or not t["name"]]
	assert not bad, f"{comp.name}: tasks missing 'name': {bad}"


@pytest.mark.parametrize("comp,fn", _ALL_DEFS, ids=[c.name for c, _ in _ALL_DEFS])
def test_make_tasks_all_have_actions(comp, fn):
	with patch("subprocess.run", side_effect=_fake_run):
		result = fn(_ENV, BAREMETAL)
	bad = [t["name"] for t in result if not t.get("actions")]
	assert not bad, f"{comp.name}: tasks missing 'actions': {bad}"
