"""
Shared test utilities for component graph tests.

build_graph_full is a replacement for conftest.build_graph that patches
subprocess.run with a dispatcher so both 'dovecot --version' and 'free -tm'
return appropriate mocks instead of the same MagicMock.
"""

from unittest.mock import patch, MagicMock

from components.runner import _discover  # noqa: PLC2701

_DOVECOT_FAKE = MagicMock(stdout="2.3.21 (abc)", returncode=0)
_FREE_FAKE = MagicMock(
	stdout=("              total        used        free\nMem:           7936        1234        6702\nSwap:          2048           0        2048\nTotal:         9984        1234        8750\n"),
	returncode=0,
)


def _subprocess_dispatch(cmd, **kwargs):
	if isinstance(cmd, list) and cmd and cmd[0] == "free":
		return _FREE_FAKE
	return _DOVECOT_FAKE


def build_graph_full(env: dict, runtime: str) -> dict:
	"""Build the component task graph with a subprocess mock that handles free -tm."""
	all_defs = _discover()
	enabled = [(c, fn) for c, fn in all_defs if runtime not in c.skip_on and (c.enabled is None or c.enabled(env))]
	result = {}
	with patch("subprocess.run", side_effect=_subprocess_dispatch):
		for comp, fn in enabled:
			tasks = fn(env, runtime)
			if tasks:
				result[comp.name] = tasks
	return result
