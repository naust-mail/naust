"""
Verify milter exclusion invariants:
1. At most one component assigns smtpd_milters= globally in any given config.
2. No config enables both rspamd and dkim simultaneously (they're mutually exclusive
   via their enabled() callbacks - rspamd handles DKIM itself, dkim is for the
   spamassassin path only).
"""

import inspect
import re

import pytest

from tests.components.conftest import CONFIG_MATRIX, make_env
from tests.components._helpers import build_graph_full

# Matches an unconditional global smtpd_milters= assignment with a hardcoded value.
# This catches rspamd and dkim which both assign "smtpd_milters=inet:...".
# ClamAV's _milter_config is excluded: it reads the current value and conditionally
# appends (the assignment in its source uses a variable: f"smtpd_milters={new_val}").
_MILTER_ASSIGN_RE = re.compile(r'"smtpd_milters=inet:')


def _action_fns(task: dict) -> list:
	"""Extract the callable from each (callable, args) entry in task['actions']."""
	fns = []
	for entry in task.get("actions", []):
		if callable(entry):
			fns.append(entry)
		elif isinstance(entry, (tuple, list)) and callable(entry[0]):
			fns.append(entry[0])
	return fns


def _source_sets_global_milter(fn) -> bool:
	"""Return True if the function source contains a global smtpd_milters= assignment."""
	try:
		src = inspect.getsource(fn)
	except (OSError, TypeError):
		return False
	return bool(_MILTER_ASSIGN_RE.search(src))


@pytest.mark.parametrize("cfg", CONFIG_MATRIX)
def test_at_most_one_global_milter_assignment(cfg, tmp_path):
	"""At most one component may assign smtpd_milters= globally per config."""
	runtime = cfg["_RUNTIME"]
	env = make_env(tmp_path, **{k: v for k, v in cfg.items() if k != "_RUNTIME"})

	graph = build_graph_full(env, runtime)

	setters = []
	for comp_name, tasks in graph.items():
		for task in tasks:
			for fn in _action_fns(task):
				if _source_sets_global_milter(fn):
					setters.append(f"{comp_name}:{task['name']}")
					break

	assert len(setters) <= 1, f"Config {cfg} has {len(setters)} global smtpd_milters= assignments: {setters}"


@pytest.mark.parametrize("cfg", CONFIG_MATRIX)
def test_rspamd_and_dkim_not_simultaneously_enabled(cfg, tmp_path):
	"""rspamd and dkim must not both be enabled in the same config."""
	runtime = cfg["_RUNTIME"]
	env = make_env(tmp_path, **{k: v for k, v in cfg.items() if k != "_RUNTIME"})

	graph = build_graph_full(env, runtime)
	enabled = set(graph.keys())

	assert not ("rspamd" in enabled and "dkim" in enabled), f"Both rspamd and dkim are enabled in config {cfg}; they are mutually exclusive"
