"""
Verify that every constant in components.task_names resolves to a real task
in at least one valid component graph configuration.

Some constants are config-specific (e.g. DKIM_POSTFIX_MILTERS only exists
when SPAM_FILTER=spamassassin). The test builds a union of task names across
all representative configs and asserts each constant appears in the union.

This is the guard that keeps task_names.py honest: if a task is renamed
without updating the constant, this test fails immediately.
"""

import inspect


import components.task_names as _task_names
from tests.components._helpers import build_graph_full
from tests.components.conftest import make_env, all_task_names

# Representative configs chosen to activate every component that owns a
# cross-component dep target at least once across the set.
_CONFIGS = [
	("rspamd+baremetal", "baremetal", {"SPAM_FILTER": "rspamd", "ENABLE_CLAMAV": "true"}),
	("spamassassin+baremetal", "baremetal", {"SPAM_FILTER": "spamassassin", "ENABLE_CLAMAV": "true"}),
	# duplicity: self-contained backend, exercised here for graph coverage
	("duplicity+baremetal", "baremetal", {"BACKUP_TOOL": "duplicity"}),
]


def _all_constants() -> dict[str, str]:
	"""Return {name: value} for every public string constant in task_names."""
	return {name: value for name, value in inspect.getmembers(_task_names) if not name.startswith("_") and isinstance(value, str)}


def test_all_task_name_constants_resolve(tmp_path):
	"""Every constant in task_names.py must name a task that exists in at least
	one valid graph configuration. Constants for mutually exclusive components
	(rspamd vs dkim) are each checked against the config where they are active."""
	all_known: set[str] = set()
	for _, runtime, overrides in _CONFIGS:
		env = make_env(tmp_path, **overrides)
		graph = build_graph_full(env, runtime)
		all_known |= all_task_names(graph)

	missing = [f"{name} = {value!r}" for name, value in _all_constants().items() if value not in all_known]

	assert not missing, "task_names constants that do not resolve in any representative graph:\n" + "\n".join(missing)
