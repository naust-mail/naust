"""
Backup component graph tests.

Backup components (restic, duplicity) are not in CONFIG_MATRIX because they
are orthogonal to the spam/webmail/optional dimensions. These tests cover the
backup-specific graph invariants separately.
"""

import pytest

from tests.components.conftest import BACKUP_CONFIGS, make_env, all_task_names
from tests.components._helpers import build_graph_full


@pytest.mark.parametrize("cfg", BACKUP_CONFIGS, ids=[c["BACKUP_TOOL"] for c in BACKUP_CONFIGS])
def test_backup_graph_no_dangling_task_deps(cfg, tmp_path):
	"""Every task_dep in the backup component graph must resolve to a real task."""
	runtime = cfg["_RUNTIME"]
	env = make_env(tmp_path, **{k: v for k, v in cfg.items() if k != "_RUNTIME"})

	graph = build_graph_full(env, runtime)
	names = all_task_names(graph)

	for comp_name, tasks in graph.items():
		for task in tasks:
			for dep in task.get("task_dep", []):
				assert dep in names, f"{comp_name}:{task['name']} has dangling task_dep {dep!r}; known tasks: {sorted(names)}"


def test_restic_in_default_graph(tmp_path):
	"""restic must appear alongside the daemon in the default graph."""
	env = make_env(tmp_path, BACKUP_TOOL="restic")
	graph = build_graph_full(env, "baremetal")
	assert "restic" in graph, "restic must be in graph when BACKUP_TOOL=restic"
	assert "managerd" in graph, "managerd must always be in graph"


def test_duplicity_owns_its_virtualenv(tmp_path):
	"""duplicity must be self-contained; its pip-install dep resolves to its own venv."""
	env = make_env(tmp_path, BACKUP_TOOL="duplicity")
	graph = build_graph_full(env, "baremetal")
	assert "duplicity" in graph, "duplicity must be in graph when BACKUP_TOOL=duplicity"
	assert "managerd" in graph, "managerd must always be in graph"

	# duplicity owns its venv now (no tie to the retired Flask management stack):
	# pip-install depends on duplicity:virtualenv, which must exist.
	names = all_task_names(graph)
	assert "duplicity:virtualenv" in names, "duplicity:virtualenv must exist for duplicity:pip-install to depend on it"


def test_restic_not_in_duplicity_graph(tmp_path):
	"""When BACKUP_TOOL=duplicity, restic must not be enabled."""
	env = make_env(tmp_path, BACKUP_TOOL="duplicity")
	graph = build_graph_full(env, "baremetal")
	assert "restic" not in graph


def test_duplicity_not_in_restic_graph(tmp_path):
	"""When BACKUP_TOOL=restic, duplicity must not be enabled."""
	env = make_env(tmp_path, BACKUP_TOOL="restic")
	graph = build_graph_full(env, "baremetal")
	assert "duplicity" not in graph
