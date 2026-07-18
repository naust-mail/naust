"""
Verify that no configuration produces a cyclic task dependency graph.

A cycle (A:task -> B:task -> A:task) would cause doit to raise
CyclicDependencyError at runtime. This is a structural property that static
analysis can catch cheaply without running any tasks.
"""

import pytest

from tests.components.conftest import CONFIG_MATRIX, BACKUP_CONFIGS, make_env
from tests.components._helpers import build_graph_full


def _has_cycle(graph: dict[str, list[dict]]) -> list[str] | None:
	"""Return a list of task names forming a cycle, or None if acyclic.

	Uses iterative DFS with a color-marking scheme:
	  white (0) - not visited
	  gray  (1) - in current DFS stack (back-edge if we reach it again)
	  black (2) - fully explored
	"""
	adj: dict[str, list[str]] = {}
	for comp_name, tasks in graph.items():
		for t in tasks:
			node = f"{comp_name}:{t['name']}"
			adj[node] = list(t.get("task_dep", []))

	color: dict[str, int] = dict.fromkeys(adj, 0)
	parent: dict[str, str | None] = dict.fromkeys(adj)

	for start in adj:
		if color[start] != 0:
			continue
		stack = [(start, iter(adj.get(start, [])))]
		color[start] = 1
		while stack:
			node, children = stack[-1]
			try:
				child = next(children)
				if child not in color:
					continue  # dangling dep - caught by test_graph_validity
				if color[child] == 1:
					# Back edge found - reconstruct cycle path.
					cycle = [child]
					cur = node
					while cur != child:
						cycle.append(cur)
						cur = parent[cur]
					cycle.append(child)
					return list(reversed(cycle))
				if color[child] == 0:
					color[child] = 1
					parent[child] = node
					stack.append((child, iter(adj.get(child, []))))
			except StopIteration:
				color[node] = 2
				stack.pop()

	return None


# ── Main parametrized suite ───────────────────────────────────────────────────


@pytest.mark.parametrize("cfg", CONFIG_MATRIX)
def test_no_cycles_in_task_graph(cfg, tmp_path):
	"""No task dependency graph produced by any CONFIG_MATRIX entry may contain a cycle."""
	runtime = cfg["_RUNTIME"]
	env = make_env(tmp_path, **{k: v for k, v in cfg.items() if k != "_RUNTIME"})
	graph = build_graph_full(env, runtime)
	cycle = _has_cycle(graph)
	assert cycle is None, f"Cycle detected in task graph for {cfg}: {' -> '.join(cycle)}"


@pytest.mark.parametrize("cfg", BACKUP_CONFIGS, ids=[c["BACKUP_TOOL"] for c in BACKUP_CONFIGS])
def test_no_cycles_in_backup_graph(cfg, tmp_path):
	"""Backup component graphs must also be acyclic."""
	runtime = cfg["_RUNTIME"]
	env = make_env(tmp_path, **{k: v for k, v in cfg.items() if k != "_RUNTIME"})
	graph = build_graph_full(env, runtime)
	cycle = _has_cycle(graph)
	assert cycle is None, f"Cycle detected in backup graph for {cfg}: {' -> '.join(cycle)}"


# ── Unit test for the cycle detector itself ───────────────────────────────────


def test_cycle_detector_finds_simple_cycle():
	"""Sanity-check the DFS cycle detector with a known cycle."""
	graph = {
		"a": [{"name": "t1", "task_dep": ["b:t1"]}],
		"b": [{"name": "t1", "task_dep": ["a:t1"]}],
	}
	cycle = _has_cycle(graph)
	assert cycle is not None, "Expected cycle to be detected"
	assert len(cycle) >= 2


def test_cycle_detector_passes_acyclic_graph():
	"""Sanity-check the DFS cycle detector with a known acyclic graph."""
	graph = {
		"a": [{"name": "t1", "task_dep": ["b:t1"]}],
		"b": [{"name": "t1", "task_dep": []}],
	}
	assert _has_cycle(graph) is None
