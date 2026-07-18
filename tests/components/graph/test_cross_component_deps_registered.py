"""
Verify that every cross-component task_dep string in defs/*.py is registered
as a constant in components.task_names.

A cross-component dep is any "X:Y" string in a task_dep list where X is not
the component that owns the file (derived from the filename).

Internal deps like "postfix:spam-filter" inside postfix.py are fine as plain
strings - they can only break the component that owns them. Cross-component
deps must go through task_names.py so renames are caught at import time.
"""

import ast
import inspect
import os

import components.task_names as _task_names
import pathlib

_DEFS_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "setup", "components", "defs"))


def _registered_values() -> set[str]:
	return {v for _, v in inspect.getmembers(_task_names) if not _.startswith("_") and isinstance(v, str)}


def _task_dep_strings(tree: ast.AST) -> list[str]:
	"""Extract every string literal inside a task_dep list in the AST."""
	results = []
	for node in ast.walk(tree):
		if not isinstance(node, ast.Dict):
			continue
		for key, val in zip(node.keys, node.values, strict=True):
			if not (isinstance(key, ast.Constant) and key.value == "task_dep"):
				continue
			if not isinstance(val, ast.List):
				continue
			results.extend(elt.value for elt in val.elts if isinstance(elt, ast.Constant) and isinstance(elt.value, str))
	return results


def test_cross_component_deps_are_registered():
	"""Any task_dep referencing a different component must be in task_names.py."""
	registered = _registered_values()
	violations = []

	for dirpath, _dirnames, filenames in os.walk(_DEFS_DIR):
		for fname in sorted(filenames):
			if not fname.endswith(".py") or fname.startswith("__"):
				continue
			component_name = fname[:-3]  # strip .py (e.g. duplicity.py -> duplicity)
			path = os.path.join(dirpath, fname)
			rel = os.path.relpath(path, _DEFS_DIR)

			source = pathlib.Path(path).read_text(encoding="utf-8")
			tree = ast.parse(source, filename=path)

			for dep in _task_dep_strings(tree):
				if ":" not in dep:
					continue
				owner = dep.split(":")[0]
				if owner == component_name:
					continue  # internal dep, fine as a plain string
				if dep not in registered:
					violations.append(f"{rel}: {dep!r} is cross-component but not in task_names.py")

	assert not violations, "\n".join(violations)
