"""
Tests for artifacts.fn_stamp().

(a) Constant sensitivity: changing a module-level constant referenced by an
    action function must change the stamp.

(b) run_once guard: DNSSEC key tasks use run_once as their uptodate sentinel
    and must NOT use config_changed (which would re-arm key rotation on edits).
"""

import importlib.util
import textwrap


from components import artifacts


# ── (a) Constant sensitivity ──────────────────────────────────────────────────


def _load_module_from_source(name: str, source: str, tmp_path):
	"""Write source to a temp file and import it as a module."""
	path = tmp_path / f"{name}.py"
	path.write_text(textwrap.dedent(source))
	spec = importlib.util.spec_from_file_location(name, str(path))
	mod = importlib.util.module_from_spec(spec)
	spec.loader.exec_module(mod)
	return mod


def test_fn_stamp_differs_when_constant_changes(tmp_path):
	"""fn_stamp must include the value of module-level constants the function reads."""
	source_a = """\
		_MY_CONST = "value_one"

		def action():
			return _MY_CONST
	"""
	source_b = """\
		_MY_CONST = "value_two"

		def action():
			return _MY_CONST
	"""
	mod_a = _load_module_from_source("mod_a", source_a, tmp_path)
	mod_b = _load_module_from_source("mod_b", source_b, tmp_path)

	stamp_a = artifacts.fn_stamp(mod_a.action)
	stamp_b = artifacts.fn_stamp(mod_b.action)

	assert stamp_a != stamp_b, "fn_stamp should differ when a referenced module-level constant changes"


# ── (b) run_once guard ────────────────────────────────────────────────────────


def test_dnssec_tasks_use_run_once_not_config_changed(tmp_path):
	"""DNSSEC key tasks must use run_once and not config_changed in their uptodate list."""
	from doit.tools import run_once
	from components.defs import dns

	env = {
		"STORAGE_ROOT": str(tmp_path / "storage"),
		"PRIVATE_IP": "",
		"PRIVATE_IPV6": "",
	}
	tasks = dns.make_tasks(env, "baremetal")

	dnssec_tasks = [t for t in tasks if t["name"].startswith("dnssec-keys-")]
	assert dnssec_tasks, "Expected at least one dnssec-keys-* task"

	for task in dnssec_tasks:
		uptodate = task.get("uptodate", [])
		assert run_once in uptodate, f"Task {task['name']!r} must have run_once in uptodate; got {uptodate!r}"
		# config_changed returns a callable; verify none of the uptodate entries
		# were produced by config_changed (they would be instances of ConfigChangedCalculator).
		for entry in uptodate:
			assert not hasattr(entry, "config_data"), f"Task {task['name']!r} uptodate contains a config_changed result, which would re-arm key regeneration on code edits"
