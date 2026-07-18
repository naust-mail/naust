"""
Structural invariants for all COMPONENT declarations.

These tests catch typos and schema violations in component definitions before
they reach runtime: wrong package names, duplicate component names, bad types.
"""

import re
import pytest

from components.runner import _discover  # noqa: PLC2701

# Load once for all tests in this module.
_ALL_DEFS = _discover()
_ALL_COMPONENTS = [comp for comp, _ in _ALL_DEFS]

# Valid apt package name: lowercase alphanumeric, hyphens, dots, plus signs.
# Matches Debian's package naming convention.
_APT_NAME_RE = re.compile(r'^[a-z0-9][a-z0-9+\-.]*$')

# Valid component name: lowercase alphanumeric and hyphens only.
_COMP_NAME_RE = re.compile(r'^[a-z][a-z0-9-]*$')


# ── Name invariants ───────────────────────────────────────────────────────────


def test_all_component_names_are_unique():
	"""No two components may share the same name - the runner indexes them by name."""
	names = [c.name for c in _ALL_COMPONENTS]
	seen: set[str] = set()
	duplicates = [n for n in names if n in seen or seen.add(n)]  # type: ignore[func-returns-value]
	assert not duplicates, f"Duplicate component names: {duplicates}"


@pytest.mark.parametrize("comp", _ALL_COMPONENTS, ids=[c.name for c in _ALL_COMPONENTS])
def test_component_name_is_valid_identifier(comp):
	"""Component name must be lowercase alphanumeric+hyphen (used in task names like 'dns:configure')."""
	assert _COMP_NAME_RE.match(comp.name), f"Component name {comp.name!r} contains invalid characters; must match [a-z][a-z0-9-]*"


# ── Package list invariants ───────────────────────────────────────────────────


@pytest.mark.parametrize("comp", _ALL_COMPONENTS, ids=[c.name for c in _ALL_COMPONENTS])
def test_packages_is_a_list(comp):
	"""COMPONENT.packages must be a list, not None or a string."""
	assert isinstance(comp.packages, list), f"{comp.name}.packages is {type(comp.packages).__name__!r}, expected list"


@pytest.mark.parametrize("comp", _ALL_COMPONENTS, ids=[c.name for c in _ALL_COMPONENTS])
def test_packages_are_non_empty_strings(comp):
	"""Every entry in COMPONENT.packages must be a non-empty string."""
	bad = [p for p in comp.packages if not isinstance(p, str) or not p.strip()]
	assert not bad, f"{comp.name}.packages contains invalid entries: {bad!r}"


@pytest.mark.parametrize("comp", _ALL_COMPONENTS, ids=[c.name for c in _ALL_COMPONENTS])
def test_package_names_are_valid_apt_names(comp):
	"""Package names must follow Debian naming conventions (no whitespace, valid chars)."""
	bad = [p for p in comp.packages if not _APT_NAME_RE.match(p)]
	assert not bad, f"{comp.name}.packages contains invalid apt package names: {bad!r}; must match [a-z0-9][a-z0-9+\\-.]*"


# ── Port order invariants ─────────────────────────────────────────────────────


@pytest.mark.parametrize("comp", _ALL_COMPONENTS, ids=[c.name for c in _ALL_COMPONENTS])
def test_port_order_is_non_negative_int(comp):
	"""COMPONENT.port_order must be a non-negative integer used for sort stability."""
	assert isinstance(comp.port_order, int), f"{comp.name}.port_order is {type(comp.port_order).__name__!r}, expected int"
	assert comp.port_order >= 0, f"{comp.name}.port_order is negative: {comp.port_order}"


def test_discovery_order_is_deterministic():
	"""Running _discover() twice must yield the same component order."""
	defs2 = _discover()
	names1 = [c.name for c, _ in _ALL_DEFS]
	names2 = [c.name for c, _ in defs2]
	assert names1 == names2, "Component discovery order is non-deterministic"


# ── Services list invariants ──────────────────────────────────────────────────


@pytest.mark.parametrize("comp", _ALL_COMPONENTS, ids=[c.name for c in _ALL_COMPONENTS])
def test_services_are_lists_of_strings(comp):
	"""COMPONENT.services and docker_services must be lists of strings."""
	for attr in ("services", "docker_services"):
		val = getattr(comp, attr)
		assert isinstance(val, list), f"{comp.name}.{attr} is not a list"
		assert all(isinstance(s, str) and s for s in val), f"{comp.name}.{attr} contains non-string or empty entries: {val!r}"
