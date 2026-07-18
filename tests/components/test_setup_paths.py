"""
Verify that SETUP_DIR resolves to the real setup/ directory and that the
conf files components depend on at runtime are actually present on disk.

These tests catch path-depth bugs (wrong number of ../.. in __init__.py)
and missing unit files before they surface as cryptic CalledProcessError
or FileNotFoundError failures during setup.
"""

import os
from pathlib import Path

import pytest

from components import SETUP_DIR

_SYSTEMD_DIR = os.path.join(SETUP_DIR, "conf", "systemd")


def test_setup_dir_exists():
	assert os.path.isdir(SETUP_DIR), f"SETUP_DIR does not exist: {SETUP_DIR!r}"


def test_setup_dir_has_expected_subdirs():
	for subdir in ("conf", "conf/systemd", "tools"):
		path = os.path.join(SETUP_DIR, subdir)
		assert os.path.isdir(path), f"Expected subdirectory missing: {path!r}"


def _unit_files() -> list[str]:
	if not os.path.isdir(_SYSTEMD_DIR):
		return []
	return [f for f in os.listdir(_SYSTEMD_DIR) if f.endswith(".service")]


@pytest.mark.parametrize("unit", _unit_files())
def test_systemd_unit_file_is_readable(unit: str):
	path = os.path.join(_SYSTEMD_DIR, unit)
	assert os.path.isfile(path), f"Unit file missing: {path!r}"
	content = Path(path).read_text(encoding="utf-8")
	assert content.strip(), f"Unit file is empty: {path!r}"
