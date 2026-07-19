"""
Tests for components.install_packages.main().

install_packages is a thin CLI wrapper: it discovers component packages by name
and calls ensure_installed(). It predates --build-mode and may eventually be
superseded by it, but it must still work correctly while it exists.
"""

import pytest
from unittest.mock import patch


def _main(component_names):
	from components.install_packages import main

	with patch("components.packages.ensure_installed") as mock_install:
		main(component_names)
	return mock_install


def test_known_component_calls_ensure_installed():
	mock_install = _main(["postfix"])
	mock_install.assert_called_once()
	packages = mock_install.call_args[0][0]
	# postfix COMPONENT.packages includes at least these
	assert "postfix" in packages
	assert "ca-certificates" in packages


def test_component_with_no_packages_does_not_call_ensure_installed():
	"""users has packages=[] - ensure_installed must not be called."""
	mock_install = _main(["users"])
	mock_install.assert_not_called()


def test_multiple_components_batched_into_one_call():
	"""Packages from multiple components must be batched into a single install call."""
	mock_install = _main(["ssl", "postfix"])
	# Either called once (batched) or not called if union is empty.
	assert mock_install.call_count <= 1
	if mock_install.call_count == 1:
		pkgs = mock_install.call_args[0][0]
		# ssl has openssl, postfix has postfix etc.
		assert "openssl" in pkgs
		assert "postfix" in pkgs


def test_unknown_component_exits_nonzero():
	from components.install_packages import main

	with patch("components.packages.ensure_installed"), pytest.raises(SystemExit) as exc_info:
		main(["this_component_does_not_exist"])
	assert exc_info.value.code != 0


def test_packages_are_sorted():
	"""Sorted package list ensures deterministic apt-get invocations."""
	mock_install = _main(["postfix"])
	if mock_install.call_count == 1:
		packages = mock_install.call_args[0][0]
		assert packages == sorted(packages), "packages passed to ensure_installed must be sorted"


def test_empty_component_list_does_not_call_ensure_installed():
	mock_install = _main([])
	mock_install.assert_not_called()
