"""
Verify that make_tasks() raises KeyError for components that use direct dict
indexing on required env keys, and that dovecot tolerates a missing
PRIMARY_HOSTNAME by falling back to a default.
"""

import pytest
from unittest.mock import patch, MagicMock


_DOVECOT_FAKE = MagicMock(stdout="2.3.21 (abc)", returncode=0)
# free -tm output: the last line is "Total  <total_mb>  <used>  <free>"
_FREE_FAKE = MagicMock(stdout="              total        used        free\nMem:           7936        1234        6702\nSwap:          2048           0        2048\nTotal:        9984        1234        8750\n", returncode=0)


def _subprocess_side_effect(cmd, **kwargs):
	if isinstance(cmd, list) and cmd and cmd[0] == "free":
		return _FREE_FAKE
	return _DOVECOT_FAKE


def test_dovecot_raises_without_storage_root():
	"""dovecot.make_tasks() directly indexes env['STORAGE_ROOT']."""
	from components.defs import dovecot

	with patch("subprocess.run", return_value=_DOVECOT_FAKE), pytest.raises(KeyError):
		dovecot.make_tasks({}, "baremetal")


def test_ssl_raises_without_storage_root():
	"""ssl.make_tasks() directly indexes env['STORAGE_ROOT']."""
	from components.defs import ssl

	with pytest.raises(KeyError):
		ssl.make_tasks({}, "baremetal")


def test_dovecot_succeeds_without_primary_hostname(tmp_path):
	"""dovecot.make_tasks() uses .get() for PRIMARY_HOSTNAME so it has a default."""
	from components.defs import dovecot

	env = {"STORAGE_ROOT": str(tmp_path)}
	with patch("subprocess.run", side_effect=_subprocess_side_effect):
		tasks = dovecot.make_tasks(env, "baremetal")
	assert isinstance(tasks, list)
	assert len(tasks) > 0
