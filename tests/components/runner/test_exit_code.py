"""
Verify that _run_doit() propagates a non-zero exit when a task has a
task_dep that does not exist.
"""

import os
import pytest
from unittest.mock import patch

from components.runner import _run_doit  # noqa: PLC2701


def test_nonzero_exit_on_bad_dep(tmp_path):
	tasks = [{"name": "broken", "actions": [], "task_dep": ["nonexistent:task"]}]
	fake_db = str(tmp_path / "setup-state.db")
	os.makedirs(str(tmp_path), exist_ok=True)

	with patch("components.runner.STATE_DB", fake_db), pytest.raises(SystemExit) as exc_info:
		_run_doit({"fake_comp": tasks})

	assert exc_info.value.code != 0
