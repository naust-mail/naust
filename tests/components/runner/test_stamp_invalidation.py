"""
Multi-step test: verify that the stamp mechanism prevents re-runs on unchanged
configs and fires selectively when a single env key changes.

This is the architectural guarantee that makes _run_all_enabled efficient:
stamps mean most tasks are no-ops even when all enabled components are evaluated.

Steps:
  1. Run full component graph (rspamd) - everything executes, stamps stored.
  2. Run again unchanged - all stamped components are skipped.
  3. Change SPAM_FILTER to spamassassin - only affected components re-run.
"""

from unittest.mock import patch

from doit.tools import run_once

import components.runner as _runner
from tests.components.conftest import make_env
from tests.components._helpers import build_graph_full


def _noopify(graph: dict[str, list[dict]]) -> dict[str, list[dict]]:
	"""Replace task actions with no-ops while preserving uptodate stamps.

	Strips targets so stamp checks rely solely on config_changed/run_once.
	Tasks with no uptodate (only targets for idempotency, e.g. dkim-key)
	get run_once added - they run exactly once then stay cached,
	which is the correct semantics for a second-run test.
	"""
	result = {}
	for comp_name, tasks in graph.items():
		nooped = []
		for task in tasks:
			t = {k: v for k, v in task.items() if k not in {"actions", "targets"}}
			t["actions"] = [lambda: None]
			if "uptodate" not in t:
				t["uptodate"] = [run_once]
			nooped.append(t)
		result[comp_name] = nooped
	return result


# Components that must be cached on a second unchanged run. These all use
# config_changed(fn_stamp(...)) or config_changed(version_stamp) - their
# uptodate result is purely stamp-driven with no filesystem side conditions.
_MUST_CACHE = {"postfix", "rspamd", "dovecot", "dns", "ssl", "management", "users", "nginx"}


def test_stamps_prevent_reruns(tmp_path):
	"""Core components must not re-run when config is unchanged."""
	state_db = str(tmp_path / "state.db")
	env = make_env(
		tmp_path,
		SPAM_FILTER="rspamd",
		WEBMAIL_CLIENT="none",
		ENABLE_CLAMAV="false",
		ENABLE_RADICALE="false",
		ENABLE_FILEBROWSER="false",
	)

	with patch.object(_runner, "STATE_DB", state_db):
		graph = build_graph_full(env, "baremetal")

		ran1 = _runner._run_doit(_noopify(graph))  # noqa: SLF001
		assert len(ran1) > 0, "First run must execute tasks"

		ran2 = _runner._run_doit(_noopify(graph))  # noqa: SLF001
		cached = _MUST_CACHE & ran1  # only assert on components that ran in run 1
		assert not (cached & ran2), f"These components ran again despite no config change: {cached & ran2}"


def test_spam_filter_switch_reruns_only_affected_components(tmp_path):
	"""Switching SPAM_FILTER must re-run only spam-related components."""
	state_db = str(tmp_path / "state.db")
	rspamd_env = make_env(
		tmp_path,
		SPAM_FILTER="rspamd",
		WEBMAIL_CLIENT="none",
		ENABLE_CLAMAV="false",
		ENABLE_RADICALE="false",
		ENABLE_FILEBROWSER="false",
	)
	spam_env = make_env(
		tmp_path,
		SPAM_FILTER="spamassassin",
		WEBMAIL_CLIENT="none",
		ENABLE_CLAMAV="false",
		ENABLE_RADICALE="false",
		ENABLE_FILEBROWSER="false",
	)

	with patch.object(_runner, "STATE_DB", state_db):
		# Prime stamps with the rspamd config.
		rspamd_graph = build_graph_full(rspamd_env, "baremetal")
		ran1 = _runner._run_doit(_noopify(rspamd_graph))  # noqa: SLF001
		assert len(ran1) > 0

		# Switch spam filter - build a fresh graph (avoid doit's in-place name mutation).
		spam_graph = build_graph_full(spam_env, "baremetal")
		ran2 = _runner._run_doit(_noopify(spam_graph))  # noqa: SLF001

		# postfix:spam-filter stamp includes the SPAM_FILTER value - must re-run.
		assert "postfix" in ran2, "postfix must re-run when SPAM_FILTER changes"

		# spamassassin and dkim are newly enabled - never stamped before.
		assert "spamassassin" in ran2, "spamassassin must run on first activation"
		assert "dkim" in ran2, "dkim must run on first activation"

		# rspamd is disabled - not in graph, cannot appear in ran.
		assert "rspamd" not in ran2, "rspamd must not run when disabled"

		# dovecot was fully stamped in run 1; spamassassin:packages depends on
		# dovecot:version but that dep is already satisfied (stamped via run_once).
		assert "dovecot" not in ran2, "dovecot must not re-run when its config is unchanged"

		# Unrelated components must not re-run.
		for unaffected in ("dns", "ssl", "management", "nginx", "users"):
			if unaffected in ran1:
				assert unaffected not in ran2, f"{unaffected} must not re-run on spam filter switch"
