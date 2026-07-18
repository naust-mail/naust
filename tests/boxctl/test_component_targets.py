"""Regression: config-writing tasks in webmail components must declare targets=.

Without targets=, doit's uptodate stamp can be valid while the artifact file
was deleted, causing setup to skip writing it. This is the stamp/artifact gap
bug fixed in 2026-06-26. Each affected task is listed explicitly so that
removing targets= fails a named test rather than silently regressing.
"""

from unittest.mock import patch

from tests.components._helpers import _subprocess_dispatch

_BASE_ENV = {
	"STORAGE_ROOT": "/tmp/test-storage",  # noqa: S108
	"PRIMARY_HOSTNAME": "box.example.com",
	"PRIVATE_IP": "10.0.0.1",
	"PRIVATE_IPV6": "",
	"PUBLIC_IP": "1.2.3.4",
	"EMAIL_ADDR": "admin@example.com",
	"SPAM_FILTER": "rspamd",
	"WEBMAIL_CLIENT": "roundcube",
	"ENABLE_RADICALE": "true",
	"ENABLE_FILEBROWSER": "false",
	"ENABLE_CLAMAV": "false",
}


def _tasks_for(module_path: str, env: dict) -> dict[str, dict]:
	"""Return {task_name: task_dict} for a component's make_tasks()."""
	mod = __import__(module_path, fromlist=["make_tasks"])
	with patch("subprocess.run", side_effect=_subprocess_dispatch):
		tasks = mod.make_tasks(env, "baremetal")
	return {t["name"]: t for t in tasks}


# ---------------------------------------------------------------------------
# roundcube
# ---------------------------------------------------------------------------


class TestRoundcubeTargets:
	def setup_method(self):
		self.tasks = _tasks_for("components.defs.webmail.roundcube", _BASE_ENV)

	def test_config_task_has_targets(self):
		assert self.tasks["config"].get("targets"), "roundcube:config must declare targets="

	def test_config_targets_contains_config_php(self):
		targets = self.tasks["config"]["targets"]
		assert any("config.inc.php" in str(t) for t in targets)

	def test_carddav_conf_task_has_targets(self):
		assert self.tasks["carddav-conf"].get("targets"), "roundcube:carddav-conf must declare targets="

	def test_carddav_conf_targets_contains_config_php(self):
		targets = self.tasks["carddav-conf"]["targets"]
		assert any("config.inc.php" in str(t) for t in targets)


# ---------------------------------------------------------------------------
# snappymail
# ---------------------------------------------------------------------------

_SNAPPYMAIL_ENV = {**_BASE_ENV, "WEBMAIL_CLIENT": "snappymail"}


class TestSnappymailTargets:
	def setup_method(self):
		self.tasks = _tasks_for("components.defs.webmail.snappymail", _SNAPPYMAIL_ENV)

	def test_config_task_has_targets(self):
		assert self.tasks["config"].get("targets"), "snappymail:config must declare targets="

	def test_config_targets_contains_config_ini(self):
		targets = self.tasks["config"]["targets"]
		assert any("config.ini" in str(t) for t in targets)

	def test_domain_task_has_targets(self):
		assert self.tasks["domain"].get("targets"), "snappymail:domain must declare targets="

	def test_domain_targets_contains_default_json(self):
		targets = self.tasks["domain"]["targets"]
		assert any("default.json" in str(t) for t in targets)


# ---------------------------------------------------------------------------
# cypht
# ---------------------------------------------------------------------------

_CYPHT_ENV = {**_BASE_ENV, "WEBMAIL_CLIENT": "cypht"}


class TestCyphtTargets:
	def setup_method(self):
		self.tasks = _tasks_for("components.defs.webmail.cypht", _CYPHT_ENV)

	def test_config_task_has_targets(self):
		assert self.tasks["config"].get("targets"), "cypht:config must declare targets="

	def test_config_targets_contains_env_file(self):
		targets = self.tasks["config"]["targets"]
		assert any(".env" in str(t) for t in targets)
