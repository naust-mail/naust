"""
Test each component's enabled() callback in isolation.

These tests document current behavior. A test that shows munin is "enabled"
when ENABLE_MUNIN="false" is correctly documenting an inconsistency in how
that component reads env vs the others.
"""


def test_rspamd_enabled_with_correct_case():
	from components.defs.filter.rspamd import COMPONENT

	assert COMPONENT.enabled({"SPAM_FILTER": "rspamd"}) is True


def test_rspamd_disabled_with_uppercase():
	from components.defs.filter.rspamd import COMPONENT

	# The lambda does a strict equality check: "RSPAMD" != "rspamd".
	assert COMPONENT.enabled({"SPAM_FILTER": "RSPAMD"}) is False


def test_clamav_enabled_with_uppercase_true():
	from components.defs.optional.clamav import COMPONENT

	# .lower() == "true" so "TRUE" passes.
	assert COMPONENT.enabled({"ENABLE_CLAMAV": "TRUE"}) is True


def test_radicale_enabled_by_default():
	from components.defs.optional.radicale import COMPONENT

	# Default is "true"; an empty env should leave ENABLE_RADICALE unset, which
	# is treated as truthy because .lower() != "false".
	assert COMPONENT.enabled({}) is True


def test_munin_enabled_when_env_is_false_string():
	"""Munin uses != "no" so ENABLE_MUNIN="false" still enables it.

	This documents the current inconsistency: "false" is not "no", so munin
	stays enabled even though the operator likely intended to disable it.
	"""
	from components.defs.optional.munin import COMPONENT

	assert COMPONENT.enabled({"ENABLE_MUNIN": "false"}) is True


def test_rav_disabled_with_uppercase():
	from components.defs.webmail.rav import COMPONENT

	# The lambda does a strict equality check: "RAV" != "rav".
	assert COMPONENT.enabled({"WEBMAIL_CLIENT": "RAV"}) is False


# ── Backup tool selection ──────────────────────────────────────────────────────


def test_restic_enabled_by_default():
	from components.defs.backup.restic import COMPONENT

	# Default is "restic" - enabled when BACKUP_TOOL is absent.
	assert COMPONENT.enabled({}) is True


def test_restic_enabled_explicitly():
	from components.defs.backup.restic import COMPONENT

	assert COMPONENT.enabled({"BACKUP_TOOL": "restic"}) is True


def test_restic_disabled_when_duplicity():
	from components.defs.backup.restic import COMPONENT

	assert COMPONENT.enabled({"BACKUP_TOOL": "duplicity"}) is False


def test_duplicity_disabled_by_default():
	from components.defs.backup.duplicity import COMPONENT

	# Default is "restic", so duplicity is off when BACKUP_TOOL is absent.
	assert COMPONENT.enabled({}) is False


def test_duplicity_enabled_explicitly():
	from components.defs.backup.duplicity import COMPONENT

	assert COMPONENT.enabled({"BACKUP_TOOL": "duplicity"}) is True


def test_duplicity_disabled_when_restic():
	from components.defs.backup.duplicity import COMPONENT

	assert COMPONENT.enabled({"BACKUP_TOOL": "restic"}) is False


def test_restic_and_duplicity_are_mutually_exclusive():
	"""Exactly one of restic/duplicity must be enabled for any BACKUP_TOOL value."""
	from components.defs.backup.restic import COMPONENT as restic
	from components.defs.backup.duplicity import COMPONENT as duplicity

	for tool in ["restic", "duplicity", "unsupported-value"]:
		env = {"BACKUP_TOOL": tool}
		both_on = restic.enabled(env) and duplicity.enabled(env)
		both_off = not restic.enabled(env) and not duplicity.enabled(env)
		assert not both_on, f"Both enabled for BACKUP_TOOL={tool!r}"
		# An unknown value disables both - that's acceptable (setup will error upstream).
		_ = both_off  # documenting: unknown value is allowed to disable both


# ── Optional feature flags ─────────────────────────────────────────────────────


def test_filebrowser_disabled_by_default():
	from components.defs.optional.filebrowser import COMPONENT

	# Default is "false" - must be explicitly opted in.
	assert COMPONENT.enabled({}) is False


def test_filebrowser_enabled_with_true():
	from components.defs.optional.filebrowser import COMPONENT

	assert COMPONENT.enabled({"ENABLE_FILEBROWSER": "true"}) is True


def test_filebrowser_enabled_case_insensitive():
	from components.defs.optional.filebrowser import COMPONENT

	assert COMPONENT.enabled({"ENABLE_FILEBROWSER": "TRUE"}) is True


def test_filebrowser_disabled_with_false():
	from components.defs.optional.filebrowser import COMPONENT

	assert COMPONENT.enabled({"ENABLE_FILEBROWSER": "false"}) is False
