"""Integration tests for mail/mailconfig/aliases.py.

kick() (which calls DNS/web update) and dovecot_quota_recalc are mocked
so tests run without system daemons.
"""

from unittest.mock import patch


# kick is imported lazily via `from .sync import kick` inside each function.
_KICK_ALIAS = "mail.mailconfig.sync.kick"
_KICK_USERS = "mail.mailconfig.sync.kick"
_DOVEADM = "mail.mailconfig.users.dovecot_quota_recalc"
_REVOKE_ALL = "mail.mailconfig.users.revoke_all_tokens"


def _add_user(email, env, pw="Password123!", privs=""):
	with patch(_KICK_USERS, return_value="ok"), patch(_DOVEADM):
		from mail.mailconfig.users import add_mail_user

		return add_mail_user(email, pw, privs, "0", env)


def _add_alias(address, forwards_to, env, permitted_senders="", update_if_exists=False):
	with patch(_KICK_ALIAS, return_value="ok"):
		from mail.mailconfig.aliases import add_mail_alias

		return add_mail_alias(address, forwards_to, permitted_senders, env, update_if_exists=update_if_exists)


def _remove_alias(address, env):
	with patch(_KICK_ALIAS, return_value="ok"):
		from mail.mailconfig.aliases import remove_mail_alias

		return remove_mail_alias(address, env)


# ---------------------------------------------------------------------------
# Basic add / validation
# ---------------------------------------------------------------------------


def test_add_mail_alias_succeeds(test_db):
	_add_user("user@example.com", test_db)
	result = _add_alias("alias@example.com", "user@example.com", test_db)
	assert not (isinstance(result, tuple) and result[1] == 400)


def test_add_mail_alias_invalid_source_returns_error(test_db):
	result = _add_alias("invalid-not-an-email", "user@example.com", test_db)
	assert isinstance(result, tuple)
	assert result[1] == 400


def test_add_mail_alias_invalid_destination_returns_error(test_db):
	result = _add_alias("alias@example.com", "not-an-email", test_db)
	assert isinstance(result, tuple)
	assert result[1] == 400


def test_add_mail_alias_empty_address_returns_error(test_db):
	result = _add_alias("", "user@example.com", test_db)
	assert isinstance(result, tuple)
	assert result[1] == 400


def test_add_catch_all_alias_succeeds(test_db):
	_add_user("catch@example.com", test_db)
	# "@domain.tld" is a catch-all - valid in alias mode.
	result = _add_alias("@catchall.example.com", "catch@example.com", test_db)
	assert not (isinstance(result, tuple) and result[1] == 400)


def test_add_alias_no_forwards_and_no_permitted_senders_returns_error(test_db):
	# forwards_to is empty and permitted_senders is also empty - must fail.
	result = _add_alias("empty@example.com", "", test_db)
	assert isinstance(result, tuple)
	assert result[1] == 400


# ---------------------------------------------------------------------------
# update_if_exists
# ---------------------------------------------------------------------------


def test_update_if_exists_true_updates_alias(test_db):
	_add_user("dest1@example.com", test_db)
	_add_user("dest2@example.com", test_db)
	_add_alias("update@example.com", "dest1@example.com", test_db)

	# Now update with a new destination.
	result = _add_alias("update@example.com", "dest2@example.com", test_db, update_if_exists=True)
	assert not (isinstance(result, tuple) and result[1] == 400)

	from mail.mailconfig.aliases import get_mail_aliases

	aliases = {src: dst for src, dst, _, _ in get_mail_aliases(test_db)}
	assert aliases.get("update@example.com") == "dest2@example.com"


def test_update_if_exists_false_on_existing_alias_returns_error(test_db):
	_add_user("only@example.com", test_db)
	_add_alias("dupe@example.com", "only@example.com", test_db)

	result = _add_alias("dupe@example.com", "only@example.com", test_db, update_if_exists=False)
	assert isinstance(result, tuple)
	assert result[1] == 400
	assert "already exists" in result[0].lower()


# ---------------------------------------------------------------------------
# remove_mail_alias
# ---------------------------------------------------------------------------


def test_remove_mail_alias_succeeds(test_db):
	_add_user("del@example.com", test_db)
	_add_alias("todel@example.com", "del@example.com", test_db)

	result = _remove_alias("todel@example.com", test_db)
	assert not (isinstance(result, tuple) and result[1] == 400)

	from mail.mailconfig.aliases import get_mail_aliases

	sources = [src for src, _, _, _ in get_mail_aliases(test_db)]
	assert "todel@example.com" not in sources


def test_remove_nonexistent_alias_returns_error(test_db):
	result = _remove_alias("ghost@example.com", test_db)
	assert isinstance(result, tuple)
	assert result[1] == 400


# ---------------------------------------------------------------------------
# DCV address restriction
# ---------------------------------------------------------------------------


def test_dcv_address_to_non_admin_returns_error(test_db):
	# admin@ is a DCV address; destination must be a system admin.
	_add_user("nonadmin@example.com", test_db)  # no admin priv
	result = _add_alias("admin@example.com", "nonadmin@example.com", test_db)
	assert isinstance(result, tuple)
	assert result[1] == 400
	assert "domain control validation" in result[0].lower()


def test_dcv_address_to_admin_succeeds(test_db):
	# admin@ forwarding to an actual admin should be permitted.
	_add_user("sysadmin@example.com", test_db, privs="admin")
	result = _add_alias("admin@example.com", "sysadmin@example.com", test_db)
	assert not (isinstance(result, tuple) and result[1] == 400)


# ---------------------------------------------------------------------------
# get_mail_aliases includes added alias
# ---------------------------------------------------------------------------


def test_get_mail_aliases_includes_added_alias(test_db):
	_add_user("listed@example.com", test_db)
	_add_alias("myalias@example.com", "listed@example.com", test_db)

	from mail.mailconfig.aliases import get_mail_aliases

	sources = [src for src, _, _, _ in get_mail_aliases(test_db)]
	assert "myalias@example.com" in sources
