"""Integration tests for mail/mailconfig/domains.py - get_mail_domains()."""

from unittest.mock import patch


# kick is imported lazily via `from .sync import kick` inside each function.
_KICK_USERS = "mail.mailconfig.sync.kick"
_KICK_ALIASES = "mail.mailconfig.sync.kick"
_DOVEADM = "mail.mailconfig.users.dovecot_quota_recalc"


def _add_user(email, env, pw="Password123!"):
	with patch(_KICK_USERS, return_value="ok"), patch(_DOVEADM):
		from mail.mailconfig.users import add_mail_user

		return add_mail_user(email, pw, "", "0", env)


def _add_alias(address, forwards_to, env):
	with patch(_KICK_ALIASES, return_value="ok"):
		from mail.mailconfig.aliases import add_mail_alias

		return add_mail_alias(address, forwards_to, "", env, update_if_exists=False)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_empty_db_returns_empty_set(test_db):
	from mail.mailconfig.domains import get_mail_domains

	domains = get_mail_domains(test_db)
	assert domains == set()


def test_user_domain_included(test_db):
	_add_user("user@example.com", test_db)
	from mail.mailconfig.domains import get_mail_domains

	domains = get_mail_domains(test_db)
	assert "example.com" in domains


def test_alias_domain_included(test_db):
	_add_user("dest@example.com", test_db)
	_add_alias("alias@other.com", "dest@example.com", test_db)
	from mail.mailconfig.domains import get_mail_domains

	domains = get_mail_domains(test_db)
	assert "other.com" in domains


def test_users_only_excludes_alias_only_domains(test_db):
	_add_user("dest@userdomain.com", test_db)
	_add_alias("alias@aliasdomain.com", "dest@userdomain.com", test_db)
	from mail.mailconfig.domains import get_mail_domains

	# With users_only=True only userdomain.com should appear.
	domains = get_mail_domains(test_db, users_only=True)
	assert "userdomain.com" in domains
	assert "aliasdomain.com" not in domains


def test_users_only_false_includes_alias_domains(test_db):
	_add_user("dest@userdomain.com", test_db)
	_add_alias("alias@aliasdomain.com", "dest@userdomain.com", test_db)
	from mail.mailconfig.domains import get_mail_domains

	domains = get_mail_domains(test_db, users_only=False)
	assert "userdomain.com" in domains
	assert "aliasdomain.com" in domains


def test_multiple_users_same_domain_counted_once(test_db):
	_add_user("a@shared.com", test_db)
	_add_user("b@shared.com", test_db)
	from mail.mailconfig.domains import get_mail_domains

	domains = get_mail_domains(test_db)
	# set semantics - domain appears once.
	assert list(domains).count("shared.com") == 1


def test_returns_set_type(test_db):
	from mail.mailconfig.domains import get_mail_domains

	result = get_mail_domains(test_db)
	assert isinstance(result, set)


def test_user_removed_domain_may_disappear(test_db):
	_add_user("solo@remove.com", test_db)
	from mail.mailconfig.domains import get_mail_domains

	assert "remove.com" in get_mail_domains(test_db)

	# revoke_all_tokens is also imported lazily inside remove_mail_user.
	with patch(_KICK_USERS, return_value="ok"), patch("auth.api_tokens.revoke_all_tokens"):
		from mail.mailconfig.users import remove_mail_user

		remove_mail_user("solo@remove.com", test_db)

	# No more users or aliases for remove.com - domain should be gone.
	assert "remove.com" not in get_mail_domains(test_db)
