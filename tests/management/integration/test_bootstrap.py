"""Integration tests for auth/bootstrap.py.

bootstrap_first_admin() writes directly to the DB without kicking DNS/web update,
so no mocks are needed for the bootstrap function itself. has_admin_users() and
the alias creation are also covered here.
"""


# bootstrap_first_admin does not call kick(); bootstrap tests need no kick mock.


# ---------------------------------------------------------------------------
# has_admin_users
# ---------------------------------------------------------------------------


def test_has_admin_users_returns_false_on_empty_db(test_db):
	from auth.bootstrap import has_admin_users

	assert has_admin_users(test_db) is False


# ---------------------------------------------------------------------------
# bootstrap_first_admin - success path
# ---------------------------------------------------------------------------


def test_bootstrap_first_admin_returns_ok(test_db):
	from auth.bootstrap import bootstrap_first_admin

	result = bootstrap_first_admin("admin@example.com", "SecurePass123!", test_db)
	assert result == "OK"


def test_has_admin_users_returns_true_after_bootstrap(test_db):
	from auth.bootstrap import bootstrap_first_admin, has_admin_users

	bootstrap_first_admin("admin@example.com", "SecurePass123!", test_db)
	assert has_admin_users(test_db) is True


def test_bootstrapped_user_has_admin_privilege(test_db):
	from auth.bootstrap import bootstrap_first_admin

	bootstrap_first_admin("admin@example.com", "SecurePass123!", test_db)

	from mail.mailconfig.users import get_mail_user_privileges

	privs = get_mail_user_privileges("admin@example.com", test_db)
	assert "admin" in privs


def test_bootstrap_creates_administrator_alias(test_db):
	from auth.bootstrap import bootstrap_first_admin

	bootstrap_first_admin("admin@example.com", "SecurePass123!", test_db)

	# The alias source is administrator@PRIMARY_HOSTNAME.
	expected_source = "administrator@" + test_db["PRIMARY_HOSTNAME"]
	from mail.mailconfig.aliases import get_mail_aliases

	sources = [src for src, _, _, _ in get_mail_aliases(test_db)]
	assert expected_source in sources, f"Expected alias {expected_source!r} not found in {sources}"


def test_bootstrap_administrator_alias_forwards_to_admin(test_db):
	from auth.bootstrap import bootstrap_first_admin

	bootstrap_first_admin("admin@example.com", "SecurePass123!", test_db)

	expected_source = "administrator@" + test_db["PRIMARY_HOSTNAME"]
	from mail.mailconfig.aliases import get_mail_aliases

	alias_map = {src: dst for src, dst, _, _ in get_mail_aliases(test_db)}
	assert alias_map.get(expected_source) == "admin@example.com"


# ---------------------------------------------------------------------------
# bootstrap_first_admin - validation failures
# ---------------------------------------------------------------------------


def test_bootstrap_invalid_email_returns_error(test_db):
	from auth.bootstrap import bootstrap_first_admin

	result = bootstrap_first_admin("not-an-email", "SecurePass123!", test_db)
	assert isinstance(result, tuple)
	assert result[1] == 400


def test_bootstrap_short_password_returns_error(test_db):
	from auth.bootstrap import bootstrap_first_admin

	result = bootstrap_first_admin("admin@example.com", "short", test_db)
	assert isinstance(result, tuple)
	assert result[1] == 400


def test_bootstrap_uppercase_email_returns_error(test_db):
	from auth.bootstrap import bootstrap_first_admin

	result = bootstrap_first_admin("Admin@Example.com", "SecurePass123!", test_db)
	assert isinstance(result, tuple)
	assert result[1] == 400


# ---------------------------------------------------------------------------
# bootstrap_first_admin - duplicate admin
# ---------------------------------------------------------------------------


def test_bootstrap_same_email_second_call_returns_409(test_db):
	# Inserting the same email twice triggers a UNIQUE constraint IntegrityError
	# which bootstrap_first_admin maps to 409.
	from auth.bootstrap import bootstrap_first_admin

	bootstrap_first_admin("admin@example.com", "SecurePass123!", test_db)
	result = bootstrap_first_admin("admin@example.com", "AnotherPass99!", test_db)
	assert isinstance(result, tuple)
	assert result[1] == 409
