# One check per network service (other than DNS, which has its own file -
# see dns_service.py). Each is independent, so they run as separate checks
# rather than as steps of one another - a downed mail port shouldn't hide
# whether the web ports are up.

from ..registry import check
from ..reporter import CheckFailed
from .. import utils


def _is_rspamd(env):
	return env.get("SPAM_FILTER", "spamassassin") == "rspamd"


def _is_spamassassin(env):
	return env.get("SPAM_FILTER", "spamassassin") != "rspamd"


# Services always present regardless of spam filter or webmail choice.
_SERVICE_NAMES_ALWAYS = [
	"Dovecot LMTP LDA",
	"Naust Management Daemon",
	"SSH Login (ssh)",
	"Public DNS (nsd4)",
	"Incoming Mail (SMTP/postfix)",
	"Outgoing Mail (SMTP 465/postfix)",
	"Outgoing Mail (SMTP 587/postfix)",
	"IMAPS (dovecot)",
	"Mail Filters (Sieve/dovecot)",
	"HTTP Web (nginx)",
	"HTTPS Web (nginx)",
]

_SERVICE_NAMES_RAV = ["rav Webmail (rav)"]

# Only present when SPAM_FILTER=spamassassin.
_SERVICE_NAMES_SPAMASSASSIN = [
	"Postgrey",
	"Spamassassin",
	"OpenDKIM",
	"OpenDMARC",
]

# Only present when SPAM_FILTER=rspamd.
_SERVICE_NAMES_RSPAMD = [
	"rspamd",
	"Redis",
]


def _make_check(service_name):
	def check_fn(env, report):
		with report.step(f"{service_name} is reachable"):
			service = next((s for s in utils.get_services(env) if s["name"] == service_name), None)
			if service is None:
				return
			ok, msg = utils.check_service_reachable(service, env)
			if not ok:
				raise CheckFailed(msg)

	return check_fn


def _is_rav(env):
	return env.get("WEBMAIL_CLIENT", "rav") == "rav"


for _name in _SERVICE_NAMES_ALWAYS:
	check(f"service:{_name}", category="services")(_make_check(_name))

for _name in _SERVICE_NAMES_RAV:
	check(f"service:{_name}", category="services", enabled=_is_rav)(_make_check(_name))

for _name in _SERVICE_NAMES_SPAMASSASSIN:
	check(f"service:{_name}", category="services", enabled=_is_spamassassin)(_make_check(_name))

for _name in _SERVICE_NAMES_RSPAMD:
	check(f"service:{_name}", category="services", enabled=_is_rspamd)(_make_check(_name))


@check("fail2ban", category="services")
def check_fail2ban(env, report):
	with report.step("fail2ban is running"):
		code, _out = utils.shell('check_output', ["fail2ban-client", "status"], capture_stderr=True, trap=True)
		if code != 0:
			raise CheckFailed("fail2ban is not running.")
