"""Tests for SPF relay verification in services/status_checks/checks/network.py.

Covers the check_outbound_smtp SPF include path added in 2026-06-27:
- relay configured + spf_include set + SPF record contains include -> no warn
- relay configured + spf_include set + SPF record missing include -> warn
- relay configured + spf_include set + no SPF record found -> warn
- relay configured + no spf_include -> warn (missing configuration)
- no relay configured -> no SPF check runs

Design: stubs are installed into sys.modules only inside the module-scoped
fixture, and restored on teardown. This prevents stub entries from leaking
into other test modules that import the real services.* packages.
"""

import importlib.util
import pathlib
import sys
import types
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Stub builders (no sys.modules side effects - called only from the fixture)
# ---------------------------------------------------------------------------

_NETWORK_PATH = pathlib.Path(__file__).parents[3] / "management" / "services" / "status_checks" / "checks" / "network.py"

_STUB_NAMES = [
	"services",
	"services.status_checks",
	"services.status_checks.checks",
	"services.status_checks.registry",
	"services.status_checks.reporter",
	"services.status_checks.utils",
]


def _build_stubs():
	"""Build stub modules for network.py's relative imports. No sys.modules side effects."""

	def _check_decorator(name, **kwargs):
		def decorator(fn):
			return fn

		return decorator

	class CheckFailed(Exception):
		pass

	class Report:
		def __init__(self):
			self.warnings = []
			self.failed_steps = []

		def warn(self, msg):
			self.warnings.append(msg)

		def step(self, label):
			return self

		def __enter__(self):
			return self

		def __exit__(self, exc_type, exc_val, exc_tb):
			if exc_type is CheckFailed:
				self.failed_steps.append(str(exc_val))
				return True
			return False

	def _shell(mode, cmd, trap=False, **kwargs):
		return (0, 0)

	def _query_dns(qname, rtype, nxdomain=None, at=None, as_list=False):
		return [] if as_list else nxdomain

	def _pkg(name):
		m = types.ModuleType(name)
		m.__path__ = []
		m.__package__ = name
		return m

	services = _pkg("services")
	sc = _pkg("services.status_checks")
	sc_checks = _pkg("services.status_checks.checks")

	registry = types.ModuleType("services.status_checks.registry")
	registry.check = _check_decorator

	reporter = types.ModuleType("services.status_checks.reporter")
	reporter.CheckFailed = CheckFailed

	utils_stub = types.ModuleType("services.status_checks.utils")
	utils_stub.shell = _shell
	utils_stub.query_dns = _query_dns

	stubs = {
		"services": services,
		"services.status_checks": sc,
		"services.status_checks.checks": sc_checks,
		"services.status_checks.registry": registry,
		"services.status_checks.reporter": reporter,
		"services.status_checks.utils": utils_stub,
	}
	return stubs, Report, CheckFailed, utils_stub


def _load_network():
	spec = importlib.util.spec_from_file_location(
		"services.status_checks.checks.network",
		_NETWORK_PATH,
		submodule_search_locations=[],
	)
	mod = importlib.util.module_from_spec(spec)
	mod.__package__ = "services.status_checks.checks"
	spec.loader.exec_module(mod)
	return mod


# ---------------------------------------------------------------------------
# Fixture: owns the stub lifecycle for this module
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def net():
	"""Install stubs, load network.py, yield context, restore sys.modules on teardown."""
	stubs, Report, CheckFailed, utils_stub = _build_stubs()

	saved = {name: sys.modules.get(name) for name in _STUB_NAMES}
	for name, mod in stubs.items():
		sys.modules[name] = mod

	network = _load_network()

	yield types.SimpleNamespace(
		network=network,
		utils_stub=utils_stub,
		Report=Report,
		CheckFailed=CheckFailed,
	)

	for name in _STUB_NAMES:
		prev = saved[name]
		if prev is None:
			sys.modules.pop(name, None)
		else:
			sys.modules[name] = prev


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_ENV = {"PRIMARY_HOSTNAME": "box.example.com", "PUBLIC_IP": "1.2.3.4"}


def _run(net, *, env=_ENV, relay_host="smtp.sendgrid.net", spf_include="sendgrid.net", port=587, shell_ok=True, txt_records=None):
	settings = {}
	if relay_host:
		settings["smtp_relay"] = {"host": relay_host, "port": port, "spf_include": spf_include}

	records = txt_records if txt_records is not None else []

	def _query_dns(qname, rtype, nxdomain=None, at=None, as_list=False):
		return records if as_list else (records[0] if records else nxdomain)

	report = net.Report()
	with patch("core.utils.load_settings", return_value=settings), patch.object(net.utils_stub, "query_dns", side_effect=_query_dns), patch.object(net.utils_stub, "shell", return_value=(0, 0 if shell_ok else 1)):
		net.network.check_outbound_smtp(env, report)
	return report


# ---------------------------------------------------------------------------
# No relay
# ---------------------------------------------------------------------------


class TestNoRelay:
	def test_no_warnings_when_port25_open(self, net):
		report = _run(net, relay_host="", spf_include="", shell_ok=True)
		assert report.warnings == []

	def test_failed_step_when_port25_blocked(self, net):
		report = _run(net, relay_host="", spf_include="", shell_ok=False)
		assert report.failed_steps


# ---------------------------------------------------------------------------
# Relay set, SPF include missing
# ---------------------------------------------------------------------------


class TestRelayNoSpfInclude:
	def test_warns_when_spf_include_missing(self, net):
		report = _run(net, spf_include="")
		assert any("SPF include" in w for w in report.warnings)

	def test_warning_mentions_relay_host(self, net):
		report = _run(net, relay_host="smtp.mailgun.org", spf_include="")
		assert any("smtp.mailgun.org" in w for w in report.warnings)


# ---------------------------------------------------------------------------
# Relay set, SPF include configured - DNS verification
# ---------------------------------------------------------------------------


class TestRelaySpfDnsVerification:
	def test_no_warning_when_spf_contains_include(self, net):
		report = _run(net, txt_records=["v=spf1 mx include:sendgrid.net -all"])
		assert report.warnings == []

	def test_warns_when_spf_missing_include(self, net):
		report = _run(net, txt_records=["v=spf1 mx -all"])
		assert any("sendgrid.net" in w for w in report.warnings)

	def test_warns_when_no_spf_record(self, net):
		report = _run(net, txt_records=["v=dkim1 k=rsa; p=abc"])
		assert any("SPF" in w or "spf" in w.lower() for w in report.warnings)

	def test_warns_when_no_txt_records(self, net):
		report = _run(net, txt_records=[])
		assert any("SPF" in w or "spf" in w.lower() for w in report.warnings)

	def test_include_substring_not_partial_match(self, net):
		# include:notsendgrid.net must not satisfy include:sendgrid.net
		report = _run(
			net,
			spf_include="sendgrid.net",
			txt_records=["v=spf1 mx include:notsendgrid.net -all"],
		)
		assert any("sendgrid.net" in w for w in report.warnings)

	def test_query_dns_raises_exception(self, net):
		# OSError from a DNS timeout must not crash the check
		def _raise(*a, **kw):
			raise OSError("network unreachable")

		settings = {"smtp_relay": {"host": "smtp.sendgrid.net", "port": 587, "spf_include": "sendgrid.net"}}
		report = net.Report()
		with patch("core.utils.load_settings", return_value=settings), patch.object(net.utils_stub, "query_dns", side_effect=_raise), patch.object(net.utils_stub, "shell", return_value=(0, 0)):
			net.network.check_outbound_smtp(_ENV, report)
		assert report.warnings  # must warn, not raise

	def test_query_dns_returns_none(self, net):
		# query_dns returning None must not crash
		def _none(*a, **kw):
			return None

		settings = {"smtp_relay": {"host": "smtp.sendgrid.net", "port": 587, "spf_include": "sendgrid.net"}}
		report = net.Report()
		with patch("core.utils.load_settings", return_value=settings), patch.object(net.utils_stub, "query_dns", side_effect=_none), patch.object(net.utils_stub, "shell", return_value=(0, 0)):
			net.network.check_outbound_smtp(_ENV, report)
		assert report.warnings  # None-safe: must warn about missing SPF

	def test_spf_redirect_not_accepted_as_include(self, net):
		# redirect= is not include: - warning is correct behavior, pin it
		report = _run(net, txt_records=["v=spf1 redirect=_spf.sendgrid.net -all"])
		assert any("sendgrid.net" in w for w in report.warnings)

	def test_multiple_spf_records_uses_first(self, net):
		# Multiple v=spf1 records: first match wins, must not false-warn
		records = ["v=dmarc1 p=none", "v=spf1 include:sendgrid.net -all", "v=spf1 -all"]
		report = _run(net, txt_records=records)
		assert report.warnings == []

	def test_spf_record_missing_space_after_tag(self, net):
		# "v=spf1include:..." (no space) is not a valid SPF record - must warn
		report = _run(net, txt_records=["v=spf1include:sendgrid.net -all"])
		assert any("SPF" in w or "spf" in w.lower() for w in report.warnings)

	def test_no_dns_check_when_hostname_absent(self, net):
		called = []

		def _query_dns(qname, rtype, nxdomain=None, at=None, as_list=False):
			called.append(qname)
			return []

		settings = {"smtp_relay": {"host": "smtp.sendgrid.net", "port": 587, "spf_include": "sendgrid.net"}}
		env = {"PRIMARY_HOSTNAME": "", "PUBLIC_IP": "1.2.3.4"}
		report = net.Report()
		with patch("core.utils.load_settings", return_value=settings), patch.object(net.utils_stub, "query_dns", side_effect=_query_dns), patch.object(net.utils_stub, "shell", return_value=(0, 0)):
			net.network.check_outbound_smtp(env, report)

		assert called == [], "query_dns must not fire when PRIMARY_HOSTNAME is empty"
