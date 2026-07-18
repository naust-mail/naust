"""Tests for check_relay in setup/boxctl/checks.py."""

import subprocess  # noqa: S404
from unittest.mock import patch


from boxctl.checks import check_relay, OK, WARN, OFF


def _make_conf(storage_root, hostname="box.example.com"):
	return {"STORAGE_ROOT": storage_root, "PRIMARY_HOSTNAME": hostname}


def _yaml_no_relay():
	return "{}\n"


def _yaml_relay(host="smtp.sendgrid.net", spf_include="sendgrid.net"):
	lines = f"smtp_relay:\n  host: {host}\n  port: 587\n  user: apikey\n"
	if spf_include:
		lines += f"  spf_include: {spf_include}\n"
	return lines


def _dig_result(spf_txt):
	"""Fake subprocess.run result with SPF in stdout."""
	r = subprocess.CompletedProcess(args=[], returncode=0)
	r.stdout = f'"{spf_txt}"\n'
	r.stderr = ""
	return r


# ---------------------------------------------------------------------------
# No relay configured
# ---------------------------------------------------------------------------


class TestCheckRelayOff:
	def test_missing_settings_file_is_off(self, tmp_path):
		status, _msg = check_relay(_make_conf(str(tmp_path)))
		assert status == OFF

	def test_empty_settings_is_off(self, tmp_path):
		(tmp_path / "settings.yaml").write_text("{}\n")
		status, _msg = check_relay(_make_conf(str(tmp_path)))
		assert status == OFF

	def test_no_relay_host_is_off(self, tmp_path):
		(tmp_path / "settings.yaml").write_text("smtp_relay:\n  host: ''\n")
		status, _msg = check_relay(_make_conf(str(tmp_path)))
		assert status == OFF


# ---------------------------------------------------------------------------
# Relay configured, SPF include missing
# ---------------------------------------------------------------------------


class TestCheckRelayNoSpfInclude:
	def test_warn_when_spf_include_absent(self, tmp_path):
		(tmp_path / "settings.yaml").write_text("smtp_relay:\n  host: smtp.sendgrid.net\n  port: 587\n  spf_include: ''\n")
		status, msg = check_relay(_make_conf(str(tmp_path)))
		assert status == WARN
		assert "SPF include not set" in msg

	def test_warn_message_contains_host(self, tmp_path):
		(tmp_path / "settings.yaml").write_text("smtp_relay:\n  host: smtp.mailgun.org\n  spf_include: ''\n")
		_status, msg = check_relay(_make_conf(str(tmp_path)))
		assert "smtp.mailgun.org" in msg


# ---------------------------------------------------------------------------
# Relay configured, SPF include set - DNS verification
# ---------------------------------------------------------------------------


class TestCheckRelayDnsVerification:
	def test_ok_when_spf_contains_include(self, tmp_path):
		(tmp_path / "settings.yaml").write_text(_yaml_relay())
		with patch("subprocess.run", return_value=_dig_result("v=spf1 mx include:sendgrid.net -all")):
			status, msg = check_relay(_make_conf(str(tmp_path)))
		assert status == OK
		assert "sendgrid.net" in msg

	def test_warn_when_spf_missing_include(self, tmp_path):
		(tmp_path / "settings.yaml").write_text(_yaml_relay())
		with patch("subprocess.run", return_value=_dig_result("v=spf1 mx -all")):
			status, msg = check_relay(_make_conf(str(tmp_path)))
		assert status == WARN
		assert "include:sendgrid.net" in msg

	def test_warn_when_no_spf_record(self, tmp_path):
		(tmp_path / "settings.yaml").write_text(_yaml_relay())
		r = subprocess.CompletedProcess(args=[], returncode=0)
		r.stdout = '"some other txt record"\n'
		r.stderr = ""
		with patch("subprocess.run", return_value=r):
			status, msg = check_relay(_make_conf(str(tmp_path)))
		assert status == WARN
		assert "cannot verify" in msg

	def test_warn_when_dig_fails(self, tmp_path):
		(tmp_path / "settings.yaml").write_text(_yaml_relay())
		r = subprocess.CompletedProcess(args=[], returncode=1)
		r.stdout = ""
		r.stderr = ""
		with patch("subprocess.run", return_value=r):
			status, _msg = check_relay(_make_conf(str(tmp_path)))
		assert status == WARN

	def test_no_dns_check_when_no_hostname(self, tmp_path):
		"""If PRIMARY_HOSTNAME is absent, skip DNS lookup and return OK."""
		(tmp_path / "settings.yaml").write_text(_yaml_relay())
		conf = {"STORAGE_ROOT": str(tmp_path), "PRIMARY_HOSTNAME": ""}
		with patch("subprocess.run") as mock_dig:
			status, _msg = check_relay(conf)
		mock_dig.assert_not_called()
		assert status == OK


# ---------------------------------------------------------------------------
# Malformed / unexpected settings.yaml content
# ---------------------------------------------------------------------------


class TestCheckRelayMalformedSettings:
	def test_malformed_yaml_returns_warn(self, tmp_path):
		(tmp_path / "settings.yaml").write_text("smtp_relay: [\nunclosed")
		status, msg = check_relay(_make_conf(str(tmp_path)))
		assert status == WARN
		assert "Cannot read settings.yaml" in msg

	def test_smtp_relay_wrong_type_list(self, tmp_path):
		# smtp_relay is a list, not a dict - must not raise AttributeError
		(tmp_path / "settings.yaml").write_text("smtp_relay:\n  - smtp.sendgrid.net\n")
		status, _msg = check_relay(_make_conf(str(tmp_path)))
		assert status == OFF  # relay.host is absent so treated as unconfigured

	def test_permissions_error_returns_warn(self, tmp_path):
		# PermissionError must fall through to WARN, not crash
		p = tmp_path / "settings.yaml"
		p.write_text(_yaml_relay())
		with patch("builtins.open", side_effect=PermissionError("denied")):
			status, _msg = check_relay(_make_conf(str(tmp_path)))
		assert status == WARN

	def test_spf_include_whitespace_only(self, tmp_path):
		# Whitespace-only spf_include must behave the same as empty
		(tmp_path / "settings.yaml").write_text("smtp_relay:\n  host: smtp.sendgrid.net\n  spf_include: '   '\n")
		status, msg = check_relay(_make_conf(str(tmp_path)))
		assert status == WARN
		assert "SPF include not set" in msg


# ---------------------------------------------------------------------------
# dig output edge cases
# ---------------------------------------------------------------------------


class TestCheckRelayDigEdgeCases:
	def test_dig_multipart_spf_record(self, tmp_path):
		# dig splits long TXT records: '"v=spf1 mx" " include:sendgrid.net -all"'
		# strip('"') only removes outer quotes - replace('"','') joins all parts
		(tmp_path / "settings.yaml").write_text(_yaml_relay())
		r = subprocess.CompletedProcess(args=[], returncode=0)
		r.stdout = '"v=spf1 mx" " include:sendgrid.net -all"\n'
		r.stderr = ""
		with patch("subprocess.run", return_value=r):
			status, _msg = check_relay(_make_conf(str(tmp_path)))
		assert status == OK

	def test_dig_redirect_not_accepted_as_include(self, tmp_path):
		# redirect= satisfies SPF delegation but is not include: - warn is correct
		(tmp_path / "settings.yaml").write_text(_yaml_relay())
		r = subprocess.CompletedProcess(args=[], returncode=0)
		r.stdout = '"v=spf1 redirect=_spf.sendgrid.net -all"\n'
		r.stderr = ""
		with patch("subprocess.run", return_value=r):
			status, msg = check_relay(_make_conf(str(tmp_path)))
		assert status == WARN
		assert "include:sendgrid.net" in msg
