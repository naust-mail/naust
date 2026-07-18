"""
OpenDKIM and OpenDMARC for the SpamAssassin path.

Active when SPAM_FILTER=spamassassin. When rspamd is active, DKIM signing
is handled by rspamd itself (no OpenDKIM needed).

Steps:
  dkim-key        - generate 2048-bit DKIM key via opendkim-genkey (skipped if exists)
  dkim-perms      - chown/chmod the dkim directory [dep: dkim-key]
  opendkim-config - write TrustedHosts, KeyTable/SigningTable stubs, opendkim.conf
  opendmarc-config - configure opendmarc.conf
  postfix-milters  - set smtpd_milters for OpenDKIM + OpenDMARC [dep: postfix:spam-filter]
"""

import os
import subprocess

from doit.tools import config_changed

from .. import artifacts
from ..component import Component
from ..task_names import POSTFIX_SPAM_FILTER

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="dkim",
	packages=["opendkim", "opendkim-tools", "opendmarc"],
	services=["opendkim", "opendmarc", "postfix"],
	docker_services=["opendkim", "opendmarc", "postfix"],
	enabled=lambda env: env.get("SPAM_FILTER", "rspamd") == "spamassassin",
)


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	storage_root = env["STORAGE_ROOT"]
	dkim_dir = os.path.join(storage_root, "mail", "dkim")
	key_path = os.path.join(dkim_dir, "mail.private")

	return [
		{
			"name": "dkim-key",
			# targets= re-runs only if the key file is missing.
			# Rotating DKIM keys invalidates published DNS TXT records.
			"targets": [key_path],
			"actions": [(_dkim_key, [dkim_dir])],
		},
		{
			"name": "dkim-perms",
			"uptodate": [config_changed(f"{storage_root}:{artifacts.fn_stamp(_dkim_perms)}")],
			"task_dep": ["dkim:dkim-key"],
			"actions": [(_dkim_perms, [dkim_dir])],
		},
		{
			"name": "opendkim-config",
			"uptodate": [config_changed(artifacts.fn_stamp(_opendkim_config))],
			"task_dep": ["dkim:dkim-perms"],
			"actions": [(_opendkim_config,)],
		},
		{
			"name": "opendmarc-config",
			"uptodate": [config_changed(artifacts.fn_stamp(_opendmarc_config))],
			"actions": [(_opendmarc_config,)],
		},
		{
			"name": "postfix-milters",
			# OpenDKIM (8891) + OpenDMARC (8893) applied on all SMTP connections.
			# Order matters: OpenDMARC relies on the OpenDKIM Authentication-Results
			# header already being present when it runs.
			"uptodate": [config_changed(artifacts.fn_stamp(_postfix_milters))],
			"task_dep": [POSTFIX_SPAM_FILTER],
			"actions": [(_postfix_milters,)],
		},
	]


# ── Action functions ──────────────────────────────────────────────────────────


def _dkim_key(dkim_dir: str) -> None:
	"""Generate a 2048-bit RSA DKIM key pair. Output: mail.private + mail.txt.

	Files are named after the selector ('mail'), which can be changed later to
	support key rotation. 1024-bit is seen as a minimum by providers like Google,
	but 2048-bit is what they and others actually use. Keys beyond 2048 bits may
	exceed DNS TXT record size limits.
	"""
	os.makedirs(dkim_dir, exist_ok=True)
	subprocess.run(
		["opendkim-genkey", "-b", "2048", "-r", "-s", "mail", "-D", dkim_dir],
		check=True,
	)


def _dkim_perms(dkim_dir: str) -> None:
	"""Own the dkim directory as opendkim if it isn't already."""
	result = subprocess.run(
		["stat", "-c", "%U", dkim_dir],
		capture_output=True,
		text=True,
		check=False,
	)
	if result.stdout.strip() != "opendkim":
		subprocess.run(["chown", "-R", "opendkim:opendkim", dkim_dir], check=True)
	subprocess.run(["chmod", "go-rwx", dkim_dir], check=True)


def _opendkim_config() -> None:
	"""Write OpenDKIM supporting files and add settings to opendkim.conf.

	TrustedHosts is used for InternalHosts and ExternalIgnoreList. KeyTable
	and SigningTable are populated by the management daemon's DNS update path.
	Settings are appended only once (guard on ExternalIgnoreList presence).
	"""
	os.makedirs("/etc/opendkim", exist_ok=True)
	artifacts.write_file("/etc/opendkim/TrustedHosts", "127.0.0.1\n")

	# Touch these files so opendkim startup doesn't fail before the management
	# daemon has written the actual key/signing entries.
	for f in ["/etc/opendkim/KeyTable", "/etc/opendkim/SigningTable"]:
		if not os.path.exists(f):
			open(f, "a", encoding="utf-8").close()

	# Append only if not already configured (guard prevents duplicate entries).
	result = subprocess.run(
		["grep", "-q", "ExternalIgnoreList", "/etc/opendkim.conf"],
		check=False,
	)
	if result.returncode != 0:
		with open("/etc/opendkim.conf", "a", encoding="utf-8") as fh:
			fh.write(
				"Canonicalization\t\trelaxed/simple\n"
				"MinimumKeyBits          1024\n"
				"ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts\n"
				"InternalHosts           refile:/etc/opendkim/TrustedHosts\n"
				"KeyTable                refile:/etc/opendkim/KeyTable\n"
				"SigningTable            refile:/etc/opendkim/SigningTable\n"
				"Socket                  inet:8891@127.0.0.1\n"
				"RequireSafeKeys         false\n"
			)

	# AlwaysAddARHeader: add an Authentication-Results header even to unsigned
	# messages from domains with no strict policy. Without this, unsigned mail
	# from non-strict domains produces no header, giving SpamAssassin nothing
	# to score against.
	artifacts.editconf(
		"/etc/opendkim.conf",
		"AlwaysAddARHeader=true",
		space_delim=True,
	)


def _opendmarc_config() -> None:
	"""Configure OpenDMARC with SPF self-validation and no failure reports.

	SPFIgnoreResults: ignore any SPF results already in the message header so
	the filter always performs its own check rather than trusting an arriving header.
	SPFSelfValidate: always perform the SPF check itself (required when
	SPFIgnoreResults is set). The resulting Authentication-Results header is
	used by SpamAssassin to score the message.
	FailureReportsOnNone: suppresses failure reports for domains that publish
	a DMARC 'none' policy (monitoring-only, not enforcement).
	"""
	artifacts.editconf(
		"/etc/opendmarc.conf",
		"Syslog=true",
		"Socket=inet:8893@[127.0.0.1]",
		"FailureReports=false",
		"SPFIgnoreResults=true",
		"SPFSelfValidate=true",
		"FailureReportsOnNone=false",
		space_delim=True,
	)
	# The package installs the config as root:root 600. The service runs as the
	# opendmarc user, so it must be able to read it. No secrets in this file.
	import os

	os.chmod("/etc/opendmarc.conf", 0o640)
	subprocess.run(["chown", "root:opendmarc", "/etc/opendmarc.conf"], check=True)
	# Explicitly enable: the package ships with the unit disabled.
	subprocess.run(["systemctl", "enable", "opendmarc"], capture_output=True, check=False)


def _postfix_milters() -> None:
	"""Wire OpenDKIM + OpenDMARC milters for inbound SMTP (port 25).

	OpenDMARC (8893) depends on the Authentication-Results header written by
	OpenDKIM (8891), so ordering matters. milter_default_action=accept keeps
	mail flowing if a milter is temporarily unavailable.
	"""
	artifacts.editconf(
		"/etc/postfix/main.cf",
		"smtpd_milters=inet:127.0.0.1:8891 inet:127.0.0.1:8893",
		r"non_smtpd_milters=$smtpd_milters",
		"milter_default_action=accept",
	)
