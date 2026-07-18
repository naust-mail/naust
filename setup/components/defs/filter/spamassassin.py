"""
SpamAssassin + spampd spam filtering (alternative to Rspamd).

Active when SPAM_FILTER=spamassassin.

spampd sits between Postfix and Dovecot: Postfix -> spampd (LMTP 10025) ->
Dovecot LMTP (10026). Spam learning (sa-learn) is triggered by moving mail
to/from the Spam folder via Dovecot plugins.

Steps:
  config          - configure spamassassin, spampd, and local.cf settings
  spf-dmarc-rules - write hostname-specific DMARC/SPF scoring rules
  bayes-dir       - create Bayes learning data directory with correct ownership
  dovecot-plugin  - version-specific Dovecot spam-learning plugin + sa-learn scripts
                    [dep: dovecot:version - shares 20-imap.conf and 10-mail.conf]
"""

import os
import subprocess

from doit.tools import config_changed

from ... import SETUP_DIR, artifacts
from ... import packages as pkg
from ...component import Component
from ...task_names import DOVECOT_VERSION
from .shared import enable_antispam_plugin, setup_dovecot_antispam_pipe, setup_dovecot_imapsieve

# Both dialects live under this dir; hashed whole so editing either invalidates
# the stamp regardless of which branch is live on this box.
_TPL_DIR = os.path.join(SETUP_DIR, "conf", "filter")

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="spamassassin",
	packages=[],  # version-conditional; handled inside make_tasks
	services=["spampd", "dovecot"],
	docker_services=["spampd", "dovecot"],
	enabled=lambda env: env.get("SPAM_FILTER", "rspamd") == "spamassassin",
)

# libmail-dkim-perl is needed to make the spamassassin DKIM module work.
# See Debian Bug #689414: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=689414
_SPAMPD_BASE = ["spampd", "libmail-dkim-perl"]


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	storage_root = env["STORAGE_ROOT"]
	hostname = env.get("PRIMARY_HOSTNAME", "localhost")

	# dovecot-antispam is a 2.3-only third-party package; absent on Ubuntu 26.04.
	# Detect version here (pure read) so the packages task stamp captures it.
	ver_result = subprocess.run(["dovecot", "--version"], capture_output=True, text=True, check=False)
	dovecot_version = ver_result.stdout.split()[0] if ver_result.stdout.strip() else "2.3"
	is_24 = dovecot_version.startswith("2.4.")

	# Both plugin branches stamped so editing either branch invalidates, plus
	# the shared filter/ template dir hash since the config text itself lives
	# outside the functions.
	plugin_stamp = "|".join([
		dovecot_version,
		artifacts.fn_stamp(_dovecot_plugin_24),
		artifacts.fn_stamp(_dovecot_plugin_23),
		artifacts.hash_files(_TPL_DIR),
	])

	return [
		{
			"name": "packages",
			# Re-runs when dovecot version changes (2.3 needs dovecot-antispam, 2.4 does not).
			# Dep on dovecot:version ensures version is known before we install.
			"uptodate": [config_changed(f"spamassassin-pkgs:{dovecot_version}")],
			"task_dep": [DOVECOT_VERSION],
			"actions": [(_install_packages, [is_24])],
		},
		{
			"name": "config",
			# Static settings for spamassassin, spampd, and local.cf.
			"uptodate": [config_changed(artifacts.fn_stamp(_config))],
			"task_dep": ["spamassassin:packages"],
			"actions": [(_config,)],
		},
		{
			"name": "spf-dmarc-rules",
			# hostname appears literally in the regex patterns.
			"uptodate": [config_changed(f"{hostname}:{artifacts.fn_stamp(_spf_dmarc_rules)}")],
			"task_dep": ["spamassassin:packages"],
			"actions": [(_spf_dmarc_rules, [hostname])],
		},
		{
			"name": "bayes-dir",
			"uptodate": [config_changed(f"{storage_root}:{artifacts.fn_stamp(_bayes_dir)}")],
			"task_dep": ["spamassassin:packages"],
			"actions": [(_bayes_dir, [storage_root])],
		},
		{
			"name": "dovecot-plugin",
			# Writes to 20-imap.conf and 10-mail.conf (2.3 path). Dep on packages
			# ensures spampd is installed and dovecot:version has run (transitively).
			"uptodate": [config_changed(plugin_stamp)],
			"task_dep": ["spamassassin:packages"],
			"actions": [(_dovecot_plugin, [dovecot_version, storage_root])],
		},
	]


# ── Action functions ──────────────────────────────────────────────────────────


def _install_packages(is_24: bool) -> None:
	"""Install spamassassin packages. dovecot-antispam is 2.3-only; absent on Ubuntu 24.04+."""
	extra = [] if is_24 else ["dovecot-antispam"]
	pkg.ensure_installed(_SPAMPD_BASE + extra)


def _config() -> None:
	"""Configure spamassassin update cron, spampd relay settings, and local.cf."""
	# Ubuntu 24.04 removed /etc/default/spamassassin; touch creates it if absent
	# so editconf doesn't abort on a missing file.
	for f in ["/etc/default/spamassassin", "/etc/default/spampd"]:
		if not os.path.exists(f):
			open(f, "a", encoding="utf-8").close()

	# Enable the spamassassin rule update cron (or systemd timer equivalent).
	artifacts.editconf("/etc/default/spamassassin", "CRON=1")

	# spampd relay: deliver to Dovecot on 10026. Increase message scan limit to
	# 2 MB (spamassassin's spamc default). Disable localmode for DKIM + DNS checks.
	artifacts.editconf(
		"/etc/default/spampd",
		"DESTPORT=10026",
		'ADDOPTS="--maxsize=2000"',
		"LOCALONLY=0",
	)

	# SpamAssassin normally wraps spam as an attachment inside a fresh email with
	# a report. This is annoying to get to, modern clients don't load remote
	# content or execute scripts, and it is confusing to most users.
	# report_safe=0: don't modify the original message except for adding
	# X-Spam-Status, X-Spam-Score, and report headers.
	artifacts.editconf(
		"/etc/spamassassin/local.cf",
		"report_safe=0",
		"add_header all Report=_REPORT_",
		"add_header all Score=_SCORE_",
		space_delim=True,
	)


def _spf_dmarc_rules(hostname: str) -> None:
	"""Write hostname-specific DMARC/SPF scoring rules for SpamAssassin.

	OpenDKIM and OpenDMARC add Authentication-Results headers with SPF/DMARC
	verdicts. Instead of blocking mail that fails these checks, we use those
	headers to score the message for spamminess. Rules go in their own file
	so that package upgrades to /etc/spamassassin/ don't remove them.

	The hostname appears literally in the regex patterns (spamassassin uses
	Perl regex), so dots must be escaped.
	"""
	# Escape dots for spamassassin regex (which uses Perl regex syntax).
	escaped = hostname.replace(".", "\\.")

	artifacts.write_file(
		"/etc/spamassassin/naust_spf_dmarc.cf",
		"# Evaluate DMARC Authentication-Results\n"
		f"header DMARC_PASS Authentication-Results =~ /{escaped}; dmarc=pass/\n"
		"describe DMARC_PASS DMARC check passed\n"
		"score DMARC_PASS -0.1\n"
		"\n"
		f"header DMARC_NONE Authentication-Results =~ /{escaped}; dmarc=none/\n"
		"describe DMARC_NONE DMARC record not found\n"
		"score DMARC_NONE 0.1\n"
		"\n"
		f"header DMARC_FAIL_NONE Authentication-Results =~ /{escaped}; dmarc=fail \\(p=none/\n"
		"describe DMARC_FAIL_NONE DMARC check failed (p=none)\n"
		"score DMARC_FAIL_NONE 2.0\n"
		"\n"
		f"header DMARC_FAIL_QUARANTINE Authentication-Results =~ /{escaped}; dmarc=fail \\(p=quarantine/\n"
		"describe DMARC_FAIL_QUARANTINE DMARC check failed (p=quarantine)\n"
		"score DMARC_FAIL_QUARANTINE 5.0\n"
		"\n"
		f"header DMARC_FAIL_REJECT Authentication-Results =~ /{escaped}; dmarc=fail \\(p=reject/\n"
		"describe DMARC_FAIL_REJECT DMARC check failed (p=reject)\n"
		"score DMARC_FAIL_REJECT 10.0\n"
		"\n"
		"# Evaluate SPF Authentication-Results\n"
		f"header SPF_PASS Authentication-Results =~ /{escaped}; spf=pass/\n"
		"describe SPF_PASS SPF check passed\n"
		"score SPF_PASS -0.1\n"
		"\n"
		f"header SPF_NONE Authentication-Results =~ /{escaped}; spf=none/\n"
		"describe SPF_NONE SPF record not found\n"
		"score SPF_NONE 2.0\n"
		"\n"
		f"header SPF_FAIL Authentication-Results =~ /{escaped}; spf=fail/\n"
		"describe SPF_FAIL SPF check failed\n"
		"score SPF_FAIL 5.0\n",
	)


def _bayes_dir(storage_root: str) -> None:
	"""Create the spamassassin Bayes learning directory with correct ownership.

	Files must be writable by the mail user (sa-learn-pipe.sh runs as mail),
	readable by the spampd user (filtering), and writable by debian-spamd
	(daily cron update). Setting mode 660/770 covers all three.
	Also configure the bayes_path so spamassassin knows where to write them.
	"""
	bayes_dir = os.path.join(storage_root, "mail", "spamassassin")
	first_run = not os.path.isdir(bayes_dir)
	os.makedirs(bayes_dir, exist_ok=True)
	if first_run:
		subprocess.run(["chown", "-R", "spampd:spampd", bayes_dir], check=True)

	# bayes_file_mode ensures spamassassin doesn't reset perms to restrictive defaults.
	artifacts.editconf(
		"/etc/spamassassin/local.cf",
		f"bayes_path={bayes_dir}/bayes",
		"bayes_file_mode=0666",
		space_delim=True,
	)

	# Ensure group-writable in case the dir was created on a previous run.
	subprocess.run(["chmod", "-R", "660", bayes_dir], check=False)
	subprocess.run(["chmod", "770", bayes_dir], check=False)


def _dovecot_plugin(dovecot_version: str, storage_root: str) -> None:
	"""Dispatch to the correct Dovecot spam-learning plugin for the installed version."""
	if dovecot_version.startswith("2.4."):
		_dovecot_plugin_24()
	else:
		_dovecot_plugin_23(storage_root)


def _dovecot_plugin_24() -> None:
	"""Dovecot 2.4 spam learning via Pigeonhole imapsieve + sieve_extprograms."""
	setup_dovecot_imapsieve("sa-learn-spam.sh", "sa-learn-ham.sh")

	artifacts.write_file(
		"/usr/local/bin/sa-learn-spam.sh",
		"#!/bin/bash\nexec /usr/bin/sa-learn --spam\n",
		mode=0o755,
	)
	artifacts.write_file(
		"/usr/local/bin/sa-learn-ham.sh",
		"#!/bin/bash\nexec /usr/bin/sa-learn --ham\n",
		mode=0o755,
	)

	# mail_access_groups needed so Dovecot can write to the spampd-owned bayes files.
	artifacts.editconf(
		"/etc/dovecot/conf.d/10-mail.conf",
		"mail_access_groups=spampd",
	)


def _dovecot_plugin_23(_storage_root: str) -> None:
	"""Dovecot 2.3 spam learning via the third-party dovecot-antispam plugin.

	Sieve-based learning is not available in 2.3. antispam_backend=pipe calls
	sa-learn-pipe.sh on Spam/Not-Spam moves. 2.4 uses imapsieve instead.
	"""
	enable_antispam_plugin()
	setup_dovecot_antispam_pipe("sa-learn-pipe.sh;--spam", "sa-learn-pipe.sh;--ham")

	# Remove legacy location before writing the canonical one.
	legacy = "/usr/bin/sa-learn-pipe.sh"
	if os.path.exists(legacy):
		os.unlink(legacy)

	artifacts.write_file(
		"/usr/local/bin/sa-learn-pipe.sh",
		'#!/bin/bash\ncat <&0 >> /tmp/sendmail-msg-$$.txt\n/usr/bin/sa-learn "$@" /tmp/sendmail-msg-$$.txt > /dev/null\nrm -f /tmp/sendmail-msg-$$.txt\nexit 0\n',
		mode=0o755,
	)

	artifacts.editconf(
		"/etc/dovecot/conf.d/10-mail.conf",
		"mail_access_groups=spampd",
	)
