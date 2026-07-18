"""
Rspamd spam filter, DKIM signing, DMARC, and greylisting.

Active when SPAM_FILTER=rspamd (the default).

Rspamd is a milter. Postfix passes mail directly to Dovecot LMTP;
no spampd relay hop is needed. Redis is required for greylisting state,
rate limiting, and Bayes learning.

Steps:
  dkim-key              - generate 2048-bit DKIM key via rspamadm (skipped if exists)
  dkim-perms            - chown/chmod the dkim dir and key file [dep: dkim-key]
  config                - write all rspamd local.d config files
  postfix-milters       - set smtpd_milters, virtual_transport, smtpd_recipient_restrictions in main.cf [dep: postfix:spam-filter]
  disable-legacy        - stop + disable spampd, opendkim, opendmarc, postgrey
  redis-enable          - systemctl enable redis-server (persists across reboots)
  dovecot-spam-learning - version-specific Dovecot spam-learning plugin + rspamc pipe scripts
                          [dep: dovecot:version - 2.3 needs dovecot-antispam, 2.4 uses imapsieve]
"""

import os
import subprocess

from doit.tools import config_changed

from ... import SETUP_DIR, artifacts
from ...component import Component
from ...task_names import DOVECOT_VERSION, POSTFIX_SPAM_FILTER
from .shared import enable_antispam_plugin, setup_dovecot_antispam_pipe, setup_dovecot_imapsieve

# Both dialects live under this dir; hashed whole so editing either invalidates
# the stamp regardless of which branch is live on this box.
_TPL_DIR = os.path.join(SETUP_DIR, "conf", "filter")

# ── Component declaration ─────────────────────────────────────────────────────


def _dovecot_antispam_needed() -> bool:
	"""dovecot-antispam exists only for Dovecot 2.3 (Ubuntu 24.04 and
	older); the 2.4 path uses imapsieve and the package is absent from
	the 26.04 archive. The distro fixes the Dovecot major version, so
	the batched install phase can know this before any package exists."""
	try:
		with open("/etc/os-release", encoding="utf-8") as fh:
			for line in fh:
				if line.startswith("VERSION_ID="):
					return float(line.split("=", 1)[1].strip().strip('"')) < 25
	except (OSError, ValueError):
		pass
	return True


COMPONENT = Component(
	name="rspamd",
	packages=["rspamd", "redis-server"] + (["dovecot-antispam"] if _dovecot_antispam_needed() else []),
	services=["rspamd", "redis-server"],
	docker_services=["rspamd", "redis-server"],
	enabled=lambda env: env.get("SPAM_FILTER", "rspamd") == "rspamd",
)


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	storage_root = env["STORAGE_ROOT"]
	dkim_dir = os.path.join(storage_root, "mail", "dkim")
	key_path = os.path.join(dkim_dir, "mail.private")

	# Detect the Dovecot version (pure read) so the spam-learning stamp
	# captures which plugin branch is live on this box.
	ver_result = subprocess.run(["dovecot", "--version"], capture_output=True, text=True, check=False)
	dovecot_version = ver_result.stdout.split()[0] if ver_result.stdout.strip() else "2.3"

	# Both plugin branches stamped so editing either branch invalidates, plus
	# the template dir hash since the config text itself lives outside the
	# functions now.
	plugin_stamp = "|".join([
		dovecot_version,
		artifacts.fn_stamp(_dovecot_spam_learning_24),
		artifacts.fn_stamp(_dovecot_spam_learning_23),
		artifacts.hash_files(_TPL_DIR),
	])

	return [
		{
			"name": "dkim-key",
			# Run only if the key file is missing. DKIM keys must not be
			# regenerated casually - it invalidates deployed DNS TXT records.
			"targets": [key_path],
			"actions": [(_dkim_key, [dkim_dir, key_path])],
		},
		{
			"name": "dkim-perms",
			# chown/chmod runs on every setup so permissions are always correct
			# even after manual edits. Stamped on storage_root to re-run if path
			# changes; fn_stamp catches permission value changes.
			"uptodate": [config_changed(f"{storage_root}:{artifacts.fn_stamp(_dkim_perms)}")],
			"task_dep": ["rspamd:dkim-key"],
			"actions": [(_dkim_perms, [dkim_dir, key_path])],
		},
		{
			"name": "config",
			# All rspamd local.d config is code-defined; fn_stamp captures any
			# changes to template strings without manual versioning.
			"uptodate": [config_changed(f"{storage_root}:{artifacts.fn_stamp(_config)}")],
			"actions": [(_config, [storage_root])],
		},
		{
			"name": "postfix-milters",
			# Set the global smtpd_milters for inbound scanning. Dep ensures we
			# run after postfix:spam-filter (which also writes main.cf).
			"uptodate": [config_changed(artifacts.fn_stamp(_postfix_milters))],
			"task_dep": [POSTFIX_SPAM_FILTER],
			"actions": [(_postfix_milters,)],
		},
		{
			"name": "disable-legacy",
			# Stop and disable services from the SpamAssassin path. Idempotent:
			# systemctl stop/disable on already-inactive units is a no-op.
			"uptodate": [config_changed(artifacts.fn_stamp(_disable_legacy))],
			"actions": [(_disable_legacy,)],
		},
		{
			"name": "redis-enable",
			# Enable redis-server to start at boot. The service itself is restarted
			# by the runner after all tasks complete (it's in COMPONENT.services).
			"uptodate": [config_changed(artifacts.fn_stamp(_redis_enable))],
			"actions": [(_redis_enable,)],
		},
		{
			"name": "dovecot-spam-learning",
			# Writes 99-local-spam-learning.conf, sieve/plugin config, and rspamc
			# pipe scripts. dovecot-antispam (2.3 path) is in COMPONENT.packages,
			# installed by the batch phase before any task runs. Dep on
			# dovecot:version ensures the right Dovecot is configured first.
			"uptodate": [config_changed(plugin_stamp)],
			"task_dep": [DOVECOT_VERSION],
			"actions": [(_dovecot_spam_learning, [dovecot_version])],
		},
	]


# ── Action functions ──────────────────────────────────────────────────────────


def _dkim_key(dkim_dir: str, key_path: str) -> None:
	"""Generate a 2048-bit DKIM key pair via rspamadm.

	Uses selector 'mail' and the same key paths as the OpenDKIM path so the
	DNS TXT record (managed by the management daemon) is identical regardless
	of which spam filter is active.
	"""
	os.makedirs(dkim_dir, exist_ok=True)
	txt_path = os.path.join(dkim_dir, "mail.txt")
	print("Generating the DKIM signing key...", flush=True)
	result = subprocess.run(
		["rspamadm", "dkim_keygen", "-s", "mail", "-b", "2048", "-k", key_path],
		capture_output=True,
		text=True,
		check=True,
	)
	artifacts.write_file(txt_path, result.stdout)
	os.chmod(txt_path, 0o644)


def _dkim_perms(dkim_dir: str, key_path: str) -> None:
	"""Set ownership and permissions on the DKIM directory and private key.

	The rspamd worker runs as _rspamd. Group-readable is enough for the dir;
	the private key must not be world-readable.
	"""
	subprocess.run(["chown", "root:_rspamd", dkim_dir], check=True)
	subprocess.run(["chmod", "750", dkim_dir], check=True)
	if os.path.exists(key_path):
		subprocess.run(["chown", "root:_rspamd", key_path], check=True)
		subprocess.run(["chmod", "640", key_path], check=True)


def _config(storage_root: str) -> None:
	"""Write all rspamd local.d config files."""
	os.makedirs("/etc/rspamd/local.d", exist_ok=True)

	# Redis backend for greylisting state, Bayes, rate limiting, and fuzzy hashes.
	artifacts.write_file(
		"/etc/rspamd/local.d/redis.conf",
		'servers = "127.0.0.1";\n',
	)

	# Milter proxy worker: Postfix connects here on 11332.
	artifacts.write_file(
		"/etc/rspamd/local.d/worker-proxy.inc",
		'bind_socket = "127.0.0.1:11332";\ntimeout = 120s;\nupstream "local" {\n  default = yes;\n  self_scan = yes;\n}\n',
	)

	# DKIM signing for outbound mail. same key location as OpenDKIM path.
	artifacts.write_file(
		"/etc/rspamd/local.d/dkim_signing.conf",
		f'allow_username_mismatch = true;\nuse_domain = "envelope";\npath = "{storage_root}/mail/dkim/${{selector}}.private";\nselector = "mail";\nsign_authenticated = true;\nsign_local = true;\n',
	)

	# Greylisting: short 60s timeout deters bots that don't retry.
	# DKIM_ALLOW whitelist skips greylisting for mail with a valid DKIM signature.
	artifacts.write_file(
		"/etc/rspamd/local.d/greylisting.conf",
		'enabled = true;\ntimeout = 60;\nexpire = 86400;\nwhitelist_symbols = ["DKIM_ALLOW"];\n',
	)

	# DMARC verification. No outbound reports - not a reporting MTA.
	artifacts.write_file(
		"/etc/rspamd/local.d/dmarc.conf",
		"reporting {\n  enabled = false;\n}\n",
	)

	# Spam-related headers on all processed messages.
	artifacts.write_file(
		"/etc/rspamd/local.d/milter_headers.conf",
		'use = ["x-spam-status", "x-spam-score", "authentication-results"];\nextended_spam_headers = true;\n',
	)

	# Spam action thresholds.
	artifacts.write_file(
		"/etc/rspamd/local.d/actions.conf",
		"reject = 15;\nadd_header = 6;\ngreylist = 4;\n",
	)


def _postfix_milters() -> None:
	"""Wire Postfix to Rspamd (milter) and Dovecot LMTP (transport).

	smtpd_milters covers port 25 (inbound) and any service without a per-service
	override. Per-service milters for submission/smtps are set in master.cf by
	the postfix component. milter_default_action=accept keeps mail flowing if
	rspamd is temporarily unavailable.

	virtual_transport routes virtual mailbox delivery directly to Dovecot's LMTP
	socket, bypassing spampd (which was the SpamAssassin relay hop).

	lmtp_destination_recipient_limit is erased so Dovecot LMTP gets all
	recipients per LMTP transaction rather than one per connection.

	smtpd_recipient_restrictions drops the Postgrey policy check (Rspamd handles
	greylisting via Redis internally) while keeping the Dovecot quota check (12340).
	"""
	artifacts.editconf(
		"/etc/postfix/main.cf",
		"smtpd_milters=inet:127.0.0.1:11332",
		r"non_smtpd_milters=$smtpd_milters",
		"milter_default_action=accept",
		"virtual_transport=lmtp:unix:private/dovecot-lmtp",
		("smtpd_recipient_restrictions=permit_sasl_authenticated,permit_mynetworks,reject_rbl_client zen.spamhaus.org=127.0.0.[2..11],reject_unlisted_recipient,check_policy_service inet:127.0.0.1:12340"),
	)
	# Erase lmtp_destination_recipient_limit so Dovecot receives all recipients
	# in one LMTP transaction rather than one connection per recipient.
	artifacts.editconf(
		"/etc/postfix/main.cf",
		"lmtp_destination_recipient_limit=",
		erase=True,
	)


def _disable_legacy() -> None:
	"""Stop and disable services from the SpamAssassin path.

	Switching from SpamAssassin to Rspamd leaves orphan services running.
	systemctl stop/disable is idempotent on already-inactive or non-existent units.
	"""
	for svc in ["spampd", "opendkim", "opendmarc", "postgrey"]:
		subprocess.run(["systemctl", "stop", svc], capture_output=True, check=False)
		subprocess.run(["systemctl", "disable", svc], capture_output=True, check=False)


def _redis_enable() -> None:
	"""Enable redis-server to start at boot."""
	subprocess.run(["systemctl", "enable", "redis-server"], check=True)


def _dovecot_spam_learning(dovecot_version: str) -> None:
	"""Dispatch to the correct Dovecot spam-learning plugin for the installed version."""
	if dovecot_version.startswith("2.4."):
		_dovecot_spam_learning_24()
	else:
		_dovecot_spam_learning_23()


def _dovecot_spam_learning_24() -> None:
	"""Set up Dovecot 2.4 imapsieve spam learning via rspamc.

	Writes the shared Dovecot imapsieve config and sieve scripts, then
	writes rspamc pipe scripts that submit messages to the local rspamd
	socket for Bayes training. No mail_access_groups change is needed -
	rspamd stores Bayes state in Redis, not on disk.
	"""
	setup_dovecot_imapsieve("rspamc-learn-spam.sh", "rspamc-learn-ham.sh")
	_write_rspamc_scripts()


def _dovecot_spam_learning_23() -> None:
	"""Dovecot 2.3 spam learning via the third-party dovecot-antispam plugin.

	Sieve-based learning (imapsieve) is not available in 2.3. antispam_backend=pipe
	calls rspamc-learn-{spam,ham}.sh on Spam/Not-Spam moves. 2.4 uses imapsieve
	instead. No mail_access_groups change is needed - rspamd stores Bayes state
	in Redis, not on disk (unlike the SpamAssassin path, which needs group access
	to on-disk bayes files).
	"""
	enable_antispam_plugin()
	setup_dovecot_antispam_pipe("rspamc-learn-spam.sh", "rspamc-learn-ham.sh")
	_write_rspamc_scripts()


def _write_rspamc_scripts() -> None:
	"""Write the rspamc pipe scripts shared by both the 2.3 and 2.4 plugin paths."""
	artifacts.write_file(
		"/usr/local/bin/rspamc-learn-spam.sh",
		"#!/bin/bash\nexec /usr/bin/rspamc learn_spam\n",
		mode=0o755,
	)
	artifacts.write_file(
		"/usr/local/bin/rspamc-learn-ham.sh",
		"#!/bin/bash\nexec /usr/bin/rspamc learn_ham\n",
		mode=0o755,
	)
