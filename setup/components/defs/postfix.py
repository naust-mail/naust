"""
Postfix (SMTP) Mail Transfer Agent.

Postfix handles transmission of email between servers using the SMTP protocol.
It listens on port 25 for incoming mail from other servers, performs basic
filtering (IP reputation, greylisting via Postgrey or Rspamd/Redis, DNSBL),
validates recipients, rewrites via aliases, then hands mail to rspamd or spampd
for spam scanning before final delivery to Dovecot via LMTP.

On ports 465/587 (SMTPS/STARTTLS), authenticated users submit outbound mail.
Postfix queries Dovecot for SASL authentication and applies DKIM signing via
the submission milter. User authentication and alias config live in users.py
due to their overlap with Dovecot configuration.

Steps and their stamps - each group re-runs only when its specific inputs change:

  header-filters   hash of template file on disk
                   → re-runs when we ship a new template version

  static           fn_stamp of _static()
                   → TLS cipher lists, queue settings, postscreen, SMTP
                     smuggling fix, message size. Re-runs when code changes.

  identity         hostname + private IPs + fn_stamp
                   → re-runs on hostname/IP change or code change

  relay            relay config from settings.yaml + fn_stamp
                   → re-runs only when relay is configured/changed/removed

  spam-filter      SPAM_FILTER value + config mtime + fn_stamp
                   → submission ports, virtual transport, sender/recipient
                     restrictions. Re-runs when filter choice changes or
                     config file is written (config_changed invalidation).

  postgrey         (spamassassin path only) storage_root + fn_stamp
                   → re-runs when STORAGE_ROOT changes or code changes

Tasks are chained via task_dep to ensure sequential writes to main.cf/master.cf
(editconf does a full read-modify-write so concurrent edits would corrupt files).
"""

import os
import shutil
import subprocess

from doit.tools import config_changed

from .. import artifacts, SETUP_DIR
from .. import packages as pkg
from ..component import Component, DOCKER
import pathlib

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="postfix",
	# Core packages always installed. postgrey is conditional - see _postgrey().
	packages=["postfix", "postfix-sqlite", "postfix-pcre", "ca-certificates"],
	services=["postfix"],
	docker_services=["postfix"],
)

_CONF_DIR = os.path.join(SETUP_DIR, "conf")


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, runtime: str) -> list[dict]:
	storage_root = env.get("STORAGE_ROOT", "")
	hostname = env.get("PRIMARY_HOSTNAME", "")
	private_ip = env.get("PRIVATE_IP", "")
	private_ipv6 = env.get("PRIVATE_IPV6", "")
	spam_filter = env.get("SPAM_FILTER", "rspamd")
	template = os.path.join(_CONF_DIR, "mail", "postfix_outgoing_mail_header_filters")

	# Config file mtime for cache invalidation when SPAM_FILTER changes.
	# doit's config_changed() compares stored stamps; including mtime ensures
	# the stamp changes when the config file is written, even if value comparison fails.
	conf_mtime = os.path.getmtime("/etc/naust.conf") if os.path.exists("/etc/naust.conf") else 0

	tasks = [
		{
			"name": "header-filters",
			# Re-runs when the shipped template file changes (new version in repo).
			"uptodate": [config_changed(artifacts.hash_files(template))],
			"actions": [(_header_filters, [env, template])],
		},
		{
			"name": "static",
			# Re-runs when any static setting in _static() changes (TLS ciphers,
			# queue tuning, postscreen, SMTP smuggling fix, message size).
			"uptodate": [config_changed(artifacts.fn_stamp(_static))],
			"task_dep": ["postfix:header-filters"],
			"actions": [(_static,)],
		},
		{
			"name": "identity",
			# Re-runs when hostname or IPs change, or code changes.
			"uptodate": [config_changed(f"{hostname}:{private_ip}:{private_ipv6}:{env.get('PUBLIC_IP', '')}:{env.get('PUBLIC_IPV6', '')}:{runtime}:{artifacts.fn_stamp(_identity)}")],
			"task_dep": ["postfix:static"],
			"actions": [(_identity, [env, runtime])],
		},
		{
			"name": "relay",
			# Re-runs when relay config in settings.yaml changes, or code changes.
			"uptodate": [config_changed(f"{_relay_stamp(storage_root)}:{artifacts.fn_stamp(_relay)}")],
			"task_dep": ["postfix:identity"],
			"actions": [(_relay, [storage_root])],
		},
		{
			"name": "spam-filter",
			# Re-runs when SPAM_FILTER changes (different milter, transport,
			# restrictions), code changes, or config file is written.
			"uptodate": [config_changed(f"{spam_filter}:{conf_mtime}:{artifacts.fn_stamp(_spam_filter)}")],
			"task_dep": ["postfix:relay"],
			"actions": [(_spam_filter, [env])],
		},
	]

	# postgrey only exists as a task in the spamassassin path so doit doesn't
	# even create a stamp entry for it when rspamd is active.
	if spam_filter == "spamassassin":
		tasks.append({
			"name": "postgrey",
			"uptodate": [config_changed(f"{storage_root}:{artifacts.fn_stamp(_postgrey)}")],
			"task_dep": ["postfix:spam-filter"],
			"actions": [
				# Install postgrey here rather than at graph-build time so make_tasks
				# remains a pure function with no apt side-effects.
				lambda: pkg.ensure_installed(["postgrey"]),
				(_postgrey, [storage_root]),
			],
		})

	return tasks


# ── Action functions ──────────────────────────────────────────────────────────


def _header_filters(env: dict, template: str) -> None:
	"""Copy the outbound mail header filter template, substituting hostname/IP.

	The filter strips privacy-sensitive headers (internal Received lines) from
	mail sent by authenticated users on ports 465/587.
	"""
	content = pathlib.Path(template).read_text(encoding="utf-8")
	content = content.replace("PRIMARY_HOSTNAME", env["PRIMARY_HOSTNAME"]).replace("PUBLIC_IP", env.get("PUBLIC_IP", ""))
	artifacts.write_file("/etc/postfix/outgoing_mail_header_filters", content)


def _static() -> None:
	"""Write postfix settings that don't depend on runtime env values.

	Covers: queue tuning, SMTP smuggling mitigation, TLS cipher lists for
	both incoming (port 25 opportunistic) and submission (mandatory), relay
	restrictions, postscreen DNSBL config, and the message size limit.

	fn_stamp(_static) is used as the doit stamp - editing this function body
	automatically triggers a re-run on the next setup invocation.
	"""
	# Queue: warn senders after 3h delay; give up after 2d (1d for bounces).
	artifacts.editconf(
		"/etc/postfix/main.cf",
		"delay_warning_time=3h",
		"maximal_queue_lifetime=2d",
		"bounce_queue_lifetime=1d",
	)

	# SMTP smuggling mitigation: erase old short-term workarounds, set the
	# long-term fix recommended at https://www.postfix.org/smtp-smuggling.html
	# Supported from backported package 3.6.4-1ubuntu1.3; unnecessary in Postfix
	# 3.9+ where normalize is the default. The "short-term" workarounds we
	# previously used (smtpd_data_restrictions, smtpd_discard_ehlo_keywords) are
	# erased back to Postfix defaults.
	artifacts.editconf(
		"/etc/postfix/main.cf",
		"smtpd_data_restrictions=",
		"smtpd_discard_ehlo_keywords=",
		erase=True,
	)
	artifacts.editconf("/etc/postfix/main.cf", "smtpd_forbid_bare_newline=normalize")

	# Incoming TLS (port 25, opportunistic - Mozilla "Old" profile).
	# Port 25 uses permissive ciphers so we can receive from legacy servers.
	artifacts.editconf(
		"/etc/postfix/main.cf",
		"smtpd_tls_security_level=may",
		"smtpd_tls_auth_only=yes",
		"smtpd_tls_protocols=!SSLv2,!SSLv3",
		"smtpd_tls_ciphers=medium",
		"tls_medium_cipherlist=ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA",
		"smtpd_tls_exclude_ciphers=aNULL,RC4",
		"tls_preempt_cipherlist=no",
		"smtpd_tls_received_header=yes",
	)

	# Submission TLS (ports 465/587, mandatory - Mozilla "Intermediate").
	# Authenticated users run modern clients so we can enforce stricter TLS.
	artifacts.editconf(
		"/etc/postfix/main.cf",
		"smtpd_tls_mandatory_protocols=!SSLv2,!SSLv3,!TLSv1,!TLSv1.1",
		"smtpd_tls_mandatory_ciphers=high",
		"tls_high_cipherlist=ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
		"smtpd_tls_mandatory_exclude_ciphers=aNULL,DES,3DES,MD5,DES+MD5,RC4",
	)

	# Outbound relay restriction: only authenticated users or localhost can relay.
	artifacts.editconf(
		"/etc/postfix/main.cf",
		"smtpd_relay_restrictions=permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination",
	)

	# Outbound TLS / DANE.
	# Preferring ("opportunistic") TLS means Postfix uses TLS if the remote end
	# offers it, otherwise transmits in the clear. DANE takes this further:
	# Postfix queries DNS for the TLSA record on the destination MX host. If no
	# TLSA records are found, opportunistic TLS is used. If found, the server
	# certificate must match or mail bounces. TLSA also requires DNSSEC on the MX
	# host. Postfix doesn't do DNSSEC itself but relies on our local unbound
	# resolver (smtp_dns_support_level=dnssec) to validate and report status.
	artifacts.editconf(
		"/etc/postfix/main.cf",
		r"smtp_tls_protocols=\!SSLv2,\!SSLv3",
		"smtp_tls_ciphers=medium",
		"smtp_tls_exclude_ciphers=aNULL,RC4",
		"smtp_tls_security_level=dane",
		"smtp_dns_support_level=dnssec",
		"smtp_tls_mandatory_protocols=!SSLv2,!SSLv3,!TLSv1,!TLSv1.1",
		"smtp_tls_mandatory_ciphers=high",
		# Suppresses 'untrusted' log warnings for opportunistic TLS connections.
		"smtp_tls_CAfile=/etc/ssl/certs/ca-certificates.crt",
		"smtp_tls_loglevel=2",
	)

	# Postscreen: reject bad senders before they get a full SMTP session.
	# postconf -M uses service/type notation (smtp/inet vs smtp/unix) so it cannot
	# accidentally comment out the outbound smtp transport the way editconf can when
	# both share the service name "smtp". Fall back to editconf if postconf is not
	# on PATH (e.g. package install race); the doctor check will catch any collision.
	try:
		subprocess.run(
			[
				"postconf",
				"-M",
				"smtp/inet=smtp inet n - y - 1 postscreen",
				"smtpd/pass=smtpd pass - - y - - smtpd",
				"dnsblog/unix=dnsblog unix - - y - 0 dnsblog",
				"tlsproxy/unix=tlsproxy unix - - y - 0 tlsproxy",
			],
			check=True,
		)
	except FileNotFoundError:
		artifacts.editconf(
			"/etc/postfix/master.cf",
			"smtp=inet n - y - 1 postscreen",
			"smtpd=pass - - y - - smtpd",
			"dnsblog=unix - - y - 0 dnsblog",
			"tlsproxy=unix - - y - 0 tlsproxy",
			space_delim=True,
		)
		# editconf matches on service name alone, so the smtp inet entry above can
		# comment out the smtp unix outbound transport as a duplicate. Restore it.
		subprocess.run(
			["sed", "-i", r"s/^#\(smtp\s\+unix\)/\1/", "/etc/postfix/master.cf"],
			check=False,
		)
	open("/etc/postfix/postscreen_access.cidr", "a", encoding="utf-8").close()
	artifacts.editconf(
		"/etc/postfix/main.cf",
		"postscreen_access_list=permit_mynetworks cidr:/etc/postfix/postscreen_access.cidr",
		"postscreen_blacklist_action=drop",
		"postscreen_dnsbl_action=enforce",
		"postscreen_dnsbl_threshold=3",
		"postscreen_dnsbl_sites=zen.spamhaus.org*3 b.barracudacentral.org*2",
		"postscreen_greet_action=enforce",
	)

	# Message size limit: 128 MB (same as nginx limit for webmail uploads).
	artifacts.editconf("/etc/postfix/main.cf", "message_size_limit=134217728")


def _identity(env: dict, runtime: str) -> None:
	"""Write settings that depend on this server's hostname and network addresses."""
	storage_root = env["STORAGE_ROOT"]
	artifacts.editconf(
		"/etc/postfix/main.cf",
		f"inet_interfaces={_inet_interfaces(env, runtime)}",
		f"smtp_bind_address={env.get('PRIVATE_IP', '')}",
		f"smtp_bind_address6={env.get('PRIVATE_IPV6', '')}",
		f"myhostname={env['PRIMARY_HOSTNAME']}",
		# Banner must begin with hostname per RFC 5321 §4.3.1.
		r"smtpd_banner=$myhostname ESMTP (Ubuntu/Postfix; see https://github.com/naust-mail/naust)",
		"mydestination=localhost",
		# TLS cert paths depend on STORAGE_ROOT which derives from identity.
		f"smtpd_tls_cert_file={storage_root}/ssl/ssl_certificate.pem",
		f"smtpd_tls_key_file={storage_root}/ssl/ssl_private_key.pem",
	)


def _inet_interfaces(env: dict, runtime: str) -> str:
	"""Build an explicit inet_interfaces list instead of 'all'.

	'all' makes Postfix call getifaddrs() and bind every interface it finds.
	On boxes with a non-IP interface in that list (a WireGuard tunnel, a
	Docker bridge, some provider-specific virtual NIC), Postfix 3.6 fails
	outright with "Address family not supported by protocol" instead of
	skipping the entry - postmap/postqueue/postfix itself refuse to start.
	An explicit list avoids the enumeration entirely.

	127.0.0.1 is always included (Dovecot SASL and local submission use it).
	::1 is only included when the box actually has IPv6 configured
	(PUBLIC_IPV6 or PRIVATE_IPV6 set) - on an IPv6-less box, Postfix tries
	to resolve "::1" as a hostname and fails outright with "host not found"
	since there's no IPv6 stack to resolve it against, confirmed on a real
	box. Public/private addresses are added only when actually configured,
	de-duplicated for the common single-NIC VPS case where they're equal.

	In Docker, PUBLIC_IP/PRIVATE_IP are the box's externally-visible
	addresses, not addresses bound to any interface inside this container -
	binding only to them leaves Postfix reachable solely on its own
	loopback, unreachable from sibling containers or via the host's
	published ports. Docker containers only ever have 'lo' plus one or two
	simple bridge NICs (never the exotic interfaces 'all' was built to
	avoid), so 'all' is safe there and is what actually makes the container
	reachable.
	"""
	if runtime == DOCKER:
		return "all"
	has_ipv6 = bool(env.get("PUBLIC_IPV6") or env.get("PRIVATE_IPV6"))
	addrs = ["127.0.0.1"]
	if has_ipv6:
		addrs.append("::1")
	for key in ("PUBLIC_IP", "PRIVATE_IP", "PUBLIC_IPV6", "PRIVATE_IPV6"):
		value = env.get(key, "")
		if value and value not in addrs:
			addrs.append(value)
	return ", ".join(addrs)


def _relay(storage_root: str) -> None:
	"""Configure or clear SMTP relay (smarthost) settings.

	Relay config is set via the admin panel and stored in settings.yaml.
	When a relay is active, smtp_tls_security_level becomes 'verify' since
	relay hosts don't publish DANE TLSA records.
	"""
	host, port = _read_relay_conf(storage_root)
	if host:
		artifacts.editconf(
			"/etc/postfix/main.cf",
			f"relayhost=[{host}]:{port}",
			"smtp_sasl_auth_enable=yes",
			# sasl_passwd is on the storage volume so it survives Docker restarts.
			f"smtp_sasl_password_maps=hash:{storage_root}/mail/relay/sasl_passwd",
			"smtp_sasl_security_options=noanonymous",
			"smtp_tls_security_level=verify",
		)
	else:
		# Clear leftover relay settings and restore direct DANE delivery.
		artifacts.editconf(
			"/etc/postfix/main.cf",
			"relayhost=",
			"smtp_sasl_auth_enable=",
			"smtp_sasl_password_maps=",
			"smtp_sasl_security_options=",
			erase=True,
		)
		artifacts.editconf("/etc/postfix/main.cf", "smtp_tls_security_level=dane")


def _spam_filter(env: dict) -> None:
	"""Write settings that differ between rspamd and spamassassin paths.

	Covers: submission port milter selection, virtual transport,
	sender restrictions, and recipient restrictions.

	rspamd:       milter on 11332, lmtp direct to Dovecot, no Postgrey
	spamassassin: milter on 8891 (OpenDKIM only), lmtp via spampd, Postgrey
	"""
	spam_filter = env.get("SPAM_FILTER", "rspamd")

	# Submission milter: Rspamd handles both spam scanning and DKIM on one port.
	# OpenDMARC is excluded from submission - it only applies to incoming mail.
	milter = "inet:127.0.0.1:11332" if spam_filter == "rspamd" else "inet:127.0.0.1:8891"
	try:
		subprocess.run(
			[
				"postconf",
				"-M",
				"smtps/inet=smtps inet n - - - - smtpd",
				"submission/inet=submission inet n - - - - smtpd",
				# authclean strips Received headers exposing internal IPs from outbound mail.
				"authclean/unix=authclean unix n - - - 0 cleanup",
			],
			check=True,
		)
		subprocess.run(
			[
				"postconf",
				"-P",
				"smtps/inet/smtpd_tls_wrappermode=yes",
				"smtps/inet/smtpd_sasl_auth_enable=yes",
				"smtps/inet/syslog_name=postfix/submission",
				f"smtps/inet/smtpd_milters={milter}",
				"smtps/inet/cleanup_service_name=authclean",
				"submission/inet/smtpd_sasl_auth_enable=yes",
				"submission/inet/syslog_name=postfix/submission",
				f"submission/inet/smtpd_milters={milter}",
				"submission/inet/smtpd_tls_security_level=encrypt",
				"submission/inet/cleanup_service_name=authclean",
				"authclean/unix/header_checks=pcre:/etc/postfix/outgoing_mail_header_filters",
				"authclean/unix/nested_header_checks=",
			],
			check=True,
		)
	except FileNotFoundError:
		artifacts.editconf(
			"/etc/postfix/master.cf",
			f"smtps=inet n       -       -       -       -       smtpd\n  -o smtpd_tls_wrappermode=yes\n  -o smtpd_sasl_auth_enable=yes\n  -o syslog_name=postfix/submission\n  -o smtpd_milters={milter}\n  -o cleanup_service_name=authclean",
			f"submission=inet n       -       -       -       -       smtpd\n  -o smtpd_sasl_auth_enable=yes\n  -o syslog_name=postfix/submission\n  -o smtpd_milters={milter}\n  -o smtpd_tls_security_level=encrypt\n  -o cleanup_service_name=authclean",
			# authclean strips Received headers exposing internal IPs from outbound mail.
			"authclean=unix  n       -       -       -       0       cleanup\n  -o header_checks=pcre:/etc/postfix/outgoing_mail_header_filters\n  -o nested_header_checks=",
			space_delim=True,
			folded=True,
		)

	# Virtual transport: Rspamd acts as milter so mail goes direct to Dovecot LMTP.
	# SpamAssassin path needs a relay hop through spampd (port 10025) first.
	if spam_filter == "rspamd":
		artifacts.editconf("/etc/postfix/main.cf", "virtual_transport=lmtp:unix:private/dovecot-lmtp")
	else:
		artifacts.editconf("/etc/postfix/main.cf", "virtual_transport=lmtp:[127.0.0.1]:10025")
	# Clear old per-message LMTP limit that was a spampd bug workaround.
	artifacts.editconf("/etc/postfix/main.cf", "lmtp_destination_recipient_limit=", erase=True)

	# Sender restrictions.
	artifacts.editconf(
		"/etc/postfix/main.cf",
		"smtpd_sender_restrictions=reject_non_fqdn_sender,reject_unknown_sender_domain,reject_authenticated_sender_login_mismatch,reject_rhsbl_sender dbl.spamhaus.org=127.0.1.[2..99]",
	)

	# Recipient restrictions. Rspamd handles greylisting internally via Redis;
	# SpamAssassin path delegates to Postgrey on port 10023.
	base = "permit_sasl_authenticated,permit_mynetworks,reject_rbl_client zen.spamhaus.org=127.0.0.[2..11],reject_unlisted_recipient"
	if spam_filter == "spamassassin":
		artifacts.editconf(
			"/etc/postfix/main.cf",
			f"smtpd_recipient_restrictions={base},check_policy_service inet:127.0.0.1:10023,check_policy_service inet:127.0.0.1:12340",
		)
	else:
		artifacts.editconf(
			"/etc/postfix/main.cf",
			f"smtpd_recipient_restrictions={base},check_policy_service inet:127.0.0.1:12340",
		)

	artifacts.ufw_allow("smtp")
	artifacts.ufw_allow("smtps")
	artifacts.ufw_allow("submission")


def _postgrey(storage_root: str) -> None:
	"""Configure Postgrey greylisting (spamassassin path only).

	Moves the Postgrey db to STORAGE_ROOT so greylist history survives OS
	reinstalls. Shorter delay (180s vs 300s default) reduces delivery latency.
	"""
	db_dir = os.path.join(storage_root, "mail", "postgrey", "db")
	postgrey_root = os.path.join(storage_root, "mail", "postgrey")

	# --dbdir path must not contain spaces (limitation of postgrey init script).
	artifacts.editconf(
		"/etc/default/postgrey",
		f'POSTGREY_OPTS="--inet=127.0.0.1:10023 --delay=180 --dbdir={db_dir}"',
	)

	if not os.path.isdir(db_dir):
		subprocess.run(["service", "postgrey", "stop"], capture_output=True, check=False)
		os.makedirs(db_dir, exist_ok=True)
		# Migrate existing db files from the default location if present.
		old_db = "/var/lib/postgrey"
		if os.path.isdir(old_db):
			for name in os.listdir(old_db):
				shutil.move(os.path.join(old_db, name), db_dir)

	# Fix ownership only if wrong - avoids traversing a large live db on every run.
	result = subprocess.run(["stat", "-c", "%U", postgrey_root], capture_output=True, text=True, check=False)
	if result.stdout.strip() != "postgrey":
		subprocess.run(["chown", "-R", "postgrey:postgrey", postgrey_root], check=True)
	os.chmod(postgrey_root, 0o700)
	os.chmod(db_dir, 0o700)

	cron_path = "/etc/cron.daily/naust-postgrey-whitelist"
	artifacts.write_file(
		cron_path,
		"#!/bin/bash\n"
		"# Naust - update Postgrey sender whitelist.\n"
		"if [ ! -f /etc/postgrey/whitelist_clients ] || "
		"find /etc/postgrey/whitelist_clients -mtime +28 | grep -q '.' ; then\n"
		"    if curl https://postgrey.schweikert.ch/pub/postgrey_whitelist_clients "
		"--output /tmp/postgrey_whitelist_clients -sS --fail > /dev/null 2>&1 ; then\n"
		'        if [ "$(file -b --mime-type /tmp/postgrey_whitelist_clients)" == "text/plain" ]; then\n'
		"            mv /tmp/postgrey_whitelist_clients /etc/postgrey/whitelist_clients\n"
		"            if pgrep -x postgrey > /dev/null 2>&1; then service postgrey restart; fi\n"
		"        else\n"
		"            rm /tmp/postgrey_whitelist_clients\n"
		"        fi\n"
		"    fi\n"
		"fi\n",
		mode=0o755,
	)
	subprocess.run([cron_path], check=False)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _read_relay_conf(storage_root: str) -> tuple[str, str]:
	"""Return (host, port) from settings.yaml smtp_relay section, or ('', '587')."""
	try:
		import rtyaml

		with open(f"{storage_root}/settings.yaml", encoding="utf-8") as f:
			cfg = rtyaml.load(f) or {}
		r = cfg.get("smtp_relay", {})
		return (r.get("host", "") or "", str(r.get("port", 587)))
	except Exception:  # noqa: BLE001 - missing/malformed settings.yaml just means "no relay configured"
		return ("", "587")


def _relay_stamp(storage_root: str) -> str:
	"""Compute a stamp string from just the relay-relevant fields in settings.yaml.

	Using only relay fields (not the whole file hash) means other settings
	changes in settings.yaml don't trigger a postfix relay re-run.
	"""
	try:
		import rtyaml

		with open(f"{storage_root}/settings.yaml", encoding="utf-8") as f:
			cfg = rtyaml.load(f) or {}
		r = cfg.get("smtp_relay", {})
		return f"{r.get('host', '')}:{r.get('port', 587)}:{r.get('user', '')}"
	except Exception:  # noqa: BLE001 - missing/malformed settings.yaml just means "no relay configured"
		return "no-relay"
