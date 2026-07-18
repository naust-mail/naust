"""
Dovecot IMAP/POP3 server and local delivery agent (LDA).

Dovecot is both the IMAP/POP server (the protocol that email applications use
to query a mailbox) and the local delivery agent (LDA), responsible for writing
emails to mailbox storage on disk. As part of local mail delivery, Dovecot
executes actions on incoming mail as defined in sieve scripts.

Dovecot's LDA role comes after spam filtering. Postfix hands mail off to
rspamd (or spampd for the spamassassin path) which in turn hands it off to
Dovecot. This all happens using the LMTP protocol.

Steps:
  sysctl    - raise fs.inotify.max_user_instances for IMAP IDLE connections
  limits    - default_process_limit, default_vsz_limit, log_path in 10-master.conf
  mailboxes - install dovecot-mailboxes.conf → 15-mailboxes.conf
  ports     - disable plain IMAP (143) and POP3 (110) in 10-master.conf [dep: limits]
  idle      - imap_idle_notify_interval in 20-imap.conf
  lda       - postmaster_address in 15-lda.conf
  auth      - disable the distro auth includes in 10-auth.conf
  version   - all version-specific config: mail location, SSL, quota, sieve, passwd-file auth
              [dep: auth, idle - both share files that version also writes]
  sieve     - copy and pre-compile sieve-spam.sieve [dep: version]
  dirs      - create mail/sieve directories, set /etc/dovecot permissions [dep: sieve]
  ufw       - allow imaps, pop3s, and sieve ports

Dovecot 2.3 (Ubuntu 22.04/24.04) and 2.4 (Ubuntu 26.04+) require completely
different config syntax. The version step branches at runtime based on the
installed binary. See the dovecot-2x-compat memory for the full breaking-change list.
Whole config files we own live as ${VAR} templates in setup/conf/dovecot/<dialect>/;
this file keeps only the logic (version dispatch, conditional blocks, edits to
distro-owned files).
"""

import os
import shutil
import subprocess

from doit.tools import config_changed

from .. import artifacts, SETUP_DIR
from ..component import Component

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="dovecot",
	packages=[
		"dovecot-core",
		"dovecot-imapd",
		"dovecot-pop3d",
		"dovecot-lmtpd",
		"dovecot-sqlite",
		"sqlite3",
		"dovecot-sieve",
		"dovecot-managesieved",
	],
	services=["dovecot"],
	docker_services=["dovecot"],
)

_CONF_DIR = os.path.join(SETUP_DIR, "conf", "mail")

# Version-dialect config templates. Whole files we own live here as ${VAR}
# templates (one directory per Dovecot config dialect); settings edited into
# distro-owned files stay as editconf/sed calls in the action functions.
_TPL_DIR = os.path.join(SETUP_DIR, "conf", "dovecot")

_SSL_CIPHERS = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	storage_root = env["STORAGE_ROOT"]
	hostname = env.get("PRIMARY_HOSTNAME", "localhost")
	# DOVECOT_IMAP_BIND controls the plain IMAP listener bind address.
	# Default is loopback; set to 0.0.0.0 when the IMAP client is on a
	# separate host or container. LMTP always stays on 127.0.0.1.
	imap_bind = env.get("DOVECOT_IMAP_BIND", "127.0.0.1")

	mailboxes_src = os.path.join(_CONF_DIR, "dovecot-mailboxes.conf")
	sieve_src = os.path.join(_CONF_DIR, "sieve-spam.txt")
	mailcrypt_lua_src = os.path.join(_CONF_DIR, "mailcrypt-auth.lua")
	mailcrypt_lua_src_23 = os.path.join(_CONF_DIR, "mailcrypt-auth-23.lua")

	# Encryption at rest (mail_crypt). When on, the passwd-file passdb chains
	# to a Lua passdb that delivers the per-user mail key at login. See the
	# mailcrypt task and _mailcrypt for the full wiring (dialect differences
	# between 2.4 and 2.3 are handled inside _mailcrypt).
	# Note: Only supported on Ubuntu 26.04+ (Dovecot 2.4 with dovecot.http).
	encryption = env.get("ENCRYPTION_AT_REST", "false").lower() == "true" and artifacts.ubuntu_supports_encryption()

	# Detect installed Dovecot version. Packages are installed before make_tasks
	# is called, so the binary is always available at this point. A silent
	# fallback here would configure the wrong dialect - fail loudly instead.
	ver_result = subprocess.run(["dovecot", "--version"], capture_output=True, text=True, check=False)
	if ver_result.returncode != 0 or not ver_result.stdout.strip():
		msg = "dovecot --version failed - is dovecot-core installed? Cannot plan the dovecot component without knowing the config dialect."
		raise RuntimeError(msg)
	dovecot_version = ver_result.stdout.split()[0]

	# System RAM (physical + swap) for vsz_limit calculation.
	mem_result = subprocess.run(["free", "-tm"], capture_output=True, text=True, check=False)
	total_mem_mb = 1024
	if mem_result.returncode == 0 and mem_result.stdout.strip():
		total_mem_mb = int(mem_result.stdout.strip().split("\n")[-1].split()[1])
	nproc = os.cpu_count() or 1

	# Stamp for the version step: re-runs when Dovecot version changes (OS upgrade),
	# storage path changes, IMAP bind address changes, or either branch of the
	# config function changes. Both branch stamps are included so editing 2.4-only
	# or 2.3-only code still invalidates the stamp even if the other branch is live.
	# The template dir hash covers the config text itself, which lives outside
	# the functions - editing a template must re-run the version step too.
	version_stamp = "|".join([
		dovecot_version,
		storage_root,
		imap_bind,
		str(encryption),
		artifacts.fn_stamp(_version_24),
		artifacts.fn_stamp(_version_23),
		artifacts.hash_files(_TPL_DIR),
	])

	tasks = [
		{
			"name": "sysctl",
			"uptodate": [config_changed(artifacts.fn_stamp(_sysctl))],
			"actions": [(_sysctl,)],
		},
		{
			"name": "limits",
			# Per-machine stamp: process limit scales with CPU, vsz with RAM.
			"uptodate": [config_changed(f"{nproc}:{total_mem_mb}:{artifacts.fn_stamp(_limits)}")],
			"actions": [(_limits, [nproc, total_mem_mb])],
		},
		{
			"name": "mailboxes",
			# Re-run when the source conf file changes (updated mailbox defaults).
			"uptodate": [config_changed(artifacts.hash_files(mailboxes_src))],
			"actions": [(_mailboxes, [mailboxes_src])],
		},
		{
			"name": "ports",
			# Shares 10-master.conf with limits; dep prevents concurrent writes.
			"uptodate": [config_changed(artifacts.fn_stamp(_ports))],
			"task_dep": ["dovecot:limits"],
			"actions": [(_ports,)],
		},
		{
			"name": "idle",
			# 20-imap.conf is also written by the version task; dep declared there.
			"uptodate": [config_changed(artifacts.fn_stamp(_idle))],
			"actions": [(_idle,)],
		},
		{
			"name": "lda",
			"uptodate": [config_changed(f"{hostname}:{artifacts.fn_stamp(_lda)}")],
			"actions": [(_lda, [hostname])],
		},
		{
			"name": "auth",
			# Forces both distro auth includes to a commented state.
			# version also writes to 10-auth.conf, so version deps on this.
			"uptodate": [config_changed(artifacts.fn_stamp(_auth))],
			"actions": [(_auth,)],
		},
		{
			"name": "version",
			# Writes to many conf.d files including 10-auth.conf and 20-imap.conf.
			# Deps on auth and idle to prevent concurrent writes to those files.
			"uptodate": [config_changed(version_stamp)],
			"task_dep": ["dovecot:auth", "dovecot:idle"],
			"actions": [(_version, [dovecot_version, storage_root, imap_bind, encryption])],
		},
		{
			"name": "sieve",
			# sievec runs doveconf internally, so all conf.d files must exist first.
			"uptodate": [config_changed(f"{artifacts.hash_files(sieve_src)}:{artifacts.fn_stamp(_sieve)}")],
			"task_dep": ["dovecot:version"],
			"actions": [(_sieve, [sieve_src])],
		},
		{
			"name": "dirs",
			# Creates mail/sieve dirs and locks down /etc/dovecot after all writes.
			"uptodate": [config_changed(f"{storage_root}:{artifacts.fn_stamp(_dirs)}")],
			"task_dep": ["dovecot:sieve"],
			"actions": [(_dirs, [storage_root])],
		},
		{
			"name": "ufw",
			"uptodate": [config_changed(artifacts.fn_stamp(_ufw))],
			"actions": [(_ufw,)],
		},
	]

	# Encryption at rest: install the Lua auth plugin, write the mail_crypt config,
	# and deploy the auth Lua script. Only added when the feature is enabled so
	# installs that don't use it never pull in dovecot-auth-lua. Runs after the
	# version step (which writes 95-auth.conf with the passdb chain) and
	# before dirs (which locks down /etc/dovecot permissions).
	if encryption:
		mailcrypt_tpls = [os.path.join(_TPL_DIR, "2.4", "95-mail-crypt.conf")] if dovecot_version.startswith("2.4.") else [os.path.join(_TPL_DIR, "2.3", "05-mail-crypt-early.conf"), os.path.join(_TPL_DIR, "2.3", "96-mail-crypt.conf")]
		tasks.append({
			"name": "mailcrypt",
			"uptodate": [config_changed(f"{artifacts.fn_stamp(_mailcrypt)}:{artifacts.hash_files(mailcrypt_lua_src, mailcrypt_lua_src_23, *mailcrypt_tpls)}")],
			"task_dep": ["dovecot:version"],
			"actions": [(_mailcrypt, [dovecot_version, mailcrypt_lua_src, mailcrypt_lua_src_23, storage_root])],
		})
		# Ensure the /etc/dovecot lockdown runs after the lua script is installed.
		for t in tasks:
			if t["name"] == "sieve":
				t.setdefault("task_dep", []).append("dovecot:mailcrypt")

	return tasks


# ── Action functions ──────────────────────────────────────────────────────────


def _sysctl() -> None:
	"""Raise inotify max_user_instances so many IMAP IDLE connections fit.

	Default is 128; at ~5 open folders per user that limits IDLE push to
	~25 concurrent users. 1024 raises it to ~200 users on a modest server.
	"""
	os.makedirs("/etc/sysctl.d", exist_ok=True)
	artifacts.write_file(
		"/etc/sysctl.d/99-inotify.conf",
		"fs.inotify.max_user_instances=1024\n",
	)
	# Apply immediately - best-effort, may silently fail inside containers.
	subprocess.run(
		["sysctl", "-p", "/etc/sysctl.d/99-inotify.conf"],
		capture_output=True,
		check=False,
	)


def _limits(nproc: int, total_mem_mb: int) -> None:
	"""Set IMAP connection limit and virtual memory cap in 10-master.conf.

	process_limit = 250 * cores (at ~5 connections/user = 50 * cores users).
	vsz_limit = total_mem / 3 so a single runaway process can't OOM the box.
	"""
	artifacts.editconf(
		"/etc/dovecot/conf.d/10-master.conf",
		f"default_process_limit={nproc * 250}",
		f"default_vsz_limit={total_mem_mb // 3}M",
		"log_path=/var/log/mail.log",
	)


def _mailboxes(src: str) -> None:
	"""Install INBOX/Drafts/Sent/Trash/Spam/Archive mailbox subscription config."""
	shutil.copy2(src, "/etc/dovecot/conf.d/15-mailboxes.conf")


def _ports() -> None:
	"""Disable plain-text IMAP (143) and POP3 (110); only TLS variants are exposed.

	The default Dovecot config has these ports commented as '#port = N'. Setting
	them to 0 disables the listener. Both seds are idempotent: after the first
	run the '#port = N' pattern no longer matches.
	"""
	for pattern in [r"s/#port = 143/port = 0/", r"s/#port = 110/port = 0/"]:
		subprocess.run(
			["sed", "-i", pattern, "/etc/dovecot/conf.d/10-master.conf"],
			check=True,
		)


def _idle() -> None:
	"""Reduce IMAP IDLE notify interval to keep NAT connections alive. See [#129]."""
	artifacts.editconf(
		"/etc/dovecot/conf.d/20-imap.conf",
		"imap_idle_notify_interval=4 mins",
	)


def _lda(hostname: str) -> None:
	"""Set postmaster_address; required or Dovecot's LMTP service refuses to start.

	An alias for postmaster@ will be created automatically by the management daemon.
	"""
	artifacts.editconf(
		"/etc/dovecot/conf.d/15-lda.conf",
		f"postmaster_address=postmaster@{hostname}",
	)


def _auth() -> None:
	"""Disable the distro's auth includes; our passdb/userdb live in 95-auth.conf.

	Both system-user auth and the sql include are forced to a commented state
	regardless of what a previous install left behind. Idempotent: s/#*X/#X/
	collapses any number of leading hashes to one.
	"""
	for pattern in [
		r"s/#*\(!include auth-system.conf.ext\)/#\1/",
		r"s/#*\(!include auth-sql.conf.ext\)/#\1/",
	]:
		subprocess.run(
			["sed", "-i", pattern, "/etc/dovecot/conf.d/10-auth.conf"],
			check=True,
		)


def _version(dovecot_version: str, storage_root: str, imap_bind: str, encryption: bool = False) -> None:
	"""Dispatch to the correct version-specific config function.

	This wrapper exists so the action signature is simple; the actual logic
	(and the fn_stamps) live in _version_24 and _version_23.
	"""
	if dovecot_version.startswith("2.4."):
		_version_24(storage_root, imap_bind, encryption)
	else:
		_version_23(storage_root, imap_bind, encryption)


def _version_24(storage_root: str, imap_bind: str, encryption: bool = False) -> None:
	"""Dovecot 2.4 config (Ubuntu 26.04+).

	Opts in to the new config format via dovecot_config_version=2.4.0, which
	makes every 2.4 incompatibility a fatal startup error. Key changes:
	- plugin{} blocks removed (quota and sieve use SET_FILTER_ARRAY blocks)
	- mail_location split into mail_driver + mail_path
	- Variable syntax: %d/%n -> %{user|domain}/%{user|username}
	- SSL settings renamed (ssl_cert -> ssl_server_cert_file, etc.)
	- mail_plugins is BOOLLIST - no $variable expansion, use plain names
	- inet_listener 'address' removed; use 'listen' instead
	- passdb/userdb are inline blocks (no separate .ext files)
	"""
	# Opt in to strict 2.4 parsing. Without this, 2.4 runs in compat mode and
	# some breakage is silent. With it, every incompatibility is a startup error.
	artifacts.editconf(
		"/etc/dovecot/dovecot.conf",
		"dovecot_config_version=2.4.0",
		"dovecot_storage_version=2.4.0",
	)

	artifacts.editconf(
		"/etc/dovecot/conf.d/10-mail.conf",
		"mail_driver=maildir",
		f"mail_path={storage_root}/mail/mailboxes/%{{user|domain}}/%{{user|username}}",
		"mail_privileged_group=mail",
		"first_valid_uid=0",
	)

	# disable_plaintext_auth inverted to auth_allow_cleartext (value also inverted).
	artifacts.editconf(
		"/etc/dovecot/conf.d/10-auth.conf",
		"auth_mechanisms=plain login",
		"auth_allow_cleartext=no",
	)

	# ssl_cert/ssl_key renamed; < prefix gone; ssl_min_protocol removed (TLSv1.2
	# is the floor in 2.4 by default). ssl_prefer_server_ciphers renamed and
	# value changed from yes/no to server/client.
	artifacts.editconf(
		"/etc/dovecot/conf.d/10-ssl.conf",
		"ssl=required",
		f"ssl_server_cert_file={storage_root}/ssl/ssl_certificate.pem",
		f"ssl_server_key_file={storage_root}/ssl/ssl_private_key.pem",
		f"ssl_cipher_list={_SSL_CIPHERS}",
		"ssl_server_prefer_ciphers=client",
	)

	# mail_plugins is a BOOLLIST in 2.4 - the parser does no $variable expansion.
	# Using "$mail_plugins quota" would try to load a plugin literally named
	# "$mail_plugins" and fail fatally. Use plain names only.
	subprocess.run(
		["sed", "-i", r"s/#mail_plugins =.*/mail_plugins = quota/", "/etc/dovecot/conf.d/10-mail.conf"],
		check=True,
	)
	# Guard the imap_quota insertion so re-runs don't duplicate the line.
	if (
		subprocess.run(
			["grep", "-q", "mail_plugins.*imap_quota", "/etc/dovecot/conf.d/20-imap.conf"],
			check=False,
		).returncode
		!= 0
	):
		subprocess.run(
			["sed", "-i", r"s/\(mail_plugins =.*\)/\1\n  mail_plugins = imap_quota/", "/etc/dovecot/conf.d/20-imap.conf"],
			check=True,
		)
	subprocess.run(
		["sed", "-i", r"s/#mail_plugins = .*/mail_plugins = sieve/", "/etc/dovecot/conf.d/20-lmtp.conf"],
		check=True,
	)

	# quota: plugin{} removed; quota roots use SET_FILTER_ARRAY syntax.
	# quota_storage_grace is now a SIZE (bytes); 10M matches the 2.3 spirit of 10%.
	artifacts.write_file(
		"/etc/dovecot/conf.d/90-quota.conf",
		artifacts.render_template(os.path.join(_TPL_DIR, "2.4", "90-quota.conf")),
	)

	# inet_listener 'address' field removed in 2.4; bind address is now 'listen'.
	artifacts.write_file(
		"/etc/dovecot/conf.d/99-local.conf",
		artifacts.render_template(
			os.path.join(_TPL_DIR, "2.4", "99-local.conf"),
			{"IMAP_BIND": imap_bind},
		),
	)

	# sieve: plugin{} removed. Pigeonhole 2.4 uses sieve_script SET_FILTER_ARRAY
	# blocks. sieve_script_active_path replaces the old 'sieve =' symlink setting.
	# sieve_before/after/dir settings are gone; sieve_script_type controls ordering.
	artifacts.write_file(
		"/etc/dovecot/conf.d/99-local-sieve.conf",
		artifacts.render_template(
			os.path.join(_TPL_DIR, "2.4", "99-local-sieve.conf"),
			{"STORAGE_ROOT": storage_root},
		),
	)

	# Auth against the manager's materialized passwd-file. Quota and the
	# per-user mail_crypt activation field (crypt_user_key_curve) arrive as
	# userdb_ extras in the file itself - managerd emits them, this config
	# never varies per user. When encryption at rest is on, the passdb must
	# not stop after verifying the password: it continues to the Lua passdb
	# (defined in 95-mail-crypt.conf) which delivers crypt_user_key_password.
	# result_failure=return-fail keeps a failed verification authoritative
	# so the Lua passdb can never override it.
	chain = "  result_success = continue\n  result_failure = return-fail\n" if encryption else ""
	artifacts.write_file(
		"/etc/dovecot/conf.d/95-auth.conf",
		artifacts.render_template(
			os.path.join(_TPL_DIR, "2.4", "95-auth.conf"),
			{"CHAIN": chain, "STORAGE_ROOT": storage_root},
		),
	)
	_remove_sql_auth()


def _version_23(storage_root: str, imap_bind: str, encryption: bool = False) -> None:
	"""Dovecot 2.3 config (Ubuntu 22.04/24.04). Uses legacy plugin{} syntax.

	Encryption-at-rest wiring mirrors _version_24's chain (passwd-file passdb
	continues to a Lua passdb that delivers the per-user mail key), adapted
	for 2.3's dialect - see the mailcrypt task and _mailcrypt for the parts
	that differ from 2.4 (2.3 has no %{passdb:...}, only %{userdb:...}, so
	the Lua passdb must go through a prefetch userdb instead of a direct
	passdb reference; see setup/conf/dovecot/2.3/05-mail-crypt-early.conf and
	96-mail-crypt.conf for the resulting two-file split).
	"""
	artifacts.editconf(
		"/etc/dovecot/conf.d/10-mail.conf",
		f"mail_location=maildir:{storage_root}/mail/mailboxes/%d/%n",
		"mail_privileged_group=mail",
		"first_valid_uid=0",
	)

	artifacts.editconf(
		"/etc/dovecot/conf.d/10-auth.conf",
		"disable_plaintext_auth=yes",
		"auth_mechanisms=plain login",
	)

	# 2.3 uses '<' prefix to read cert/key from file. ssl_min_protocol caps at
	# TLSv1.2 since 2.3 does not support TLSv1.3.
	artifacts.editconf(
		"/etc/dovecot/conf.d/10-ssl.conf",
		"ssl=required",
		f"ssl_cert=<{storage_root}/ssl/ssl_certificate.pem",
		f"ssl_key=<{storage_root}/ssl/ssl_private_key.pem",
		"ssl_min_protocol=TLSv1.2",
		f"ssl_cipher_list={_SSL_CIPHERS}",
		"ssl_prefer_server_ciphers=no",
	)

	# 2.3 mail_plugins use $mail_plugins to append to the package defaults.
	subprocess.run(
		["sed", "-i", r"s/#mail_plugins =\(.*\)/mail_plugins =\1 $mail_plugins quota/", "/etc/dovecot/conf.d/10-mail.conf"],
		check=True,
	)
	if (
		subprocess.run(
			["grep", "-q", r"mail_plugins.* imap_quota", "/etc/dovecot/conf.d/20-imap.conf"],
			check=False,
		).returncode
		!= 0
	):
		subprocess.run(
			["sed", "-i", r"s/\(mail_plugins =.*\)/\1\n  mail_plugins = $mail_plugins imap_quota/", "/etc/dovecot/conf.d/20-imap.conf"],
			check=True,
		)
	subprocess.run(
		["sed", "-i", r"s/#mail_plugins = .*/mail_plugins = $mail_plugins sieve/", "/etc/dovecot/conf.d/20-lmtp.conf"],
		check=True,
	)

	artifacts.write_file(
		"/etc/dovecot/conf.d/90-quota.conf",
		artifacts.render_template(os.path.join(_TPL_DIR, "2.3", "90-quota.conf")),
	)

	# 2.3 pop3_uidl_format: must be set explicitly. 2.4's default is already
	# equivalent (%{uid|hex(8)}%{uidvalidity|hex(8)}) and does not accept this
	# printf-style format, so this setting is 2.3-only.
	artifacts.editconf(
		"/etc/dovecot/conf.d/20-pop3.conf",
		"pop3_uidl_format=%08Xu%08Xv",
	)

	# 2.3 uses 'address' inside inet_listener blocks.
	artifacts.write_file(
		"/etc/dovecot/conf.d/99-local.conf",
		artifacts.render_template(
			os.path.join(_TPL_DIR, "2.3", "99-local.conf"),
			{"IMAP_BIND": imap_bind},
		),
	)

	# 2.3 sieve uses plugin{} with sieve_before/after/dir settings.
	artifacts.write_file(
		"/etc/dovecot/conf.d/99-local-sieve.conf",
		artifacts.render_template(
			os.path.join(_TPL_DIR, "2.3", "99-local-sieve.conf"),
			{"STORAGE_ROOT": storage_root},
		),
	)

	# 2.3 reads the same materialized passwd-file as 2.4, in its own dialect.
	# When encryption is on, pass = yes lets the chain continue to the Lua
	# passdb in 96-mail-crypt.conf (see _mailcrypt) instead of stopping here.
	chain = "  pass = yes\n" if encryption else ""
	artifacts.write_file(
		"/etc/dovecot/conf.d/95-auth.conf",
		artifacts.render_template(
			os.path.join(_TPL_DIR, "2.3", "95-auth.conf"),
			{"CHAIN": chain, "STORAGE_ROOT": storage_root},
		),
	)
	_remove_sql_auth()


def _remove_sql_auth() -> None:
	"""Drop the pre-flip SQL auth include; nothing references it anymore."""
	stale = "/etc/dovecot/conf.d/auth-sql.conf.ext"
	if os.path.exists(stale):
		os.remove(stale)


def _mailcrypt(dovecot_version: str, lua_src: str, lua_src_23: str, storage_root: str) -> None:
	"""Configure encryption at rest (mail_crypt).

	Loads the mail_crypt plugin, gives it a per-home file attribute dict (where it
	stores key metadata), and adds the Lua passdb that delivers the per-user mail
	key at login (the passwd-file passdb chains into it - see _version_24 and
	_version_23). Both dialects call the same managerd unwrap endpoint from Lua;
	only the Dovecot-side field delivery differs (2.4 uses a direct passdb field,
	2.3 has no %{passdb:...} at all and must go through a prefetch userdb - see
	setup/conf/mail/mailcrypt-auth-23.lua for why).

	Deliberately does NOT set a global crypt_user_key_curve/mail_crypt_curve:
	that would make mail_crypt auto-generate keypairs for every user on delivery
	and encrypt everyone's mail. Instead, a user's keypair is generated explicitly
	only when they enable encryption (management runs `doveadm mailbox cryptokey
	generate`). So keypair existence is the per-user switch, and non-opted-in
	mailboxes are untouched.
	"""
	# Install the Lua auth plugin only now (feature is opt-in).
	from .. import packages

	packages.ensure_installed(["dovecot-auth-lua"])

	dest_lua = "/etc/dovecot/mailcrypt-auth.lua"
	is_24 = dovecot_version.startswith("2.4.")

	if is_24:
		# No template substitution needed - the 2.4 script never reads the
		# passwd-file itself, only the storage-root-independent unwrap endpoint.
		shutil.copy2(lua_src, dest_lua)
	else:
		# 2.3 also reads the materialized passwd-file directly for uid/gid/home
		# (see that script's docstring), so it needs STORAGE_ROOT substituted in.
		artifacts.write_file(
			dest_lua,
			artifacts.render_template(lua_src_23, {"STORAGE_ROOT": storage_root}),
		)
	subprocess.run(["chown", "root:dovecot", dest_lua], check=True)
	subprocess.run(["chmod", "0640", dest_lua], check=True)

	# mail_crypt config. crypt_write_algorithm is the default; set explicitly for
	# clarity. mail_attribute uses the 2.4 dict-block form (validated on 2.4.2).
	if is_24:
		artifacts.write_file(
			"/etc/dovecot/conf.d/95-mail-crypt.conf",
			artifacts.render_template(os.path.join(_TPL_DIR, "2.4", "95-mail-crypt.conf")),
		)
	else:
		# Split across two files for load-order reasons - see each file's
		# own header comment (mail_plugins/prefetch-userdb timing vs the
		# passdb-chain-must-follow-95-auth.conf requirement).
		artifacts.write_file(
			"/etc/dovecot/conf.d/05-mail-crypt-early.conf",
			artifacts.render_template(os.path.join(_TPL_DIR, "2.3", "05-mail-crypt-early.conf")),
		)
		artifacts.write_file(
			"/etc/dovecot/conf.d/96-mail-crypt.conf",
			artifacts.render_template(os.path.join(_TPL_DIR, "2.3", "96-mail-crypt.conf")),
		)


def _sieve(src: str) -> None:
	"""Copy and pre-compile the global spam sieve script.

	sievec runs doveconf internally to validate the script against the active
	config. It must run after the version step has written all conf.d files.
	Pre-compiling as root avoids silent failures at LMTP delivery time when
	Dovecot's LMTP process lacks write access to /etc/dovecot.
	"""
	dest = "/etc/dovecot/sieve-spam.sieve"
	shutil.copy2(src, dest)
	subprocess.run(["sievec", dest], check=True)


def _dirs(storage_root: str) -> None:
	"""Create mail/sieve directories and lock down /etc/dovecot permissions.

	chown -R is only issued on first creation to avoid traversing a live mail
	store on every run. Directory creation is always idempotent.
	"""
	mailboxes = os.path.join(storage_root, "mail", "mailboxes")
	first_run = not os.path.isdir(mailboxes)
	os.makedirs(mailboxes, exist_ok=True)
	if first_run:
		subprocess.run(["chown", "-R", "mail:mail", mailboxes], check=True)

	sieve_root = os.path.join(storage_root, "mail", "sieve")
	first_run_sieve = not os.path.isdir(sieve_root)
	for d in [
		sieve_root,
		os.path.join(sieve_root, "global_before"),
		os.path.join(sieve_root, "global_after"),
	]:
		os.makedirs(d, exist_ok=True)
	if first_run_sieve:
		subprocess.run(["chown", "-R", "mail:mail", sieve_root], check=True)

	# Dovecot binds its SASL auth socket inside the Postfix spool chroot.
	# Postfix creates this directory on its first start, but dovecot starts
	# first on a fresh install. Create it with postfix:postfix 0700 so
	# postfix can bind sockets there - root:root 0755 causes Permission Denied.
	priv = "/var/spool/postfix/private"
	if not os.path.isdir(priv):
		import pwd as _pwd
		import grp as _grp

		os.makedirs(priv)
		pw = _pwd.getpwnam("postfix")
		os.chown(priv, pw.pw_uid, _grp.getgrnam("postfix").gr_gid)
		os.chmod(priv, 0o700)

	# Lock down /etc/dovecot: owned by mail:dovecot, not world-readable.
	# Run after all conf.d files are written (sieve task is the last writer).
	owner = subprocess.run(
		["stat", "-c", "%U", "/etc/dovecot"],
		capture_output=True,
		text=True,
		check=False,
	).stdout.strip()
	if owner != "mail":
		subprocess.run(["chown", "-R", "mail:dovecot", "/etc/dovecot"], check=True)
	subprocess.run(["chmod", "-R", "o-rwx", "/etc/dovecot"], check=True)


def _ufw() -> None:
	"""Allow IMAPS (993), POP3S (995), and Sieve (4190) through the firewall."""
	artifacts.ufw_allow("imaps")
	artifacts.ufw_allow("pop3s")
	artifacts.ufw_allow("sieve")
