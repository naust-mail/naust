"""Bare metal wizard steps and validators."""

import contextlib
import ipaddress
import pathlib
from .ui import select_prompt, text_prompt, multiselect_prompt, filter_prompt
from components import artifacts

# ── Validators ────────────────────────────────────────────────────────────────


def validate_email(addr):
	if not addr.strip():
		return "Email address cannot be empty."
	try:
		from email_validator import validate_email as _chk

		_chk(addr.strip(), check_deliverability=False)
	except ImportError:
		return True  # validator not available; bare metal boot venv will have it
	except Exception as exc:  # noqa: BLE001 - turns any validator-raised error into a user-facing message
		return str(exc)
	else:
		return True


def validate_ipv4(addr):
	if not addr.strip():
		return "IPv4 address cannot be empty."
	try:
		ipaddress.IPv4Address(addr.strip())
	except ValueError:
		return "Enter a valid IPv4 address (e.g. 1.2.3.4)."
	else:
		return True


def validate_ipv6(addr):
	if not addr.strip():
		return "IPv6 address cannot be empty."
	try:
		ipaddress.IPv6Address(addr.strip())
	except ValueError:
		return "Enter a valid IPv6 address (e.g. 2001:db8::1)."
	else:
		return True


def validate_hostname(name):
	name = name.strip()
	if not name:
		return "Hostname cannot be empty."
	if len(name) > 253:
		return "Hostname is too long (max 253 characters)."
	labels = name.rstrip(".").split(".")
	if len(labels) < 2:
		return "Hostname must contain at least one dot (e.g. box.example.com)."
	for label in labels:
		if not label or len(label) > 63:
			return "Each hostname part must be 1-63 characters."
		if label.startswith("-") or label.endswith("-"):
			return "Hostname parts cannot start or end with a hyphen."
		if not all(c.isalnum() or c == "-" for c in label):
			return "Hostname parts may only contain letters, digits, and hyphens."
	return True


# ── Steps ─────────────────────────────────────────────────────────────────────


def step_email(args, answers):
	domain = args.default_hostname[4:] if args.default_hostname.startswith("box.") else ""
	default = answers.get("__EMAIL_ADDR") or (f"me@{domain}" if domain else "")
	return text_prompt(
		"What email address should this server manage?",
		"The domain part (after @) will be used to suggest a hostname.",
		default,
		validate_email,
	)


def step_hostname(args, answers):
	email = answers.get("__EMAIL_ADDR", "")
	suggested = f"box.{email.split('@')[-1]}" if email else (args.default_hostname or "")
	current = answers.get("PRIMARY_HOSTNAME")
	options = []
	if suggested:
		options.append((suggested, "Recommended - subdomain of your email domain.", suggested))
	options.append(("✎  Enter a custom hostname", "Type any valid fully-qualified hostname.", "__custom__"))
	return select_prompt(
		"Choose a hostname for your Naust box.",
		"The hostname is your server's address on the internet (e.g. box.example.com).",
		options,
		current or suggested or None,
		current is not None,
		validate_fn=validate_hostname,
	)


def step_ipv4(args, answers):
	current = answers.get("PUBLIC_IP")
	options = []
	if args.guessed_ipv4:
		options.append((args.guessed_ipv4, "Auto-detected from the internet.", args.guessed_ipv4))
	if args.default_ipv4 and args.default_ipv4 != args.guessed_ipv4:
		options.append((args.default_ipv4, "Previously configured address.", args.default_ipv4))
	options.append(("✎  Enter a custom address", "Type an IPv4 address manually.", "__custom__"))
	return select_prompt(
		"What is the public IPv4 address of this server?",
		"This is the IP your hosting provider assigned to the server.",
		options,
		current,
		current is not None,
		validate_fn=validate_ipv4,
	)


def step_ipv6(args, answers):
	current = answers.get("PUBLIC_IPV6")
	options = [("No IPv6", "Most setups work fine with IPv4 only.", "")]
	if args.guessed_ipv6:
		options.append((args.guessed_ipv6, "Auto-detected from the internet.", args.guessed_ipv6))
	if args.default_ipv6 and args.default_ipv6 not in {"", args.guessed_ipv6}:
		options.append((args.default_ipv6, "Previously configured address.", args.default_ipv6))
	options.append(("✎  Enter a custom address", "Type an IPv6 address manually.", "__custom__"))
	return select_prompt(
		"Does this server have a public IPv6 address?",
		"IPv6 is optional but recommended if your provider supports it.",
		options,
		current,
		current is not None,
		validate_fn=validate_ipv6,
	)


def step_filebrowser(_args, answers):
	current = answers.get("ENABLE_FILEBROWSER")
	options = [
		("Yes", "Install a web-based file manager at /files.", "true"),
		("No", "Skip - can be enabled later in /etc/naust.conf.", "false"),
	]
	return select_prompt(
		"Would you like to install FileBrowser?",
		"FileBrowser lets mail users browse and manage their files via the browser.",
		options,
		current or "true",
		current is not None,
	)


def step_optionals(_args, answers):
	current = {
		"ENABLE_RADICALE": answers.get("ENABLE_RADICALE", "true"),
		"ENABLE_CLAMAV": answers.get("ENABLE_CLAMAV", "false"),
		"WEBMAIL_PGP": answers.get("WEBMAIL_PGP", "false"),
	}
	options = [
		("Radicale", "CalDAV/CardDAV server. Sync calendars and contacts with your devices.", "ENABLE_RADICALE"),
		("ClamAV", "Virus scanner for email attachments. Requires ~500MB additional RAM.", "ENABLE_CLAMAV"),
		("Webmail PGP", "In-browser OpenPGP encryption/signing for the webmail client.", "WEBMAIL_PGP"),
	]
	return multiselect_prompt(
		"Which optional features would you like to install?",
		"Toggle on or off. These can be changed later in /etc/naust.conf.",
		options,
		current,
	)


def step_webmail(_args, answers):
	current = answers.get("WEBMAIL_CLIENT")
	options = [
		("rav", "Modern webmail built with Rust + Bun. Fast and lightweight.", "rav"),
		("SnappyMail", "Lightweight, modern PHP webmail client.", "snappymail"),
		("Roundcube", "Long-established, widely-deployed PHP webmail client.", "roundcube"),
		("Cypht", "Modular PHP webmail with multi-account aggregation.", "cypht"),
		("None (external clients)", "No webmail - use Thunderbird, Apple Mail, etc. directly.", "none"),
	]
	return select_prompt(
		"Which webmail client would you like to install?",
		"Webmail lets users access email from any browser. Choose none to skip.",
		options,
		current or "rav",
		current is not None,
	)


def step_encryption_at_rest(_args, answers):
	current = answers.get("ENCRYPTION_AT_REST")
	options = [
		("No", "Mail is stored unencrypted (default).", "false"),
		("Yes", "Encrypt each user's mail at rest with a per-user key.", "true"),
	]
	return select_prompt(
		"Enable encryption at rest for mailboxes?",
		"Each user's mail is encrypted with a key unwrapped by their login password. "
		"WARNING: losing all recovery codes AND the password AND any passkey means the "
		"mail is permanently unrecoverable - there is no master key. A password reset by "
		"an admin requires a recovery code or passkey to restore mailbox access. Opt-in.",
		options,
		current or "false",
		current is not None,
	)


def step_dns_mode(_args, answers):
	current = answers.get("DNS_MODE")
	options = [
		("Self-hosted DNS", "This box manages DNS for your domain (default behavior).", "self"),
		("External DNS", "You manage DNS via Cloudflare, Route53, etc. Box is mail-only.", "external"),
	]
	return select_prompt(
		"How is DNS managed for your domain?",
		"Self-hosted lets this box serve DNS. External skips nameserver checks in status reports.",
		options,
		current or "self",
		current is not None,
	)


def step_spam_filter(_args, answers):
	current = answers.get("SPAM_FILTER")
	options = [
		("Rspamd", "Modern, fast all-in-one filter. Handles DKIM, DMARC, greylisting and Bayes. Recommended.", "rspamd"),
		("SpamAssassin", "Classic rule-based filter. Uses separate OpenDKIM, OpenDMARC, and Postgrey services.", "spamassassin"),
	]
	return select_prompt(
		"Which spam filter would you like to use?",
		"Rspamd replaces four separate services with one, and has better performance.",
		options,
		current or "rspamd",
		current is not None,
	)


def step_backup_tool(_args, answers):
	current = answers.get("BACKUP_TOOL")
	options = [
		("restic", "Faster, deduplicating backups. Recommended for new installs.", "restic"),
		("duplicity", "The original backup tool. Still fully supported.", "duplicity"),
	]
	return select_prompt(
		"Which backup tool should this box use?",
		"Switching later starts a brand-new, empty backup history under the new tool - existing backups are left in place but no longer managed. Nothing migrates automatically.",
		options,
		current or "restic",
		current is not None,
	)


def step_monitoring(_args, answers):
	current = answers.get("MONITORING_TOOL")
	options = [
		("None", "No monitoring dashboard installed.", "none"),
		("Beszel", "Lightweight Go dashboard (~30MB). Clean UI, non-root, WebSocket real-time updates.", "beszel"),
		("Netdata", "Real-time metrics dashboard (~100MB). Auto-discovers mail services. Non-root.", "netdata"),
		("Munin", "Classic RRD-based graphs. Runs as root. Lower RAM, higher disk over time.", "munin"),
	]
	return select_prompt(
		"Which monitoring tool would you like to install?",
		"Provides a web dashboard for system metrics. Can be changed later in /etc/naust.conf.",
		options,
		current or "none",
		current is not None,
	)


def step_timezone(_args, answers):
	import subprocess

	current = answers.get("TIMEZONE", "")

	# Detect current system timezone as default
	default = "UTC"
	if not current:
		with contextlib.suppress(Exception):
			r = subprocess.run(
				["timedatectl", "show", "--property=Timezone", "--value"],
				capture_output=True,
				text=True,
			)
			tz = r.stdout.strip()
			if tz:
				default = tz
		if default == "UTC":
			with contextlib.suppress(Exception):
				tz = pathlib.Path("/etc/timezone").read_text(encoding="utf-8").strip()
				if tz:
					default = tz

	try:
		r = subprocess.run(
			["timedatectl", "list-timezones"],
			capture_output=True,
			text=True,
		)
		timezones = [z for z in r.stdout.splitlines() if z.strip()]
	except Exception:  # noqa: BLE001 - best-effort; any failure just falls back to a single UTC option
		timezones = ["UTC"]

	return filter_prompt(
		"What timezone should this server use?",
		"Backup tasks and cron jobs run at local midnight in this timezone.",
		timezones,
		current or default,
	)


# ── Install profiles ──────────────────────────────────────────────────────────

# Pre-filled answer sets for Recommended and Original installs.
# Keys not present here are left to auto-detection (IPs) or left unset (timezone).
# On re-installs, existing conf values take precedence over these defaults.
PROFILES: dict[str, dict[str, str]] = {
	"recommended": {
		"WEBMAIL_CLIENT": "rav",
		"SPAM_FILTER": "rspamd",
		"DNS_MODE": "external",
		"BACKUP_TOOL": "restic",
		"MONITORING_TOOL": "beszel",
		"ENABLE_RADICALE": "true",
		"ENABLE_FILEBROWSER": "false",
		"ENABLE_CLAMAV": "false",
		"WEBMAIL_PGP": "false",
		"ENCRYPTION_AT_REST": "false",
	},
	"original": {
		"WEBMAIL_CLIENT": "roundcube",
		"SPAM_FILTER": "spamassassin",
		"DNS_MODE": "self",
		"BACKUP_TOOL": "duplicity",
		"MONITORING_TOOL": "munin",
		"ENABLE_RADICALE": "true",
		"ENABLE_FILEBROWSER": "true",
		"ENABLE_CLAMAV": "false",
		"WEBMAIL_PGP": "false",
		"ENCRYPTION_AT_REST": "false",
	},
}


# ── Step registry ─────────────────────────────────────────────────────────────

# Each entry: (argparse_flag, conf_key, nav_label, step_fn)
_ALL_STEPS = [
	("ask_email", "__EMAIL_ADDR", "Email", step_email),
	("ask_hostname", "PRIMARY_HOSTNAME", "Hostname", step_hostname),
	("ask_ipv4", "PUBLIC_IP", "IPv4", step_ipv4),
	("ask_ipv6", "PUBLIC_IPV6", "IPv6", step_ipv6),
	("ask_timezone", "TIMEZONE", "Timezone", step_timezone),
	("ask_webmail", "WEBMAIL_CLIENT", "Webmail", step_webmail),
	("ask_encryption_at_rest", "ENCRYPTION_AT_REST", "Encryption at Rest", step_encryption_at_rest),
	("ask_spam_filter", "SPAM_FILTER", "Spam", step_spam_filter),
	("ask_dns_mode", "DNS_MODE", "DNS", step_dns_mode),
	("ask_backup_tool", "BACKUP_TOOL", "Backup", step_backup_tool),
	("ask_filebrowser", "ENABLE_FILEBROWSER", "FileBrowser", step_filebrowser),
	("ask_monitoring", "MONITORING_TOOL", "Monitoring", step_monitoring),
	("ask_optionals", "__optionals__", "Optionals", step_optionals),
]

# Encryption at Rest needs Ubuntu 26.04+ (Dovecot 2.4's dovecot.http binding).
# Dropped from the registry entirely on older versions so it never appears in
# the wizard, nav bar, or confirm screen - not just disabled/greyed out.
STEPS = _ALL_STEPS if artifacts.ubuntu_supports_encryption() else [s for s in _ALL_STEPS if s[1] != "ENCRYPTION_AT_REST"]

VALUE_DISPLAY = {
	"ENABLE_FILEBROWSER": {"true": "Yes", "false": "No"},
	"WEBMAIL_PGP": {"true": "Yes", "false": "No"},
	"ENCRYPTION_AT_REST": {"true": "Yes", "false": "No"},
	"SPAM_FILTER": {"rspamd": "Rspamd", "spamassassin": "SpamAssassin"},
	"WEBMAIL_CLIENT": {"rav": "rav", "roundcube": "Roundcube", "snappymail": "SnappyMail", "cypht": "Cypht", "none": "None (external clients)"},
	"DNS_MODE": {"self": "Self-hosted", "external": "External"},
	"BACKUP_TOOL": {"restic": "restic", "duplicity": "duplicity"},
	"MONITORING_TOOL": {"none": "None", "beszel": "Beszel", "netdata": "Netdata", "munin": "Munin"},
}
