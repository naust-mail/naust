"""Docker wizard - questions, .env generation, and compose command builder."""

import os
from .ui import select_prompt, text_prompt, bold, gray_desc, green, lavender, clear
from .questions import validate_hostname, validate_ipv4, validate_ipv6

# ── Steps ─────────────────────────────────────────────────────────────────────


def step_hostname(_args, answers):
	current = answers.get("PRIMARY_HOSTNAME", "")
	return text_prompt(
		"What hostname will this mail server use?",
		"e.g. mail.example.com - must have an A record pointing to this machine.",
		current,
		validate_hostname,
	)


def step_public_ip(_args, answers):
	current = answers.get("PUBLIC_IP", "")
	return text_prompt(
		"What is the public IPv4 address of this server?",
		"This is the IP your hosting provider assigned to the machine.",
		current,
		validate_ipv4,
	)


def step_public_ipv6(_args, answers):
	current = answers.get("PUBLIC_IPV6", "")
	options = [
		("None", "Most setups work fine with IPv4 only.", ""),
		("✎  Enter an IPv6 address", "Type a public IPv6 address manually.", "__custom__"),
	]
	return select_prompt(
		"Does this server have a public IPv6 address?",
		"IPv6 is optional but recommended if your provider supports it.",
		options,
		current,
		current is not None,
		validate_fn=validate_ipv6,
	)


def step_dns_mode(_args, answers):
	current = answers.get("DNS_MODE")
	options = [
		("Self-hosted DNS", "This box is the authoritative nameserver for your domain.", "self"),
		("External DNS", "DNS is managed via Cloudflare, Route53, etc. Box is mail-only.", "external"),
	]
	return select_prompt(
		"How is DNS managed for your domain?",
		"Self-hosted requires NS glue records at your registrar pointing here.",
		options,
		current or "self",
		current is not None,
	)


def step_webmail(_args, answers):
	current = answers.get("WEBMAIL_CLIENT")
	options = [
		("rav", "Rust-based webmail client. Adds the 'rav' profile.", "rav"),
		("None (external clients)", "No webmail - use Thunderbird, Apple Mail, etc.", "none"),
	]
	return select_prompt(
		"Which webmail client would you like to run?",
		"Can be changed later by editing .env and rebuilding.",
		options,
		current or "rav",
		current is not None,
	)


def step_filebrowser(_args, answers):
	current = answers.get("ENABLE_FILEBROWSER")
	options = [
		("Yes", "Web-based file manager at /files. Adds the 'filebrowser' profile.", "true"),
		("No", "Skip.", "false"),
	]
	return select_prompt(
		"Would you like to run FileBrowser?",
		"Lets mail users browse and manage their files from the browser.",
		options,
		current or "true",
		current is not None,
	)


def step_radicale(_args, answers):
	current = answers.get("ENABLE_RADICALE")
	options = [
		("Yes", "CalDAV/CardDAV sync at /radicale. Adds the 'radicale' profile.", "true"),
		("No", "Skip.", "false"),
	]
	return select_prompt(
		"Would you like to run Radicale (CalDAV/CardDAV)?",
		"Lets mail users sync calendars and contacts with their devices.",
		options,
		current or "true",
		current is not None,
	)


def step_monitoring(_args, answers):
	current = answers.get("_MONITORING")
	options = [
		("Yes", "Munin monitoring dashboard. Adds the 'monitoring' profile.", "true"),
		("No", "Skip.", "false"),
	]
	return select_prompt(
		"Would you like to run Munin monitoring?",
		"System health graphs accessible from the admin panel.",
		options,
		current or "true",
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


def step_ports(_args, answers):
	current = answers.get("_PORT_PROFILE")
	options = [
		("Development", "Safe local ports: HTTP 8080, HTTPS 8443, SMTP 2525, DNS 5354. No root required.", "dev"),
		("Production", "Standard ports: HTTP 80, HTTPS 443, SMTP 25, DNS 53. Requires root.", "prod"),
	]
	return select_prompt(
		"Which port profile should be used?",
		"Use development ports locally. Switch to production on a real server.",
		options,
		current or "dev",
		current is not None,
	)


# ── Step registry ─────────────────────────────────────────────────────────────

# Keys prefixed with _ are wizard-only (not written to .env).
STEPS = [
	("PRIMARY_HOSTNAME", "Hostname", step_hostname),
	("PUBLIC_IP", "IPv4", step_public_ip),
	("PUBLIC_IPV6", "IPv6", step_public_ipv6),
	("DNS_MODE", "DNS", step_dns_mode),
	("WEBMAIL_CLIENT", "Webmail", step_webmail),
	("ENABLE_FILEBROWSER", "FileBrowser", step_filebrowser),
	("ENABLE_RADICALE", "Radicale", step_radicale),
	("_MONITORING", "Monitoring", step_monitoring),
	("BACKUP_TOOL", "Backup", step_backup_tool),
	("_PORT_PROFILE", "Ports", step_ports),
]

VALUE_DISPLAY = {
	"PUBLIC_IPV6": {"": "None"},
	"DNS_MODE": {"self": "Self-hosted", "external": "External"},
	"ENABLE_FILEBROWSER": {"true": "Yes", "false": "No"},
	"ENABLE_RADICALE": {"true": "Yes", "false": "No"},
	"WEBMAIL_CLIENT": {"rav": "rav", "none": "None (external clients)"},
	"_MONITORING": {"true": "Yes", "false": "No"},
	"BACKUP_TOOL": {"restic": "restic", "duplicity": "duplicity"},
	"_PORT_PROFILE": {"dev": "Development", "prod": "Production"},
}

# ── Output generation ─────────────────────────────────────────────────────────


def build_compose_command(answers):
	"""Return the docker compose command string for the given answers."""
	profiles = []
	if answers.get("WEBMAIL_CLIENT") == "rav":
		profiles.append("rav")
	if answers.get("ENABLE_FILEBROWSER") == "true":
		profiles.append("filebrowser")
	if answers.get("ENABLE_RADICALE") == "true":
		profiles.append("radicale")
	if answers.get("_MONITORING") == "true":
		profiles.append("monitoring")

	base = "docker compose -f deploy/docker/docker-compose.yml"
	if answers.get("_PORT_PROFILE") == "prod":
		base += " -f deploy/docker/docker-compose.prod.yml"

	profile_flags = " \\\n  ".join(f"--profile {p}" for p in profiles)
	if profile_flags:
		return f"{base} \\\n  {profile_flags} \\\n  up --build"
	return f"{base} up --build"


def write_env(path, answers, existing=None):
	"""Write a Docker .env file from wizard answers (skip wizard-only _ keys).

	Custom keys present in the existing file but not managed by the wizard are
	preserved so that manual edits are not silently dropped on re-run.
	"""
	# Start from the existing file so manually added keys survive.
	env_vars = dict(existing or {})
	# Overlay with wizard answers, skipping internal wizard-only keys.
	env_vars.update({k: v for k, v in answers.items() if not k.startswith("_")})

	# Always set DOVECOT_IMAP_BIND to 0.0.0.0 in Docker - webmail runs in a
	# separate container and cannot reach the mail container's loopback.
	env_vars["DOVECOT_IMAP_BIND"] = "0.0.0.0"

	tmp = path + ".tmp"
	with open(tmp, "w", encoding="utf-8") as f:
		f.writelines(f"{k}={v}\n" for k, v in env_vars.items())
	os.replace(tmp, path)


def run(env_path):
	"""Run the Docker wizard, write .env, and print the compose command."""
	from .runner import run_questions, load_conf

	existing = load_conf(env_path)

	clear()
	print(f"\n  {bold('Naust - Docker Setup')}")
	if existing:
		print(f"  {gray_desc(f'Loaded existing config from {env_path}')}")
	print(f"  {gray_desc('Configure your Docker deployment.')}\n")

	answers = run_questions(STEPS, None, VALUE_DISPLAY, initial=existing)

	write_env(env_path, answers, existing=existing)
	command = build_compose_command(answers)

	clear()
	print(f"\n  {green('✓')} {bold('Configuration saved to')} {env_path}\n")
	print(f"  {bold('Run this command to start Naust:')}\n")
	print(f"  {lavender(command)}\n")
	print(f"  {gray_desc('Re-run at any time: python3 setup/boxctl docker')}\n")
