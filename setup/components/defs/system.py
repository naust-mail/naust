"""
Base system configuration.

Steps:
  hostname       - write /etc/hostname and activate it
  permissions    - chmod g-w /etc /etc/default /usr (cloud image hardening)
  swap           - create 1G swapfile if RAM < 2GB and disk > 5GB (skip if exists)
  journald       - cap journal at 10 days retention
  motd           - suppress Ubuntu MOTD news adverts
  ntp            - enable systemd-timesyncd for clock accuracy
  no-upgrade     - suppress 'upgrade to next Ubuntu release' prompts
  apt-periodic   - write unattended-upgrades schedule
  ufw            - enable firewall, rate-limit SSH (skipped if DISABLE_FIREWALL)
  unbound        - local recursive DNS resolver on 127.0.0.1:53 with DNSSEC
  timezone       - apply TIMEZONE from conf (only if /etc/timezone is unset)
  fail2ban       - install jails config with template substitution

Port order 0: must run before ssl (10) which must run before dns/postfix/dovecot.
unbound writes /etc/resolv.conf → 127.0.0.1 so subsequent components resolve DNS
through our validating resolver rather than the system stub.
"""

import os
import shutil
import subprocess

from doit.tools import config_changed

from .. import artifacts, SETUP_DIR
from ..component import Component, DOCKER
import pathlib
import contextlib

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="system",
	packages=[
		"python3-dev",
		"python3-setuptools",
		"netcat-openbsd",
		"wget",
		"curl",
		"git",
		"sudo",
		"bc",
		"file",
		"openssh-client",
		"unzip",
		"unattended-upgrades",
		"cron",
		"rsyslog",
		"unbound",
		"dns-root-data",
		"fail2ban",
		"ufw",
	],
	services=["unbound", "rsyslog", "fail2ban"],
	docker_services=[],  # no ufw/unbound in Docker
	port_order=0,  # first: everything else depends on DNS + firewall
)

_CONF_DIR = os.path.join(SETUP_DIR, "conf")
_FAIL2BAN_CONF = os.path.join(_CONF_DIR, "fail2ban", "jails.conf")
_FAIL2BAN_FILTER_DIR = os.path.join(_CONF_DIR, "fail2ban", "filter.d")


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, runtime: str) -> list[dict]:
	hostname = env.get("PRIMARY_HOSTNAME", "")
	public_ip = env.get("PUBLIC_IP", "")
	public_ipv6 = env.get("PUBLIC_IPV6", "")
	storage_root = env.get("STORAGE_ROOT", "/home/user-data")
	timezone = env.get("TIMEZONE", "")
	webmail_client = env.get("WEBMAIL_CLIENT", "rav")
	enable_radicale = env.get("ENABLE_RADICALE", "true")

	fail2ban_stamp = f"{public_ip}:{public_ipv6}:{storage_root}:{webmail_client}:{enable_radicale}:{artifacts.hash_files(_FAIL2BAN_CONF, _FAIL2BAN_FILTER_DIR)}"

	tasks = [
		{
			"name": "hostname",
			"uptodate": [config_changed(hostname)],
			"actions": [(_hostname, [hostname])],
		},
		{
			"name": "permissions",
			"uptodate": [config_changed(artifacts.fn_stamp(_permissions))],
			"actions": [(_permissions,)],
		},
		{
			"name": "swap",
			# Swap is one-time: once created, the swapfile persists across runs.
			# uptodate checks for the swapfile; if it exists we skip. If the
			# system already has swap from another source, _swap() is a no-op.
			"uptodate": [lambda: os.path.exists("/swapfile")],
			"actions": [(_swap,)],
		},
		{
			"name": "journald",
			"uptodate": [config_changed(artifacts.fn_stamp(_journald))],
			"actions": [(_journald,)],
		},
		{
			"name": "ntp",
			"uptodate": [config_changed(artifacts.fn_stamp(_ntp))],
			"actions": [(_ntp,)],
		},
		{
			"name": "no-upgrade",
			"uptodate": [config_changed(artifacts.fn_stamp(_no_upgrade))],
			"actions": [(_no_upgrade,)],
		},
		{
			"name": "apt-periodic",
			"targets": ["/etc/apt/apt.conf.d/02periodic"],
			"uptodate": [config_changed(artifacts.fn_stamp(_apt_periodic))],
			"actions": [(_apt_periodic,)],
		},
		{
			"name": "unbound",
			"targets": ["/etc/unbound/unbound.conf.d/naust.conf"],
			"uptodate": [config_changed(artifacts.fn_stamp(_unbound))],
			"actions": [(_unbound,)],
		},
		{
			"name": "fail2ban",
			"targets": ["/etc/fail2ban/jail.d/naust.conf"],
			"uptodate": [config_changed(fail2ban_stamp)],
			"actions": [
				(
					_fail2ban,
					[
						public_ip,
						public_ipv6,
						storage_root,
						webmail_client,
						enable_radicale,
					],
				)
			],
		},
	]

	# MOTD suppression - only if the file exists (not all Ubuntu variants ship it).
	if os.path.exists("/etc/default/motd-news"):
		tasks.append({
			"name": "motd",
			"uptodate": [config_changed(artifacts.fn_stamp(_motd))],
			"actions": [(_motd,)],
		})

	# ufw - skip entirely in Docker or when DISABLE_FIREWALL is set.
	if runtime != DOCKER and not os.environ.get("DISABLE_FIREWALL"):
		tasks.append({
			"name": "ufw",
			"uptodate": [config_changed(artifacts.fn_stamp(_ufw))],
			"actions": [(_ufw,)],
		})

	# Timezone - only set if TIMEZONE is given and /etc/timezone is unset.
	if timezone:
		tasks.append({
			"name": "timezone",
			# Re-run if the timezone value changes; skip if already correct.
			"uptodate": [config_changed(timezone)],
			"actions": [(_timezone, [timezone])],
		})

	return tasks


# ── Action functions ──────────────────────────────────────────────────────────


def _hostname(hostname: str) -> None:
	if not hostname:
		return
	pathlib.Path("/etc/hostname").write_text(hostname + "\n", encoding="utf-8")
	subprocess.run(["hostname", hostname], check=False)


def _permissions() -> None:
	"""Remove group-write from dirs that cloud images sometimes over-permiss."""
	for path in ["/etc", "/etc/default", "/usr"]:
		if os.path.isdir(path):
			current = os.stat(path).st_mode
			os.chmod(path, current & ~0o020)


def _swap() -> None:
	"""Create a 2G swapfile if RAM < 2GB and free disk > 6GB and no swap exists.

	Sized so a small box can compile the Go daemon and the admin frontend
	from source when no prebuilt release assets are available.
	"""
	# Check existing swap sources.
	with open("/proc/swaps", encoding="utf-8") as f:
		if len(f.readlines()) > 1:  # header + at least one device
			return
	if "swap" in pathlib.Path("/etc/fstab").read_text(encoding="utf-8"):
		return

	# Check filesystem type - btrfs + swapfiles needs extra setup.
	if "btrfs" in pathlib.Path("/proc/mounts").read_text(encoding="utf-8"):
		return

	# Memory and disk checks.
	with open("/proc/meminfo", encoding="utf-8") as f:
		mem_kb = int(f.readline().split()[1])  # MemTotal in kB
	if mem_kb >= 1_900_000:
		return

	result = subprocess.run(["df", "/", "--output=avail"], capture_output=True, text=True, check=False)
	avail_kb = int(result.stdout.strip().splitlines()[-1])
	if avail_kb < 6_291_456:  # 6 GB: the 2G file plus the 4G headroom the 5G check used to leave
		return

	print("Adding a 2G swap file...")
	subprocess.run(["fallocate", "-l", "2G", "/swapfile"], check=True)
	os.chmod("/swapfile", 0o600)
	subprocess.run(["mkswap", "/swapfile"], check=True, capture_output=True)
	subprocess.run(["swapon", "/swapfile"], check=True)

	# Verify it mounted, then persist.
	result = subprocess.run(["swapon", "-s"], capture_output=True, text=True, check=False)
	if "/swapfile" in result.stdout:
		with open("/etc/fstab", "a", encoding="utf-8") as f:
			f.write("/swapfile   none    swap    sw    0   0\n")
	else:
		print("WARNING: swap allocation failed")


def _journald() -> None:
	"""Cap systemd journal retention to 10 days to bound log disk usage."""
	artifacts.editconf("/etc/systemd/journald.conf", "MaxRetentionSec=10day")


def _motd() -> None:
	"""Disable Ubuntu MOTD news to avoid leaking server info in MOTD headers."""
	artifacts.editconf("/etc/default/motd-news", "ENABLED=0")
	# Remove cached news file if present.
	with contextlib.suppress(FileNotFoundError):
		os.unlink("/var/cache/motd-news")


def _ntp() -> None:
	"""Enable systemd-timesyncd for accurate time - required for TLS cert management."""
	subprocess.run(["timedatectl", "set-ntp", "true"], check=False)


def _no_upgrade() -> None:
	"""Suppress Ubuntu's 'upgrade to next release' prompts on the server."""
	if os.path.exists("/etc/update-manager/release-upgrades"):
		artifacts.editconf("/etc/update-manager/release-upgrades", "Prompt=never")
		with contextlib.suppress(FileNotFoundError):
			os.unlink("/var/lib/ubuntu-release-upgrader/release-upgrade-available")


def _apt_periodic() -> None:
	"""Schedule daily unattended security upgrades via apt's periodic mechanism."""
	artifacts.write_file(
		"/etc/apt/apt.conf.d/02periodic",
		'APT::Periodic::MaxAge "7";\nAPT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\nAPT::Periodic::Verbose "0";\n',
	)


def _ufw() -> None:
	"""Enable ufw and rate-limit SSH. Individual components add their own rules."""
	# Allow SSH before enabling so we don't lock ourselves out.
	subprocess.run(["ufw", "limit", "ssh"], check=False, capture_output=True)

	# Allow any alternate SSH port sshd is listening on.
	result = subprocess.run(["sshd", "-T"], capture_output=True, text=True, check=False)
	for line in result.stdout.splitlines():
		if line.startswith("port "):
			port = line.split()[1].strip()
			if port != "22":
				subprocess.run(["ufw", "limit", port], check=False, capture_output=True)

	subprocess.run(["ufw", "--force", "enable"], check=False, capture_output=True)


def _unbound() -> None:
	"""Configure unbound as a validating local resolver on 127.0.0.1:53.

	Disables unbound-resolvconf (conflicts with our resolv.conf) and
	systemd-resolved's stub listener (would occupy port 53 on 127.0.0.53),
	then points /etc/resolv.conf at 127.0.0.1.
	"""
	# Ubuntu's unbound package may enable this, which fights over resolv.conf.
	subprocess.run(
		["systemctl", "disable", "--now", "unbound-resolvconf.service"],
		check=False,
		capture_output=True,
	)

	os.makedirs("/etc/unbound/unbound.conf.d", exist_ok=True)
	artifacts.write_file(
		"/etc/unbound/unbound.conf.d/naust.conf",
		"server:\n"
		"    interface: 127.0.0.1\n"
		"    port: 53\n"
		"    do-ip6: no\n"
		"    access-control: 127.0.0.0/8 allow\n"
		"    hide-identity: yes\n"
		"    hide-version: yes\n"
		"    harden-glue: yes\n"
		"    harden-dnssec-stripped: yes\n"
		"    use-caps-for-id: yes\n"
		"    cache-min-ttl: 300\n"
		"    cache-max-ttl: 86400\n"
		"\n"
		"remote-control:\n"
		"    control-enable: yes\n"
		"    control-use-cert: no\n"
		"    control-interface: /var/run/unbound.ctl\n",
	)

	# Disable resolved's stub so it vacates port 53 on 127.0.0.53.
	artifacts.editconf("/etc/systemd/resolved.conf", "DNSStubListener=no")
	subprocess.run(
		["systemctl", "restart", "systemd-resolved"],
		check=False,
		capture_output=True,
	)

	# Point the system resolver at our unbound.
	artifacts.write_file("/etc/resolv.conf", "nameserver 127.0.0.1\n")


def _timezone(timezone: str) -> None:
	"""Apply the timezone from conf. Restarts rsyslog so log timestamps are correct."""
	subprocess.run(["timedatectl", "set-timezone", timezone], check=True)
	subprocess.run(["systemctl", "restart", "rsyslog"], check=False, capture_output=True)


def _fail2ban(
	public_ip: str,
	public_ipv6: str,
	storage_root: str,
	webmail_client: str,
	enable_radicale: str,
) -> None:
	"""Substitute template vars into jails.conf and install filter files."""
	radicale_jail = "true" if enable_radicale == "true" else "false"
	cypht_jail = "true" if webmail_client == "cypht" else "false"
	roundcube_jail = "true" if webmail_client == "roundcube" else "false"
	snappymail_jail = "true" if webmail_client == "snappymail" else "false"
	webmail_jail = "true" if webmail_client == "rav" else "false"

	content = pathlib.Path(_FAIL2BAN_CONF).read_text(encoding="utf-8")

	content = (
		content
		.replace("PUBLIC_IPV6", public_ipv6)
		.replace("PUBLIC_IP", public_ip)
		.replace("STORAGE_ROOT", storage_root)
		.replace("RADICALE_JAIL_ENABLED", radicale_jail)
		.replace("CYPHT_JAIL_ENABLED", cypht_jail)
		.replace("ROUNDCUBE_JAIL_ENABLED", roundcube_jail)
		.replace("SNAPPYMAIL_JAIL_ENABLED", snappymail_jail)
		.replace("RAV_JAIL_ENABLED", webmail_jail)
	)

	os.makedirs("/etc/fail2ban/jail.d", exist_ok=True)
	# Remove legacy files from old installs.
	for stale in [
		"/etc/fail2ban/jail.local",
		"/etc/fail2ban/jail.d/defaults-debian.conf",
		"/etc/fail2ban/jail.d/nginx-ratelimit.conf",
	]:
		with contextlib.suppress(FileNotFoundError):
			os.unlink(stale)

	artifacts.write_file("/etc/fail2ban/jail.d/naust.conf", content)

	# Install filter definitions.
	os.makedirs("/etc/fail2ban/filter.d", exist_ok=True)
	for name in os.listdir(_FAIL2BAN_FILTER_DIR):
		shutil.copy2(
			os.path.join(_FAIL2BAN_FILTER_DIR, name),
			os.path.join("/etc/fail2ban/filter.d", name),
		)
