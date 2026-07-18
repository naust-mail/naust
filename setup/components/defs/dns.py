"""
DNS server setup.

Steps:
  dnssec-keys-{algo} - generate KSK+ZSK per algorithm (run_once per algo;
                        re-runs if conf file is deleted)
  configure          - write nsd.conf, logrotate, install dns_update tool,
                       write cron, open firewall ports. Stamp covers: private
                       IPs (affect nsd bind addresses), dns_update tool content
                       (tool binary changed), and this function's source (catches
                       logrotate/cron template changes).

Zone files are NOT written here. The management daemon's /dns/update API
generates zones from live mail users and aliases.
"""

import os
import shutil
import subprocess

from doit.tools import config_changed, run_once

from .. import artifacts, SETUP_DIR
from ..component import Component

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="dns",
	packages=[
		"nsd",
		"ldnsutils",
		"openssh-client",
		"unbound",
		"unbound-anchor",  # recursive resolver; also serves other containers in Docker
	],
	services=["nsd"],
	docker_services=["nsd"],
)

# TLDs, registrars, and validating nameservers don't all support the same
# algorithms, so we generate keys for multiple algorithms so dns_update.py can
# choose when generating zones. See #1953 for recent discussion.
# Files for previously used algorithms (e.g. RSASHA1-NSEC3-SHA1) may still
# exist in the dnssec directory; we continue to support signing with them so
# that trust isn't broken with deployed DS records, but we won't generate
# those keys on new systems.
_DNSSEC_ALGOS = ["RSASHA256", "ECDSAP256SHA256"]

_TOOLS_DIR = os.path.join(SETUP_DIR, "tools")


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	storage_root = env["STORAGE_ROOT"]
	dnssec_dir = os.path.join(storage_root, "dns", "dnssec")
	dns_update_src = os.path.join(_TOOLS_DIR, "dns_update")

	tasks = []

	# One task per algorithm so doit can independently skip already-generated keys.
	# run_once: never regenerate (rotating DNSSEC keys breaks deployed DS records).
	# targets: also re-runs if the conf file is manually deleted.
	for algo in _DNSSEC_ALGOS:
		conf = os.path.join(dnssec_dir, f"{algo}.conf")
		tasks.append({
			"name": f"dnssec-keys-{algo.lower()}",
			"targets": [conf],
			"uptodate": [run_once],
			"actions": [(_generate_dnssec_keys, [algo, dnssec_dir])],
		})

	# Configure stamp: re-runs when private IPs change (nsd bind addresses),
	# when dns_update binary changes (new version shipped), or when this
	# function's code changes (logrotate/cron template updates).
	tool_hash = artifacts.hash_files(dns_update_src) if os.path.exists(dns_update_src) else ""
	configure_stamp = "|".join([
		env.get("PRIVATE_IP", ""),
		env.get("PRIVATE_IPV6", ""),
		tool_hash,
		artifacts.fn_stamp(_configure),
	])
	tasks.append({
		"name": "configure",
		"uptodate": [config_changed(configure_stamp)],
		"task_dep": [f"dns:dnssec-keys-{a.lower()}" for a in _DNSSEC_ALGOS],
		"actions": [(_configure, [env, dns_update_src])],
	})

	return tasks


# ── Action functions ──────────────────────────────────────────────────────────


def _generate_dnssec_keys(algo: str, dnssec_dir: str) -> None:
	"""Generate KSK and ZSK for one DNSSEC algorithm.

	Uses _domain_ as a placeholder - dns_update.py substitutes the real zone
	name when signing. Key filenames are recorded in <algo>.conf so dns_update.py
	knows which files are the current active pair.

	DNSSEC keys MUST NEVER be regenerated - doing so breaks DNS validation for
	all zones currently using these keys (the DS records in parent zones won't
	match). This function refuses to run if the keys already exist, even if
	forced via --always-execute.
	"""
	os.makedirs(dnssec_dir, exist_ok=True)
	conf_file = os.path.join(dnssec_dir, f"{algo}.conf")

	# Refuse to regenerate existing keys - this is a critical safeguard that
	# prevents accidental DNSSEC key rotation which would break all DNS validation
	# for zones currently using these keys.
	if os.path.exists(conf_file):
		print(f"DNSSEC keys for {algo} already exist - refusing to regenerate.")
		print(f"(Regenerating DNSSEC keys breaks DNS validation. Key files: {conf_file})")
		return

	print(f"Generating DNSSEC signing keys for {algo}...")

	old_umask = os.umask(0o077)
	try:
		ksk = subprocess.run(
			["ldns-keygen", "-r", "/dev/urandom", "-a", algo, "-k", "_domain_"],
			cwd=dnssec_dir,
			check=True,
			capture_output=True,
			text=True,
		).stdout.strip()
		zsk = subprocess.run(
			["ldns-keygen", "-r", "/dev/urandom", "-a", algo, "_domain_"],
			cwd=dnssec_dir,
			check=True,
			capture_output=True,
			text=True,
		).stdout.strip()
	finally:
		os.umask(old_umask)

	artifacts.write_file(
		os.path.join(dnssec_dir, f"{algo}.conf"),
		f"KSK={ksk}\nZSK={zsk}\n",
	)


def _configure(env: dict, dns_update_src: str) -> None:
	"""Write nsd config, install dns_update tool, write cron, open firewall."""
	# Dirs must exist before apt installs nsd, otherwise postinst may fail.
	for d in ["/var/run/nsd", "/etc/nsd", "/etc/nsd/zones", "/etc/nsd/nsd.conf.d"]:
		os.makedirs(d, exist_ok=True)

	# nsd must bind only to PRIVATE_IP/PRIVATE_IPV6 to avoid conflicting with
	# unbound, which listens on localhost for recursive DNS queries.
	ip_lines = "".join(f"  ip-address: {ip}\n" for ip in filter(None, [env.get("PRIVATE_IP", ""), env.get("PRIVATE_IPV6", "")]))
	artifacts.write_file(
		"/etc/nsd/nsd.conf",
		"# Do not edit. Overwritten by Naust setup.\n"
		"server:\n"
		"  hide-version: yes\n"
		'  logfile: "/var/log/nsd.log"\n'
		'  identity: ""\n'
		'  zonesdir: "/etc/nsd/zones"\n'
		# ip-transparent: allows nsd to start before interfaces are fully up.
		"  ip-transparent: yes\n"
		"\n" + ip_lines + "\n"
		# zones.conf is generated by the management daemon /dns/update endpoint.
		"include: /etc/nsd/nsd.conf.d/*.conf\n",
	)

	# Remove old zones.conf location (now lives in nsd.conf.d/).
	old = "/etc/nsd/zones.conf"
	if os.path.exists(old):
		os.unlink(old)

	artifacts.write_file(
		"/etc/logrotate.d/nsd",
		"/var/log/nsd.log {\n  weekly\n  missingok\n  rotate 12\n  compress\n  delaycompress\n  notifempty\n}\n",
	)

	# Install dns_update to a fixed path. Vestigial: managerd now re-signs zones
	# natively (ldns-signzone via its daily applier kick), so this tool has no
	# runtime caller and its former daily cron is retired. Kept until the
	# tree-cleanup pass removes setup/tools/dns_update.
	dest = "/usr/local/lib/naust/dns_update"
	if os.path.exists(dns_update_src):
		shutil.copy2(dns_update_src, dest)
		os.chmod(dest, 0o755)

	artifacts.ufw_allow("domain")
