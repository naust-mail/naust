"""Entry point: python3 management/services/status_checks [--show-changes|--check-primary-hostname|--version|--only domain...]"""

import json
import os
import sys

# When run as `python3 management/services/status_checks`, __package__ is ''
# and relative imports fail - same situation setup/wizard/__main__.py solves.
# Add management/ to sys.path so absolute imports work either way.
if __package__ in (None, ''):
	sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
	from core.utils import load_environment
	from services.status_checks.orchestrator import run_checks
	from services.status_checks.serialize import results_to_list
	from services.status_checks import utils
else:
	from core.utils import load_environment
	from .orchestrator import run_checks
	from .serialize import results_to_list
	from . import utils

_STATUS_CACHE_FILE = "/var/cache/naust/status_checks.json"


def render_console(results):
	by_category = {}
	for r in results.values():
		by_category.setdefault(r.category, []).append(r)

	symbol = {"ok": "+", "warning": "?", "error": "x", "skipped": "-"}
	for category in sorted(by_category):
		print()
		heading = category.replace("-", " ").title()
		print(heading)
		print("=" * len(heading))
		for r in sorted(by_category[category], key=lambda r: (r.name, r.domain or "")):
			label = r.name if r.domain is None else f"{r.name} [{r.domain}]"
			line = f"{symbol.get(r.status, ' ')}  {label}"
			if r.message:
				line += f": {r.message}"
			print(line)
			for s in r.steps:
				if s.status in {"warning", "error"}:
					print(f"      - {s.name}: {s.message}" if s.message else f"      - {s.name}")


def show_changes(env):
	"""Run checks, diff against the last saved snapshot, print only what changed,
	and save the new snapshot. This is what the nightly cron emails to the admin."""
	results = run_checks(env)
	cur = results_to_list(results)

	prev = []
	if os.path.exists(_STATUS_CACHE_FILE):
		try:
			file_size = os.path.getsize(_STATUS_CACHE_FILE)
			if file_size <= 10485760:  # 10MB limit, same guard as before
				with open(_STATUS_CACHE_FILE, encoding="utf-8") as f:
					prev = json.loads(f.read(10485760))
				if not isinstance(prev, list):
					prev = []
		except (json.JSONDecodeError, OSError, ValueError, MemoryError):
			prev = []

	prev_by_key = {(p["category"], p["name"], p.get("domain")): p for p in prev}
	cur_by_key = {(c["category"], c["name"], c.get("domain")): c for c in cur}

	added = [c for key, c in cur_by_key.items() if key not in prev_by_key]
	removed = [p for key, p in prev_by_key.items() if key not in cur_by_key]
	changed = [(prev_by_key[key], c) for key, c in cur_by_key.items() if key in prev_by_key and prev_by_key[key]["status"] != c["status"]]

	if not (added or removed or changed):
		print("No changes since the last check.")
	else:
		for c in added:
			print(f"ADDED: {c['category']}/{c['name']} [{c.get('domain') or '-'}]: {c['status']} {c['message']}")
		for p in removed:
			print(f"REMOVED: {p['category']}/{p['name']} [{p.get('domain') or '-'}]")
		for p, c in changed:
			print(f"CHANGED: {c['category']}/{c['name']} [{c.get('domain') or '-'}]: {p['status']} -> {c['status']} {c['message']}")

	os.makedirs(os.path.dirname(_STATUS_CACHE_FILE), exist_ok=True)
	with open(_STATUS_CACHE_FILE, "w", encoding="utf-8") as f:
		json.dump(cur, f, indent=True)


if __name__ == "__main__":
	env = load_environment()

	if len(sys.argv) == 1:
		render_console(run_checks(env))

	elif sys.argv[1] == "--show-changes":
		show_changes(env)

	elif sys.argv[1] == "--check-primary-hostname":
		# See if the primary hostname appears resolvable and has a signed certificate.
		from services.ssl_certificates import get_ssl_certificates, get_domain_ssl_files, check_certificate

		domain = env['PRIMARY_HOSTNAME']
		if utils.query_dns(domain, "A") != env['PUBLIC_IP']:
			sys.exit(1)
		ssl_certificates = get_ssl_certificates(env)
		tls_cert = get_domain_ssl_files(domain, ssl_certificates, env)
		if not os.path.exists(tls_cert["certificate"]):
			sys.exit(1)
		cert_status, _details = check_certificate(domain, tls_cert["certificate"], tls_cert["private-key"], warn_if_expiring_soon=False)
		sys.exit(0 if cert_status == "OK" else 1)

	elif sys.argv[1] == "--version":
		print(utils.what_version_is_this(env))

	elif sys.argv[1] == "--only":
		render_console(run_checks(env, domains_filter=set(sys.argv[2:])))
