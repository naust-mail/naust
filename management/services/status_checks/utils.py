import datetime
import os
import os.path
import re
import threading

import dns.resolver

from core.utils import shell, get_ssh_port

# DNS query cache - thread-safe with TTL for security
_dns_cache = {}
_dns_cache_lock = threading.Lock()
_DNS_CACHE_TTL = 60  # 1 minute TTL to prevent stale/poisoned cache entries
_DNS_CACHE_MAX_SIZE = 1000  # Max entries to prevent memory exhaustion attacks


def clear_dns_cache():
	"""Clear the DNS cache - useful when DNS changes are expected."""
	global _dns_cache
	with _dns_cache_lock:
		_dns_cache = {}


def _is_cache_entry_valid(timestamp):
	return (datetime.datetime.now() - timestamp).total_seconds() < _DNS_CACHE_TTL


def _evict_expired_cache_entries():
	global _dns_cache
	now = datetime.datetime.now()
	_dns_cache = {k: v for k, v in _dns_cache.items() if (now - v[1]).total_seconds() < _DNS_CACHE_TTL}


def normalize_ip(ip):
	# Use ipaddress module to normalize the IPv6 notation and
	# ensure we are matching IPv6 addresses written in different
	# representations according to rfc5952.
	import ipaddress

	try:
		return str(ipaddress.ip_address(ip))
	except Exception:
		return ip


def query_dns(qname, rtype, nxdomain='[Not Set]', at=None, as_list=False):
	global _dns_cache

	# Input validation: prevent DNS amplification and injection attacks
	if isinstance(qname, str):
		if len(qname) > 253:  # RFC 1035 max domain name length
			return nxdomain
		if not all(c.isalnum() or c in '.-_' for c in qname.replace('.', '')):
			return nxdomain

	valid_rtypes = {'A', 'AAAA', 'MX', 'NS', 'TXT', 'PTR', 'DS', 'TLSA', 'SOA', 'CNAME'}
	if rtype not in valid_rtypes:
		return nxdomain

	cache_key = (str(qname), rtype, at, as_list)

	with _dns_cache_lock:
		if cache_key in _dns_cache:
			cached_result, cached_time = _dns_cache[cache_key]
			if _is_cache_entry_valid(cached_time):
				return cached_result
			del _dns_cache[cache_key]

	# Make the qname absolute by appending a period. Without this, dns.resolver.query
	# will fall back a failed lookup to a second query with this machine's hostname
	# appended. This has been causing some false-positive Spamhaus reports. The
	# reverse DNS lookup will pass a dns.name.Name instance which is already
	# absolute so we should not modify that.
	if isinstance(qname, str):
		qname += "."

	resolver = dns.resolver.get_default_resolver()

	if at and at not in {'[Not set]', '[timeout]'}:
		resolver = dns.resolver.Resolver()
		resolver.nameservers = [at]

	resolver.timeout = 3
	resolver.lifetime = 3

	try:
		response = resolver.resolve(qname, rtype)
		if len(response) > 100:
			response = list(response)[:100]  # Cap at 100 records
	except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
		result = nxdomain
	except dns.exception.Timeout:
		result = "[timeout]"
	except (ValueError, UnicodeError, UnicodeDecodeError):
		result = nxdomain
	except Exception:
		result = nxdomain
	else:
		try:
			if rtype in {"A", "AAAA"}:
				response = [normalize_ip(str(r)) for r in response]

			if as_list:
				result = response
			else:
				response_strs = [str(r).rstrip('.') for r in response]
				response_strs = [s[:1024] for s in response_strs if len(s) < 2048]
				result = "; ".join(sorted(response_strs))
		except Exception:
			result = nxdomain

	with _dns_cache_lock:
		if len(_dns_cache) >= _DNS_CACHE_MAX_SIZE:
			_evict_expired_cache_entries()
			if len(_dns_cache) >= _DNS_CACHE_MAX_SIZE:
				_dns_cache = {}
		_dns_cache[cache_key] = (result, datetime.datetime.now())

	return result


def get_services(env):
	# Service host addresses come from env (set via /etc/naust.conf).
	# On bare metal everything defaults to 127.0.0.1; in Docker these point
	# to the container service names written by write_naust_conf.
	mail_host = env.get('MAIL_HOST', '127.0.0.1')
	dns_host = env.get('DNS_HOST', '127.0.0.1')
	webmail_host = env.get('WEBMAIL_HOST', '127.0.0.1')

	spam_filter = env.get("SPAM_FILTER", "spamassassin")
	rspamd_host = env.get('RSPAMD_HOST', '127.0.0.1')
	redis_host = env.get('REDIS_HOST', '127.0.0.1')

	services = [
		{"name": "Local DNS (unbound)", "port": 53, "public": False, "host": dns_host},
		{"name": "Dovecot LMTP LDA", "port": 10026, "public": False, "host": mail_host},
		{"name": "Naust Management Daemon", "port": 10222, "public": False},
		{"name": "SSH Login (ssh)", "port": get_ssh_port(), "public": True},
		{"name": "Public DNS (nsd4)", "port": 53, "public": True, "host": dns_host},
		{"name": "Incoming Mail (SMTP/postfix)", "port": 25, "public": True, "host": mail_host},
		{"name": "Outgoing Mail (SMTP 465/postfix)", "port": 465, "public": True, "host": mail_host},
		{"name": "Outgoing Mail (SMTP 587/postfix)", "port": 587, "public": True, "host": mail_host},
		{"name": "IMAPS (dovecot)", "port": 993, "public": True, "host": mail_host},
		{"name": "Mail Filters (Sieve/dovecot)", "port": 4190, "public": True, "host": mail_host},
		{"name": "HTTP Web (nginx)", "port": 80, "public": True},
		{"name": "HTTPS Web (nginx)", "port": 443, "public": True},
	]

	if spam_filter == "rspamd":
		# rspamd proxy worker (milter interface used by postfix) + its Redis backend
		services += [
			{"name": "rspamd", "port": 11332, "public": False, "host": rspamd_host},
			{"name": "Redis", "port": 6379, "public": False, "host": redis_host},
		]
	else:
		services += [
			{"name": "Postgrey", "port": 10023, "public": False, "host": mail_host},
			{"name": "Spamassassin", "port": 10025, "public": False, "host": mail_host},
			{"name": "OpenDKIM", "port": 8891, "public": False, "host": mail_host},
			{"name": "OpenDMARC", "port": 8893, "public": False, "host": mail_host},
		]

	if env.get("WEBMAIL_CLIENT", "rav") == "rav":
		services.append({"name": "rav Webmail (rav)", "port": 3001, "public": False, "host": webmail_host})
	return services


_apt_updates = None
_apt_updates_lock = threading.Lock()  # Prevent concurrent apt-get operations


def list_apt_updates(apt_update=True):
	# See if we have this information cached recently. Keep it for 8 hours.
	global _apt_updates

	with _apt_updates_lock:
		if _apt_updates is not None and _apt_updates[0] > datetime.datetime.now() - datetime.timedelta(hours=8):
			return _apt_updates[1]

		if apt_update:
			shell("check_call", ["/usr/bin/apt-get", "-qq", "update"])

		simulated_install = shell("check_output", ["/usr/bin/apt-get", "-qq", "-s", "upgrade"])
		pkgs = []
		for line in simulated_install.split('\n'):
			if line.strip() == "":
				continue
			if re.match(r'^Conf .*', line):
				continue
			m = re.match(r'^Inst (.*) \[(.*)\] \((\S*)', line)
			if m:
				pkgs.append({"package": m.group(1), "version": m.group(3), "current_version": m.group(2)})
			else:
				pkgs.append({"package": "[" + line + "]", "version": "", "current_version": ""})

		_apt_updates = (datetime.datetime.now(), pkgs)

	return pkgs


def is_reboot_needed_due_to_package_installation():
	return os.path.exists("/var/run/reboot-required")


_VERSION_FILE = "/usr/local/share/naust/version"


def what_version_is_this(env):
	# Prefer the version written by the installer so this works even if the
	# source repo is no longer present. Fall back to git for local dev.
	if os.path.exists(_VERSION_FILE):
		with open(_VERSION_FILE, encoding="utf-8") as f:
			v = f.read().strip()
		if v:
			return v
	naust_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
	return shell("check_output", ["/usr/bin/git", "rev-parse", "HEAD"], env={"GIT_DIR": os.path.join(naust_dir, '.git')}).strip()


def get_latest_naust_version():
	# Fetches the latest commit SHA on main from the GitHub API.
	import json
	from urllib.request import urlopen, Request, HTTPError, URLError

	try:
		req = Request(
			"https://api.github.com/repos/naust-mail/naust/commits/main",
			headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
		)
		data = json.loads(urlopen(req, timeout=5).read())
		return data["sha"]
	except (TimeoutError, HTTPError, URLError, KeyError, ValueError):
		return None


def evaluate_spamhaus_code(zen):
	"""Translate a Spamhaus-style RBL return code into (status, message). Shared
	by the network-wide ZEN check and the per-domain DBL check - same codes,
	same meaning either way."""
	if zen is None:
		return "ok", None
	if zen == "[timeout]":
		return "warning", "Connection to the blacklist server timed out. Could not determine blacklist status. Please try again later."
	if zen == "[Not Set]":
		return "warning", "Could not connect to the blacklist server. Could not determine blacklist status. Please try again later."
	if zen == "127.255.255.252":
		return "warning", "Incorrect spamhaus query. Could not determine blacklist status."
	if zen == "127.255.255.254":
		return "warning", "Naust is configured to use a public DNS server. This is not supported by spamhaus. Could not determine blacklist status."
	if zen == "127.255.255.255":
		return "warning", "Too many queries have been performed on the spamhaus server. Could not determine blacklist status."
	return "error", f"Listed in the Spamhaus block list (code {zen}), which may prevent recipients from receiving your mail."


import socket


def _try_connect(ip, port):
	s = socket.socket(socket.AF_INET if ":" not in ip else socket.AF_INET6, socket.SOCK_STREAM)
	s.settimeout(1)
	s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
	try:
		s.connect((ip, port))
		return True
	except OSError:
		return False
	finally:
		s.close()


def check_service_reachable(service, env):
	"""Try to connect to a service's port. Returns (running: bool, error_message: str|None).
	Mirrors the old check_service() logic exactly (public vs private, IPv4/IPv6 fallback)."""
	if not service["port"]:
		return True, None  # nothing to check (e.g. no sshd configured)

	if service["public"]:
		if _try_connect(env["PUBLIC_IP"], service["port"]):
			if not env.get("PUBLIC_IPV6") or service.get("ipv6") is False or _try_connect(env["PUBLIC_IPV6"], service["port"]):
				return True, None
			if service["port"] != 53 and _try_connect(env["PRIVATE_IPV6"], service["port"]):
				return False, "%s is running (and available over IPv4 and the local IPv6 address), but it is not publicly accessible at %s:%d." % (service['name'], env['PUBLIC_IPV6'], service['port'])
			return False, "%s is running and available over IPv4 but is not accessible over IPv6 at %s port %d." % (service['name'], env['PUBLIC_IPV6'], service['port'])
		if service["port"] != 53 and _try_connect(service.get('host', '127.0.0.1'), service["port"]):
			return False, "%s is running but is not publicly accessible at %s:%d." % (service['name'], env['PUBLIC_IP'], service['port'])
		msg = "%s is not running (port %d)." % (service['name'], service['port'])
		if service["port"] in {80, 443}:
			detail = shell('check_output', ['nginx', '-t'], capture_stderr=True, trap=True)[1].strip()
			if detail:
				msg += " " + detail
		return False, msg
	if _try_connect(service.get('host', '127.0.0.1'), service["port"]):
		return True, None
	return False, "%s is not running (port %d)." % (service['name'], service['port'])


def alias_exists_message(alias_name, alias, env):
	"""Returns (ok: bool, message: str) for whether a mail alias exists and has a destination."""
	from mail.mailconfig import get_mail_aliases

	mail_aliases = {address: receivers for address, receivers, *_ in get_mail_aliases(env)}
	if alias in mail_aliases:
		if mail_aliases[alias]:
			return True, f"{alias_name} exists as a mail alias. [{alias} -> {mail_aliases[alias]}]"
		return False, f"You must set the destination of the mail alias for {alias} to direct email to you or another administrator."
	return False, f"You must add a mail alias for {alias} which directs email to you or another administrator."


def is_docker():
	return os.environ.get("RUNTIME") == "docker"
