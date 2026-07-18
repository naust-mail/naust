import os.path
import pathlib

# DO NOT import non-standard modules. This module is imported by
# migrate.py which runs on fresh machines before anything is installed
# besides Python.

# THE ENVIRONMENT FILE AT /etc/naust.conf


def load_environment():
	# Load settings from /etc/naust.conf.
	return load_env_vars_from_file("/etc/naust.conf")


def load_env_vars_from_file(fn):
	# Load settings from a KEY=VALUE file.
	# Uses shlex to handle shell-quoted values (KEY='value') written by the
	# boxctl wizard, as well as plain unquoted values written by save_environment().
	import collections
	import shlex

	env = collections.OrderedDict()
	with open(fn, encoding="utf-8") as f:
		for line in f:
			line = line.strip()
			if not line or line.startswith("#") or "=" not in line:
				continue
			k, _, rest = line.partition("=")
			try:
				v = shlex.split(rest)[0] if rest else ""
			except ValueError:
				v = rest
			env.setdefault(k.strip(), v)
	return env


def save_environment(env):
	with open("/etc/naust.conf", "w", encoding="utf-8") as f:
		f.writelines(f"{k}={v}\n" for k, v in env.items())


# THE SETTINGS FILE AT STORAGE_ROOT/settings.yaml.


def write_settings(config, env):
	import rtyaml

	fn = os.path.join(env['STORAGE_ROOT'], 'settings.yaml')
	tmp_fn = fn + ".tmp"
	pathlib.Path(tmp_fn).write_text(rtyaml.dump(config), encoding="utf-8")
	os.replace(tmp_fn, fn)


def load_settings(env):
	import logging
	import rtyaml

	fn = os.path.join(env['STORAGE_ROOT'], 'settings.yaml')
	try:
		with open(fn, encoding="utf-8") as f:
			config = rtyaml.load(f)
		if not isinstance(config, dict):
			raise ValueError  # caught below
		return config
	except FileNotFoundError:
		return {}
	except Exception:
		logging.getLogger(__name__).warning("Failed to load %s - treating as empty.", fn, exc_info=True)
		return {}


# UTILITIES


def safe_domain_name(name):
	# Sanitize a domain name so it is safe to use as a file name on disk.
	import urllib.parse

	return urllib.parse.quote(name, safe='')


def sort_domains(domain_names, env):
	# Put domain names in a nice sorted order.

	# The nice order will group domain names by DNS zone, i.e. the top-most
	# domain name that we serve that ecompasses a set of subdomains. Map
	# each of the domain names to the zone that contains them. Walk the domains
	# from shortest to longest since zones are always shorter than their
	# subdomains.
	zones = {}
	for domain in sorted(domain_names, key=len):
		for z in zones.values():
			if domain.endswith("." + z):
				# We found a parent domain already in the list.
				zones[domain] = z
				break
		else:
			# 'break' did not occur: there is no parent domain, so it is its
			# own zone.
			zones[domain] = domain

	# Sort the zones.
	zone_domains = sorted(
		zones.values(),
		key=lambda d: (
			# PRIMARY_HOSTNAME or the zone that contains it is always first.
			not (d == env['PRIMARY_HOSTNAME'] or env['PRIMARY_HOSTNAME'].endswith("." + d)),
			# Then just dumb lexicographically.
			d,
		),
	)

	# Now sort the domain names that fall within each zone.
	return sorted(
		domain_names,
		key=lambda d: (
			# First by zone.
			zone_domains.index(zones[d]),
			# PRIMARY_HOSTNAME is always first within the zone that contains it.
			d != env['PRIMARY_HOSTNAME'],
			# Followed by any of its subdomains.
			not d.endswith("." + env['PRIMARY_HOSTNAME']),
			# Then in right-to-left lexicographic order of the .-separated parts of the name.
			list(reversed(d.split("."))),
		),
	)


def sort_email_addresses(email_addresses, env):
	email_addresses = set(email_addresses)
	domains = {email.split("@", 1)[1] for email in email_addresses if "@" in email}
	ret = []
	for domain in sort_domains(domains, env):
		domain_emails = {email for email in email_addresses if email.endswith("@" + domain)}
		ret.extend(sorted(domain_emails))
		email_addresses -= domain_emails
	ret.extend(sorted(email_addresses))  # whatever is left
	return ret


def shell(method, cmd_args, env=None, capture_stderr=False, suppress_stderr=False, return_bytes=False, trap=False, input=None):
	# A safe way to execute processes.
	# Some processes like apt-get require being given a sane PATH.
	import subprocess

	if env is None:
		env = {}
	env.update({"PATH": "/sbin:/bin:/usr/sbin:/usr/bin"})
	if capture_stderr:
		stderr_dest = subprocess.STDOUT  # merge into stdout
	elif suppress_stderr:
		stderr_dest = subprocess.DEVNULL  # discard silently
	else:
		stderr_dest = None  # inherit from parent
	kwargs = {
		'env': env,
		'stderr': stderr_dest,
	}
	if method == "check_output" and input is not None:
		kwargs['input'] = input

	try:
		ret = getattr(subprocess, method)(cmd_args, **kwargs)
		code = 0
	except subprocess.CalledProcessError as e:
		if not trap:
			if False:
				import sys
				import shlex

				print(shlex.join(cmd_args), file=sys.stderr)
				raise
			raise
		ret = e.output
		code = e.returncode
	except FileNotFoundError:
		if not trap:
			raise
		ret = b'' if method == 'check_output' else None
		code = 127
	if not return_bytes and isinstance(ret, bytes):
		ret = ret.decode("utf8")
	if not trap:
		return ret
	return code, ret


def create_syslog_handler():
	import logging
	import logging.handlers

	# In Docker there is no syslog daemon; /dev/log may not exist or may become
	# invalid after the socket is created, causing noisy "Logging error" output.
	# Fall back to stdout in that case.
	if os.environ.get('RUNTIME') == 'docker':
		handler = logging.StreamHandler()
		handler.setLevel(logging.WARNING)
		return handler
	try:
		handler = logging.handlers.SysLogHandler(address='/dev/log')
	except (OSError, ConnectionRefusedError):
		handler = logging.StreamHandler()
	handler.setLevel(logging.WARNING)
	return handler


def du(path):
	# Computes the size of all files in the path, like the `du` command.
	# Based on http://stackoverflow.com/a/17936789. Takes into account
	# soft and hard links.
	total_size = 0
	seen = set()
	for dirpath, _dirnames, filenames in os.walk(path):
		for f in filenames:
			fp = os.path.join(dirpath, f)
			try:
				stat = os.lstat(fp)
			except OSError:
				continue
			if stat.st_ino in seen:
				continue
			seen.add(stat.st_ino)
			total_size += stat.st_size
	return total_size


def wait_for_service(port, public, env, timeout):
	# Block until a service on a given port (bound privately or publicly)
	# is taking connections, with a maximum timeout.
	import socket
	import time

	start = time.perf_counter()
	while True:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(timeout / 3)
		try:
			s.connect(("127.0.0.1" if not public else env['PUBLIC_IP'], port))
			return True
		except OSError:
			if time.perf_counter() > start + timeout:
				return False
		time.sleep(min(timeout / 4, 1))


def get_ssh_port():
	port_value = get_ssh_config_value("port")

	if port_value:
		return int(port_value)

	return None


def get_ssh_config_value(parameter_name):
	# Returns ssh configuration value for the provided parameter
	import subprocess

	try:
		output = shell('check_output', ['sshd', '-T'])
	except FileNotFoundError:
		# sshd is not installed. That's ok.
		return None
	except subprocess.CalledProcessError:
		# error while calling shell command
		return None

	for line in output.split("\n"):
		if " " not in line:
			continue  # there's a blank line at the end
		key, values = line.split(" ", 1)
		if key == parameter_name:
			return values  # space-delimited if there are multiple values

	# Did not find the parameter!
	return None


def acquire_process_lock(path: str) -> "object":
	"""Acquire an exclusive advisory lock on path using fcntl.
	Exits immediately if another process holds the lock.
	The returned file handle must stay in scope for the lock to be held."""
	import fcntl
	import sys

	f = open(path, 'w')
	try:
		fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
	except BlockingIOError:
		f.close()
		sys.exit(f"Another process is already running (lock: {path}).")
	return f


if __name__ == "__main__":
	import sys

	sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
	from services.web_update import get_web_domains

	env = load_environment()
	domains = get_web_domains(env)
	for domain in domains:
		print(domain)
