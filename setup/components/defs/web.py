"""
Nginx web server setup.

Only core/shared nginx config lives here. Per-domain server blocks, webmail
proxies, and TLS certificate wiring are handled by the management service
(web_update) because those depend on which mail accounts exist - information
that isn't available at this point in the setup pipeline.

Steps:
  remove-apache    - purge apache2 if installed (runs if apache2 binary exists)
  nginx-defaults   - disable default site, set server_names_hash_bucket_size + ssl_protocols
  ssl-conf         - install nginx-ssl.conf with STORAGE_ROOT substituted
  static-files     - install admin-down.html, 500.html; build iOS/autoconfig/autodiscover/mta-sts XML
  www-root         - create default web root directory
  logrotate        - write nginx logrotate config (copytruncate for fail2ban inotify)
  web-update       - install web_update helper to fixed FHS path
  ufw              - allow http and https

The iOS/autoconfig/autodiscover/mta-sts files are hostname + mode dependent,
so they re-run when PRIMARY_HOSTNAME or MTA_STS_MODE changes.
"""

import contextlib
import os
import shutil
import subprocess
import uuid

from doit.tools import config_changed

from .. import artifacts, SETUP_DIR
from ..component import Component, DOCKER
import pathlib

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="web",
	packages=["nginx", "idn2"],
	services=["nginx"],
	docker_services=["nginx"],
)

_CONF_DIR = os.path.join(SETUP_DIR, "conf")
_TOOLS_DIR = os.path.join(SETUP_DIR, "tools")


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, runtime: str) -> list[dict]:
	storage_root = env["STORAGE_ROOT"]
	hostname = env.get("PRIMARY_HOSTNAME", "localhost")
	mta_sts_mode = env.get("MTA_STS_MODE", "enforce")
	storage_user = env.get("STORAGE_USER", "user-data")

	ssl_conf_src = os.path.join(_CONF_DIR, "nginx", "nginx-ssl.conf")
	web_conf_dir = os.path.join(_CONF_DIR, "web")
	web_update_src = os.path.join(_TOOLS_DIR, "web_update")

	tasks = []

	# Remove apache2 only if it is present.
	if os.path.exists("/usr/sbin/apache2"):
		tasks.append({
			"name": "remove-apache",
			"uptodate": [config_changed(artifacts.fn_stamp(_remove_apache))],
			"actions": [(_remove_apache,)],
		})

	tasks += [
		{
			"name": "nginx-defaults",
			"uptodate": [config_changed(artifacts.fn_stamp(_nginx_defaults))],
			"actions": [(_nginx_defaults,)],
		},
		{
			"name": "ssl-conf",
			# Re-run when the ssl.conf template, STORAGE_ROOT, or runtime changes
			# (STORAGE_ROOT for DH params path, runtime for Docker resolver address).
			"uptodate": [config_changed(f"{storage_root}:{runtime}:{artifacts.hash_files(ssl_conf_src)}")],
			"actions": [(_ssl_conf, [ssl_conf_src, storage_root, runtime])],
		},
		{
			"name": "static-files",
			# hostname + MTA_STS_MODE appear in generated XML files.
			"uptodate": [config_changed(f"{hostname}:{mta_sts_mode}:{artifacts.hash_files(web_conf_dir)}")],
			"actions": [(_static_files, [web_conf_dir, hostname, mta_sts_mode])],
		},
		{
			"name": "www-root",
			"uptodate": [config_changed(f"{storage_root}:{storage_user}:{artifacts.fn_stamp(_www_root)}")],
			"actions": [(_www_root, [storage_root, storage_user, web_conf_dir])],
		},
		{
			"name": "managed-sites",
			"uptodate": [config_changed(f"{runtime}:{artifacts.fn_stamp(_managed_sites)}")],
			"actions": [(_managed_sites, [runtime])],
		},
		{
			"name": "logrotate",
			# copytruncate keeps fail2ban's inotify watch on access.log valid
			# across daily rotation (no inode change = no watch gap).
			"uptodate": [config_changed(artifacts.fn_stamp(_logrotate))],
			"actions": [(_logrotate,)],
		},
		{
			"name": "web-update",
			"uptodate": [config_changed(artifacts.hash_files(web_update_src))],
			"actions": [(_web_update, [web_update_src])],
		},
		{
			"name": "ufw",
			"uptodate": [config_changed(artifacts.fn_stamp(_ufw))],
			"actions": [(_ufw,)],
		},
	]
	return tasks


# ── Action functions ──────────────────────────────────────────────────────────


def _remove_apache() -> None:
	"""Purge apache2 since we use nginx. Autoremove cleans up orphaned deps."""
	subprocess.run(
		["apt-get", "-y", "purge", "apache2", "apache2-*"],
		check=False,
		capture_output=True,
	)
	subprocess.run(
		["apt-get", "-y", "--purge", "autoremove"],
		check=False,
		capture_output=True,
	)


def _nginx_defaults() -> None:
	"""Disable the default nginx site and apply core settings."""
	default_site = "/etc/nginx/sites-enabled/default"
	if os.path.exists(default_site):
		os.unlink(default_site)

	# server_names_hash_bucket_size: The default depends on "the size of the
	# processor's cache line" and can be as low as 32. Was raised to 64 in 2014
	# for a 20-char domain, but a 58-char domain still failed (#93), so raised
	# again to 128.
	# ssl_protocols: drop TLSv1.0/1.1 per Mozilla Intermediate recommendations
	# (https://ssl-config.mozilla.org/#server=nginx&config=intermediate).
	artifacts.editconf(
		"/etc/nginx/nginx.conf",
		"server_names_hash_bucket_size=128;",
		"ssl_protocols=TLSv1.2 TLSv1.3;",
		space_delim=True,
	)


def _ssl_conf(ssl_conf_src: str, storage_root: str, runtime: str) -> None:
	"""Install nginx SSL config with STORAGE_ROOT and resolver substituted."""
	# Remove old location (pre-repo reorganisation).
	old = "/etc/nginx/nginx-ssl.conf"
	if os.path.exists(old):
		os.unlink(old)

	# Docker uses 127.0.0.11 (Docker's embedded DNS); bare metal uses 127.0.0.1 (unbound).
	# Using a variable in proxy_pass requires a resolver so nginx defers DNS lookup to
	# request time instead of crashing at startup when an optional service isn't running.
	resolver_line = "resolver 127.0.0.11 valid=10s ipv6=off;" if runtime == "docker" else "resolver 127.0.0.1 valid=86400 ipv6=off;"

	content = pathlib.Path(ssl_conf_src).read_text(encoding="utf-8")
	content = content.replace("STORAGE_ROOT", storage_root)
	content = content.replace("NGINX_RESOLVER_LINE", resolver_line)
	artifacts.write_file("/etc/nginx/conf.d/ssl.conf", content)


def _static_files(web_conf_dir: str, hostname: str, mta_sts_mode: str) -> None:
	"""Install static HTML error pages and client auto-configuration XML files.

	These files are served directly by nginx. The XML files contain the hostname
	and (for mta-sts) the policy mode, so they are regenerated when those change.
	UUID fields in ios-profile.xml are randomised on every regeneration - that is
	intentional; the profile is re-imported by clients only when its UUID changes.
	"""
	os.makedirs("/var/lib/naust", exist_ok=True)
	os.chmod("/var/lib/naust", 0o755)

	for name in ["admin-down.html", "500.html"]:
		shutil.copy2(os.path.join(web_conf_dir, name), f"/var/lib/naust/{name}")

	# iOS mobile configuration profile: UUIDs are randomised each run so that
	# the profile UUID changes → clients notice and re-import the profile.
	ios_content = pathlib.Path(os.path.join(web_conf_dir, "ios-profile.xml")).read_text(encoding="utf-8")
	for i in range(1, 5):
		ios_content = ios_content.replace(f"UUID{i}", str(uuid.uuid4()).upper())
	ios_content = ios_content.replace("PRIMARY_HOSTNAME", hostname)
	artifacts.write_file("/var/lib/naust/mobileconfig.xml", ios_content, mode=0o644)

	# Mozilla autoconfig: served at /.well-known/autoconfig/mail/config-v1.1.xml.
	# Format: https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat
	mozilla_content = pathlib.Path(os.path.join(web_conf_dir, "mozilla-autoconfig.xml")).read_text(encoding="utf-8").replace("PRIMARY_HOSTNAME", hostname)
	artifacts.write_file("/var/lib/naust/mozilla-autoconfig.xml", mozilla_content, mode=0o644)

	# Outlook autodiscover: served at /autodiscover/autodiscover.xml and
	# /.well-known/autoconfig/autodiscover.xml for Outlook and compatible clients.
	autodiscover_content = pathlib.Path(os.path.join(web_conf_dir, "autodiscover.xml")).read_text(encoding="utf-8").replace("PRIMARY_HOSTNAME", hostname)
	artifacts.write_file("/var/lib/naust/autodiscover.xml", autodiscover_content, mode=0o644)

	# mta-sts: served at /.well-known/mta-sts.txt. Default mode is "enforce".
	# Set MTA_STS_MODE=testing in /etc/naust.conf to get reports without
	# enforcement if unsure (messages still delivered), or "none" to disable.
	# Hostname is punycode-encoded for international domain support.
	result = subprocess.run(["idn2", hostname], capture_output=True, text=True, check=False)
	puny_hostname = result.stdout.strip() if result.returncode == 0 else hostname

	mta_sts_content = pathlib.Path(os.path.join(web_conf_dir, "mta-sts.txt")).read_text(encoding="utf-8").replace("MODE", mta_sts_mode).replace("PRIMARY_HOSTNAME", puny_hostname)
	artifacts.write_file("/var/lib/naust/mta-sts.txt", mta_sts_content, mode=0o644)


def _www_root(storage_root: str, storage_user: str, web_conf_dir: str) -> None:
	"""Create the default web root directory and install the default index.html."""
	www_dir = os.path.join(storage_root, "www")
	# Migration: rename 'static' to 'default' if it exists from an old install.
	old_static = os.path.join(www_dir, "static")
	new_default = os.path.join(www_dir, "default")
	if os.path.isdir(old_static) and not os.path.isdir(new_default):
		os.rename(old_static, new_default)

	os.makedirs(new_default, exist_ok=True)

	default_index = os.path.join(new_default, "index.html")
	if not os.path.exists(default_index):
		shutil.copy2(os.path.join(web_conf_dir, "www_default.html"), default_index)

	result = subprocess.run(["stat", "-c", "%U", www_dir], capture_output=True, text=True, check=False)
	if not os.path.isdir(www_dir) or result.stdout.strip() != storage_user:
		subprocess.run(["chown", "-R", storage_user, www_dir], check=True)


def _managed_sites(runtime: str) -> None:
	"""Create the Go daemon's managed sites directory and its include.

	helperd's web.sync_sites intent reconciles /etc/nginx/naust.d/;
	this include makes nginx read it. Safe while the directory is empty
	(a glob with no matches is a no-op), so it can be installed before
	the Go web stack takes over.

	The legacy local.conf (upstream Mail-in-a-Box's web_update output) is
	removed here on bare metal: nginx treats duplicate server names as a
	warning, not an error, and conf.d sorts local.conf before
	naust-sites.conf, so a leftover copy silently shadows every managed
	site. It is machine-generated from data that managerd re-renders into
	naust.d, so nothing user-authored is lost. In Docker, management no
	longer writes local.conf at all (Flask is retired there), so this
	stays a bare-metal-only cleanup step - deleting it in Docker would
	just race whatever ran before this one, for no benefit.
	"""
	os.makedirs("/etc/nginx/naust.d", exist_ok=True)
	os.chmod("/etc/nginx/naust.d", 0o755)
	artifacts.write_file(
		"/etc/nginx/conf.d/naust-sites.conf",
		"include /etc/nginx/naust.d/*.conf;\n",
	)
	if runtime != DOCKER:
		with contextlib.suppress(FileNotFoundError):
			os.remove("/etc/nginx/conf.d/local.conf")


def _logrotate() -> None:
	"""Write nginx logrotate config using copytruncate.

	copytruncate truncates the active log file after copying, preserving the
	inode. This keeps fail2ban's inotify watch on access.log valid across daily
	rotation - a new-inode rotation causes a brief watch gap.
	"""
	artifacts.write_file(
		"/etc/logrotate.d/nginx",
		"/var/log/nginx/*.log {\n    daily\n    missingok\n    rotate 14\n    compress\n    delaycompress\n    notifempty\n    copytruncate\n}\n",
	)


def _web_update(src: str) -> None:
	"""Install web_update to a fixed path so boxctl doesn't depend on the repo."""
	dest = "/usr/local/lib/naust/web_update"
	shutil.copy2(src, dest)
	os.chmod(dest, 0o755)


def _ufw() -> None:
	"""Allow HTTP (80) and HTTPS (443) through the firewall."""
	artifacts.ufw_allow("http")
	artifacts.ufw_allow("https")
