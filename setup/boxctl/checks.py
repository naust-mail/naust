"""
Health check functions for boxctl doctor.

Each check_* function takes a conf dict and returns (status, msg).
Status values: OK, WARN, ERR, OFF.
"""

import datetime
import glob
import os
import re
import socket
import pathlib
import subprocess
import contextlib

OK = "ok"
WARN = "warn"
ERR = "error"
OFF = "off"

# -- Low-level probes -----------------------------------------------------------


def _systemd_active(service):
	r = subprocess.run(["systemctl", "is-active", "--quiet", service], capture_output=True)
	return r.returncode == 0


def _systemd_installed(service):
	r = subprocess.run(["systemctl", "cat", service], capture_output=True)
	return r.returncode == 0


def _port_open(host, port, timeout=2):
	try:
		s = socket.create_connection((host, port), timeout=timeout)
	except (TimeoutError, ConnectionRefusedError, OSError):
		return False
	else:
		s.close()
		return True


def _cert_days(storage_root):
	cert = os.path.join(storage_root, "ssl", "ssl_certificate.pem")
	if not os.path.exists(cert):
		return None
	r = subprocess.run(
		["openssl", "x509", "-enddate", "-noout", "-in", cert],
		capture_output=True,
		text=True,
	)
	m = re.search(r"notAfter=(.+)", r.stdout)
	if not m:
		return None
	try:
		expiry = datetime.datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
		return (expiry - datetime.datetime.utcnow()).days
	except ValueError:
		return None


def _postfix_milters():
	"""Return the value of smtpd_milters from postfix config, or None if postconf fails."""
	r = subprocess.run(["postconf", "smtpd_milters"], capture_output=True, text=True)
	if r.returncode != 0:
		return None
	_, _, val = r.stdout.partition("=")
	return val.strip()


def _smtp_unix_present() -> bool | None:
	"""Check the smtp unix outbound transport is active in master.cf.

	Returns True (present), False (missing), or None (cannot determine).
	Tries postconf -M first; falls back to parsing master.cf directly so
	the check still works if postconf is temporarily unavailable.
	"""
	try:
		r = subprocess.run(["postconf", "-M", "smtp/unix"], capture_output=True, text=True, timeout=5)
		if r.returncode == 0:
			return bool(r.stdout.strip())
	except (FileNotFoundError, subprocess.TimeoutExpired):
		pass
	# Fallback: scan master.cf for an uncommented smtp unix line.
	try:
		with open("/etc/postfix/master.cf", encoding="utf-8") as f:
			for line in f:
				if line.startswith("#") or not line.strip():
					continue
				parts = line.split()
				if len(parts) >= 2 and parts[0] == "smtp" and parts[1] == "unix":
					return True
	except OSError:
		return None  # can't read master.cf - skip check rather than false-positive
	else:
		return False


# -- Service checks -------------------------------------------------------------


def check_mail(_conf):
	ok_p = _systemd_active("postfix")
	ok_d = _systemd_active("dovecot")
	parts = []
	if not ok_p:
		r = subprocess.run(["postfix", "check"], capture_output=True, text=True)
		if r.returncode != 0:
			err = next((line.strip() for line in r.stderr.splitlines() if line.strip()), "config error")
			parts.append(f"Postfix not active - {err}")
		else:
			parts.append("Postfix not active")
	if not ok_d:
		parts.append("Dovecot not active")
	# Ports clients use: SMTP relay, submission (clients), IMAPS, Sieve (filter management)
	for port, label in [(25, "25/SMTP"), (587, "587/submission"), (993, "993/IMAPS"), (4190, "4190/sieve")]:
		if not _port_open("127.0.0.1", port):
			parts.append(f"port {label} not responding")
	if parts:
		return ERR, "; ".join(parts)
	# Verify the smtp unix outbound transport is present in master.cf.
	# It can be silently removed by config tools that match on service name alone.
	transport_ok = _smtp_unix_present()
	if transport_ok is False:
		return WARN, "smtp unix transport missing from master.cf - re-run setup"
	# Warn if any messages have been stuck in the deferred queue for >2h.
	# A large queue from a burst is normal; messages old enough to have retried
	# multiple times without success indicate a persistent delivery problem.
	r = subprocess.run(
		["find", "/var/spool/postfix/deferred", "-type", "f", "-mmin", "+120"],
		capture_output=True,
		text=True,
	)
	old_deferred = len(r.stdout.splitlines()) if r.returncode == 0 else 0
	if old_deferred > 0:
		return WARN, f"Running ({old_deferred} message{'s' if old_deferred != 1 else ''} deferred >2h)"
	return OK, "Postfix + Dovecot running"


def check_spam(conf):
	spam = conf.get("SPAM_FILTER", "rspamd")
	if spam == "rspamd":
		if not _systemd_active("rspamd"):
			return ERR, "Rspamd not running"
		if not _port_open("127.0.0.1", 11332):
			return WARN, "Rspamd running but milter port 11332 not responding"
		redis = _systemd_active("redis-server")
		if not redis:
			return WARN, "Rspamd running but Redis not active (greylisting/Bayes affected)"
		# Verify postfix is actually wired to use the rspamd milter
		milters = _postfix_milters()
		if milters is not None and "11332" not in milters:
			return WARN, "Rspamd running but not wired to postfix milters (re-run setup)"
		return OK, "Rspamd running (milter active)"
	if not _systemd_active("spampd"):
		return ERR, "spampd not running"
	if not _systemd_active("opendkim"):
		return WARN, "spampd running but OpenDKIM not active"
	return OK, "SpamAssassin + spampd running"


def check_webmail(conf):
	client = conf.get("WEBMAIL_CLIENT", "rav")
	if client == "none":
		return OFF, "No webmail configured"
	if client == "rav":
		if not _systemd_active("rav"):
			return ERR, "rav service not running"
		if not _port_open("127.0.0.1", 3001):
			return WARN, "rav running but not responding on port 3001"
		# HTTP probe to confirm the app is actually serving responses
		try:
			import urllib.request

			with urllib.request.urlopen("http://127.0.0.1:3001/", timeout=3) as resp:
				if resp.status >= 500:
					return WARN, f"rav responding with HTTP {resp.status}"
		except Exception:  # noqa: BLE001
			return WARN, "rav port open but HTTP probe failed"
		return OK, "rav running"
	# php-fpm service name varies by version; find any active unit matching the pattern
	r = subprocess.run(
		["systemctl", "list-units", "--state=active", "--no-legend", "--plain", "php*-fpm.service"],
		capture_output=True,
		text=True,
	)
	fpm_ok = bool(r.stdout.strip())
	label = {"roundcube": "Roundcube", "snappymail": "SnappyMail", "cypht": "Cypht"}.get(client, client)
	if not fpm_ok:
		return ERR, f"{label} installed but PHP-FPM not running"
	return OK, f"{label} running via PHP-FPM"


def check_dns(conf):
	if not _systemd_active("nsd"):
		return ERR, "NSD not running"
	# NSD binds to external interfaces only, not loopback - use nsd-control
	r = subprocess.run(["nsd-control", "status"], capture_output=True)
	if r.returncode != 0:
		return WARN, "NSD running but nsd-control status failed"
	zone_dir = "/etc/nsd/zones"
	zones = len([f for f in os.listdir(zone_dir) if f.endswith(".txt")]) if os.path.isdir(zone_dir) else 0
	if zones == 0:
		return WARN, "NSD running but no zone files found - run dns_update"
	# Test that NSD can actually answer a query for the box's own hostname
	hostname = conf.get("PRIMARY_HOSTNAME", "")
	if hostname:
		r2 = subprocess.run(
			["dig", "@127.0.0.1", "+short", "+time=2", "+tries=1", hostname, "A"],
			capture_output=True,
			text=True,
		)
		if r2.returncode != 0 or not r2.stdout.strip():
			return WARN, f"NSD running ({zones} zones) but cannot resolve {hostname}"
	return OK, f"NSD running ({zones} zone{'s' if zones != 1 else ''})"


def check_certs(conf):
	storage_root = conf.get("STORAGE_ROOT", "/home/user-data")
	hostname = conf.get("PRIMARY_HOSTNAME", "")
	cert = os.path.join(storage_root, "ssl", "ssl_certificate.pem")
	days = _cert_days(storage_root)
	if days is None:
		return WARN, "Could not read certificate expiry"
	if days < 0:
		return ERR, "Certificate has expired"
	# Verify the cert actually covers this hostname (CN or SAN)
	if hostname and os.path.exists(cert):
		r = subprocess.run(
			["openssl", "x509", "-noout", "-subject", "-text", "-in", cert],
			capture_output=True,
			text=True,
		)
		in_subject = hostname in r.stdout.split("subject=", 1)[-1].split("\n")[0]
		in_san = any(hostname in line for line in r.stdout.splitlines() if "DNS:" in line)
		if not in_subject and not in_san:
			return WARN, f"Certificate does not cover {hostname}"
	if days < 14:
		return WARN, f"Certificate expires in {days} days - renewal needed"
	if days < 30:
		return WARN, f"Certificate expires in {days} days"
	return OK, f"Valid (expires in {days} days)"


def check_radicale(conf):
	if conf.get("ENABLE_RADICALE", "false") != "true":
		return OFF, "Disabled"
	venv = "/usr/local/lib/radicale"
	data = "/var/lib/radicale"
	if not os.path.isdir(venv):
		return ERR, "Not installed - re-run setup"
	if not _systemd_active("radicale"):
		r = subprocess.run(
			["systemctl", "show", "radicale", "--property=ExecMainStatus,NRestarts"],
			capture_output=True,
			text=True,
		)
		props = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
		restarts = int(props.get("NRestarts", "0"))
		restart_hint = f" ({restarts} restarts)" if restarts > 3 else ""
		if props.get("ExecMainStatus") == "226":
			if not os.path.isdir(data):
				return ERR, f"Storage directory missing{restart_hint} - re-run setup"
			return ERR, f"Kernel lacks mount namespace support{restart_hint} (sandbox limitation)"
		return ERR, f"Radicale not running{restart_hint}"
	if not _port_open("127.0.0.1", 5232):
		return WARN, "Radicale running but port 5232 not responding"
	return OK, "Running"


def check_filebrowser(conf):
	if conf.get("ENABLE_FILEBROWSER", "false") != "true":
		return OFF, "Disabled"
	binary = "/usr/local/bin/filebrowser"
	if not os.path.exists(binary):
		return ERR, "Binary missing - re-run setup"
	if not _systemd_installed("filebrowser"):
		return ERR, "Service not configured - re-run setup"
	if not _systemd_active("filebrowser"):
		r = subprocess.run(
			["systemctl", "show", "filebrowser", "--property=ActiveState,Result"],
			capture_output=True,
			text=True,
		)
		props = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
		result = props.get("Result", "")
		if result and result != "success":
			return ERR, f"FileBrowser failed ({result}) - check: journalctl -u filebrowser"
		return ERR, "FileBrowser not running"
	if not _port_open("127.0.0.1", 8080):
		return WARN, "FileBrowser running but not responding on port 8080"
	return OK, "Running"


def check_nginx(_conf):
	if not _systemd_active("nginx"):
		# Try to surface why nginx failed to start.
		r = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
		if r.returncode != 0:
			first_err = next(
				(line.strip() for line in r.stderr.splitlines() if "emerg" in line or "error" in line),
				"config error",
			)
			return ERR, f"nginx not running - config error: {first_err}"
		return ERR, "nginx not running"
	if not glob.glob("/etc/nginx/naust.d/*.conf"):
		return WARN, "No site config generated yet - is naust-managerd running?"
	if not _port_open("127.0.0.1", 443):
		# Distinguish nothing listening vs TLS-level failure.
		if not _port_open("127.0.0.1", 80):
			return ERR, "nginx running but not listening on 80 or 443 - check nginx config"
		return WARN, "nginx running, port 80 OK but 443 not responding"
	return OK, "Running"


def check_unbound(_conf):
	if not _systemd_active("unbound"):
		return ERR, "Unbound not running (DANE and DNS blocklists affected)"
	if not _port_open("127.0.0.1", 53):
		return WARN, "Unbound running but port 53 not responding"
	# Verify resolv.conf points here
	try:
		resolv = pathlib.Path("/etc/resolv.conf").read_text(encoding="utf-8")
		if "nameserver 127.0.0.1" not in resolv:
			return WARN, "Running but /etc/resolv.conf does not point to 127.0.0.1"
	except OSError:
		pass
	# Test actual resolution via Unbound
	r = subprocess.run(
		["dig", "@127.0.0.1", "+short", "+time=2", "+tries=1", "cloudflare.com", "A"],
		capture_output=True,
		text=True,
	)
	if r.returncode != 0 or not r.stdout.strip():
		return WARN, "Unbound running but resolution test failed"
	return OK, "Running"


def check_clamav(conf):
	if conf.get("ENABLE_CLAMAV", "false") != "true":
		if _systemd_installed("clamav-daemon"):
			return OFF, "Installed but disabled"
		return OFF, "Not installed"
	if not _systemd_active("clamav-daemon"):
		return ERR, "ClamAV daemon not running"
	clamd_sock = "/run/clamav/clamd.ctl"
	if not os.path.exists(clamd_sock):
		return WARN, "clamav-daemon running but socket not ready yet"
	if not _systemd_active("clamav-freshclam"):
		return WARN, "ClamAV running but freshclam not active (virus definitions may be stale)"
	return OK, "Running"


def _beszel_api_ok(port: int = 8090) -> bool:
	"""Return True if the PocketBase /api/health endpoint responds 200."""
	try:
		conn = socket.create_connection(("127.0.0.1", port), timeout=2)
		conn.settimeout(2)
		conn.sendall(b"GET /api/health HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
		# Read until we have enough for the status line; loop to handle partial recvs.
		buf = b""
		while len(buf) < 32:
			chunk = conn.recv(32 - len(buf))
			if not chunk:
				break
			buf += chunk
		conn.close()
		resp = buf.decode("ascii", errors="replace")
		return resp.startswith("HTTP/") and " 200 " in resp
	except OSError:
		return False


def _netdata_api_ok(port: int = 19999) -> bool:
	"""Return True if the Netdata /api/v1/info endpoint returns valid JSON."""
	try:
		conn = socket.create_connection(("127.0.0.1", port), timeout=2)
		conn.settimeout(2)
		conn.sendall(b"GET /api/v1/info HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
		data = b""
		while len(data) < 65536:
			chunk = conn.recv(256)
			if not chunk:
				break
			data += chunk
			if b'"version"' in data:
				break
		conn.close()
	except OSError:
		return False
	else:
		return b'"version"' in data


def _munin_node_responsive() -> bool:
	"""Return True if munin-node answers the 'list' command on port 4949."""
	try:
		conn = socket.create_connection(("127.0.0.1", 4949), timeout=2)
		conn.settimeout(2)
		# munin-node sends a banner on connect; read it then send 'list'
		conn.recv(256)
		conn.sendall(b"list\n")
		resp = conn.recv(256).decode("ascii", errors="replace").strip()
		conn.close()
		# Valid response is a space-separated list of plugin names; error lines start with '#'
		return bool(resp) and not resp.startswith("#")
	except OSError:
		return False


def check_monitoring(conf):
	tool = conf.get("MONITORING_TOOL", "none")
	if tool == "none":
		return OFF, "Disabled"

	if tool == "beszel":
		hub_ok = _systemd_active("beszel-hub")
		agent_ok = _systemd_active("beszel-agent")
		if not hub_ok and not agent_ok:
			if not _systemd_installed("beszel-hub"):
				return ERR, "Not installed - re-run setup"
			return ERR, "beszel-hub and beszel-agent not running"
		if not hub_ok:
			return ERR, "beszel-hub not running"
		if not agent_ok:
			return WARN, "beszel-hub running but beszel-agent not running"
		if not _port_open("127.0.0.1", 8090):
			return WARN, "Beszel running but port 8090 not responding"
		storage_root = conf.get("STORAGE_ROOT", "/home/user-data")
		key_path = os.path.join(storage_root, "beszel", "id_ed25519")
		agent_env = os.path.join(storage_root, "beszel", "agent.env")
		if not os.path.isfile(key_path):
			return ERR, "Ed25519 keypair missing - re-run setup (agent cannot authenticate)"
		if not os.path.isfile(agent_env):
			return ERR, "agent.env missing - re-run setup (agent has no credentials)"
		if not _beszel_api_ok():
			return WARN, "Beszel running but API not responding (DB may still be initializing)"
		return OK, "Running"

	if tool == "netdata":
		if not _systemd_active("netdata"):
			if not _systemd_installed("netdata"):
				return ERR, "Not installed - re-run setup"
			return ERR, "Netdata not running"
		if not os.path.isfile("/opt/netdata/bin/netdata"):
			return ERR, "Netdata binary missing at /opt/netdata/bin/netdata - re-run setup"
		if not _port_open("127.0.0.1", 19999):
			return WARN, "Netdata running but port 19999 not responding"
		if not _netdata_api_ok():
			return WARN, "Netdata running but API not responding"
		# Warn if bind address was changed away from loopback (security)
		conf_file = "/opt/netdata/etc/netdata/netdata.conf"
		try:
			text = pathlib.Path(conf_file).read_text(encoding="utf-8")
			for line in text.splitlines():
				stripped = line.strip()
				if stripped.startswith("#"):
					continue
				if "bind to" in stripped and "127.0.0.1" not in stripped.split("bind to")[1]:
					return WARN, "Netdata may be listening on a public interface - check netdata.conf"
					break
		except OSError:
			pass
		return OK, "Running"

	if tool == "munin":
		if not _systemd_active("munin-node"):
			if not _systemd_installed("munin-node"):
				return ERR, "Not installed - re-run setup"
			return ERR, "munin-node not running"
		if not os.path.isfile("/etc/munin/munin.conf"):
			return ERR, "munin.conf missing - re-run setup"
		if not _munin_node_responsive():
			return WARN, "munin-node running but not responding on port 4949 (plugins may have failed to load)"
		# Check RRD data was collected recently (munin-cron runs every 5 min)
		rrd_dir = pathlib.Path("/var/lib/munin")
		if rrd_dir.is_dir():
			rrds = list(rrd_dir.rglob("*.rrd"))
			if not rrds:
				return WARN, "munin-node running but no RRD data yet (cron may not have run)"
			mtimes = []
			for f in rrds:
				with contextlib.suppress(OSError):
					mtimes.append(f.stat().st_mtime)
			if mtimes:
				age_min = (datetime.datetime.now().timestamp() - max(mtimes)) / 60
				if age_min > 12:
					return WARN, f"munin data is {age_min:.0f}m old (cron may not be running)"
		return OK, "Running"

	return WARN, f"Unknown monitoring tool: {tool}"


def check_system(conf):
	storage_root = conf.get("STORAGE_ROOT", "/home/user-data")
	errs, warns = [], []
	# Disk space on storage root partition
	try:
		st = os.statvfs(storage_root)
		used_pct = 100 * (1 - st.f_bavail / st.f_blocks) if st.f_blocks else 0
		if used_pct > 90:
			errs.append(f"disk {used_pct:.0f}% full")
		elif used_pct > 75:
			warns.append(f"disk {used_pct:.0f}% full")
	except OSError:
		pass
	# Memory: read /proc/meminfo directly to avoid subprocess overhead
	try:
		mem = {}
		with open("/proc/meminfo", encoding="utf-8") as f:
			for line in f:
				k, _, v = line.partition(":")
				mem[k.strip()] = int(v.split()[0])
		total = mem.get("MemTotal", 0)
		avail = mem.get("MemAvailable", 0)
		if total > 0:
			used_pct = 100 * (1 - avail / total)
			if used_pct > 90:
				errs.append(f"memory {used_pct:.0f}% used")
			elif used_pct > 80:
				warns.append(f"memory {used_pct:.0f}% used")
	except OSError:
		pass
	if not _systemd_active("fail2ban"):
		warns.append("fail2ban not running")
	if errs:
		return ERR, "; ".join(errs)
	if warns:
		return WARN, "; ".join(warns)
	return OK, "Disk OK · fail2ban active"


def check_management(_conf):
	if not _systemd_active("naust-managerd"):
		return ERR, "Management daemon not running"
	if not _port_open("127.0.0.1", 10223):
		return WARN, "Service active but API port 10223 not responding"
	return OK, "Running"


def check_relay(conf):
	storage_root = conf.get("STORAGE_ROOT", "/home/user-data")
	settings_path = os.path.join(storage_root, "settings.yaml")
	try:
		import yaml
	except ImportError:
		return WARN, "PyYAML not installed - cannot read relay settings"
	try:
		with open(settings_path, encoding="utf-8") as f:
			settings = yaml.safe_load(f) or {}
	except FileNotFoundError:
		return OFF, "No relay configured"
	except Exception:  # noqa: BLE001 - malformed/unreadable settings.yaml, surfaced as a health-check warning not a crash
		return WARN, "Cannot read settings.yaml"

	relay = settings.get("smtp_relay", {}) if isinstance(settings, dict) else {}
	if not isinstance(relay, dict):
		relay = {}
	host = (relay.get("host") or "").strip()
	if not host:
		return OFF, "No relay configured"

	spf_include = (relay.get("spf_include") or "").strip()
	if not spf_include:
		return WARN, f"Relay via {host} - SPF include not set (forwarded mail may fail SPF at recipients)"

	# Verify the live SPF TXT record contains the include.
	primary = conf.get("PRIMARY_HOSTNAME", "")
	if primary:
		r = subprocess.run(
			["dig", "+short", "+time=5", "+tries=1", primary, "TXT"],
			capture_output=True,
			text=True,
		)
		# dig may split long TXT records into multiple quoted strings on one line
		# e.g. '"v=spf1 mx" " include:sendgrid.net -all"' - strip all quotes to join them.
		spf_txt = next(
			(line.replace('"', '') for line in r.stdout.splitlines() if "v=spf1 " in line),
			None,
		)
		if r.returncode != 0 or spf_txt is None:
			return WARN, f"Relay via {host} - cannot verify SPF record for {primary}"
		if f"include:{spf_include}" not in spf_txt:
			return WARN, f"Relay via {host} - SPF record missing include:{spf_include} (forwarded mail may fail)"

	return OK, f"Relay via {host} (SPF: include:{spf_include})"


def check_backup(conf):
	storage_root = conf.get("STORAGE_ROOT", "/home/user-data")
	backup_tool = conf.get("BACKUP_TOOL", "restic")

	# restic stores snapshots in a subdirectory; duplicity writes directly to its dir
	check_path = os.path.join(storage_root, "backups", "restic", "snapshots") if backup_tool == "restic" else os.path.join(storage_root, "backups", "duplicity")

	if not os.path.isdir(check_path):
		return WARN, f"No backup data yet ({backup_tool})"

	try:
		entries = os.listdir(check_path)
	except OSError:
		return WARN, "Cannot read backup directory"

	if not entries:
		return WARN, "Backup directory empty - first backup may still be running"

	try:
		latest = max(os.path.getmtime(os.path.join(check_path, e)) for e in entries)
	except OSError:
		return WARN, "Cannot stat backup files"

	hours_ago = (datetime.datetime.now().timestamp() - latest) / 3600
	if hours_ago > 72:
		return ERR, f"Last backup {hours_ago / 24:.0f} days ago - check backup config"
	if hours_ago > 36:
		return WARN, f"Last backup {hours_ago:.0f}h ago"
	return OK, f"Last backup {hours_ago:.0f}h ago ({backup_tool})"
