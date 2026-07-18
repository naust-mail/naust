import datetime
import os
import re

import dateutil.parser
import dateutil.relativedelta
import dateutil.tz
import psutil

from ..registry import check
from ..reporter import CheckFailed
from .. import utils


def _not_docker(env):
	return not utils.is_docker()


@check("ufw", category="system", enabled=_not_docker)
def check_ufw(env, report):
	with report.step("Firewall is active"):
		if not os.path.isfile('/usr/sbin/ufw'):
			report.warn("The ufw program was not installed. If your system is able to run iptables, rerun the setup.")
			return

		code, ufw = utils.shell('check_output', ['ufw', 'status'], trap=True)
		if code != 0:
			report.warn("The firewall is not working on this machine. To investigate run 'sudo ufw status'.")
			return

		ufw_lines = ufw.splitlines()
		if ufw_lines[0] != "Status: active":
			report.warn("""The firewall is disabled on this machine. This might be because the system
				is protected by an external firewall. Connect via ssh and run: ufw enable.""")
			return

		not_allowed = []
		for service in utils.get_services(env):
			if service["public"] and not any(re.match(str(service["port"]) + r"[/ \t].*", item) for item in ufw_lines):
				not_allowed.append(service)
		if not_allowed:
			raise CheckFailed("; ".join("Port {} ({}) should be allowed in the firewall, please re-run the setup.".format(s["port"], s["name"]) for s in not_allowed))


@check("ssh-password-auth", category="system", enabled=_not_docker)
def check_ssh_password(env, report):
	with report.step("SSH disallows password-based login"):
		config_value = utils.get_ssh_config_value("passwordauthentication")
		if config_value and config_value != "no":
			raise CheckFailed("""The SSH server on this machine permits password-based login. A more secure
				way to log in is using a public key. Add your SSH public key to $HOME/.ssh/authorized_keys, check
				that you can log in without a password, set 'PasswordAuthentication no' in /etc/ssh/sshd_config,
				and restart ssh via 'sudo service ssh restart'.""")


@check("software-updates", category="system", enabled=_not_docker)
def check_software_updates(env, report):
	with report.step("System software is up to date"):
		if utils.is_reboot_needed_due_to_package_installation():
			raise CheckFailed("System updates have been installed and a reboot of the machine is required.")
		pkgs = utils.list_apt_updates(apt_update=False)
		if len(pkgs) > 0:
			raise CheckFailed("There are %d software packages that can be updated: %s" % (len(pkgs), ", ".join(f"{p['package']} ({p['version']})" for p in pkgs)))


@check("system-aliases", category="system")
def check_system_aliases(env, report):
	with report.step("System administrator address exists"):
		ok, msg = utils.alias_exists_message("System administrator address", "administrator@" + env['PRIMARY_HOSTNAME'], env)
		if not ok:
			raise CheckFailed(msg)


@check("free-disk-space", category="system")
def check_free_disk_space(env, report):
	with report.step("Disk has enough free space"):
		st = os.statvfs(env['STORAGE_ROOT'])
		bytes_total = st.f_blocks * st.f_frsize
		bytes_free = st.f_bavail * st.f_frsize
		disk_msg = "The disk has %.2f GB space remaining." % (bytes_free / 1024.0 / 1024.0 / 1024.0)

		if bytes_free <= 0.15 * bytes_total:
			raise CheckFailed(disk_msg)
		if bytes_free <= 0.3 * bytes_total:
			report.warn(disk_msg)

		backup_cache_path = os.path.join(env['STORAGE_ROOT'], 'backup/cache')
		try:
			backup_cache_count = len(os.listdir(backup_cache_path))
		except OSError:
			backup_cache_count = 0
		if backup_cache_count > 1:
			report.warn(f"The backup cache directory {backup_cache_path} has more than one backup target cache. Consider clearing this directory to save disk space.")


@check("free-memory", category="system")
def check_free_memory(env, report):
	with report.step("System has enough free memory"):
		percent_free = 100 - psutil.virtual_memory().percent
		memory_msg = f"System memory is {round(percent_free)!s}% free."
		if percent_free < 10:
			raise CheckFailed(memory_msg)
		if percent_free < 20:
			report.warn(memory_msg)


@check("backup", category="system")
def check_backup(env, report):
	from services.backup import get_backup_config, backup_status

	with report.step("Backups are enabled and recent"):
		backup_config = get_backup_config(env, for_ui=True)
		if backup_config.get("target", "off") == "off":
			report.warn("Backups are disabled. It is recommended to enable a backup for your box.")
			return

		backup_stat = backup_status(env)
		backups = backup_stat.get("backups", {})
		if not backups:
			raise CheckFailed("Could not obtain backup status or no backup has been made (yet). This could happen if you have just enabled backups. In that case, check back tomorrow.")

		most_recent = backups[0]["date"]
		now = datetime.datetime.now(dateutil.tz.tzlocal())
		bk_date = dateutil.parser.parse(most_recent).astimezone(dateutil.tz.tzlocal())
		bk_age = dateutil.relativedelta.relativedelta(now, bk_date)
		if bk_age.days > 7:
			raise CheckFailed("Backup is more than a week old.")


@check("time-sync", category="system", enabled=_not_docker)
def check_time_synchronization(env, report):
	with report.step("System time is synchronized"):
		code, result = utils.shell('check_output', ['timedatectl', 'status'], capture_stderr=True, trap=True)
		if code != 0:
			report.warn("Could not check time synchronization status (timedatectl not available).")
			return

		lines = result.lower()
		ntp_enabled = 'ntp service: active' in lines or 'system clock synchronized: yes' in lines or 'ntp synchronized: yes' in lines
		if not ntp_enabled:
			raise CheckFailed("""System clock is not synchronized. Time synchronization is critical for DNSSEC, SSL certificates,
				and log accuracy. Enable NTP with: timedatectl set-ntp true""")


@check("disk-health", category="system", enabled=_not_docker)
def check_disk_health(env, report):
	with report.step("No disk I/O errors in system logs"):
		code, dmesg_output = utils.shell('check_output', ['dmesg'], capture_stderr=True, trap=True)
		if code != 0:
			return  # can't read dmesg, skip silently like before

		error_patterns = [
			'I/O error',
			'Buffer I/O error',
			'disk error',
			'ata.*error',
			'sd.*error',
			'read error',
			'write error',
			'SMART.*error',
			'medium error',
			'disk failure',
		]
		errors_found = []
		for line in dmesg_output.split('\n'):
			line_lower = line.lower()
			if any(p.lower() in line_lower for p in error_patterns) and line not in errors_found:
				errors_found.append(line)

		if errors_found:
			recent = errors_found[-10:]
			detail = "; ".join(e[:200] for e in recent[:3])
			raise CheckFailed(f"Disk I/O errors detected in system logs ({len(errors_found)} total). This may indicate failing hardware. Recent: {detail}")


def _webmail_enabled(env):
	return env.get("WEBMAIL_CLIENT", "rav") != "none"


@check("webmail", category="system", enabled=_webmail_enabled)
def check_webmail(env, report):
	import glob
	import json
	import urllib.request
	import urllib.error

	webmail = env.get("WEBMAIL_CLIENT", "rav")

	if webmail == "rav":
		with report.step("rav is running and healthy"):
			webmail_host = env.get('WEBMAIL_HOST', '127.0.0.1')
			try:
				with urllib.request.urlopen(f"http://{webmail_host}:3001/api/health", timeout=5) as resp:
					data = json.loads(resp.read())
					if resp.status != 200 or data.get("status") != "ok":
						raise CheckFailed(f"rav returned an unexpected health response (HTTP {resp.status}).")
			except urllib.error.URLError as e:
				raise CheckFailed(f"rav is not responding to requests: {e.reason}. Run: systemctl restart rav")

		with report.step("rav data directory is present and writable"):
			rav_data = os.path.join(env["STORAGE_ROOT"], "rav")
			if not os.path.isdir(rav_data):
				raise CheckFailed(f"rav data directory {rav_data} is missing. Re-run setup.")
			if not os.access(rav_data, os.W_OK):
				raise CheckFailed(f"rav data directory {rav_data} is not writable. Check permissions (should be owned by rav).")

		with report.step("rav configuration is present"):
			if not os.path.isfile("/etc/rav/config.env"):
				raise CheckFailed("rav configuration /etc/rav/config.env is missing. Re-run setup.")

	elif webmail in ("roundcube", "snappymail", "cypht"):
		_WEBMAIL_DIRS = {
			"roundcube": "/usr/local/lib/roundcube",
			"snappymail": "/usr/local/lib/snappymail",
			"cypht": "/usr/local/lib/cypht",
		}
		_WEBMAIL_LABELS = {
			"roundcube": "Roundcube",
			"snappymail": "SnappyMail",
			"cypht": "Cypht",
		}
		label = _WEBMAIL_LABELS[webmail]
		webmail_dir = _WEBMAIL_DIRS[webmail]

		with report.step(f"{label} is installed"):
			if not os.path.isdir(webmail_dir):
				raise CheckFailed(f"{label} directory {webmail_dir} is missing. Re-run setup.")

		with report.step("PHP-FPM is running"):
			fpm_sockets = glob.glob("/run/php/php*-fpm.sock")
			if not fpm_sockets:
				# Fall back to checking for a running process
				fpm_procs = [p for p in psutil.process_iter(['name']) if 'php-fpm' in (p.info['name'] or '')]
				if not fpm_procs:
					raise CheckFailed("PHP-FPM is not running. Run: systemctl start php*-fpm")


@check("filebrowser", category="system")
def check_filebrowser(env, report):
	import json
	import urllib.request
	import urllib.error

	if env.get("ENABLE_FILEBROWSER", "false").lower() != "true":
		return  # optional, disabled

	with report.step("FileBrowser is running and healthy"):
		filebrowser_host = env.get('FILEBROWSER_HOST', '127.0.0.1')
		try:
			with urllib.request.urlopen(f"http://{filebrowser_host}:8080/files/health", timeout=5) as resp:
				data = json.loads(resp.read())
				if resp.status != 200 or data.get("status") != "OK":
					raise CheckFailed(f"FileBrowser returned an unexpected health response (HTTP {resp.status}). Run: journalctl -u filebrowser")
		except urllib.error.URLError as e:
			raise CheckFailed(f"FileBrowser is not responding to requests: {e.reason}. Run: systemctl restart filebrowser")

	with report.step("FileBrowser database is present"):
		fb_db = os.path.join(env["STORAGE_ROOT"], "filebrowser", "filebrowser.db")
		if not os.path.isfile(fb_db):
			raise CheckFailed(f"FileBrowser database {fb_db} is missing. Re-run setup.")

	with report.step("FileBrowser auth hook is present and executable"):
		hook = "/usr/local/lib/filebrowser-auth.py"
		if not os.path.isfile(hook):
			raise CheckFailed(f"FileBrowser auth hook {hook} is missing. Re-run setup.")
		if not os.access(hook, os.X_OK):
			raise CheckFailed(f"FileBrowser auth hook {hook} is not executable. Run: chmod +x {hook}")

	with report.step("FileBrowser files root is present"):
		files_root = os.path.join(env["STORAGE_ROOT"], "files")
		if not os.path.isdir(files_root):
			raise CheckFailed(f"FileBrowser files root {files_root} is missing. Re-run setup.")


@check("naust-version", category="system")
def check_naust_version(env, report):
	with report.step("Naust is up to date"):
		config = utils.load_settings(env)
		try:
			this_ver = utils.what_version_is_this(env)
		except Exception:
			this_ver = "Unknown"

		if config.get("privacy", True):
			report.warn(f"You are running version Naust {this_ver}. Version check disabled by privacy setting.")
			return

		latest_ver = utils.get_latest_naust_version()
		if latest_ver is None:
			raise CheckFailed(f"Latest Naust version could not be determined. You are running version {this_ver}.")
		if this_ver != latest_ver:
			raise CheckFailed(f"A new version is available. You are running {this_ver}. The latest is {latest_ver}. See https://github.com/naust-mail/naust.")
