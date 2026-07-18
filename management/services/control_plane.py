"""
Control-plane shim for service lifecycle actions.

Single interface; two backends:
  bare metal  - subprocess.run() directly (raises on failure)
  Docker      - Unix socket RPC to the container that owns the service
                (raises on failure, same semantics as bare metal)

Wire protocol (per connection, newline-delimited):
  Request:  "<service>\\n<action>\\n"
  Response: "OK\\n"  or  "ERROR: <message>\\n"

Socket paths: STORAGE_ROOT/sockets/<role>.sock
  dns.sock         -> nsd, unbound
  mail.sock        -> postfix, dovecot, opendkim, opendmarc, spampd
  nginx.sock       -> nginx
  filebrowser.sock -> filebrowser

On bare metal, service lifecycle is delegated to the privileged helper
(helperd, daemon/cmd/helperd) over /run/naust/helper.sock when it is
installed, so this process does not need root for it. The direct
subprocess path remains only for installs without the helper.

Callers contain zero RUNTIME checks; all environment branching lives here.
"""

import json
import os
import socket
import subprocess
from pathlib import Path

RUNTIME = os.environ.get("RUNTIME", "baremetal")

HELPER_SOCKET = os.environ.get("NAUST_HELPER_SOCKET", "/run/naust/helper.sock")

# Maps service name to the socket role that owns it.
_SERVICE_SOCKET: dict[str, str] = {
	"nsd": "dns",
	"unbound": "dns",
	"postfix": "mail",
	"dovecot": "mail",
	"opendkim": "mail",
	"opendmarc": "mail",
	"spampd": "mail",
	"nginx": "nginx",
	"filebrowser": "filebrowser",
}

# Services whose bare-metal reload requires a non-standard command sequence.
# nsd uses nsd-control (not `service nsd reload`) for zone reconfig + reload.
_BARE_METAL_RELOAD: dict[str, list[list[str]]] = {
	"nsd": [
		["/usr/sbin/nsd-control", "reconfig"],
		["/usr/sbin/nsd-control", "reload"],
	],
	# unbound cache flush is expressed as a "reload" at the caller level.
	"unbound": [
		["/usr/sbin/unbound-control", "-c", "/etc/unbound/unbound.conf", "flush_zone", "."],
	],
}

# Fallback restart command if a custom reload sequence fails.
_BARE_METAL_RELOAD_FALLBACK: dict[str, list[str]] = {
	"nsd": ["/usr/sbin/service", "nsd", "restart"],
}


def _socket_dir() -> Path:
	storage = os.environ.get("STORAGE_ROOT", "/home/user-data")
	return Path(storage) / "sockets"


def _send(service: str, action: str) -> None:
	role = _SERVICE_SOCKET.get(service)
	if not role:
		raise RuntimeError(f"control_plane: no socket role configured for service '{service}'")

	sock_path = _socket_dir() / f"{role}.sock"
	sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	sock.settimeout(35)
	try:
		sock.connect(str(sock_path))
		sock.sendall(f"{service}\n{action}\n".encode())
		response = sock.recv(256).decode().strip()
	finally:
		sock.close()

	if not response.startswith("OK"):
		raise RuntimeError(f"control_plane: {service} {action}: {response}")


def _helper_send(intent: str, args: dict[str, str], timeout: float = 120) -> str:
	"""Send one intent to the privileged helper and raise on failure.

	Wire protocol: one JSON line per request, one JSON line back
	({"ok": true, "result": "..."} or {"ok": false, "error": "..."}).
	Returns the result string (command output for host.* intents, empty
	for everything else).
	"""
	sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	sock.settimeout(timeout)
	buf = b""
	try:
		sock.connect(HELPER_SOCKET)
		sock.sendall(json.dumps({"intent": intent, "args": args}).encode() + b"\n")
		while not buf.endswith(b"\n"):
			chunk = sock.recv(4096)
			if not chunk:
				break
			buf += chunk
	finally:
		sock.close()
	resp = json.loads(buf.decode())
	if not resp.get("ok"):
		raise RuntimeError(f"helper: {intent}: {resp.get('error', 'unknown error')}")
	return resp.get("result", "")


def _run_bare_metal(service: str, action: str) -> None:
	if os.path.exists(HELPER_SOCKET):
		# Custom reload sequences (nsd, unbound) live in the helper's
		# allowlist too, so delegation covers every service uniformly.
		_helper_send(f"service.{action}", {"service": service})
		return
	if action == "reload" and service in _BARE_METAL_RELOAD:
		try:
			for cmd in _BARE_METAL_RELOAD[service]:
				subprocess.run(cmd, check=True)
		except Exception:
			fallback = _BARE_METAL_RELOAD_FALLBACK.get(service)
			if fallback:
				subprocess.run(fallback, check=True)
			else:
				raise
	elif action == "restart":
		subprocess.run(["/usr/sbin/service", service, "restart"], check=True)
	else:
		subprocess.run(["/usr/sbin/service", service, action], check=True)


def restart(service: str) -> None:
	"""Restart a service. Raises on failure in both environments."""
	if RUNTIME == "docker":
		_send(service, "restart")
	else:
		_run_bare_metal(service, "restart")


def reload(service: str) -> None:
	"""Reload a service config without dropping connections. Raises on failure."""
	if RUNTIME == "docker":
		_send(service, "reload")
	else:
		_run_bare_metal(service, "reload")


def stop(service: str) -> None:
	"""Stop a service. Raises on failure in both environments."""
	if RUNTIME == "docker":
		_send(service, "stop")
	else:
		_run_bare_metal(service, "stop")


def disable(service: str) -> None:
	"""Disable service autostart on boot.

	On bare metal this calls 'systemctl disable'. In Docker the container's
	presence in the compose profile controls autostart, so this is a no-op -
	the caller is expected to write the config flag before calling this.
	"""
	if RUNTIME == "docker":
		return
	if os.path.exists(HELPER_SOCKET):
		_helper_send("service.disable", {"service": service})
		return
	subprocess.run(["systemctl", "disable", service], check=True)


# ── Privileged file/config/host operations ────────────────────────────────────
# Same pattern as service lifecycle: delegate to the helper when its socket
# exists, otherwise perform the operation directly (pre-helper installs and
# Docker, where the management container does these itself or not at all).

# Paths for config_write targets when no helper is present. Must stay in
# sync with configTargets in daemon/internal/helper/allowlists.go.
_CONFIG_TARGETS = {
	"nginx_local": "/etc/nginx/conf.d/local.conf",
}


def config_write(target: str, content: str) -> None:
	"""Write a named config file. Target names are a closed set; callers
	never pass paths."""
	if RUNTIME != "docker" and os.path.exists(HELPER_SOCKET):
		_helper_send("config.write", {"target": target, "content": content})
		return
	path = _CONFIG_TARGETS[target]
	tmp = path + ".tmp"
	Path(tmp).write_text(content, encoding="utf-8")
	os.replace(tmp, path)


def postfix_set(settings: dict[str, str]) -> None:
	"""Set Postfix main.cf parameters (helper allowlist restricts keys)."""
	if RUNTIME != "docker" and os.path.exists(HELPER_SOCKET):
		for key, value in settings.items():
			_helper_send("postfix.set", {"key": key, "value": value})
		return
	subprocess.run(
		["postconf", "-e"] + [f"{key}={value}" for key, value in settings.items()],
		check=True,
	)


def apt_update() -> str:
	"""Refresh the apt package index. Returns command output."""
	if RUNTIME != "docker" and os.path.exists(HELPER_SOCKET):
		return _helper_send("host.apt_update", {}, timeout=630)
	result = subprocess.run(["/usr/bin/apt-get", "-qq", "update"], check=True, capture_output=True, text=True)
	return result.stdout


def apt_upgrade() -> str:
	"""Upgrade installed packages. Returns command output."""
	if RUNTIME != "docker" and os.path.exists(HELPER_SOCKET):
		return _helper_send("host.apt_upgrade", {}, timeout=1230)
	result = subprocess.run(
		["/usr/bin/apt-get", "-y", "upgrade"],
		check=True,
		capture_output=True,
		text=True,
		env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
	)
	return result.stdout


def host_reboot() -> str:
	"""Reboot the host. Returns command output (usually nothing arrives
	before the daemon itself goes down with the host)."""
	if RUNTIME != "docker" and os.path.exists(HELPER_SOCKET):
		return _helper_send("host.reboot", {})
	result = subprocess.run(["/sbin/shutdown", "-r", "now"], check=True, capture_output=True, text=True)
	return result.stdout + result.stderr
