#!/usr/bin/env python3
"""Shared socket client for the management-container shims (systemctl, nginx,
nsd-control, unbound-control). Speaks the same wire protocol as
control-socket-server.py: "<service>\\n<action>\\n" -> "OK\\n" / "ERROR: ...\\n".

Usage: _socket_send.py <socket_path> <service> <action>
"""

import socket
import sys


def main() -> None:
	sock_path, service, action = sys.argv[1], sys.argv[2], sys.argv[3]
	sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	sock.settimeout(35)
	try:
		sock.connect(sock_path)
		sock.sendall(f"{service}\n{action}\n".encode())
		response = sock.recv(256).decode().strip()
	finally:
		sock.close()

	if not response.startswith("OK"):
		print(response, file=sys.stderr)
		sys.exit(1)


if __name__ == "__main__":
	main()
