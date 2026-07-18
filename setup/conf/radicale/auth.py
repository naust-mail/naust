# SPDX-License-Identifier: GPL-3.0-or-later
"""
Radicale auth plugin for Naust.
Validates credentials via managerd's /internal/auth/verify endpoint.

management_host is read from the [auth] section of /etc/radicale/config.
The component runner writes the correct value at setup time (127.0.0.1 on
bare metal, the management container service name in Docker).
"""

import logging
import urllib.error
import urllib.parse
import urllib.request

from radicale.auth import BaseAuth

logger = logging.getLogger(__name__)


class Auth(BaseAuth):
	def __init__(self, configuration):
		super().__init__(configuration)
		try:
			self._management_host = configuration.get("auth", "management_host")
		except Exception:  # noqa: BLE001 - missing/malformed config option, fall back to the bare-metal default
			self._management_host = "127.0.0.1"

	def _login(self, login: str, password: str) -> str:
		try:
			data = urllib.parse.urlencode({"email": login, "password": password}).encode()
			req = urllib.request.Request(
				f"http://{self._management_host}:10223/internal/auth/verify",
				data=data,
				method="POST",
			)
			with urllib.request.urlopen(req, timeout=5) as resp:
				return login if resp.status == 200 else ""
		except urllib.error.HTTPError as e:
			if e.code == 401:
				return ""
			logger.warning("Radicale auth error for %s: HTTP %s", login, e.code)
			return ""
		except Exception as e:  # noqa: BLE001 - auth check: any unexpected failure must deny, never fail open
			logger.warning("Radicale auth error for %s: %s", login, e)
			return ""
