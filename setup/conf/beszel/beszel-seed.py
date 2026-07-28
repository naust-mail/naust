#!/usr/bin/env python3
"""Seed the Beszel hub's single trusted-header user on first boot.

Beszel authenticates dashboard requests by matching the X-Beszel-User header
(injected by nginx after it validates the admin session) against a "users"
record. Password auth is disabled, so the password below exists only to satisfy
the create-user API: it is generated in memory, used once, and never written to
disk. This runs on every boot but no-ops as soon as a user exists, so a wiped
Beszel database self-heals on the next start rather than locking the operator
out.

config.yml's systems: block is also written here, not at setup time: the hub
syncs config.yml against the users table on every boot before its API opens,
and a systems entry with no matching user fails that sync and aborts hub
startup entirely (hub v0.18.7, internal/hub/config/config.go). Writing it only
after the user above exists avoids that deadlock. beszel-hub-restart.service
picks up the NEEDS_RESTART_FILE marker this leaves and restarts the hub once
so the sync (which only runs at boot) actually picks up the new config.
"""

import json
import os
import pathlib
import secrets
import sys
import time
import urllib.error
import urllib.request

HUB = "http://127.0.0.1:8090"
USER_FILE = "${DATA_DIR}/beszel-user"
AGENT_ENV_FILE = "${DATA_DIR}/agent.env"
CONFIG_FILE = "${DATA_DIR}/config.yml"
NEEDS_RESTART_FILE = "${DATA_DIR}/.needs-hub-restart"
AGENT_HOST = "${AGENT_HOST}"
SYSTEM_NAME = "${SYSTEM_NAME}"


def _get_json(path: str):
	with urllib.request.urlopen(HUB + path, timeout=5) as resp:
		return json.load(resp)


def main() -> int:
	# Wait (bounded) for the hub API to accept connections. The seed unit is
	# ordered after beszel-hub.service, but systemd considers the hub started
	# when the process execs, not when it is listening.
	state = None
	for _ in range(30):
		try:
			state = _get_json("/api/beszel/first-run")
			break
		except (OSError, urllib.error.URLError):
			time.sleep(1)
	if state is None:
		print("beszel-seed: hub API never became reachable", file=sys.stderr)
		return 1

	if not state.get("firstRun"):
		return 0  # already seeded - nothing to do

	email = pathlib.Path(USER_FILE).read_text(encoding="utf-8").strip()

	# Never stored and never used to authenticate - it only has to satisfy the
	# create-user endpoint's non-empty password requirement. token_urlsafe(48)
	# yields 64 chars; keep this under 71, PocketBase's password field max
	# (bcrypt's 72-byte limit), or create-user fails with HTTP 500.
	password = secrets.token_urlsafe(48)

	body = json.dumps({"email": email, "password": password}).encode()
	req = urllib.request.Request(
		HUB + "/api/beszel/create-user",
		data=body,
		headers={"Content-Type": "application/json"},
		method="POST",
	)
	with urllib.request.urlopen(req, timeout=5) as resp:
		json.load(resp)
	print(f"beszel-seed: created trusted-header user {email}")

	# The pre-shared token the agent already has in agent.env - reused here so
	# the fingerprint the hub creates on resync matches what the agent presents.
	token = ""
	with open(AGENT_ENV_FILE, encoding="utf-8") as f:
		for line in f:
			if line.startswith("TOKEN="):
				token = line.removeprefix("TOKEN=").strip()
				break

	config_yaml = (
		"systems:\n"
		f"  - name: {SYSTEM_NAME}\n"
		f"    host: {AGENT_HOST}\n"
		"    port: 45876\n"
		f"    token: {token}\n"
		"    users:\n"
		f"      - {email}\n"
	)
	pathlib.Path(CONFIG_FILE).write_text(config_yaml, encoding="utf-8")
	os.chmod(CONFIG_FILE, 0o640)

	pathlib.Path(NEEDS_RESTART_FILE).touch()
	print("beszel-seed: wrote config.yml, hub will restart to pick up the new system")
	return 0


if __name__ == "__main__":
	sys.exit(main())
