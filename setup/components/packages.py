"""
Single batched apt-get install across all enabled components. No-op in Docker
(packages are pre-baked into the container image).
"""

import os
import subprocess

from .component import DOCKER
import pathlib
import contextlib

_POLICY_RC = "/usr/sbin/policy-rc.d"


def ensure_installed(packages: list[str]) -> None:
	if not packages:
		return
	if os.environ.get("RUNTIME") == DOCKER:
		return
	env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_SUSPEND": "1"}
	print(f"Installing {len(packages)} apt packages...", flush=True)

	# Debian postinst scripts restart their services via invoke-rc.d.
	# Mid-setup our configs can be half-written (e.g. dovecot pointing
	# at a cert a later component provisions), so a triggered restart
	# can fail the whole dpkg run. policy-rc.d exit 101 makes
	# invoke-rc.d skip service actions during the install; the runner
	# (re)starts every service at the end of setup anyway. Root-only:
	# writing /usr/sbin needs it, and unprivileged callers are tests.
	guard = os.geteuid() == 0 and not os.path.exists(_POLICY_RC)
	if guard:
		pathlib.Path(_POLICY_RC).write_text("#!/bin/sh\nexit 101\n", encoding="utf-8")
		os.chmod(_POLICY_RC, 0o755)
	try:
		subprocess.run(["apt-get", "-qq", "update"], check=True, env=env)
		subprocess.run(
			[
				"apt-get",
				"install",
				"-y",
				"--no-install-recommends",
				"-o",
				"Dpkg::Options::=--force-confdef",
				"-o",
				"Dpkg::Options::=--force-confnew",
				"-o",
				"DPkg::Lock::Timeout=300",
				*packages,
			],
			check=True,
			env=env,
		)
	finally:
		if guard:
			with contextlib.suppress(FileNotFoundError):
				os.unlink(_POLICY_RC)
