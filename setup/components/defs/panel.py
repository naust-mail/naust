"""
Admin panel (Vue frontend).

managerd serves the API; nginx serves this static bundle at /admin and proxies
/api to managerd. Nothing here touches the (retired) Flask daemon - the panel
is a pure static asset set.

Steps:
  frontend - build or fetch the prebuilt Vue admin bundle
  install  - rsync dist to the FHS share path and stamp boot.js with the hostname

Baremetal only: the Docker image bakes the built bundle in at image-build time.
"""

import json
import os
import pathlib
import shutil
import subprocess
import tempfile

from doit.tools import config_changed

from .. import artifacts, SETUP_DIR
from ..component import Component

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="panel",
	# rsync deploys the built bundle to the share path.
	packages=["rsync"],
	services=[],
	docker_services=[],
	skip_on=["docker"],
)

_SHARE_DIR = "/usr/local/share/naust"


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	repo_root = os.path.dirname(SETUP_DIR)
	frontend_src = os.path.join(repo_root, "frontend")
	frontend_dist = os.path.join(frontend_src, "dist")

	return [
		{
			"name": "frontend",
			# Re-runs when frontend source files change. The content hash is the same
			# key CI uses to publish prebuilt artifacts, so a box never needs to build
			# from source when an identical artifact was already built by CI.
			# When source is absent (VPS install), fall back to dist hash so the
			# task doesn't re-run just because the source hash changed between
			# the build machine and the target box.
			"uptodate": [config_changed(artifacts.hash_files(frontend_src) if os.path.isdir(frontend_src) else artifacts.hash_files(f"{_SHARE_DIR}/frontend/dist") if os.path.isdir(f"{_SHARE_DIR}/frontend/dist") else "")],
			"actions": [(_frontend, [frontend_src, frontend_dist])],
		},
		{
			"name": "install",
			# Re-runs when the built bundle changes or the hostname changes (boot.js).
			"uptodate": [
				config_changed(
					"|".join([
						artifacts.hash_files(frontend_dist) if os.path.isdir(frontend_dist) else "",
						env.get("PRIMARY_HOSTNAME", ""),
					])
				)
			],
			"task_dep": ["panel:frontend"],
			"actions": [(_install, [frontend_dist, env.get("PRIMARY_HOSTNAME", "")])],
		},
	]


# ── Action functions ──────────────────────────────────────────────────────────


def _frontend(frontend_src: str, frontend_dist: str) -> None:
	"""Build or fetch the Vue admin frontend.

	The content hash of frontend/ matches what CI uses as the artifact tag, so
	a box can almost always fetch a prebuilt artifact. Builds from source only
	when no prebuilt exists (local dev, unmerged changes).
	"""
	fe_hash = artifacts.hash_files(frontend_src)
	fe_tag = f"frontend-{fe_hash}"
	# URL constructed from the project's github repo release endpoint.
	fe_url = f"https://github.com/naust-mail/naust/releases/download/{fe_tag}/frontend-dist.tar.gz"

	fetched = False
	# Try the prebuilt artifact. The sha256 sidecar is fetched from the same
	# host as the tarball (unlike the pinned-hash pattern used for third-party
	# tools like restic) - that's intentional: this artifact is published by our
	# own CI from our own source, so same-source is fine. It verifies transit
	# integrity, not provenance independent of the publisher.
	tmp_dir = tempfile.mkdtemp(prefix="naust-frontend-")
	tmp_tarball = os.path.join(tmp_dir, "frontend-dist.tar.gz")
	tmp_sha = os.path.join(tmp_dir, "frontend-dist.tar.gz.sha256")
	try:
		sha_url = f"{fe_url}.sha256"
		sha_result = subprocess.run(
			["curl", "-fsSL", "-o", tmp_sha, sha_url],
			check=False,
			capture_output=True,
		)
		if sha_result.returncode == 0:
			print("Downloading the prebuilt admin frontend...", flush=True)
			dl = subprocess.run(
				["wget", "-q", "-O", tmp_tarball, fe_url],
				check=False,
				capture_output=True,
			)
			if dl.returncode == 0:
				expected = pathlib.Path(tmp_sha).read_text(encoding="utf-8").strip()
				result = subprocess.run(
					["sha256sum", "--check", "--strict"],
					input=f"{expected}  {tmp_tarball}",
					text=True,
					capture_output=True,
					check=False,
				)
				if result.returncode == 0:
					shutil.rmtree(frontend_dist, ignore_errors=True)
					os.makedirs(frontend_dist, exist_ok=True)
					subprocess.run(
						["tar", "-xzf", tmp_tarball, "-C", frontend_dist],
						check=True,
					)
					fetched = True
	finally:
		shutil.rmtree(tmp_dir, ignore_errors=True)

	if not fetched:
		if not os.path.isdir(frontend_src):
			installed_dist = f"{_SHARE_DIR}/frontend/dist"
			if os.path.isdir(installed_dist) and os.listdir(installed_dist):
				# Already installed to system path, no source to rebuild from - skip.
				return
			msg = f"No prebuilt admin frontend found for this build and frontend source directory does not exist ({frontend_src}). Push to CI to publish a release artifact, or run setup from the repo root."
			raise RuntimeError(msg)
		print("No prebuilt admin frontend found - building from source...")
		# Download bun to a scratch dir, use it, then delete it.
		# Avoids touching system packages or apt sources.
		bun_install = tempfile.mkdtemp(prefix="naust-bun-")
		bun_bin = f"{bun_install}/bin/bun"
		try:
			subprocess.run(  # noqa: S602 - hardcoded, non-interpolated command; no injection surface
				"curl -fsSL https://bun.sh/install | bash",
				shell=True,
				check=True,
				env={**os.environ, "BUN_INSTALL": bun_install},
			)

			subprocess.run([bun_bin, "install", "--frozen-lockfile"], cwd=frontend_src, check=True)
			# vite only empties its own outDir subtree; clear the whole dist/
			# so output from an older layout never ships in the rsync.
			shutil.rmtree(frontend_dist, ignore_errors=True)
			subprocess.run([bun_bin, "x", "vite", "build"], cwd=frontend_src, check=True)
		finally:
			shutil.rmtree(bun_install, ignore_errors=True)


def _install(frontend_dist: str, primary_hostname: str) -> None:
	"""Rsync the built bundle to the FHS share path and stamp boot.js.

	After setup completes the repo can be deleted; nginx serves the panel from
	/usr/local/share/naust/frontend/dist.
	"""
	dest = f"{_SHARE_DIR}/frontend/dist"
	os.makedirs(dest, exist_ok=True)

	if os.path.isdir(frontend_dist):
		subprocess.run(
			["rsync", "-a", "--delete", f"{frontend_dist}/", f"{dest}/"],
			check=True,
			capture_output=True,
		)

	# Stamp the box hostname into the panel's boot loader so first paint
	# never waits on the API. dist/ ships a placeholder boot.js; the real
	# file must be written here, after the rsync, because --delete would
	# otherwise restore the placeholder on every re-install.
	if primary_hostname:
		artifacts.write_file(
			f"{dest}/admin/boot.js",
			f"window.__BOX__ = {{ hostname: {json.dumps(primary_hostname)} }}\ndocument.title = window.__BOX__.hostname\n",
		)
