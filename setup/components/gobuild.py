"""
Fetch-or-build for the fork's Go daemon binaries (defs/daemon.py is
the only consumer).

The normal path fetches prebuilt binaries from the versioned project
release the box installed from: project-release.yml attaches
<cmd>-linux-<arch> assets plus sha256 sidecars and a daemon.hash
manifest (content hash of daemon/ at tag time). The manifest guards a
modified source tree - if the local daemon/ does not hash to what the
release shipped, the prebuilts do not correspond to this source and a
local build happens instead. Sidecars come from the same host as the
binaries - same-source verification (transit integrity, not
provenance independent of the publisher), fine because our own CI
publishes them from our own source.

The fallback (dev checkout without a VERSION file, modified daemon/,
release assets unreachable) builds with an ephemeral Go toolchain
under /tmp: latest stable release, sha256-verified against the go.dev
manifest, deleted after the build. The box never carries a compiler.
Set BUILD_DAEMON=1 to skip the fetch and always build locally.

Escape hatch: NAUST_UNSAFE_BINARIES=<dir> installs binaries found there
by name (helperd, managerd, muninweb, boxctl) with no verification whatsoever -
the operator vouches for them. Anything missing from the dir follows the
normal fetch-or-build path.
"""

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile

from . import artifacts
import contextlib

_RELEASE_BASE = "https://github.com/naust-mail/naust/releases/download"

# The release-base probe (VERSION read + daemon.hash comparison) is the
# same answer for every binary in one setup run; cache it per source dir.
_release_base_cache: dict[str, str | None] = {}


def fetch_or_build(daemon_src: str, package: str, out_path: str) -> None:
	"""Install one daemon binary: operator-supplied, release asset, or source build."""
	name = os.path.basename(out_path)
	unsafe_dir = os.environ.get("NAUST_UNSAFE_BINARIES")
	if unsafe_dir:
		candidate = os.path.join(unsafe_dir, name)
		if os.path.exists(candidate):
			# Repeated on purpose: a single line vanishes from the
			# installer's rolling panel; five do not, and all ten land in
			# the setup log as a durable record of what was trusted.
			for _ in range(5):
				print(f"!! UNVERIFIED prebuilt {name}: installing {candidate} (NAUST_UNSAFE_BINARIES)", flush=True)
			os.makedirs(os.path.dirname(out_path), exist_ok=True)
			shutil.copy2(candidate, out_path)
			os.chmod(out_path, 0o755)
			digest = hashlib.sha256(pathlib.Path(out_path).read_bytes()).hexdigest()
			for _ in range(5):
				print(f"!! UNVERIFIED prebuilt {name} installed to {out_path} sha256={digest}", flush=True)
			return
	if os.environ.get("BUILD_DAEMON") != "1":
		base = _release_base(daemon_src)
		if base and _fetch_one(base, package, out_path):
			return
		print(f"No prebuilt {os.path.basename(package)} found - building from source...")
	_build(daemon_src, package, out_path)


def _arch() -> str:
	arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine)
	if arch is None:
		msg = f"unsupported architecture for Go binaries: {os.uname().machine}"
		raise RuntimeError(msg)
	return arch


def _release_base(daemon_src: str) -> str | None:
	"""Asset URL base for this box's release, or None when this checkout
	is not an unmodified release (no VERSION file, or daemon/ differs
	from the daemon.hash the release shipped)."""
	if daemon_src in _release_base_cache:
		return _release_base_cache[daemon_src]
	_release_base_cache[daemon_src] = None

	try:
		version = pathlib.Path(os.path.join(os.path.dirname(daemon_src), "VERSION")).read_text(encoding="utf-8").strip()
	except FileNotFoundError:
		return None
	if not version:
		return None
	base = f"{_RELEASE_BASE}/{version}"

	manifest = subprocess.run(
		["curl", "-fsSL", f"{base}/daemon.hash"],
		check=False,
		capture_output=True,
		text=True,
	)
	if manifest.returncode != 0:
		return None
	if manifest.stdout.strip() != artifacts.hash_files(daemon_src):
		print("daemon/ does not match the release build - falling back to source build.")
		return None

	_release_base_cache[daemon_src] = base
	return base


def _fetch_one(base: str, package: str, out_path: str) -> bool:
	asset = f"{os.path.basename(package)}-linux-{_arch()}"
	url = f"{base}/{asset}"
	tmp_dir = tempfile.mkdtemp(prefix="naust-gobuild-")
	tmp_bin = os.path.join(tmp_dir, asset)
	tmp_sha = f"{tmp_bin}.sha256"
	try:
		sha_result = subprocess.run(
			["curl", "-fsSL", "-o", tmp_sha, f"{url}.sha256"],
			check=False,
			capture_output=True,
		)
		if sha_result.returncode != 0:
			return False
		dl = subprocess.run(
			["curl", "-fsSL", "-o", tmp_bin, url],
			check=False,
			capture_output=True,
		)
		if dl.returncode != 0:
			return False
		expected = pathlib.Path(tmp_sha).read_text(encoding="utf-8").strip().split()[0]
		check = subprocess.run(
			["sha256sum", "--check", "--strict"],
			input=f"{expected}  {tmp_bin}",
			text=True,
			capture_output=True,
			check=False,
		)
		if check.returncode != 0:
			return False
		os.makedirs(os.path.dirname(out_path), exist_ok=True)
		shutil.move(tmp_bin, out_path)
		os.chmod(out_path, 0o755)
		return True
	finally:
		shutil.rmtree(tmp_dir, ignore_errors=True)


def _build(daemon_src: str, package: str, out_path: str) -> None:
	"""Build one package from the daemon module with an ephemeral toolchain."""
	arch = _arch()

	manifest = subprocess.run(
		["curl", "-fsSL", "https://go.dev/dl/?mode=json"],
		check=True,
		capture_output=True,
		text=True,
	)
	release = json.loads(manifest.stdout)[0]
	tarball = next(f for f in release["files"] if f["os"] == "linux" and f["arch"] == arch and f["kind"] == "archive")

	work = tempfile.mkdtemp(prefix="naust-go-toolchain-")
	swap_path = None
	try:
		tar_path = os.path.join(work, tarball["filename"])
		size_mb = tarball.get("size", 0) // (1024 * 1024)
		print(f"Downloading Go toolchain {release['version']} (~{size_mb} MB)...", flush=True)
		subprocess.run(
			["curl", "-fsSL", "-o", tar_path, f"https://go.dev/dl/{tarball['filename']}"],
			check=True,
			capture_output=True,
		)
		subprocess.run(
			["sha256sum", "--check", "--strict"],
			input=f"{tarball['sha256']}  {tar_path}",
			text=True,
			check=True,
			capture_output=True,
		)
		subprocess.run(["tar", "-xzf", tar_path, "-C", work], check=True, capture_output=True)

		os.makedirs(os.path.dirname(out_path), exist_ok=True)
		build_env = os.environ.copy()
		build_env.update({
			"CGO_ENABLED": "0",
			"GOCACHE": os.path.join(work, "cache"),
			"GOPATH": os.path.join(work, "gopath"),
		})
		# Small VPSes get OOM-killed compiling the big packages: even
		# alone, modernc.org/sqlite and the generated ent package outgrow
		# 1 GB. Single-package builds plus an aggressive GC ceiling trade
		# speed for peak memory, and a temporary swap file covers what is
		# left (removed again after the build).
		with open("/proc/meminfo", encoding="utf-8") as fh:
			mem = {line.split(":")[0]: int(line.split()[1]) for line in fh}
		if mem["MemTotal"] < 2_500_000:
			build_env["GOFLAGS"] = "-p=1"
			build_env["GOGC"] = "32"
			print("Low memory: compiling one package at a time with an aggressive GC ceiling (slower, but avoids the OOM killer).", flush=True)
			if mem["MemTotal"] + mem.get("SwapTotal", 0) < 2_500_000:
				swap_path = _add_build_swap()
		print(f"Compiling {package} (first build downloads module deps; this can take several minutes)...", flush=True)
		# Deliberately NOT captured: "go: downloading ..." and "-v" package
		# lines stream into the installer's log panel so a long build shows
		# life, and a compile error lands on screen instead of dying in a
		# swallowed pipe.
		subprocess.run(
			[os.path.join(work, "go", "bin", "go"), "build", "-v", "-trimpath", "-ldflags", "-s -w", "-o", out_path, package],
			cwd=daemon_src,
			env=build_env,
			check=True,
		)
		os.chmod(out_path, 0o755)
		print(f"Built {out_path}.", flush=True)
	finally:
		if swap_path:
			_remove_build_swap(swap_path)
		shutil.rmtree(work, ignore_errors=True)


def _add_build_swap() -> str | None:
	"""Attach a temporary 2 GB swap file for the duration of a build.

	Ephemeral like the toolchain: no fstab entry, removed in _build's
	cleanup. Skipped on btrfs (swap files need special setup there) and
	when disk is too tight; the build then proceeds and may still be
	OOM-killed, which is no worse than before.
	"""
	if "btrfs" in pathlib.Path("/proc/mounts").read_text(encoding="utf-8"):
		return None
	stat = os.statvfs("/var/tmp")  # noqa: S108 - checking free space on the mount, not writing a file
	if stat.f_bavail * stat.f_frsize < 3 * 1024**3:
		return None

	path_fd, path = tempfile.mkstemp(dir="/var/tmp", prefix="naust-build-swap-")
	os.close(path_fd)
	print("Low memory: attaching a temporary 2 GB swap file for the build...", flush=True)
	try:
		subprocess.run(["fallocate", "-l", "2G", path], check=True, capture_output=True)
		os.chmod(path, 0o600)
		subprocess.run(["mkswap", path], check=True, capture_output=True)
		subprocess.run(["swapon", path], check=True, capture_output=True)
	except (subprocess.CalledProcessError, OSError) as e:
		print(f"Could not attach build swap ({e}); continuing without it.", flush=True)
		with contextlib.suppress(FileNotFoundError):
			os.unlink(path)
		return None
	return path


def _remove_build_swap(path: str) -> None:
	subprocess.run(["swapoff", path], check=False, capture_output=True)
	with contextlib.suppress(FileNotFoundError):
		os.unlink(path)
