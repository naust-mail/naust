"""
Helpers used in component configure functions. No stamp logic here - that's handled by doit.
"""

import hashlib
import inspect
import os
import subprocess
import sys
import tempfile
import pathlib
import contextlib


_TOOLS_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "tools"))
_EDITCONF = os.path.join(_TOOLS_DIR, "editconf.py")

_EXCLUDE_DIRS = {"node_modules", ".next", "dist", "out", "target"}


def hash_files(*paths: str) -> str:
	"""sha256 over files/directories (sorted, recursive).

	Paths embedded in the hash are relative to each root passed in, so the
	result is stable regardless of where on disk the repo lives.
	"""
	h = hashlib.sha256()
	# (relative_path_for_hash, absolute_path_for_read)
	entries: list[tuple[str, str]] = []
	for path in paths:
		if os.path.isdir(path):
			for root, dirs, files in os.walk(path, topdown=True):
				dirs[:] = sorted(d for d in dirs if d not in _EXCLUDE_DIRS)
				for fname in sorted(files):
					abs_path = os.path.join(root, fname)
					entries.append((os.path.relpath(abs_path, path), abs_path))
		elif os.path.isfile(path):
			entries.append((os.path.basename(path), path))
	entries.sort()
	for rel_path, abs_path in entries:
		digest = hashlib.sha256(pathlib.Path(abs_path).read_bytes()).hexdigest()
		h.update(f"{digest}  {rel_path}\n".encode())
	return h.hexdigest()


def fetch_prebuilt(url: str, sha256: str, dest: str) -> None:
	"""Download url, verify sha256, install atomically. Equivalent to wget_verify_sha256."""
	import urllib.request

	fd, tmp = tempfile.mkstemp()
	try:
		os.close(fd)
		print(f"  Downloading {url}...")
		urllib.request.urlretrieve(url, tmp)
		actual = hashlib.sha256(pathlib.Path(tmp).read_bytes()).hexdigest()
		if actual != sha256:
			msg = f"Checksum mismatch for {url}\n  expected: {sha256}\n  got:      {actual}"
			raise RuntimeError(msg)
		os.makedirs(os.path.dirname(dest), exist_ok=True)
		os.replace(tmp, dest)
	except Exception:
		with contextlib.suppress(OSError):
			os.unlink(tmp)
		raise


def write_file(path: str, content: str, *, mode: int = 0o644) -> bool:
	"""Write content to path atomically. Returns True if the file changed."""
	encoded = content.encode()
	if os.path.exists(path) and pathlib.Path(path).read_bytes() == encoded:
		return False
	os.makedirs(os.path.dirname(path), exist_ok=True)
	fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
	try:
		os.write(fd, encoded)
		os.close(fd)
		os.chmod(tmp, mode)
		os.replace(tmp, path)
	except Exception:
		os.close(fd)
		os.unlink(tmp)
		raise
	return True


def render_template(path: str, subs: dict[str, str] | None = None) -> str:
	"""Read a config template and substitute ${KEY} placeholders.

	Only keys present in subs are replaced; every other character - including
	Dovecot %{...} variables and Postfix $names - passes through untouched.
	Plain string replacement with an explicit key list, mirroring how envsubst
	is used for the systemd unit templates.
	"""
	text = pathlib.Path(path).read_text(encoding="utf-8")
	for key, value in (subs or {}).items():
		text = text.replace("${" + key + "}", value)
	return text


def editconf(
	conf_file: str,
	*settings: str,
	erase: bool = False,
	space_delim: bool = False,
	folded: bool = False,
) -> None:
	"""Edit key=value pairs in a config file. Thin wrapper around setup/tools/editconf.py."""
	# editconf.py expects: editconf.py <filename> [flags] <settings...>
	cmd = [sys.executable, _EDITCONF, conf_file]
	if erase:
		cmd.append("-e")
	if space_delim:
		cmd.append("-s")
	if folded:
		cmd.append("-w")
	cmd.extend(settings)
	subprocess.run(cmd, check=True)


def file_hash(path: str) -> str:
	"""md5 of a file, or empty string if missing. Used for before/after change detection."""
	if not os.path.exists(path):
		return ""
	return hashlib.md5(open(path, "rb").read()).hexdigest()  # noqa: S324 -- change-detection fingerprint, not security-sensitive


def fn_stamp(fn: object, _seen: set | None = None) -> str:
	"""sha256 of a function's source *and everything it references in its own module*.

	Use as the value inside doit's config_changed() for tasks whose behaviour is
	defined in code (static settings, cipher lists, cron templates). The stamp
	changes whenever the step's logic changes, so doit re-runs the step without
	any manual version bumping.

	Why this is not just hash(source):
	    A bare hash of inspect.getsource(fn) only sees the function's own text.
	    If the function reads a module-level constant or calls a sibling helper,
	    editing that constant or helper changes the step's *behaviour* but not
	    fn's source, so the stamp would stay the same and doit would skip a step
	    that actually needs to re-run. That silent staleness is the bug this
	    version exists to prevent: e.g. editing a shared _SSL_CIPHERS constant
	    must invalidate every task that bakes it into a config file.

	What it captures:
	    - fn's own source text.
	    - The *value* of any module-level constant fn references (str/int/float/
	      bytes/tuple/frozenset). Value, not name, so changing the value counts.
	    - The source of any helper fn calls that is defined in the same module,
	      followed recursively.

	What it deliberately does NOT capture (known boundary - keep edits in mind):
	    - Helpers imported from other modules (e.g. artifacts.editconf). Those are
	      stable infra; if their behaviour changes, bump them deliberately or hash
	      the relevant module at the call site. co_names cannot tell a cross-module
	      call from a local one without the __module__ check below, and recursing
	      across modules would pull in half the stdlib.
	    - Mutable globals (list/dict/set). repr() of those is not a stable identity,
	      so they are skipped rather than hashed misleadingly. Don't drive config
	      off a mutable module global and expect the stamp to track it.
	    - Builtins and imported modules (they live in co_names but not as our own
	      module-level constants/functions, so the lookups below skip them).

	Do NOT use on a run_once task (e.g. DNSSEC key generation). The whole point of
	run_once is that the stamp must never track source; folding this in would
	re-arm key rotation on every edit and break deployed DS records.

	Fragility: inspect.getsource raises OSError if the .py source is not on disk
	(stripped / byte-compiled-only deploys). Git deployments keep source so this
	is fine in practice; callers that need to survive source-less installs should
	treat a raised stamp as "always invalidate" rather than letting it crash setup.

	Example:
	    'uptodate': [config_changed(fn_stamp(_configure_static))]
	"""
	# Cycle guard: mutual recursion between helpers (a -> b -> a) would otherwise
	# loop forever. Seen functions contribute nothing further to the hash.
	if _seen is None:
		_seen = set()
	if fn in _seen:
		return ""
	_seen.add(fn)

	h = hashlib.sha256()

	# 1. The function's own source text. Catches any edit to the body itself,
	#    including comments and the docstring (a comment-only change forces a
	#    re-run, which is the safe direction - re-running is idempotent).
	try:
		h.update(inspect.getsource(fn).encode())
	except OSError:
		# Source file unavailable (repo deleted post-install). Force re-run by
		# hashing the function's bytecode instead - stable enough for idempotent tasks.
		h.update(fn.__code__.co_code)

	# __globals__ is the module namespace fn was defined in. co_names is every
	# name fn references by bytecode (constants, called functions, attributes).
	# Together they let us resolve which module-level objects this function
	# actually depends on, without parsing the source ourselves.
	module_globals = getattr(fn, "__globals__", {})
	module_name = getattr(fn, "__module__", None)

	for name in fn.__code__.co_names:
		if name not in module_globals:
			# Not a module-level name (local var, builtin, imported submodule
			# attribute, etc.). Nothing stable for us to fold in.
			continue
		value = module_globals[name]

		if callable(value) and getattr(value, "__module__", None) == module_name:
			# A helper defined in THIS module. Recurse so edits to it invalidate
			# us too. The __module__ check is what keeps recursion from escaping
			# into imported/3rd-party/stdlib functions.
			h.update(fn_stamp(value, _seen).encode())
		elif isinstance(value, (str, int, float, bytes, tuple, frozenset)):
			# An immutable module-level constant. Hash name=value so that
			# changing the value (not just renaming) changes the stamp.
			h.update(f"{name}={value!r}".encode())
		elif isinstance(value, (list, dict, set)):
			# Mutable container referenced by this function - fn_stamp cannot capture
			# it safely. Raise so the component author uses config_changed() explicitly.
			msg = f"fn_stamp: {fn.__qualname__} references module-level {type(value).__name__} '{name}' which fn_stamp cannot track. Use config_changed() with an explicit serialisation (e.g. config_changed(':'.join({name}))) instead."
			raise TypeError(msg)
		# Anything else (modules, classes, etc.) is intentionally skipped.

	return h.hexdigest()


def ufw_allow(rule: str) -> None:
	"""ufw allow <rule>. No-op in Docker or when DISABLE_FIREWALL is set."""
	if os.environ.get("RUNTIME", BAREMETAL) == DOCKER:
		return
	if os.environ.get("DISABLE_FIREWALL"):
		return
	subprocess.run(["ufw", "allow", rule], check=True, capture_output=True)


def ufw_limit(rule: str) -> None:
	"""ufw limit <rule>. No-op in Docker or when DISABLE_FIREWALL is set."""
	if os.environ.get("RUNTIME", BAREMETAL) == DOCKER:
		return
	if os.environ.get("DISABLE_FIREWALL"):
		return
	subprocess.run(["ufw", "limit", rule], check=True, capture_output=True)


def ubuntu_supports_encryption() -> bool:
	"""Encryption at rest requires Ubuntu 26.04+ (Dovecot 2.4 with dovecot.http).

	Ubuntu 22.04/24.04 use Dovecot 2.3 which lacks dovecot.http in the Lua auth
	module, blocking mailcrypt.
	"""
	try:
		with open("/etc/os-release", encoding="utf-8") as fh:
			for line in fh:
				if line.startswith("VERSION_ID="):
					version = float(line.split("=", 1)[1].strip().strip('"'))
					return version >= 26
	except (OSError, ValueError):
		pass
	return False


# Import runtime constants here so defs files only need `from .. import artifacts`.
from .component import BAREMETAL, DOCKER  # noqa: E402
