"""
Scan all defs/*.py files for key/random generation primitives and assert that
every match is inside a function that is either explicitly gated (MUST_GATE)
or documented as having its own guard (DOCUMENTED_EXEMPT).

Any generation primitive found outside these sets is a test failure: it means
a key-generation call can run on every setup invocation rather than only once.
"""

import os
import re


_DEFS_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "setup", "components", "defs"))

# Patterns that indicate a key/random generation call.
_PATTERNS = [
	re.compile(r"\bkeygen\b"),
	re.compile(r"\bgenrsa\b"),
	re.compile(r"openssl\s+rand"),
	re.compile(r"\brspamadm\b"),
	re.compile(r"\bsecrets\."),
	re.compile(r"/dev/urandom"),
]

# Functions that MUST have an existence gate (tested in test_idempotency.py).
MUST_GATE = {
	"_generate_dnssec_keys",
	"_generate_dkim_key",
	"_generate_backup_key",
	"_backup_key",
	"_dkim_key",
	"_des_key",
	"_generate_key",
}

# Functions that use generation primitives but are exempt because they have
# their own documented guard (targets= in the task dict, checked by doit),
# or because they run conditionally (e.g. only on first install).
DOCUMENTED_EXEMPT = {
	"_generate_cert",
	"_start_script",
	# backup/__init__.py: ssh-keygen for the rsync/sftp backup key - guarded by targets= in doit.
	"_ssh_key",
	# managerd.py: openssl rand for the mailcrypt unwrap secret - guarded by targets= in doit plus its own existence check.
	"_unwrap_key",
	# beszel.py: ssh-keygen for hub->agent keypair - guarded by targets= in doit.
	"_generate_keypair",
}

_ALL_ALLOWED = MUST_GATE | DOCUMENTED_EXEMPT


def _enclosing_function(lines: list[str], match_lineno: int) -> str | None:
	"""Return the name of the def statement that most recently precedes match_lineno."""
	fn_re = re.compile(r"^def (\w+)\(")
	last_fn = None
	for i, line in enumerate(lines):
		if i >= match_lineno:
			break
		m = fn_re.match(line)
		if m:
			last_fn = m.group(1)
	return last_fn


def _collect_violations() -> list[str]:
	violations = []
	for dirpath, _dirnames, filenames in os.walk(_DEFS_DIR):
		for fname in sorted(filenames):
			if not fname.endswith(".py") or fname.startswith("__"):
				continue
			path = os.path.join(dirpath, fname)
			rel = os.path.relpath(path, _DEFS_DIR)
			with open(path, encoding="utf-8") as fh:
				lines = fh.readlines()
			for lineno, line in enumerate(lines):
				for pat in _PATTERNS:
					if pat.search(line):
						fn_name = _enclosing_function(lines, lineno)
						# fn_name is None for matches at module level (docstrings,
						# comments). Module-level mentions are acceptable (e.g.
						# rspamd.py's docstring describes the step using "rspamadm").
						if fn_name is None:
							break
						if fn_name not in _ALL_ALLOWED:
							violations.append(f"{rel}:{lineno + 1}: pattern {pat.pattern!r} in function {fn_name!r} (not in MUST_GATE or DOCUMENTED_EXEMPT)")
						break  # Only report a line once even if multiple patterns match.
	return violations


def test_generation_primitives_are_gated():
	"""Every key/random generation call must be in a gated or exempted function."""
	violations = _collect_violations()
	assert not violations, "Ungated generation primitives found:\n" + "\n".join(violations)
