"""
SSL/TLS certificate bootstrap.

The RSA private key and self-signed certificate generated here are used for:
  - DNSSEC DANE TLSA records
  - IMAP (Dovecot)
  - SMTP opportunistic TLS on port 25 and submission on ports 465/587 (Postfix)
  - HTTPS (nginx)

The certificate CN is set to PRIMARY_HOSTNAME and is also used for other
domains served over HTTPS until the user installs a better certificate for
those domains via the admin panel (certbot/Let's Encrypt).

Steps:
  key   - generate RSA private key (skipped if key file already exists)
  cert  - generate self-signed cert with SAN (skipped if cert symlink exists)
  cron  - install ssl_cleanup tool + daily cron (re-runs if cleanup script or
          cron installer code changes)

Port order: first component - everything else needs certs to exist.
"""

import os
import shutil
import subprocess
import tempfile
from datetime import date

from doit.tools import config_changed

from .. import artifacts, SETUP_DIR
from ..component import Component

# ── Component declaration ─────────────────────────────────────────────────────

COMPONENT = Component(
	name="ssl",
	packages=["openssl"],
	# No services: cert generation doesn't require restarting anything.
	# Downstream services (postfix, dovecot, nginx) pick up the cert when
	# they restart for their own reasons.
	port_order=10,  # After system (0), before everything that needs certs.
)

_TOOLS_DIR = os.path.join(SETUP_DIR, "tools")


# ── Tasks ─────────────────────────────────────────────────────────────────────


def make_tasks(env: dict, _runtime: str) -> list[dict]:
	storage_root = env["STORAGE_ROOT"]
	ssl_dir = os.path.join(storage_root, "ssl")
	key = os.path.join(ssl_dir, "ssl_private_key.pem")
	cert_link = os.path.join(ssl_dir, "ssl_certificate.pem")
	cleanup_src = os.path.join(_TOOLS_DIR, "ssl_cleanup")

	return [
		{
			"name": "key",
			# targets= causes doit to re-run if the key file is missing,
			# regardless of stamp state. Handles the "accidentally deleted" case.
			"targets": [key],
			"actions": [(_generate_key, [key])],
		},
		{
			"name": "cert",
			"targets": [cert_link],
			# cert depends on the key existing.
			"task_dep": ["ssl:key"],
			"actions": [(_generate_cert, [env, key, ssl_dir, cert_link])],
		},
		{
			"name": "cron",
			# Re-runs when either the cleanup script on disk changes (new version
			# shipped in the repo) or our installer code changes.
			"uptodate": [config_changed(artifacts.hash_files(cleanup_src) + artifacts.fn_stamp(_install_cron))],
			"actions": [(_install_cron, [cleanup_src])],
		},
	]


# ── Action functions ──────────────────────────────────────────────────────────


def _generate_key(key: str) -> None:
	"""Generate a 2048-bit RSA private key. umask 0177 keeps it root-readable only.

	Key quality depends on /dev/urandom entropy at generation time. Cloud VMs
	and embedded systems can have poor entropy at boot (zeroed memory, predictable
	PID, fixed-time clocks). system.sh seeds /dev/urandom via haveged/rng-tools
	before this runs, so we should be fine in practice.
	"""
	ssl_dir = os.path.dirname(key)
	os.makedirs(ssl_dir, exist_ok=True)
	# Explicit chmod: os.makedirs's mode is masked by the ambient umask, which
	# isn't controlled here. The directory must stay world-traversable so
	# services like rav (via the ssl-cert group) can reach ssl_certificate.pem
	# inside it - a restrictive umask (e.g. 027) would otherwise block that
	# even though the cert file itself is correctly group-readable.
	os.chmod(ssl_dir, 0o755)
	print("Generating a 2048-bit RSA private key...", flush=True)
	old_umask = os.umask(0o177)
	try:
		subprocess.run(
			["openssl", "genrsa", "-out", key, "2048"],
			check=True,
			capture_output=True,
		)
	finally:
		os.umask(old_umask)


def _generate_cert(env: dict, key: str, ssl_dir: str, cert_link: str) -> None:
	"""Generate a self-signed cert with SAN extensions and symlink it.

	Creates a dated backing file (e.g. box.example.com-selfsigned-20260621.pem)
	so ssl_cleanup can identify and rotate expired certs by filename date.
	SSL_EXTRA_SANS (comma-separated) adds extra SAN entries - used in Docker
	so webmail containers can verify Dovecot's cert via the 'mail' service name.
	"""
	hostname = env.get("PRIMARY_HOSTNAME", "localhost")

	san_parts = [f"DNS:{hostname}"]
	for raw_extra in os.environ.get("SSL_EXTRA_SANS", "").split(","):
		extra = raw_extra.strip()
		if extra:
			san_parts.append(f"IP:{extra}" if extra[0].isdigit() else f"DNS:{extra}")

	dated = os.path.join(ssl_dir, f"{hostname}-selfsigned-{date.today().strftime('%Y%m%d')}.pem")

	with tempfile.NamedTemporaryFile(suffix=".csr", delete=False) as f:
		csr = f.name
	with tempfile.NamedTemporaryFile(encoding="utf-8", mode="w", suffix=".ext", delete=False) as f:
		f.write(f"subjectAltName={','.join(san_parts)}\n")
		ext = f.name
	try:
		subprocess.run(
			["openssl", "req", "-new", "-key", key, "-out", csr, "-sha256", "-subj", f"/CN={hostname}"],
			check=True,
			capture_output=True,
		)
		old_umask = os.umask(0o177)
		try:
			subprocess.run(
				["openssl", "x509", "-req", "-days", "365", "-in", csr, "-signkey", key, "-out", dated, "-extfile", ext],
				check=True,
				capture_output=True,
			)
		finally:
			os.umask(old_umask)
	finally:
		os.unlink(csr)
		os.unlink(ext)

	# Cert is public data (transmitted in every TLS handshake). Make it readable
	# by the ssl-cert group so services like rav can verify loopback TLS connections
	# without a copy. Private key stays 0600/root.
	shutil.chown(dated, group="ssl-cert")
	os.chmod(dated, 0o640)

	if not os.path.lexists(cert_link) or os.readlink(cert_link) != dated:
		if os.path.lexists(cert_link):
			os.unlink(cert_link)
		os.symlink(dated, cert_link)


def _install_cron(cleanup_src: str) -> None:
	"""Copy ssl_cleanup to a fixed system path and write the daily cron job.

	Installing to /usr/local/lib/naust/ means the cron survives the
	setup repo being deleted after install.
	"""
	dest = "/usr/local/lib/naust/ssl_cleanup"
	if os.path.exists(cleanup_src):
		shutil.copy2(cleanup_src, dest)
		os.chmod(dest, 0o755)

	artifacts.write_file(
		"/etc/cron.daily/naust-ssl-cleanup",
		f"#!/bin/bash\n# Naust - remove SSL certs that expired more than 7 days ago.\n{dest}\n",
		mode=0o755,
	)
