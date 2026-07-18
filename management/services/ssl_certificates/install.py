# Installing a certificate uploaded from the control panel (the manual path,
# as opposed to provisioning.py's automatic Let's Encrypt path).

import os
import shutil
import tempfile

from core.utils import shell, safe_domain_name


def create_csr(domain, ssl_key, country_code, env):
	return shell("check_output", ["openssl", "req", "-new", "-key", ssl_key, "-sha256", "-subj", f"/C={country_code}/CN={domain}"])


def install_cert(domain, ssl_cert, ssl_chain, env, raw=False):
	from .validation import check_certificate

	# Write the combined cert+chain to a temporary path and validate that it is OK.
	# The certificate always goes above the chain.
	fd, fn = tempfile.mkstemp('.pem')
	os.write(fd, (ssl_cert + '\n' + ssl_chain).encode("ascii"))
	os.close(fd)

	# Do validation on the certificate before installing it.
	ssl_private_key = os.path.join(os.path.join(env["STORAGE_ROOT"], 'ssl', 'ssl_private_key.pem'))
	cert_status, cert_status_details = check_certificate(domain, fn, ssl_private_key)
	if cert_status != "OK":
		if cert_status == "SELF-SIGNED":
			cert_status = "This is a self-signed certificate. I can't install that."
		os.unlink(fn)
		if cert_status_details is not None:
			cert_status += " " + cert_status_details
		return cert_status

	# Copy certificate into ssl directory.
	install_cert_copy_file(fn, env)

	# Run post-install steps.
	ret = post_install_func(env)
	if raw:
		return ret
	return "\n".join(ret)


def install_cert_copy_file(fn, env):
	from .validation import load_pem, load_cert_chain, get_certificate_domains

	# Where to put it?
	# Make a unique path for the certificate.
	from cryptography.hazmat.primitives import hashes
	from binascii import hexlify

	cert = load_pem(load_cert_chain(fn)[0])
	_all_domains, cn = get_certificate_domains(cert)
	path = "{}-{}-{}.pem".format(
		safe_domain_name(cn),  # common name, which should be filename safe because it is IDNA-encoded, but in case of a malformed cert make sure it's ok to use as a filename
		cert.not_valid_after_utc.date().isoformat().replace("-", ""),  # expiration date
		hexlify(cert.fingerprint(hashes.SHA256())).decode("ascii")[0:8],  # fingerprint prefix
	)
	ssl_certificate = os.path.join(os.path.join(env["STORAGE_ROOT"], 'ssl', path))

	# Install the certificate.
	os.makedirs(os.path.dirname(ssl_certificate), exist_ok=True)
	shutil.move(fn, ssl_certificate)
	# mkstemp creates 0600 files; make the cert readable by ssl-cert group
	# so services like rav can verify loopback TLS without keeping a stale copy.
	shutil.chown(ssl_certificate, group="ssl-cert")
	os.chmod(ssl_certificate, 0o640)


def post_install_func(env):
	from .selection import get_ssl_certificates, get_domain_ssl_files

	ret = []

	# Get the certificate to use for PRIMARY_HOSTNAME.
	ssl_certificates = get_ssl_certificates(env)
	cert = get_domain_ssl_files(env['PRIMARY_HOSTNAME'], ssl_certificates, env, use_main_cert=False)
	if not cert:
		# Ruh-row, we don't have any certificate usable
		# for the primary hostname.
		ret.append("there is no valid certificate for " + env['PRIMARY_HOSTNAME'])

	# Symlink the best cert for PRIMARY_HOSTNAME to the system
	# certificate path, which is hard-coded for various purposes, and then
	# restart postfix and dovecot.
	system_ssl_certificate = os.path.join(os.path.join(env["STORAGE_ROOT"], 'ssl', 'ssl_certificate.pem'))
	if cert and os.readlink(system_ssl_certificate) != cert['certificate']:
		# Update symlink.
		ret.append("updating primary certificate")
		ssl_certificate = cert['certificate']
		os.unlink(system_ssl_certificate)
		os.symlink(ssl_certificate, system_ssl_certificate)

		# Restart postfix and dovecot so they pick up the new certificate.
		from services.control_plane import restart as cp_restart

		cp_restart("postfix")
		cp_restart("dovecot")
		cp_restart("rav")
		ret.append("mail services restarted")

		# The DANE TLSA record will remain valid so long as the private key
		# hasn't changed. We don't ever change the private key automatically.
		# If the user does it, they must manually update DNS.

	# Update the web configuration so nginx picks up the new certificate file.
	from services.web_update import do_web_update

	ret.append(do_web_update(env))

	return ret
