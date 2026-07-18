import base64
import hashlib
import os
import subprocess

from core.utils import shell, get_ssh_port


def build_tlsa_record(env):
	# A DANE TLSA record in DNS specifies that connections on a port
	# must use TLS and the certificate must match a particular criteria.
	#
	# Thanks to http://blog.huque.com/2012/10/dnssec-and-certificates.html
	# and https://community.letsencrypt.org/t/please-avoid-3-0-1-and-3-0-2-dane-tlsa-records-with-le-certificates/7022
	# for explaining all of this! Also see https://tools.ietf.org/html/rfc6698#section-2.1
	# and https://github.com/mail-in-a-box/mailinabox/issues/268#issuecomment-167160243.
	#
	# There are several criteria. We used to use "3 0 1" criteria, which
	# meant to pin a leaf (3) certificate (0) with SHA256 hash (1). But
	# certificates change, and especially as we move to short-lived certs
	# they change often. The TLSA record handily supports the criteria of
	# a leaf certificate (3)'s subject public key (1) with SHA256 hash (1).
	# The subject public key is the public key portion of the private key
	# that generated the CSR that generated the certificate. Since we
	# generate a private key once the first time Naust is set up
	# and reuse it for all subsequent certificates, the TLSA record will
	# remain valid indefinitely.

	from services.ssl_certificates import load_cert_chain, load_pem
	from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

	fn = os.path.join(env["STORAGE_ROOT"], "ssl", "ssl_certificate.pem")
	cert = load_pem(load_cert_chain(fn)[0])

	subject_public_key = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
	# We could have also loaded ssl_private_key.pem and called priv_key.public_key().public_bytes(...)

	pk_hash = hashlib.sha256(subject_public_key).hexdigest()

	# Specify the TLSA parameters:
	# 3: Match the (leaf) certificate. (No CA, no trust path needed.)
	# 1: Match its subject public key.
	# 1: Use SHA256.
	return "3 1 1 " + pk_hash


def build_sshfp_records():
	# The SSHFP record is a way for us to embed this server's SSH public
	# key fingerprint into the DNS so that remote hosts have an out-of-band
	# method to confirm the fingerprint. See RFC 4255 and RFC 6594. This
	# depends on DNSSEC.
	#
	# On the client side, set SSH's VerifyHostKeyDNS option to 'ask' to
	# include this info in the key verification prompt or 'yes' to trust
	# the SSHFP record.
	#
	# See https://github.com/xelerance/sshfp for inspiriation.

	algorithm_number = {
		"ssh-rsa": 1,
		"ecdsa-sha2-nistp256": 3,
		"ssh-ed25519": 4,
	}

	# Get our local fingerprints by running ssh-keyscan. The output looks
	# like the known_hosts file: hostname, keytype, fingerprint. The order
	# of the output is arbitrary, so sort it to prevent spurious updates
	# to the zone file (that trigger bumping the serial number). However,
	# if SSH has been configured to listen on a nonstandard port, we must
	# specify that port to sshkeyscan.

	port = get_ssh_port()

	# If nothing returned, SSH is probably not installed.
	if not port:
		return

	# DSA removed: OpenSSH dropped DSA support in Ubuntu 26.04+
	# Wrapped in try/except so any ssh-keyscan failure (SSH not listening,
	# unsupported key type, etc.) skips SSHFP records rather than crashing
	# the entire DNS update.
	try:
		keys = shell("check_output", ["ssh-keyscan", "-4", "-t", "rsa,ecdsa,ed25519", "-p", str(port), "localhost"], suppress_stderr=True)
	except subprocess.CalledProcessError:
		return
	keys = sorted(keys.split("\n"))

	for key in keys:
		if key.strip() == "" or key[0] == "#":
			continue
		try:
			_host, keytype, pubkey = key.split(" ")
			yield "%d %d ( %s )" % (
				algorithm_number[keytype],
				2,  # specifies we are using SHA-256 on next line
				hashlib.sha256(base64.b64decode(pubkey)).hexdigest().upper(),
			)
		except Exception:
			# Lots of things can go wrong. Don't let it disturb the DNS
			# zone.
			pass
