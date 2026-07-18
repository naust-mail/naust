# Acquiring new certificates from Let's Encrypt via certbot.

import functools
import operator
import os
import subprocess
import sys
import tempfile

from core.utils import sort_domains
import pathlib


def get_certificates_to_provision(env, limit_domains=None, show_valid_certs=True):
	# Get a set of domain names that we can provision certificates for
	# using certbot. We start with domains that the box is serving web
	# for and subtract:
	# * domains not in limit_domains if limit_domains is not empty
	# * domains with custom "A" records, i.e. they are hosted elsewhere
	# * domains with actual "A" records that point elsewhere (misconfiguration)
	# * domains that already have certificates that will be valid for a while

	from services.web_update import get_web_domains
	from services.status_checks import query_dns, normalize_ip
	from .selection import get_ssl_certificates, get_domain_ssl_files
	from .validation import check_certificate

	existing_certs = get_ssl_certificates(env)

	plausible_web_domains = get_web_domains(env, exclude_dns_elsewhere=False)
	actual_web_domains = get_web_domains(env)

	domains_to_provision = set()
	domains_cant_provision = {}

	for domain in plausible_web_domains:
		# Skip domains that the user doesn't want to provision now.
		if limit_domains and domain not in limit_domains:
			continue

		# Check that there isn't an explicit A/AAAA record.
		if domain not in actual_web_domains:
			domains_cant_provision[domain] = "The domain has a custom DNS A/AAAA record that points the domain elsewhere, so there is no point to installing a TLS certificate here and we could not automatically provision one anyway because provisioning requires access to the website (which isn't here)."

		# Check that the DNS resolves to here.
		else:
			# Does the domain resolve to this machine in public DNS? If not,
			# we can't do domain control validation. For IPv6 is configured,
			# make sure both IPv4 and IPv6 are correct because we don't know
			# how Let's Encrypt will connect.
			bad_dns = []
			for rtype, value in [("A", env["PUBLIC_IP"]), ("AAAA", env.get("PUBLIC_IPV6"))]:
				if not value:
					continue  # IPv6 is not configured
				response = query_dns(domain, rtype)
				if response != normalize_ip(value):
					bad_dns.append(f"{response} ({rtype})")

			if bad_dns:
				domains_cant_provision[domain] = "The domain name does not resolve to this machine: " + (", ".join(bad_dns)) + "."

			else:
				# DNS is all good.

				# Check for a good existing cert.
				existing_cert = get_domain_ssl_files(domain, existing_certs, env, use_main_cert=False, allow_missing_cert=True)
				if existing_cert:
					existing_cert_check = check_certificate(domain, existing_cert['certificate'], existing_cert['private-key'], warn_if_expiring_soon=14)
					if existing_cert_check[0] == "OK":
						if show_valid_certs:
							domains_cant_provision[domain] = "The domain has a valid certificate already. ({} Certificate: {}, private key {})".format(existing_cert_check[1], existing_cert['certificate'], existing_cert['private-key'])
						continue

				domains_to_provision.add(domain)

	return (domains_to_provision, domains_cant_provision)


def provision_certificates(env, limit_domains):
	from .install import install_cert_copy_file, post_install_func
	from .validation import load_pem, load_cert_chain

	# What domains should we provision certificates for? And what
	# errors prevent provisioning for other domains.
	domains, domains_cant_provision = get_certificates_to_provision(env, limit_domains=limit_domains)

	# Build a list of what happened on each domain or domain-set.
	ret = []
	for domain, error in domains_cant_provision.items():
		ret.append({
			"domains": [domain],
			"log": [error],
			"result": "skipped",
		})

	# Break into groups by DNS zone: Group every domain with its parent domain, if
	# its parent domain is in the list of domains to request a certificate for.
	# Start with the zones so that if the zone doesn't need a certificate itself,
	# its children will still be grouped together. Sort the provision domains to
	# put parents ahead of children.
	# Since Let's Encrypt requests are limited to 100 domains at a time,
	# we'll create a list of lists of domains where the inner lists have
	# at most 100 items. By sorting we also get the DNS zone domain as the first
	# entry in each list (unless we overflow beyond 100) which ends up as the
	# primary domain listed in each certificate.
	from services.dns_update import get_dns_zones

	certs = {}
	for zone, _zonefile in get_dns_zones(env):
		certs[zone] = [[]]
	for domain in sort_domains(domains, env):
		# Does the domain end with any domain we've seen so far.
		for parent in certs:
			if domain.endswith("." + parent):
				# Add this to the parent's list of domains.
				# Start a new group if the list already has
				# 100 items.
				if len(certs[parent][-1]) == 100:
					certs[parent].append([])
				certs[parent][-1].append(domain)
				break
		else:
			# This domain is not a child of any domain we've seen yet, so
			# start a new group. This shouldn't happen since every zone
			# was already added.
			certs[domain] = [[domain]]

	# Flatten to a list of lists of domains (from a mapping). Remove empty
	# lists (zones with no domains that need certs).
	certs = functools.reduce(operator.iadd, certs.values(), [])
	certs = [_ for _ in certs if len(_) > 0]

	# Prepare to provision.

	# Where should we put our Let's Encrypt account info and state cache.
	account_path = os.path.join(env['STORAGE_ROOT'], 'ssl/lets_encrypt')
	if not os.path.exists(account_path):
		os.mkdir(account_path)

	# Provision certificates.
	for domain_list in certs:
		ret.append({
			"domains": domain_list,
			"log": [],
		})
		try:
			# Create a CSR file for our master private key so that certbot
			# uses our private key.
			key_file = os.path.join(env['STORAGE_ROOT'], 'ssl', 'ssl_private_key.pem')
			with tempfile.NamedTemporaryFile() as csr_file:
				# We could use openssl, but certbot requires
				# that the CN domain and SAN domains match
				# the domain list passed to certbot, and adding
				# SAN domains openssl req is ridiculously complicated.
				# subprocess.check_output([
				# 	"openssl", "req", "-new",
				# 	"-key", key_file,
				# 	"-out", csr_file.name,
				# 	"-subj", "/CN=" + domain_list[0],
				# 	"-sha256" ])
				from cryptography import x509
				from cryptography.hazmat.backends import default_backend
				from cryptography.hazmat.primitives.serialization import Encoding
				from cryptography.hazmat.primitives import hashes
				from cryptography.x509.oid import NameOID

				builder = x509.CertificateSigningRequestBuilder()
				builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain_list[0])]))
				builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
				builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(d) for d in domain_list]), critical=False)
				request = builder.sign(load_pem(load_cert_chain(key_file)[0]), hashes.SHA256(), default_backend())
				pathlib.Path(csr_file.name).write_bytes(request.public_bytes(Encoding.PEM))

				# Provision, writing to a temporary file.
				webroot = os.path.join(account_path, 'webroot')
				os.makedirs(webroot, exist_ok=True)
				with tempfile.TemporaryDirectory() as d:
					cert_file = os.path.join(d, 'cert_and_chain.pem')
					print("Provisioning TLS certificates for " + ", ".join(domain_list) + ".")
					certbotret = subprocess.check_output(
						[
							"certbot",
							"certonly",
							# "-v", # just enough to see ACME errors
							"--non-interactive",  # will fail if user hasn't registered during Naust setup
							"-d",
							",".join(domain_list),  # first will be main domain
							"--csr",
							csr_file.name,  # use our private key; unfortunately this doesn't work with auto-renew so we need to save cert manually
							"--cert-path",
							os.path.join(d, 'cert'),  # we only use the full chain
							"--chain-path",
							os.path.join(d, 'chain'),  # we only use the full chain
							"--fullchain-path",
							cert_file,
							"--webroot",
							"--webroot-path",
							webroot,
							"--config-dir",
							account_path,
							# "--staging",
						],
						stderr=subprocess.STDOUT,
					).decode("utf8")
					install_cert_copy_file(cert_file, env)

			ret[-1]["log"].append(certbotret)
			ret[-1]["result"] = "installed"
		except subprocess.CalledProcessError as e:
			ret[-1]["log"].append(e.output.decode("utf8"))
			ret[-1]["result"] = "error"
		except Exception as e:
			ret[-1]["log"].append(str(e))
			ret[-1]["result"] = "error"

	# Run post-install steps.
	ret.extend(post_install_func(env))

	# Return what happened with each certificate request.
	return ret


def provision_certificates_cmdline():
	from core.utils import load_environment, acquire_process_lock

	_ssl_lock = acquire_process_lock("/tmp/naust-ssl.lock")
	env = load_environment()

	quiet = False
	domains = []

	for arg in sys.argv[1:]:
		if arg == "-q":
			quiet = True
		else:
			domains.append(arg)

	# Go.
	status = provision_certificates(env, limit_domains=domains)

	# Show what happened.
	for request in status:
		if isinstance(request, str):
			print(request)
		else:
			if quiet and request['result'] == 'skipped':
				continue
			print(request['result'] + ":", ", ".join(request['domains']) + ":")
			for line in request["log"]:
				print(line)
			print()
