import base64
import hashlib
import os
import re

from core.utils import safe_domain_name, sort_domains


def get_dns_domains(env):
	# Add all domain names in use by email users and mail aliases, any
	# domains we serve web for (except www redirects because that would
	# lead to infinite recursion here) and ensure PRIMARY_HOSTNAME is in the list.
	from mail.mailconfig import get_mail_domains
	from services.web_update import get_web_domains

	domains = set()
	domains |= set(get_mail_domains(env))
	domains |= set(get_web_domains(env, include_www_redirects=False))
	domains.add(env['PRIMARY_HOSTNAME'])
	return domains


def get_dns_zones(env):
	# What domains should we create DNS zones for? Never create a zone for
	# a domain & a subdomain of that domain.
	domains = get_dns_domains(env)

	# Exclude domains that are subdomains of other domains we know. Proceed
	# by looking at shorter domains first.
	zone_domains = set()
	for domain in sorted(domains, key=len):
		for d in zone_domains:
			if domain.endswith("." + d):
				# We found a parent domain already in the list.
				break
		else:
			# 'break' did not occur: there is no parent domain.
			zone_domains.add(domain)

	# Make a nice and safe filename for each domain.
	zonefiles = [[domain, safe_domain_name(domain) + ".txt"] for domain in zone_domains]

	# Sort the list so that the order is nice and so that nsd.conf has a
	# stable order so we don't rewrite the file & restart the service
	# meaninglessly.
	zone_order = sort_domains([zone[0] for zone in zonefiles], env)
	zonefiles.sort(key=lambda zone: zone_order.index(zone[0]))

	return zonefiles


def do_dns_update(env, force=False):
	from services.dns_update.nsd import write_nsd_zone, write_nsd_conf
	from services.dns_update.dnssec import sign_zone
	from services.dns_update.opendkim import write_opendkim_tables
	from services.dns_update.custom_records import get_custom_dns_config

	# Write zone files.
	os.makedirs('/etc/nsd/zones', exist_ok=True)
	zonefiles = []
	updated_domains = []
	for domain, zonefile, records in build_zones(env):
		# The final set of files will be signed.
		zonefiles.append((domain, zonefile + ".signed"))

		# See if the zone has changed, and if so update the serial number
		# and write the zone file.
		if not write_nsd_zone(domain, "/etc/nsd/zones/" + zonefile, records, env, force):
			# Zone was not updated. There were no changes.
			continue

		# Mark that we just updated this domain.
		updated_domains.append(domain)

		# Sign the zone.
		#
		# Every time we sign the zone we get a new result, which means
		# we can't sign a zone without bumping the zone's serial number.
		# Thus we only sign a zone if write_nsd_zone returned True
		# indicating the zone changed, and thus it got a new serial number.
		# write_nsd_zone is smart enough to check if a zone's signature
		# is nearing expiration and if so it'll bump the serial number
		# and return True so we get a chance to re-sign it.
		sign_zone(domain, zonefile, env)

	# Write the main nsd.conf file.
	if write_nsd_conf(zonefiles, list(get_custom_dns_config(env)), env):
		# Make sure updated_domains contains *something* if we wrote an updated
		# nsd.conf so that we know to restart nsd.
		if len(updated_domains) == 0:
			updated_domains.append("DNS configuration")

	from services.control_plane import reload as cp_reload

	if len(updated_domains) > 0:
		cp_reload("nsd")

	# Write the OpenDKIM configuration tables for all of the mail domains.
	from mail.mailconfig import get_mail_domains

	if write_opendkim_tables(get_mail_domains(env), env):
		cp_reload("opendkim")
		if len(updated_domains) == 0:
			updated_domains.append("OpenDKIM configuration")

	# Flush unbound's recursive cache so local DNS resolution reflects the new zones.
	cp_reload("unbound")

	if len(updated_domains) == 0:
		# if nothing was updated (except maybe OpenDKIM's files), don't show any output
		return ""
	return "updated DNS: " + ",".join(updated_domains) + "\n"


def build_zones(env):
	from services.dns_update.custom_records import get_custom_dns_config

	# What domains (and their zone filenames) should we build?
	domains = get_dns_domains(env)
	zonefiles = get_dns_zones(env)

	# Create a dictionary of domains to a set of attributes for each
	# domain, such as whether there are mail users at the domain.
	from mail.mailconfig import get_mail_domains
	from services.web_update import get_web_domains

	mail_domains = set(get_mail_domains(env))
	mail_user_domains = set(get_mail_domains(env, users_only=True))  # i.e. will log in for mail
	web_domains = set(get_web_domains(env))
	auto_domains = web_domains - set(get_web_domains(env, include_auto=False))
	domains |= auto_domains  # www redirects not included in the initial list, see above

	# Add ns1/ns2+PRIMARY_HOSTNAME which must also have A/AAAA records
	# when the box is acting as authoritative DNS server for its domains.
	for ns in ("ns1", "ns2"):
		d = ns + "." + env["PRIMARY_HOSTNAME"]
		domains.add(d)
		auto_domains.add(d)

	domains = {
		domain: {
			"user": domain in mail_user_domains,
			"mail": domain in mail_domains,
			"web": domain in web_domains,
			"auto": domain in auto_domains,
		}
		for domain in domains
	}

	# For MTA-STS, we'll need to check if the PRIMARY_HOSTNAME certificate is
	# singned and valid. Check that now rather than repeatedly for each domain.
	domains[env["PRIMARY_HOSTNAME"]]["certificate-is-valid"] = is_domain_cert_signed_and_valid(env["PRIMARY_HOSTNAME"], env)

	# Load custom records to add to zones.
	additional_records = list(get_custom_dns_config(env))

	# Build DNS records for each zone.
	for domain, zonefile in zonefiles:
		# Build the records to put in the zone.
		records = build_zone(domain, domains, additional_records, env)
		yield (domain, zonefile, records)


def build_zone(domain, domain_properties, additional_records, env, is_zone=True):
	from services.dns_update.records import build_tlsa_record, build_sshfp_records
	from services.dns_update.custom_records import get_secondary_dns, filter_custom_records

	records = []

	# For top-level zones, define the authoritative name servers.
	#
	# Normally we are our own nameservers. Some TLDs require two distinct IP addresses,
	# so we allow the user to override the second nameserver definition so that
	# secondary DNS can be set up elsewhere.
	#
	# 'False' in the tuple indicates these records would not be used if the zone
	# is managed outside of the box.
	if is_zone:
		# Obligatory NS record to ns1.PRIMARY_HOSTNAME.
		records.append((None, "NS", "ns1.{}.".format(env["PRIMARY_HOSTNAME"]), None))

		# NS record to ns2.PRIMARY_HOSTNAME or whatever the user overrides.
		# User may provide one or more additional nameservers
		secondary_ns_list = get_secondary_dns(additional_records, mode="NS") or ["ns2." + env["PRIMARY_HOSTNAME"]]
		records.extend((None, "NS", secondary_ns + '.', None) for secondary_ns in secondary_ns_list)

	# In PRIMARY_HOSTNAME...
	if domain == env["PRIMARY_HOSTNAME"]:
		# Set the A/AAAA records. Do this early for the PRIMARY_HOSTNAME so that the user cannot override them
		# and we can provide different explanatory text.
		records.append((None, "A", env["PUBLIC_IP"], 'required'))
		if env.get("PUBLIC_IPV6"):
			records.append((None, "AAAA", env["PUBLIC_IPV6"], 'required'))

		# Add a DANE TLSA record for SMTP.
		records.append(("_25._tcp", "TLSA", build_tlsa_record(env), 'recommended'))

		# Add a DANE TLSA record for HTTPS, which some browser extensions might make use of.
		records.append(("_443._tcp", "TLSA", build_tlsa_record(env), 'optional'))

		# Add a SSHFP records to help SSH key validation. One per available SSH key on this system.
		records.extend((None, "SSHFP", value, 'optional') for value in build_sshfp_records())

	# Add DNS records for any subdomains of this domain. We should not have a zone for
	# both a domain and one of its subdomains.
	if is_zone:  # don't recurse when we're just loading data for a subdomain
		subdomains = [d for d in domain_properties if d.endswith("." + domain)]
		for subdomain in subdomains:
			subdomain_qname = subdomain[0 : -len("." + domain)]
			subzone = build_zone(subdomain, domain_properties, additional_records, env, is_zone=False)
			for child_qname, child_rtype, child_value, child_category in subzone:
				if child_qname is None:
					child_qname = subdomain_qname
				else:
					child_qname += "." + subdomain_qname
				records.append((child_qname, child_rtype, child_value, child_category))

	has_rec_base = list(records)  # clone current state

	def has_rec(qname, rtype, prefix=None):
		return any(rec[0] == qname and rec[1] == rtype and (prefix is None or rec[2].startswith(prefix)) for rec in has_rec_base)

	# The user may set other records that don't conflict with our settings.
	# Don't put any TXT records above this line, or it'll prevent any custom TXT records.
	for qname, rtype, value in filter_custom_records(domain, additional_records):
		# Don't allow custom records for record types that override anything above.
		# But allow multiple custom records for the same rtype --- see how has_rec_base is used.
		if has_rec(qname, rtype):
			continue

		# The "local" keyword on A/AAAA records are short-hand for our own IP.
		# This also flags for web configuration that the user wants a website here.
		if rtype == "A" and value == "local":
			value = env["PUBLIC_IP"]
		if rtype == "AAAA" and value == "local":
			if "PUBLIC_IPV6" in env:
				value = env["PUBLIC_IPV6"]
			else:
				continue
		records.append((qname, rtype, value, 'optional'))

	# Add A/AAAA defaults if not overridden by the user's custom settings (and not otherwise configured).
	# Any CNAME or A record on the qname overrides A and AAAA. But when we set the default A record,
	# we should not cause the default AAAA record to be skipped because it thinks a custom A record
	# was set. So set has_rec_base to a clone of the current set of DNS settings, and don't update
	# during this process.
	has_rec_base = list(records)
	a_cat: str | None = 'required'
	if domain_properties[domain]["auto"]:
		if domain.startswith(("ns1.", "ns2.")):
			a_cat = None  # omit from external DNS page - only relevant if box is its own DNS server
		if domain.startswith(("www.", "mta-sts.")):
			a_cat = 'optional'
		if domain.startswith(("autoconfig.", "autodiscover.")):
			a_cat = 'recommended'
	defaults = [
		(None, "A", env["PUBLIC_IP"], a_cat),
		(None, "AAAA", env.get('PUBLIC_IPV6'), 'optional'),
	]
	for qname, rtype, value, category in defaults:
		if value is None or value.strip() == "":
			continue  # skip IPV6 if not set
		if not is_zone and qname == "www":
			continue  # don't create any default 'www' subdomains on what are themselves subdomains
		# Set the default record, but not if:
		# (1) there is not a user-set record of the same type already
		# (2) there is not a CNAME record already, since you can't set both and who knows what takes precedence
		# (2) there is not an A record already (if this is an A record this is a dup of (1), and if this is an AAAA record then don't set a default AAAA record if the user sets a custom A record, since the default wouldn't make sense and it should not resolve if the user doesn't provide a new AAAA record)
		if not has_rec(qname, rtype) and not has_rec(qname, "CNAME") and not has_rec(qname, "A"):
			records.append((qname, rtype, value, category))

	# Don't pin the list of records that has_rec checks against anymore.
	has_rec_base = records

	if domain_properties[domain]["mail"]:
		# The MX record says where email for the domain should be delivered: Here!
		if not has_rec(None, "MX", prefix="10 "):
			records.append((None, "MX", "10 {}.".format(env["PRIMARY_HOSTNAME"]), 'required'))

		# SPF record: Permit the box ('mx', see above) to send mail on behalf of
		# the domain. If an outbound relay is configured, also authorize its servers
		# via an include: mechanism. Skip if the user has set a custom SPF record.
		if not has_rec(None, "TXT", prefix="v=spf1 "):
			from core.utils import load_settings

			_relay = load_settings(env).get("smtp_relay", {})
			_spf_include = (_relay.get("spf_include") or "").strip()
			spf_value = f"v=spf1 mx include:{_spf_include} -all" if _spf_include else "v=spf1 mx -all"
			records.append((None, "TXT", spf_value, 'recommended'))

		# Append the DKIM TXT record to the zone as generated by OpenDKIM.
		# Skip if the user has set a DKIM record already.
		opendkim_record_file = os.path.join(env['STORAGE_ROOT'], 'mail/dkim/mail.txt')
		with open(opendkim_record_file, encoding="utf-8") as orf:
			m = re.match(r'(\S+)\s+IN\s+TXT\s+\( ((?:"[^"]+"\s+)+)\)', orf.read(), re.DOTALL)
			val = "".join(re.findall(r'"([^"]+)"', m.group(2)))
			if not has_rec(m.group(1), "TXT", prefix="v=DKIM1; "):
				records.append((m.group(1), "TXT", val, 'recommended'))

		# Append a DMARC record.
		# Skip if the user has set a DMARC record already.
		if not has_rec("_dmarc", "TXT", prefix="v=DMARC1; "):
			records.append(("_dmarc", "TXT", 'v=DMARC1; p=quarantine;', 'recommended'))

	# If this is a domain name that there are email addresses configured for, i.e. "something@"
	# this domain name, then the domain name is a MTA-STS (https://tools.ietf.org/html/rfc8461)
	# Policy Domain.
	#
	# A "_mta-sts" TXT record signals the presence of a MTA-STS policy. The id field helps clients
	# cache the policy. It should be stable so we don't update DNS unnecessarily but change when
	# the policy changes. It must be at most 32 letters and numbers, so we compute a hash of the
	# policy file.
	#
	# The policy itself is served at the "mta-sts" (no underscore) subdomain over HTTPS. Therefore
	# the TLS certificate used by Postfix for STARTTLS must be a valid certificate for the MX
	# domain name (PRIMARY_HOSTNAME) *and* the TLS certificate used by nginx for HTTPS on the mta-sts
	# subdomain must be valid certificate for that domain. Do not set an MTA-STS policy if either
	# certificate in use is not valid (e.g. because it is self-signed and a valid certificate has not
	# yet been provisioned). Since we cannot provision a certificate without A/AAAA records, we
	# always set them (by including them in the www domains) --- only the TXT records depend on there
	# being valid certificates.
	mta_sts_records = []
	if domain_properties[domain]["mail"] and domain_properties[env["PRIMARY_HOSTNAME"]]["certificate-is-valid"] and is_domain_cert_signed_and_valid("mta-sts." + domain, env):
		# Compute an up-to-32-character hash of the policy file. We'll take a SHA-1 hash of the policy
		# file (20 bytes) and encode it as base-64 (28 bytes, using alphanumeric alternate characters
		# instead of '+' and '/' which are not allowed in an MTA-STS policy id) but then just take its
		# first 20 characters, which is more than sufficient to change whenever the policy file changes
		# (and ensures any '=' padding at the end of the base64 encoding is dropped).
		with open("/var/lib/naust/mta-sts.txt", "rb") as f:
			mta_sts_policy_id = base64.b64encode(hashlib.sha1(f.read()).digest(), altchars=b"AA").decode("ascii")[0:20]  # noqa: S324 -- content-addressing id, not security-sensitive
		mta_sts_records.extend([("_mta-sts", "TXT", "v=STSv1; id=" + mta_sts_policy_id, 'optional')])

		# Enable SMTP TLS reporting (https://tools.ietf.org/html/rfc8460) if the user has set a config option.
		# Skip if the rules below if the user has set a custom _smtp._tls record.
		if env.get("MTA_STS_TLSRPT_RUA") and not has_rec("_smtp._tls", "TXT", prefix="v=TLSRPTv1;"):
			mta_sts_records.append(("_smtp._tls", "TXT", "v=TLSRPTv1; rua=" + env["MTA_STS_TLSRPT_RUA"], 'optional'))
	for qname, rtype, value, category in mta_sts_records:
		if not has_rec(qname, rtype):
			records.append((qname, rtype, value, category))

	# Add no-mail-here records for any qname that has an A or AAAA record
	# but no MX record. This would include domain itself if domain is a
	# non-mail domain and also may include qnames from custom DNS records.
	# Do this once at the end of generating a zone.
	if is_zone:
		qnames_with_a = {qname for (qname, rtype, value, _cat) in records if rtype in {"A", "AAAA"}}
		qnames_with_mx = {qname for (qname, rtype, value, _cat) in records if rtype == "MX"}
		for qname in qnames_with_a - qnames_with_mx:
			# Mark this domain as not sending mail with hard-fail SPF and DMARC records.
			if not has_rec(qname, "TXT", prefix="v=spf1 "):
				records.append((qname, "TXT", 'v=spf1 -all', 'hardening'))
			if not has_rec("_dmarc" + ("." + qname if qname else ""), "TXT", prefix="v=DMARC1; "):
				records.append(("_dmarc" + ("." + qname if qname else ""), "TXT", 'v=DMARC1; p=reject;', 'hardening'))
			# Null MX record (https://explained-from-first-principles.com/email/#null-mx-record)
			if not has_rec(qname, "MX"):
				records.append((qname, "MX", '0 .', 'hardening'))

	# Sort the records. The None records *must* go first in the nsd zone file. Otherwise it doesn't matter.
	records.sort(key=lambda rec: list(reversed(rec[0].split(".")) if rec[0] is not None else ""))

	return records


def is_domain_cert_signed_and_valid(domain, env):
	from services.ssl_certificates import get_ssl_certificates, check_certificate

	cert = get_ssl_certificates(env).get(domain)
	if not cert:
		return False  # no certificate provisioned
	cert_status = check_certificate(domain, cert['certificate'], cert['private-key'])
	return cert_status[0] == 'OK'
