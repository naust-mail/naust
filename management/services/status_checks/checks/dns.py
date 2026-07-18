import os

from ..registry import check
from ..reporter import CheckFailed
from .. import utils
from itertools import starmap
import pathlib


def _get_dns_zonefiles(env):
	from services.dns_update import get_dns_zones

	return dict(get_dns_zones(env))


def _check_dnssec(env, report, domain, dns_zonefiles, is_checking_primary=False):
	"""Shared by the primary-hostname check and the per-zone check: does this
	domain have a valid DNSSEC DS record at the registrar matching one of the
	keys we signed the zone with? Ported as-is from the original implementation -
	this is security-sensitive path/file validation, kept byte-for-byte faithful."""
	alg_name_map = {'7': 'RSASHA1-NSEC3-SHA1', '8': 'RSASHA256', '13': 'ECDSAP256SHA256'}
	digalg_name_map = {'1': 'SHA-1', '2': 'SHA-256', '4': 'SHA-384'}

	expected_ds_records = {}

	zonefile_name = dns_zonefiles.get(domain, '')
	if not zonefile_name or '..' in zonefile_name or '/' in zonefile_name:
		return  # invalid zonefile name, abort silently like the original

	ds_file = '/etc/nsd/zones/' + zonefile_name + '.ds'

	try:
		real_path = os.path.realpath(ds_file)
		if not real_path.startswith('/etc/nsd/zones/'):
			return  # path traversal attempt detected
	except (OSError, ValueError):
		return

	if not os.path.exists(ds_file):
		return  # DNS has not yet been updated for this domain

	try:
		ds_content = pathlib.Path(ds_file).read_text(encoding="utf-8")
		if len(ds_content) > 1048576:  # 1MB limit
			return

		for rr_ds in ds_content.splitlines():
			if not rr_ds.strip():
				continue
			rr_ds = rr_ds.rstrip()
			ds_keytag, ds_alg, ds_digalg, ds_digest = rr_ds.split("\t")[4].split(" ")

			if ds_alg not in alg_name_map or ds_digalg not in digalg_name_map:
				continue

			dnssec_keys = utils.load_env_vars_from_file(os.path.join(env['STORAGE_ROOT'], f'dns/dnssec/{alg_name_map[ds_alg]}.conf'))

			ksk_name = dnssec_keys.get('KSK', '')
			if not ksk_name or '..' in ksk_name or '/' in ksk_name:
				continue

			key_file = os.path.join(env['STORAGE_ROOT'], 'dns/dnssec/' + ksk_name + '.key')

			real_key_path = os.path.realpath(key_file)
			expected_prefix = os.path.realpath(os.path.join(env['STORAGE_ROOT'], 'dns/dnssec/'))
			if not real_key_path.startswith(expected_prefix):
				continue

			with open(key_file, encoding="utf-8") as kf:
				key_content = kf.read()
				if len(key_content) > 10240:  # 10KB limit
					continue
				dnsssec_pubkey = key_content.split("\t")[3].split(" ")[3]

			expected_ds_records[ds_keytag, ds_alg, ds_digalg, ds_digest] = {
				"record": rr_ds,
				"keytag": ds_keytag,
				"alg": ds_alg,
				"alg_name": alg_name_map[ds_alg],
				"digalg": ds_digalg,
				"digalg_name": digalg_name_map[ds_digalg],
				"digest": ds_digest,
				"pubkey": dnsssec_pubkey,
			}
	except (OSError, IndexError, KeyError, ValueError):
		return  # malformed data - fail safely, same as original

	ds = utils.query_dns(domain, "DS", nxdomain=None, as_list=True)
	if ds is None or isinstance(ds, str):
		ds = []
	ds = [tuple(str(rr).split(" ")) for rr in ds if len(str(rr).split(" ")) == 4]

	suggestion_text = _format_ds_suggestions(expected_ds_records, ds)

	if len(ds) == 0:
		report.warn("This domain's DNSSEC DS record is not set. The DS record is optional. " + suggestion_text)
		return

	matched_ds = set(ds) & set(expected_ds_records)
	if matched_ds:
		if {r[1] for r in matched_ds} == {'13'} and {r[2] for r in matched_ds} <= {'2', '4'}:
			return  # all alg 13, digest 2/4 - fully correct, nothing to report
		if any(r[1] == '13' and r[2] in {'2', '4'} for r in matched_ds):
			return  # some are alg 13 - correct enough
		report.warn("DNSSEC 'DS' record set at registrar is valid but should be updated to ECDSAP256SHA256 and SHA-256. IMPORTANT: Do not delete existing DNSSEC 'DS' records until the new one is confirmed valid. " + suggestion_text)
		return

	if is_checking_primary:
		raise CheckFailed(f"The DNSSEC 'DS' record for {domain} is incorrect. {suggestion_text}")
	raise CheckFailed("This domain's DNSSEC DS record is incorrect. The chain of trust is broken between the public DNS system and this machine's DNS server. " + suggestion_text)


def _format_ds_suggestions(expected_ds_records, current_ds):
	preferred_ds_order = [(7, 2), (8, 4), (13, 4), (8, 2), (13, 2)]  # low to high, see upstream issue #1998

	def order_key(s):
		k = (int(s['alg']), int(s['digalg']))
		return preferred_ds_order.index(k) if k in preferred_ds_order else -1

	lines = ["Follow the instructions provided by your domain name registrar to set a DS record. Use the first option that works:"]
	for i, s in enumerate(sorted(expected_ds_records.values(), key=order_key, reverse=True)):
		if order_key(s) == -1:
			continue
		lines.append(f"Option {i + 1}: Key Tag {s['keytag']}, Flags KSK/257, Algorithm {s['alg']}/{s['alg_name']}, Digest Type {s['digalg']}/{s['digalg_name']}, Digest {s['digest']}")
	if current_ds:
		lines.append("Currently set to: " + "; ".join(starmap("Key Tag {}, Algorithm {}, Digest Type {}, Digest {}".format, sorted(current_ds))))
	return " ".join(lines)


@check("primary-hostname-dns", category="dns", depends_on=["unbound"])
def check_primary_hostname_dns(env, report):
	from services.dns_update import build_tlsa_record
	import dns.reversename as _rn

	domain = env["PRIMARY_HOSTNAME"]
	dns_zonefiles = _get_dns_zonefiles(env)
	dns_domains = set(dns_zonefiles)

	has_dnssec = False
	with report.step("DNSSEC is correctly configured (if enabled)"):
		for zone in dns_domains:
			if (zone == domain or domain.endswith("." + zone)) and utils.query_dns(zone, "DS", nxdomain=None) is not None:
				has_dnssec = True
				_check_dnssec(env, report, zone, dns_zonefiles, is_checking_primary=True)

	ip = utils.query_dns(domain, "A")

	if env.get("DNS_MODE", "self") == "self":
		with report.step("Nameserver glue records are correct at registrar"):
			ns_ips = utils.query_dns("ns1." + domain, "A") + '/' + utils.query_dns("ns2." + domain, "A")
			if ns_ips != env['PUBLIC_IP'] + '/' + env['PUBLIC_IP']:
				if ip == env['PUBLIC_IP']:
					report.warn(f"Nameserver glue records (ns1/ns2.{domain}) should report this box's IP ({env['PUBLIC_IP']}). They currently report {ns_ips}. If you have set up External DNS, this may be OK.")
				else:
					raise CheckFailed(f"Nameserver glue records are incorrect. ns1/ns2.{domain} must be configured at your registrar with IP {env['PUBLIC_IP']}. They currently report {ns_ips}.")

	with report.step("Domain resolves to this box's IP address"):
		ipv6 = utils.query_dns(domain, "AAAA") if env.get("PUBLIC_IPV6") else None
		my_ips = env['PUBLIC_IP'] + ((" / " + env['PUBLIC_IPV6']) if env.get("PUBLIC_IPV6") else "")
		if not (ip == env['PUBLIC_IP'] and not (ipv6 and env['PUBLIC_IPV6'] and ipv6 != utils.normalize_ip(env['PUBLIC_IPV6']))):
			raise CheckFailed(f"This domain must resolve to this box's IP address ({my_ips}) but currently resolves to {ip + ((' / ' + ipv6) if ipv6 is not None else '')}.")

	with report.step("Reverse DNS is set correctly at ISP"):
		existing_rdns_v4 = utils.query_dns(_rn.from_address(env['PUBLIC_IP']), "PTR")
		existing_rdns_v6 = utils.query_dns(_rn.from_address(env['PUBLIC_IPV6']), "PTR") if env.get("PUBLIC_IPV6") else None
		if not (existing_rdns_v4 == domain and existing_rdns_v6 in {None, domain}):
			raise CheckFailed(f"This box's reverse DNS is currently {existing_rdns_v4}" + (f" (IPv4) and {existing_rdns_v6} (IPv6)" if existing_rdns_v6 not in {None, existing_rdns_v4} else "") + f", but it should be {domain}. Your ISP or cloud provider has instructions for setting up reverse DNS.")

	with report.step("DANE TLSA record for incoming mail is correct"):
		tlsa_qname = "_25._tcp." + domain
		tlsa25 = utils.query_dns(tlsa_qname, "TLSA", nxdomain=None)
		tlsa25_expected = build_tlsa_record(env)
		if tlsa25 != tlsa25_expected:
			if tlsa25 is None:
				if has_dnssec:
					report.warn("The DANE TLSA record for incoming mail is not set. This is optional.")
			else:
				raise CheckFailed(f"The DANE TLSA record for incoming mail ({tlsa_qname}) is '{tlsa25}' but should be '{tlsa25_expected}'.")

	with report.step("Hostmaster contact address exists"):
		ok, msg = utils.alias_exists_message("Hostmaster contact address", "hostmaster@" + domain, env)
		if not ok:
			raise CheckFailed(msg)


@check("dns-zone", category="dns", per_domain=lambda env: _get_dns_zonefiles(env).keys(), depends_on=["unbound"])
def check_dns_zone(env, domain, report):
	from services.dns_update import get_custom_dns_config, get_secondary_dns, get_custom_dns_records
	from services.web_update import get_domains_with_a_records

	dns_zonefiles = _get_dns_zonefiles(env)

	has_ds = utils.query_dns(domain, "DS", nxdomain=None) is not None
	if has_ds:
		# If a DS record is set at the registrar, check DNSSEC first since it affects the NS query.
		with report.step("DNSSEC is correctly configured"):
			_check_dnssec(env, report, domain, dns_zonefiles)

	custom_dns_records = list(get_custom_dns_config(env))
	correct_ip = "; ".join(sorted(get_custom_dns_records(custom_dns_records, domain, "A"))) or env['PUBLIC_IP']
	custom_secondary_ns = get_secondary_dns(custom_dns_records, mode="NS")
	secondary_ns = custom_secondary_ns or ["ns2." + env['PRIMARY_HOSTNAME']]

	probably_external_dns = env.get("DNS_MODE", "self") == "external"

	with report.step("Nameservers are set correctly at registrar"):
		if probably_external_dns:
			pass  # external DNS mode: nameserver delegation isn't ours to check
		else:
			ip = utils.query_dns(domain, "A")
			existing_ns = utils.query_dns(domain, "NS")
			correct_ns = "; ".join(sorted(["ns1." + env["PRIMARY_HOSTNAME"], *secondary_ns]))

			if existing_ns.lower() != correct_ns.lower():
				if ip == correct_ip:
					report.warn(f"The nameservers set on this domain at your registrar should be {correct_ns}. They are currently {existing_ns}. If you are using External DNS, this may be OK.")
					probably_external_dns = True
				else:
					raise CheckFailed(f"The nameservers set on this domain are incorrect. They are currently {existing_ns}. Set them to {correct_ns} at your registrar.")

	if custom_secondary_ns and not probably_external_dns:
		with report.step("Secondary nameservers are configured correctly"):
			SOARecord = utils.query_dns(domain, "SOA", at=env['PUBLIC_IP'])
			problems = []
			for ns in custom_secondary_ns:
				ns_ips = utils.query_dns(ns, "A")
				if not ns_ips or ns_ips in {'[Not Set]', '[timeout]'}:
					problems.append(f"Secondary nameserver {ns} is not valid (it doesn't resolve to an IP address).")
					continue
				ns_ip = ns_ips.split('; ')[0]
				checkSOA = SOARecord != '[timeout]'

				ip = utils.query_dns(domain, "A", at=ns_ip, nxdomain=None)
				if ip is None:
					problems.append(f"Secondary nameserver {ns} is not configured to resolve this domain.")
					checkSOA = False
				elif ip == '[timeout]':
					problems.append(f"Secondary nameserver {ns} did not resolve this domain (timeout).")
					checkSOA = False
				elif ip != correct_ip:
					problems.append(f"Secondary nameserver {ns} resolved this domain as {ip}. It should be {correct_ip}.")

				if checkSOA:
					SOASecondary = utils.query_dns(domain, "SOA", at=ns_ip)
					if SOASecondary == '[Not Set]':
						problems.append(f"Secondary nameserver {ns} has no SOA record configured.")
					elif SOASecondary == '[timeout]':
						report.warn(f"Secondary nameserver {ns} timed out on checking SOA record.")
					elif SOARecord != SOASecondary:
						problems.append(f"Secondary nameserver {ns} has inconsistent SOA record (primary: {SOARecord} vs secondary: {SOASecondary}). Check synchronization.")
			if problems:
				raise CheckFailed("; ".join(problems))

	with report.step("No custom DNS records are silently disabling web hosting"):
		domains_with_a_records = get_domains_with_a_records(env)
		warnings = []
		if domain in domains_with_a_records:
			warnings.append("Web has been disabled for this domain because you have set a custom DNS record.")
		if "www." + domain in domains_with_a_records:
			warnings.append(f"A redirect from 'www.{domain}' has been disabled because you have set a custom DNS record on the www subdomain.")
		if warnings:
			report.warn(" ".join(warnings))

	if not has_ds:
		# DNSSEC is optional - if no DS record is set at the registrar, suggest it last.
		with report.step("DNSSEC suggestion"):
			_check_dnssec(env, report, domain, dns_zonefiles)
