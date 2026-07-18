import ipaddress
import os
import re

import rtyaml
import dns.resolver
import pathlib

# From https://stackoverflow.com/questions/3026957/how-to-validate-a-domain-name-using-regex-php/16491074#16491074
# This regular expression matches domain names according to RFCs, it also accepts fqdn with an leading dot,
# underscores, as well as asterisks which are allowed in domain names but not hostnames (i.e. allowed in
# DNS but not in URLs), which are common in certain record types like for DKIM.
DOMAIN_RE = r"^(?!\-)(?:[*][.])?(?:[a-zA-Z\d\-_]{0,62}[a-zA-Z\d_]\.){1,126}(?!\d+)[a-zA-Z\d_]{1,63}(\.?)$"


def get_custom_dns_config(env, only_real_records=False):
	try:
		with open(os.path.join(env['STORAGE_ROOT'], 'dns/custom.yaml'), encoding="utf-8") as f:
			custom_dns = rtyaml.load(f)
		if not isinstance(custom_dns, dict):
			raise ValueError  # caught below
	except Exception:
		return []

	for qname, value in custom_dns.items():
		if qname == "_secondary_nameserver" and only_real_records:
			continue  # skip fake record

		# Short form. Mapping a domain name to a string is short-hand
		# for creating A records.
		if isinstance(value, str):
			values = [("A", value)]

		# A mapping creates multiple records.
		elif isinstance(value, dict):
			values = value.items()

		# No other type of data is allowed - skip and log rather than aborting all records.
		else:
			import sys

			print(f"WARNING: custom DNS entry {qname!r} has unexpected type {type(value).__name__!r}, skipping", file=sys.stderr)
			continue

		for rtype, value2 in values:
			if isinstance(value2, str):
				yield (qname, rtype, value2)
			elif isinstance(value2, list):
				for value3 in value2:
					yield (qname, rtype, value3)
			# No other type of data is allowed - skip and log rather than aborting all records.
			else:
				import sys

				print(f"WARNING: custom DNS record {qname!r} {rtype!r} has unexpected value type {type(value2).__name__!r}, skipping", file=sys.stderr)
				continue


def filter_custom_records(domain, custom_dns_iter):
	for qname, rtype, value in custom_dns_iter:
		# We don't count the secondary nameserver config (if present) as a record - that would just be
		# confusing to users. Instead it is accessed/manipulated directly via (get/set)_custom_dns_config.
		if qname == "_secondary_nameserver":
			continue

		# Is this record for the domain or one of its subdomains?
		# If `domain` is None, return records for all domains.
		if domain is not None and qname != domain and not qname.endswith("." + domain):
			continue

		# Turn the fully qualified domain name in the YAML file into
		# our short form (None => domain, or a relative QNAME) if
		# domain is not None.
		if domain is not None:
			qname = None if qname == domain else qname[0 : len(qname) - len("." + domain)]

		yield (qname, rtype, value)


def write_custom_dns_config(config, env):
	# We get a list of (qname, rtype, value) triples. Convert this into a
	# nice dictionary format for storage on disk.
	from collections import OrderedDict

	config = list(config)
	dns_conf = OrderedDict()
	seen_qnames = set()

	# Process the qnames in the order we see them.
	for qname in [rec[0] for rec in config]:
		if qname in seen_qnames:
			continue
		seen_qnames.add(qname)

		records = [(rec[1], rec[2]) for rec in config if rec[0] == qname]
		if len(records) == 1 and records[0][0] == "A":
			dns_conf[qname] = records[0][1]
		else:
			dns_conf[qname] = OrderedDict()
			seen_rtypes = set()

			# Process the rtypes in the order we see them.
			for rtype in [rec[0] for rec in records]:
				if rtype in seen_rtypes:
					continue
				seen_rtypes.add(rtype)

				values = [rec[1] for rec in records if rec[0] == rtype]
				if len(values) == 1:
					values = values[0]
				dns_conf[qname][rtype] = values

	# Write.
	config_yaml = rtyaml.dump(dns_conf)
	pathlib.Path(os.path.join(env['STORAGE_ROOT'], 'dns/custom.yaml')).write_text(config_yaml, encoding="utf-8")


def set_custom_dns_record(qname, rtype, value, action, env):
	from services.dns_update.zones import get_dns_zones

	# validate qname
	matched_zone = None
	for zone, _fn in get_dns_zones(env):
		# It must match a zone apex or be a subdomain of a zone
		# that we are otherwise hosting.
		if qname == zone or qname.endswith("." + zone):
			matched_zone = zone
			break
	else:
		# No match.
		if qname != "_secondary_nameserver":
			msg = "That name is not a domain or subdomain managed by this box."
			raise ValueError(msg)

	# validate rtype
	rtype = rtype.upper()
	if value is not None and qname != "_secondary_nameserver":
		# Skip regex check for zone apexes - they already passed the zone
		# lookup above, and single-label zones (e.g. 'localhost') would
		# fail DOMAIN_RE even though they're valid.
		if qname != matched_zone and not re.search(DOMAIN_RE, qname):
			raise ValueError("The name is not valid. Use letters, numbers, hyphens, and dots only (e.g. sub.example.com).")

		if rtype in {"A", "AAAA"}:
			if value != "local":  # "local" is a special flag for us
				v = ipaddress.ip_address(value)  # raises a ValueError if there's a problem
				if rtype == "A" and not isinstance(v, ipaddress.IPv4Address):
					raise ValueError("That's an IPv6 address.")
				if rtype == "AAAA" and not isinstance(v, ipaddress.IPv6Address):
					raise ValueError("That's an IPv4 address.")
		elif rtype in {"CNAME", "NS"}:
			if rtype == "NS" and qname == zone:
				msg = "NS records can only be set for subdomains."
				raise ValueError(msg)

			# ensure value has a trailing dot
			if not value.endswith("."):
				value += "."

			if not re.search(DOMAIN_RE, value):
				msg = "Invalid value."
				raise ValueError(msg)
		elif rtype in {"TXT", "SRV", "MX", "SSHFP", "CAA"}:
			if '\n' in value or '\r' in value:
				raise ValueError("Record value may not contain newlines.")
		elif rtype == "CNAME":
			pass
		else:
			msg = "Unknown record type."
			raise ValueError(msg)

	# load existing config
	config = list(get_custom_dns_config(env))

	# update
	newconfig = []
	made_change = False
	needs_add = True
	for _qname, _rtype, _value in config:
		if action == "add":
			if (_qname, _rtype, _value) == (qname, rtype, value):
				# Record already exists. Bail.
				return False
		elif action == "set":
			if (_qname, _rtype) == (qname, rtype):
				if _value == value:
					# Flag that the record already exists, don't
					# need to add it.
					needs_add = False
				else:
					# Drop any other values for this (qname, rtype).
					made_change = True
					continue
		elif action == "remove":
			if (_qname, _rtype, _value) == (qname, rtype, value):
				# Drop this record.
				made_change = True
				continue
			if value is None and (_qname, _rtype) == (qname, rtype):
				# Drop all qname-rtype records.
				made_change = True
				continue
		else:
			raise ValueError("Invalid action: " + action)

		# Preserve this record.
		newconfig.append((_qname, _rtype, _value))

	if action in {"add", "set"} and needs_add and value is not None:
		newconfig.append((qname, rtype, value))
		made_change = True

	if made_change:
		# serialize & save
		write_custom_dns_config(newconfig, env)
	return made_change


def get_secondary_dns(custom_dns, mode=None):
	resolver = dns.resolver.get_default_resolver()
	resolver.timeout = 10
	resolver.lifetime = 10

	values = []
	for qname, _rtype, value in custom_dns:
		if qname != '_secondary_nameserver':
			continue
		for hostname in value.split(" "):
			hostname = hostname.strip()
			if mode is None:
				# Just return the setting.
				values.append(hostname)
				continue

			# If the entry starts with "xfr:" only include it in the zone transfer settings.
			if hostname.startswith("xfr:"):
				if mode != "xfr":
					continue
				hostname = hostname[4:]

			# If is a hostname, before including in zone xfr lines,
			# resolve to an IP address.
			# It may not resolve to IPv6, so don't throw an exception if it
			# doesn't. Skip the entry if there is a DNS error.
			if mode == "xfr":
				try:
					ipaddress.ip_interface(hostname)  # test if it's an IP address or CIDR notation
					values.append(hostname)
				except ValueError:
					try:
						response = dns.resolver.resolve(hostname + '.', "A", raise_on_no_answer=False)
						values.extend(map(str, response))
					except dns.exception.DNSException:
						pass
					try:
						response = dns.resolver.resolve(hostname + '.', "AAAA", raise_on_no_answer=False)
						values.extend(map(str, response))
					except dns.exception.DNSException:
						pass

			else:
				values.append(hostname)

	return values


def set_secondary_dns(hostnames, env):
	from services.dns_update.zones import do_dns_update

	if len(hostnames) > 0:
		# Validate that all hostnames are valid and that all zone-xfer IP addresses are valid.
		resolver = dns.resolver.get_default_resolver()
		resolver.timeout = 5
		resolver.lifetime = 5

		for item in hostnames:
			if not item.startswith("xfr:"):
				# Resolve hostname.
				try:
					resolver.resolve(item, "A")
				except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
					try:
						resolver.resolve(item, "AAAA")
					except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
						msg = "Could not resolve the IP address of the nameserver."
						raise ValueError(msg)
			else:
				# Validate IP address.
				try:
					if "/" in item[4:]:
						ipaddress.ip_network(item[4:])  # raises a ValueError if there's a problem
					else:
						ipaddress.ip_address(item[4:])  # raises a ValueError if there's a problem
				except ValueError:
					raise ValueError("The value is not a valid IPv4 or IPv6 address or subnet.")

		# Set.
		set_custom_dns_record("_secondary_nameserver", "A", " ".join(hostnames), "set", env)
	else:
		# Clear.
		set_custom_dns_record("_secondary_nameserver", "A", None, "set", env)

	# Apply.
	return do_dns_update(env)


def get_custom_dns_records(custom_dns, qname, rtype):
	for qname1, rtype1, value in custom_dns:
		if qname1 == qname and rtype1 == rtype:
			yield value
