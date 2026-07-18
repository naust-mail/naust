import os
import pathlib


def write_opendkim_tables(domains, env):
	# Append a record to OpenDKIM's KeyTable and SigningTable for each domain
	# that we send mail from (zones and all subdomains).

	opendkim_key_file = os.path.join(env['STORAGE_ROOT'], 'mail/dkim/mail.private')

	if not os.path.exists(opendkim_key_file):
		return False

	import shutil

	if not shutil.which("opendkim"):
		# Rspamd path: DKIM key exists but OpenDKIM is not installed. DNS records
		# are still generated from mail.txt; no OpenDKIM table files to write.
		return False

	config = {
		# The SigningTable maps email addresses to a key in the KeyTable that
		# specifies signing information for matching email addresses. Here we
		# map each domain to a same-named key.
		#
		# Elsewhere we set the DMARC policy for each domain such that mail claiming
		# to be From: the domain must be signed with a DKIM key on the same domain.
		# So we must have a separate KeyTable entry for each domain.
		"SigningTable": "".join(f"*@{domain} {domain}\n" for domain in domains),
		# The KeyTable specifies the signing domain, the DKIM selector, and the
		# path to the private key to use for signing some mail. Per DMARC, the
		# signing domain must match the sender's From: domain.
		"KeyTable": "".join(f"{domain} {domain}:mail:{opendkim_key_file}\n" for domain in domains),
	}

	did_update = False
	for filename, content in config.items():
		# Don't write the file if it doesn't need an update.
		if os.path.exists("/etc/opendkim/" + filename):
			with open("/etc/opendkim/" + filename, encoding="utf-8") as f:
				if f.read() == content:
					continue

		# The contents needs to change.
		pathlib.Path("/etc/opendkim/" + filename).write_text(content, encoding="utf-8")
		did_update = True

	# Return whether the files changed. If they didn't change, there's
	# no need to kick the opendkim process.
	return did_update
