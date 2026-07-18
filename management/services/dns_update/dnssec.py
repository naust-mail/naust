import datetime
import hashlib
import os
import shutil
import tempfile

from core.utils import shell, load_env_vars_from_file
import pathlib


def find_dnssec_signing_keys(domain, env):
	# For key that we generated (one per algorithm)...
	d = os.path.join(env['STORAGE_ROOT'], 'dns/dnssec')
	keyconfs = [f for f in os.listdir(d) if f.endswith(".conf")]
	for keyconf in keyconfs:
		# Load the file holding the KSK and ZSK key filenames.
		keyconf_fn = os.path.join(d, keyconf)
		keyinfo = load_env_vars_from_file(keyconf_fn)

		# Skip this key if the conf file has a setting named DOMAINS,
		# holding a comma-separated list of domain names, and if this
		# domain is not in the list. This allows easily disabling a
		# key by setting "DOMAINS=" or "DOMAINS=none", other than
		# deleting the key's .conf file, which might result in the key
		# being regenerated next upgrade. Keys should be disabled if
		# they are not needed to reduce the DNSSEC query response size.
		if "DOMAINS" in keyinfo and domain not in [dd.strip() for dd in keyinfo["DOMAINS"].split(",")]:
			continue

		for keytype in ("KSK", "ZSK"):
			yield keytype, keyinfo[keytype]


def hash_dnssec_keys(domain, env):
	# Create a stable (by sorting the items) hash of all of the private keys
	# that will be used to sign this domain.
	keydata = []
	for keytype, keyfn in sorted(find_dnssec_signing_keys(domain, env)):
		oldkeyfn = os.path.join(env['STORAGE_ROOT'], 'dns/dnssec', keyfn + ".private")
		keydata.extend((keytype, keyfn))
		with open(oldkeyfn, encoding="utf-8") as fr:
			keydata.append(fr.read())
	keydata = "".join(keydata).encode("utf8")
	return hashlib.sha1(keydata).hexdigest()  # noqa: S324 -- change-detection fingerprint, not security-sensitive


def sign_zone(domain, zonefile, env):
	# Sign the zone with all of the keys that were generated during
	# setup so that the user can choose which to use in their DS record at
	# their registrar, and also to support migration to newer algorithms.

	# In order to use the key files generated at setup which are for
	# the domain _domain_, we have to re-write the files and place
	# the actual domain name in it, so that ldns-signzone works.
	#
	# Patch each key, storing the patched version in a private temp directory.
	# Each key has a .key and .private file. Collect a list of filenames
	# for all of the keys (and separately just the key-signing keys).
	#
	# Use mkdtemp (mode 0700) rather than predictable /tmp/<keyfn> paths to
	# prevent a symlink-race attack where a local user pre-creates the path.
	# Use mkdtemp (mode 0700) rather than predictable /tmp/<keyfn> paths to
	# prevent a symlink-race where a local user pre-creates the path as a symlink.
	tmpdir = tempfile.mkdtemp(prefix="naust-dnssec-", dir="/tmp")
	os.chmod(tmpdir, 0o700)
	all_keys = []
	ksk_keys = []
	try:
		for keytype, keyfn in find_dnssec_signing_keys(domain, env):
			newkeyfn = os.path.join(tmpdir, keyfn.replace("_domain_", domain))

			for ext in (".private", ".key"):
				# Copy the .key and .private files to patch them up.
				oldkeyfn = os.path.join(env['STORAGE_ROOT'], 'dns/dnssec', keyfn + ext)
				keydata = pathlib.Path(oldkeyfn).read_text(encoding="utf-8")
				keydata = keydata.replace("_domain_", domain)
				pathlib.Path(newkeyfn + ext).write_text(keydata, encoding="utf-8")

			# Put the patched key filename base (without extension) into the list of keys we'll sign with.
			all_keys.append(newkeyfn)
			if keytype == "KSK":
				ksk_keys.append(newkeyfn)

		# Do the signing.
		expiry_date = (datetime.datetime.now() + datetime.timedelta(days=30)).strftime("%Y%m%d")
		shell(
			'check_call',
			[
				"/usr/bin/ldns-signzone",
				# expire the zone after 30 days
				"-e",
				expiry_date,
				# use NSEC3
				"-n",
				# zonefile to sign
				"/etc/nsd/zones/" + zonefile,
				# keys to sign with (order doesn't matter -- it'll figure it out)
				*all_keys,
			],
		)

		# Create a DS record based on the patched-up key files. The DS record is specific to the
		# zone being signed, so we can't use the .ds files generated when we created the keys.
		# The DS record points to the KSK only. Write this next to the zone file so we can
		# get it later to give to the user with instructions on what to do with it.
		#
		# Generate a DS record for each key. There are also several possible hash algorithms that may
		# be used, so we'll pre-generate all for each key. One DS record per line. Only one
		# needs to actually be deployed at the registrar. We'll select the preferred one
		# in the status checks.
		with open("/etc/nsd/zones/" + zonefile + ".ds", "w", encoding="utf-8") as f:
			for key in ksk_keys:
				for digest_type in ('1', '2', '4'):
					rr_ds = shell(
						'check_output',
						[
							"/usr/bin/ldns-key2ds",
							"-n",  # output to stdout
							"-" + digest_type,  # 1=SHA1, 2=SHA256, 4=SHA384
							key + ".key",
						],
					)
					f.write(rr_ds)

	finally:
		# Remove the private temp directory and all patched key files.
		shutil.rmtree(tmpdir, ignore_errors=True)
