# Creates an nginx configuration file so we serve HTTP/HTTPS on all
# domains for which a mail account has been set up.
########################################################################

import os
import os.path
import re
import rtyaml

from mail.mailconfig import get_mail_domains
from services.dns_update import get_custom_dns_config, get_dns_zones
from services.ssl_certificates import get_ssl_certificates, get_domain_ssl_files, check_certificate
from core.utils import safe_domain_name, sort_domains


def get_web_domains(env, include_www_redirects=True, include_auto=True, exclude_dns_elsewhere=True):
	# What domains should we serve HTTP(S) for?
	domains = set()

	# Serve web for all mail domains so that we might at least
	# provide auto-discover of email settings, and also a static website
	# if the user wants to make one.
	domains |= get_mail_domains(env)

	if include_www_redirects and include_auto:
		# Add 'www.' subdomains that we want to provide default redirects
		# to the main domain for. We'll add 'www.' to any DNS zones, i.e.
		# the topmost of each domain we serve.
		domains |= {'www.' + zone for zone, zonefile in get_dns_zones(env)}

	if include_auto:
		# Add Autoconfiguration domains for domains that there are user accounts at:
		# 'autoconfig.' for Mozilla Thunderbird auto setup.
		# 'autodiscover.' for client autodiscovery.
		domains |= {'autoconfig.' + maildomain for maildomain in get_mail_domains(env, users_only=True)}
		domains |= {'autodiscover.' + maildomain for maildomain in get_mail_domains(env, users_only=True)}

		# 'mta-sts.' for MTA-STS support for all domains that have email addresses.
		domains |= {'mta-sts.' + maildomain for maildomain in get_mail_domains(env)}

	if exclude_dns_elsewhere:
		# ...Unless the domain has an A/AAAA record that maps it to a different
		# IP address than this box. Remove those domains from our list.
		domains -= get_domains_with_a_records(env)

	# Ensure the PRIMARY_HOSTNAME is in the list so we can serve webmail
	# and other services. This can't be removed by a custom A/AAAA record
	# and is never a 'www.' redirect.
	domains.add(env['PRIMARY_HOSTNAME'])

	# Sort the list so the nginx conf gets written in a stable order.
	return sort_domains(domains, env)


def get_domains_with_a_records(env):
	domains = set()
	dns = get_custom_dns_config(env)
	for domain, rtype, value in dns:
		if rtype == "CNAME" or (rtype in {"A", "AAAA"} and value not in {"local", env['PUBLIC_IP'], env['PUBLIC_IPV6']}):
			domains.add(domain)
	return domains


def get_web_domains_with_root_overrides(env):
	# Load custom settings so we can tell what domains have a redirect or proxy set up on '/',
	# which means static hosting is not happening.
	root_overrides = {}
	nginx_conf_custom_fn = os.path.join(env["STORAGE_ROOT"], "www/custom.yaml")
	if os.path.exists(nginx_conf_custom_fn):
		with open(nginx_conf_custom_fn, encoding='utf-8') as f:
			custom_settings = rtyaml.load(f)
		for domain, settings in custom_settings.items():
			for type, value in [('redirect', settings.get('redirects', {}).get('/')), ('proxy', settings.get('proxies', {}).get('/'))]:
				if value:
					root_overrides[domain] = (type, value)
	return root_overrides


def get_php_fpm_socket():
	# Debian/Ubuntu's php-fpm
	# packages always name their default pool socket
	# /run/php/php{MAJOR}.{MINOR}-fpm.sock, so glob for whatever version is
	# actually installed instead of hardcoding one that breaks the moment
	# Ubuntu's default PHP version changes.
	import glob

	matches = sorted(glob.glob("/run/php/php*-fpm.sock"))
	return matches[0] if matches else "/run/php/php8.3-fpm.sock"


def do_web_update(env):
	# Backend hostnames: 127.0.0.1 on bare metal; container service names in Docker.
	# Set MANAGEMENT_HOST etc. in the environment to override (docker-compose does this).
	env.setdefault('MANAGEMENT_HOST', os.environ.get('MANAGEMENT_HOST', '127.0.0.1'))
	env.setdefault('RADICALE_HOST', os.environ.get('RADICALE_HOST', '127.0.0.1'))
	env.setdefault('WEBMAIL_HOST', os.environ.get('WEBMAIL_HOST', '127.0.0.1'))
	env.setdefault('FILEBROWSER_HOST', os.environ.get('FILEBROWSER_HOST', '127.0.0.1'))
	env.setdefault('BESZEL_HUB_HOST', os.environ.get('BESZEL_HUB_HOST', '127.0.0.1'))

	# Pre-load what SSL certificates we will use for each domain.
	ssl_certificates = get_ssl_certificates(env)

	# Helper for reading config files and templates
	_NGINX_TEMPLATES = "/usr/local/share/naust/nginx-templates"
	_NGINX_TEMPLATES_FALLBACK = os.path.join(os.path.dirname(__file__), "../../setup/conf/nginx")

	def read_conf(conf_fn):
		base = _NGINX_TEMPLATES if os.path.isdir(_NGINX_TEMPLATES) else _NGINX_TEMPLATES_FALLBACK
		with open(os.path.join(base, conf_fn), encoding='utf-8') as f:
			return f.read()

	# Build an nginx configuration file.
	nginx_conf = read_conf("nginx-top.conf")

	# Load the templates.
	template0 = read_conf("nginx.conf")
	template1 = read_conf("nginx-alldomains.conf")
	template2 = read_conf("nginx-primaryonly.conf")
	template3 = "\trewrite ^(.*) https://$REDIRECT_DOMAIN$1 permanent;\n"

	# Add the PRIMARY_HOST configuration first so it becomes nginx's default server.
	#
	# Template assembly uses a # ADDITIONAL DIRECTIVES HERE chain: each template
	# consumes the placeholder left by the previous one and may pass it on.
	# The three base templates (nginx.conf -> alldomains -> primaryonly) form the
	# wrapping chain. Everything else - radicale, filebrowser, webmail - are
	# sibling location blocks injected at primaryonly's slot. They are
	# concatenated into one string so no intermediate template needs to carry the
	# passthrough comment; only the final webmail template needs it (for
	# nginx_conf_extra that make_domain_config appends after).
	primary_templates = [template0, template1, template2]

	extras = [read_conf("nginx-internal-auth.conf")]
	if env.get('ENABLE_RADICALE', 'true') == 'true':
		extras.append(read_conf("nginx-radicale.conf"))
	if env.get('ENABLE_FILEBROWSER', 'true') == 'true':
		extras.append(read_conf("nginx-filebrowser.conf"))
	monitoring = env.get('MONITORING_TOOL', 'none')
	if monitoring == 'netdata':
		extras.append(read_conf("nginx-netdata.conf"))
	elif monitoring == 'beszel':
		user_file = os.path.join(env['STORAGE_ROOT'], 'beszel', 'beszel-user')
		beszel_user = open(user_file).read().strip() if os.path.isfile(user_file) else ''
		extras.append(read_conf("nginx-beszel.conf").replace('${BESZEL_USER}', beszel_user))

	# The webmail catch-all (location /) depends on which client is selected.
	# 'none' means no catch-all: the primary domain falls back to the same
	# static-file serving every other domain gets from nginx-alldomains.conf.
	webmail_client = env.get('WEBMAIL_CLIENT', 'rav')
	if webmail_client == 'rav':
		extras.append(read_conf("nginx-webmail-rav.conf"))
	elif webmail_client == 'roundcube':
		extras.append(read_conf("nginx-webmail-roundcube.conf"))
	elif webmail_client == 'snappymail':
		extras.append(read_conf("nginx-webmail-snappymail.conf"))
	elif webmail_client == 'cypht':
		extras.append(read_conf("nginx-webmail-cypht.conf"))

	if extras:
		primary_templates.append("\n".join(extras))

	nginx_conf += make_domain_config(env['PRIMARY_HOSTNAME'], primary_templates, ssl_certificates, env)

	# Add configuration all other web domains.
	has_root_proxy_or_redirect = get_web_domains_with_root_overrides(env)
	web_domains_not_redirect = get_web_domains(env, include_www_redirects=False)
	for domain in get_web_domains(env):
		if domain == env['PRIMARY_HOSTNAME']:
			# PRIMARY_HOSTNAME is handled above.
			continue
		if domain in web_domains_not_redirect:
			# This is a regular domain.
			if domain not in has_root_proxy_or_redirect:
				nginx_conf += make_domain_config(domain, [template0, template1], ssl_certificates, env)
			else:
				nginx_conf += make_domain_config(domain, [template0], ssl_certificates, env)
		else:
			# Add default 'www.' redirect.
			nginx_conf += make_domain_config(domain, [template0, template3], ssl_certificates, env)

	# Did the file change? If not, don't bother writing & restarting nginx.
	nginx_conf_fn = "/etc/nginx/conf.d/local.conf"
	if os.path.exists(nginx_conf_fn):
		with open(nginx_conf_fn, encoding='utf-8') as f:
			if f.read() == nginx_conf:
				return ""

	# Save the file.
	from services.control_plane import config_write

	config_write("nginx_local", nginx_conf)

	# Kick nginx. Reload (not restart) to avoid dropping open connections.
	# On first boot nginx may not be up yet (socket missing or not listening);
	# swallow OSError - nginx will read the config when it starts.
	from services.control_plane import reload as cp_reload

	try:
		cp_reload("nginx")
	except OSError:
		pass

	return "web updated\n"


def make_domain_config(domain, templates, ssl_certificates, env):
	# GET SOME VARIABLES

	# Where will its root directory be for static files?
	root = get_web_root(domain, env)

	# What private key and SSL certificate will we use for this domain?
	tls_cert = get_domain_ssl_files(domain, ssl_certificates, env)

	# ADDITIONAL DIRECTIVES.

	nginx_conf_extra = ""

	# Because the certificate may change, we should recognize this so we
	# can trigger an nginx update.
	def hashfile(filepath):
		import hashlib

		sha1 = hashlib.sha1()  # noqa: S324 -- change-detection fingerprint, not security-sensitive
		with open(filepath, 'rb') as f:
			sha1.update(f.read())
		return sha1.hexdigest()

	nginx_conf_extra += "\t# ssl files sha1: {} / {}\n".format(hashfile(tls_cert["private-key"]), hashfile(tls_cert["certificate"]))

	# Add in any user customizations in YAML format.
	hsts = "yes"
	nginx_conf_custom_fn = os.path.join(env["STORAGE_ROOT"], "www/custom.yaml")
	if os.path.exists(nginx_conf_custom_fn):
		with open(nginx_conf_custom_fn, encoding='utf-8') as f:
			yaml = rtyaml.load(f)
		if domain in yaml:
			yaml = yaml[domain]

			# any proxy or redirect here?
			for path, url in yaml.get("proxies", {}).items():
				# Parse some flags in the fragment of the URL.
				pass_http_host_header = False
				proxy_redirect_off = False
				frame_options_header_sameorigin = False
				web_sockets = False
				m = re.search(r"#(.*)$", url)
				if m:
					for flag in m.group(1).split(","):
						if flag == "pass-http-host":
							pass_http_host_header = True
						elif flag == "no-proxy-redirect":
							proxy_redirect_off = True
						elif flag == "frame-options-sameorigin":
							frame_options_header_sameorigin = True
						elif flag == "web-sockets":
							web_sockets = True
					url = re.sub(r"#(.*)$", "", url)

				nginx_conf_extra += f"\tlocation {path} {{"
				nginx_conf_extra += f"\n\t\tproxy_pass {url};"
				if proxy_redirect_off:
					nginx_conf_extra += "\n\t\tproxy_redirect off;"
				if pass_http_host_header:
					nginx_conf_extra += "\n\t\tproxy_set_header Host $http_host;"
				if frame_options_header_sameorigin:
					nginx_conf_extra += "\n\t\tproxy_set_header X-Frame-Options SAMEORIGIN;"
				if web_sockets:
					nginx_conf_extra += "\n\t\tproxy_http_version 1.1;"
					nginx_conf_extra += "\n\t\tproxy_set_header Upgrade $http_upgrade;"
					nginx_conf_extra += "\n\t\tproxy_set_header Connection 'Upgrade';"
				nginx_conf_extra += "\n\t\tproxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"
				nginx_conf_extra += "\n\t\tproxy_set_header X-Forwarded-Host $http_host;"
				nginx_conf_extra += "\n\t\tproxy_set_header X-Forwarded-Proto $scheme;"
				nginx_conf_extra += "\n\t\tproxy_set_header X-Real-IP $remote_addr;"
				nginx_conf_extra += "\n\t}\n"
			for path, alias in yaml.get("aliases", {}).items():
				nginx_conf_extra += f"\tlocation {path} {{"
				nginx_conf_extra += f"\n\t\talias {alias};"
				nginx_conf_extra += "\n\t}\n"
			for path, url in yaml.get("redirects", {}).items():
				nginx_conf_extra += f"\trewrite {path} {url} permanent;\n"

			# override the HSTS directive type
			hsts = yaml.get("hsts", hsts)

	# Add the HSTS header.
	if hsts == "yes":
		nginx_conf_extra += '\tadd_header Strict-Transport-Security "max-age=15768000" always;\n'
	elif hsts == "preload":
		nginx_conf_extra += '\tadd_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload" always;\n'

	# Add in any user customizations in the includes/ folder.
	nginx_conf_custom_include = os.path.join(env["STORAGE_ROOT"], "www", safe_domain_name(domain) + ".conf")
	if os.path.exists(nginx_conf_custom_include):
		nginx_conf_extra += f"\tinclude {nginx_conf_custom_include};\n"
	# PUT IT ALL TOGETHER

	# Combine the pieces. Iteratively place each template into the "# ADDITIONAL DIRECTIVES HERE" placeholder
	# of the previous template.
	nginx_conf = "# ADDITIONAL DIRECTIVES HERE\n"
	for t in [*templates, nginx_conf_extra]:
		nginx_conf = re.sub("[ \t]*# ADDITIONAL DIRECTIVES HERE *\n", t, nginx_conf)

	# Replace substitution strings in the template & return.
	nginx_conf = nginx_conf.replace("$STORAGE_ROOT", env['STORAGE_ROOT'])
	nginx_conf = nginx_conf.replace("$HOSTNAME", domain)
	nginx_conf = nginx_conf.replace("$ROOT", root)
	nginx_conf = nginx_conf.replace("$SSL_KEY", tls_cert["private-key"])
	nginx_conf = nginx_conf.replace("$SSL_CERTIFICATE", tls_cert["certificate"])
	nginx_conf = nginx_conf.replace("$MANAGEMENT_HOST", env.get('MANAGEMENT_HOST', '127.0.0.1'))
	nginx_conf = nginx_conf.replace("$RADICALE_HOST", env.get('RADICALE_HOST', '127.0.0.1'))
	nginx_conf = nginx_conf.replace("$WEBMAIL_HOST", env.get('WEBMAIL_HOST', '127.0.0.1'))
	nginx_conf = nginx_conf.replace("$FILEBROWSER_HOST", env.get('FILEBROWSER_HOST', '127.0.0.1'))
	nginx_conf = nginx_conf.replace("$BESZEL_HUB_HOST", env.get('BESZEL_HUB_HOST', '127.0.0.1'))
	nginx_conf = nginx_conf.replace("$PHP_FPM_SOCK", get_php_fpm_socket())
	return nginx_conf.replace("$REDIRECT_DOMAIN", re.sub(r"^www\.", "", domain))  # for default www redirects to parent domain


def get_web_root(domain, env, test_exists=True):
	# Try STORAGE_ROOT/web/domain_name if it exists, but fall back to STORAGE_ROOT/web/default.
	for test_domain in (domain, 'default'):
		root = os.path.join(env["STORAGE_ROOT"], "www", safe_domain_name(test_domain))
		if os.path.exists(root) or not test_exists:
			break
	return root


def get_web_domains_info(env):
	www_redirects = set(get_web_domains(env)) - set(get_web_domains(env, include_www_redirects=False))
	has_root_proxy_or_redirect = set(get_web_domains_with_root_overrides(env))
	ssl_certificates = get_ssl_certificates(env)

	# for the SSL config panel, get cert status
	def check_cert(domain):
		try:
			tls_cert = get_domain_ssl_files(domain, ssl_certificates, env, allow_missing_cert=True)
		except OSError:  # PRIMARY_HOSTNAME cert is missing
			tls_cert = None
		if tls_cert is None:
			return ("danger", "No certificate installed.")
		cert_status, cert_status_details = check_certificate(domain, tls_cert["certificate"], tls_cert["private-key"])
		if cert_status == "OK":
			return ("success", "Signed & valid. " + cert_status_details)
		if cert_status == "SELF-SIGNED":
			return ("warning", "Self-signed. Get a signed certificate to stop warnings.")
		return ("danger", "Certificate has a problem: " + cert_status)

	return [
		{
			"domain": domain,
			"root": get_web_root(domain, env),
			"custom_root": get_web_root(domain, env, test_exists=False),
			"ssl_certificate": check_cert(domain),
			"static_enabled": domain not in (www_redirects | has_root_proxy_or_redirect),
		}
		for domain in get_web_domains(env)
	]
