package web

import (
	"fmt"
	"strings"
)

// Per-app location blocks, keyed by registry service name. These are
// the nginx-specific shapes of each app: proxy vs PHP-FPM vs
// admin-session-gated. Placeable apps take their path from the mount;
// fixed apps (admin, radicale, monitoring) receive their registry
// DefaultMount from the applier and render it the same way.

func appBlock(b *strings.Builder, cfg Config, m Mount) error {
	switch m.App {
	case "admin":
		adminBlock(b, m)
	case "webmail-rav":
		ravBlock(b, m)
	case "webmail-roundcube", "webmail-snappymail", "webmail-cypht":
		if m.Path != "/" {
			return fmt.Errorf("%s only mounts at /", m.App)
		}
		if cfg.PHPSocket == "" {
			return fmt.Errorf("%s needs Config.PHPSocket", m.App)
		}
		switch m.App {
		case "webmail-roundcube":
			roundcubeBlock(b, cfg)
		case "webmail-snappymail":
			snappymailBlock(b, cfg)
		case "webmail-cypht":
			cyphtBlock(b, cfg)
		}
	case "filebrowser":
		filebrowserBlock(b, m)
	case "radicale":
		radicaleBlock(b, m)
	case "netdata":
		netdataBlock(b, m)
	case "beszel":
		beszelBlock(b, m)
	case "munin":
		muninBlock(b, m)
	default:
		return fmt.Errorf("no location block for app %q", m.App)
	}
	return nil
}

// backendVar names the per-app nginx variable used to defer backend
// hostname resolution to request time, so nginx starts (and nginx -t
// passes) even when the app's container or service is down.
func backendVar(app string) string {
	return "$" + strings.ReplaceAll(app, "-", "_") + "_backend"
}

// openPrefix starts a prefix location at path: a plain catch-all for
// "/", otherwise a bare-path 301 to path/ followed by the prefix
// location itself.
func openPrefix(b *strings.Builder, path string) {
	if path == "/" {
		b.WriteString("\tlocation / {\n")
		return
	}
	fmt.Fprintf(b, "\tlocation = %s {\n\t\treturn 301 %s/;\n\t}\n", path, path)
	fmt.Fprintf(b, "\tlocation %s/ {\n", path)
}

func adminBlock(b *strings.Builder, m Mount) {
	fmt.Fprintf(b, `	# Autodiscover - Outlook POSTs to this endpoint; proxied because
	# nginx will not serve a static file for POST. Both casings,
	# clients vary.
	location ~* ^/(autodiscover|Autodiscover)/(autodiscover|Autodiscover)\.xml$ {
		proxy_pass http://%[1]s:%[2]d;
		proxy_set_header X-Forwarded-For $remote_addr;
	}

	# Control panel SPA - static files installed by setup; the daemon
	# is only in the path for /api, so a down daemon still serves the
	# panel shell, which reports connection errors itself.
	rewrite ^%[3]s$ %[3]s/;
	location %[3]s/ {
		root /usr/local/share/naust/frontend/dist;
		try_files $uri $uri/ %[3]s/index.html;
		add_header Strict-Transport-Security "max-age=15768000" always;
		add_header X-Frame-Options "DENY" always;
		add_header X-Content-Type-Options nosniff always;
		add_header Content-Security-Policy "frame-ancestors 'none';" always;
	}

	# Rate-limited ahead of the general API block below (nginx matches the
	# longest prefix, so this takes precedence for this one path only) -
	# login spends a deliberate, real bcrypt cost per call; see the login
	# zone in nginx-top.conf for the full reasoning and the burst tradeoff.
	location %[3]s/api/auth/login {
		limit_req zone=login burst=20 nodelay;
		proxy_pass http://%[1]s:%[2]d/api/auth/login;
		proxy_set_header X-Forwarded-For $remote_addr;
		add_header Strict-Transport-Security "max-age=15768000" always;
		add_header X-Content-Type-Options nosniff always;
	}

	# Management API. Mounted under the panel path - root /api belongs
	# to whatever app is mounted at / (rav's own API lives there).
	location %[3]s/api/ {
		proxy_pass http://%[1]s:%[2]d/api/;
		proxy_set_header X-Forwarded-For $remote_addr;
		add_header Strict-Transport-Security "max-age=15768000" always;
		add_header X-Content-Type-Options nosniff always;
	}

	# Internal auth subrequest target used by admin-gated app mounts
	# (auth_request); the daemon answers 200 only for a valid admin
	# credential. /internal/ is never proxied, so only this
	# subrequest can reach it.
	location = /internal/admin-auth {
		internal;
		proxy_pass http://%[1]s:%[2]d/internal/auth/admin;
		proxy_pass_request_body off;
		proxy_set_header Content-Length "";
		proxy_set_header X-Original-URI $request_uri;
	}

`, m.BackendHost, m.BackendPort, m.Path)
}

func ravBlock(b *strings.Builder, m Mount) {
	v := backendVar(m.App)
	openPrefix(b, m.Path)
	fmt.Fprintf(b, `		set %[1]s "%[2]s";
		proxy_pass http://%[1]s:%[3]d;
		proxy_set_header Host $host;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-For $remote_addr;
		proxy_set_header X-Forwarded-Proto $scheme;
		proxy_http_version 1.1;
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header Connection $connection_upgrade;
		proxy_connect_timeout 5s;
		proxy_send_timeout 10s;
		proxy_read_timeout 300s;
		add_header Strict-Transport-Security "max-age=15768000" always;
		add_header X-Frame-Options "DENY" always;
		add_header X-Content-Type-Options nosniff always;
		add_header Content-Security-Policy "frame-ancestors 'none';" always;
	}

`, v, m.BackendHost, m.BackendPort)
}

func filebrowserBlock(b *strings.Builder, m Mount) {
	v := backendVar(m.App)
	openPrefix(b, m.Path)
	fmt.Fprintf(b, `		set %[1]s "%[2]s";
		proxy_pass http://%[1]s:%[3]d;
		proxy_set_header Host $host;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-For $remote_addr;
		proxy_set_header X-Forwarded-Proto $scheme;
		add_header Strict-Transport-Security "max-age=15768000" always;
		add_header X-Frame-Options "DENY" always;
		add_header X-Content-Type-Options nosniff always;
	}

`, v, m.BackendHost, m.BackendPort)
}

func radicaleBlock(b *strings.Builder, m Mount) {
	v := backendVar(m.App)
	fmt.Fprintf(b, `	# Radicale CardDAV/CalDAV.
	location %[4]s/ {
		set %[1]s "%[2]s";
		rewrite ^%[4]s/(.*) /$1 break;
		proxy_pass http://%[1]s:%[3]d;
		proxy_set_header Host $host;
		proxy_set_header X-Forwarded-For $remote_addr;
		proxy_set_header X-Script-Name %[4]s;
		proxy_pass_header Authorization;
		add_header Strict-Transport-Security "max-age=15768000" always;
		add_header X-Frame-Options "DENY" always;
		add_header X-Content-Type-Options nosniff always;
	}

	# DAV auto-discovery redirects.
	location = /.well-known/carddav { return 301 https://$host%[4]s/; }
	location = /.well-known/caldav  { return 301 https://$host%[4]s/; }

`, v, m.BackendHost, m.BackendPort, m.Path)
}

func netdataBlock(b *strings.Builder, m Mount) {
	fmt.Fprintf(b, `	# Netdata real-time monitoring. Auth is enforced via
	# auth_request against the admin session check; netdata itself
	# binds to loopback only, this is the sole external entry point.
	location = %[3]s {
		return 301 %[3]s/;
	}
	location %[3]s/ {
		auth_request /internal/admin-auth;
		error_page 401 403 =403 /admin/;
		# Proxy to /v1/ directly - the classic local dashboard. The
		# root serves a loader that fetches the cloud UI and nags
		# about missing plugins.
		proxy_pass http://%[1]s:%[2]d/v1/;
		proxy_set_header Host $host;
		proxy_set_header X-Forwarded-For $remote_addr;
		proxy_set_header X-Forwarded-Proto $scheme;
		# Netdata streams data via chunked responses.
		proxy_buffering off;
		proxy_read_timeout 60s;
		add_header Strict-Transport-Security "max-age=15768000" always;
		add_header X-Frame-Options "DENY" always;
		add_header X-Content-Type-Options nosniff always;
	}

`, m.BackendHost, m.BackendPort, m.Path)
}

func beszelBlock(b *strings.Builder, m Mount) {
	fmt.Fprintf(b, `	# Beszel monitoring dashboard. The hub trusts the identity
	# header nginx injects after validating the admin session; any
	# authenticated admin maps to the same beszel account, which is
	# correct because monitoring data is not per-user.
	location = %[4]s {
		return 301 %[4]s/;
	}
	location %[4]s/ {
		auth_request /internal/admin-auth;
		error_page 401 403 =403 /admin/;

		# nginx overwrites any client-supplied value.
		proxy_set_header X-Beszel-User "%[3]s";

		proxy_pass http://%[1]s:%[2]d/;
		proxy_set_header Host $host;
		proxy_set_header X-Forwarded-For $remote_addr;
		proxy_set_header X-Forwarded-Proto $scheme;
		proxy_http_version 1.1;
		# Beszel uses WebSockets for real-time updates.
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header Connection "upgrade";
		proxy_read_timeout 3600s;
		add_header Strict-Transport-Security "max-age=15768000" always;
		add_header X-Content-Type-Options nosniff always;
	}

`, m.BackendHost, m.BackendPort, m.AuthUser, m.Path)
}

func muninBlock(b *strings.Builder, m Mount) {
	fmt.Fprintf(b, `	# Munin monitoring. muninweb serves the cron-rendered static
	# site and the graph CGI on loopback; auth is enforced here via
	# auth_request against the admin session check.
	location = %[3]s {
		return 301 %[3]s/;
	}
	location %[3]s/ {
		auth_request /internal/admin-auth;
		error_page 401 403 =403 /admin/;
		proxy_pass http://%[1]s:%[2]d/;
		proxy_set_header X-Forwarded-For $remote_addr;
		add_header Strict-Transport-Security "max-age=15768000" always;
		add_header X-Frame-Options "DENY" always;
		add_header X-Content-Type-Options nosniff always;
	}

`, m.BackendHost, m.BackendPort, m.Path)
}

func roundcubeBlock(b *strings.Builder, cfg Config) {
	fmt.Fprintf(b, `	# Roundcube catch-all. Root must point at public_html/
	# (Roundcube 1.7+) so index.php is found. Assets are served via
	# static.php with PATH_INFO.
	location / {
		root /usr/local/share/roundcube/public_html;
		index index.php;

		location ~ /\.(?!well-known) {
			deny all;
			return 404;
		}

		location ~ \.php$ {
			try_files $uri =404;
			fastcgi_pass unix:%[1]s;
			fastcgi_index index.php;
			fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
			include fastcgi_params;
		}

		try_files $uri $uri/ /index.php$is_args$args;

		add_header Strict-Transport-Security "max-age=15768000" always;
		add_header X-Frame-Options "SAMEORIGIN" always;
		add_header X-Content-Type-Options nosniff always;
	}

	# Roundcube routes all static assets (skins, plugins, program/js)
	# through static.php with PATH_INFO, e.g.
	# static.php/skins/elastic/styles/styles.min.css - the ~ \.php$
	# location above won't match that pattern.
	location ~ ^/static\.php {
		root /usr/local/share/roundcube/public_html;
		fastcgi_split_path_info ^(/static\.php)(/.+)$;
		fastcgi_pass unix:%[1]s;
		fastcgi_param SCRIPT_FILENAME $document_root/static.php;
		fastcgi_param PATH_INFO $fastcgi_path_info;
		include fastcgi_params;
	}

`, cfg.PHPSocket)
}

func snappymailBlock(b *strings.Builder, cfg Config) {
	fmt.Fprintf(b, `	# SnappyMail catch-all. The bundled top-level data/ directory is
	# unused (storage is redirected to STORAGE_ROOT/snappymail) but is
	# still denied below in case it's ever served by mistake.
	location / {
		root /usr/local/share/snappymail;
		index index.php;

		location ~ ^/(data)(/|$) {
			deny all;
			return 404;
		}

		location ~ /\.(?!well-known) {
			deny all;
			return 404;
		}

		location ~ \.php$ {
			try_files $uri =404;
			fastcgi_pass unix:%[1]s;
			fastcgi_index index.php;
			fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
			include fastcgi_params;
		}

		try_files $uri $uri/ /index.php$is_args$args;

		add_header Strict-Transport-Security "max-age=15768000" always;
		add_header X-Frame-Options "DENY" always;
		add_header X-Content-Type-Options nosniff always;
	}

`, cfg.PHPSocket)
}

func cyphtBlock(b *strings.Builder, cfg Config) {
	fmt.Fprintf(b, `	# Cypht catch-all. The .env file and several directories contain
	# sensitive data and must not be served - nginx ignores .htaccess
	# so the restrictions Cypht ships for Apache are reimplemented
	# explicitly here.
	location / {
		root /usr/local/share/cypht;
		index index.php;

		# Static assets within modules/themes are public - must come
		# before the modules deny rule since nginx picks the first
		# matching regex location.
		location ~ ^/modules/.*\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
			root /usr/local/share/cypht;
			expires 30d;
			add_header Cache-Control "public";
		}

		# Sensitive directories - never web-accessible.
		location ~ ^/(config|scripts|database|tests|lib|modules|third_party|language)(/|$) {
			deny all;
			return 404;
		}

		# Block .env and other sensitive file types. .env lives in the
		# web root and contains credentials - this rule is not optional.
		location ~ \.(env|ini|log|conf|lock|yml|yaml|sh|sql|db)$ {
			deny all;
			return 404;
		}

		location ~ /\.(?!well-known) {
			deny all;
			return 404;
		}

		location ~ \.php$ {
			try_files $uri =404;
			fastcgi_pass unix:%[1]s;
			fastcgi_index index.php;
			fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
			include fastcgi_params;
		}

		try_files $uri $uri/ /index.php$is_args$args;

		add_header Strict-Transport-Security "max-age=15768000" always;
		add_header X-Frame-Options "DENY" always;
		add_header X-Content-Type-Options nosniff always;
	}

`, cfg.PHPSocket)
}
