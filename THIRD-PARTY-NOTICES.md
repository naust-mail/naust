# Third-Party Notices

This project installs and configures third-party software on the user's server.
The project itself does not bundle or redistribute these components - they are
fetched at setup time from their official sources (apt, GitHub releases, PyPI).

Where a binary is downloaded directly by the setup scripts, the source and
license are noted below so operators are aware of their obligations.

---

## System and infrastructure

**Unbound** - Recursive DNS resolver
License: BSD 3-Clause
Source: https://nlnetlabs.nl/projects/unbound/

**NSD** - Authoritative DNS server
License: BSD 3-Clause
Source: https://nlnetlabs.nl/projects/nsd/

**ldnsutils** - DNSSEC tools (ldns-signzone)
License: BSD 3-Clause
Source: https://nlnetlabs.nl/projects/ldns/

**Fail2ban** - Intrusion prevention
License: GPL v2+
Source: https://github.com/fail2ban/fail2ban

**UFW** - Firewall frontend
License: GPL v3
Source: https://launchpad.net/ufw

**OpenSSL** - TLS/SSL library and tools
License: Apache 2.0 (OpenSSL 3.x)
Source: https://openssl.org/

**rsync** - File synchronisation
License: GPL v3
Source: https://rsync.samba.org/

**unattended-upgrades** - Automatic security updates
License: GPL v2
Source: https://wiki.debian.org/UnattendedUpgrades

**sqlite3** - Embedded relational database
License: Public Domain
Source: https://sqlite.org/

---

## Mail

**Postfix** - SMTP server
License: Eclipse Public License 2.0 + IBM Public License 1.0
Source: https://www.postfix.org/

**Dovecot** - IMAP/POP3/LMTP server
License: MIT (core) + LGPL 2.1 (remaining modules)
Source: https://dovecot.org/

**OpenDKIM / OpenDMARC** - DKIM signing and DMARC policy enforcement
License: BSD 3-Clause + Sendmail Open Source License 1.1
Source: http://opendkim.org/ / http://www.trusteddomain.org/opendmarc.html

**SpamAssassin** - Spam filtering
License: Apache 2.0
Source: https://spamassassin.apache.org/

**spampd** - SpamAssassin SMTP proxy
License: GPL v2
Source: https://github.com/mpaperno/spampd

**libmail-dkim-perl** - DKIM Perl library
License: Apache 2.0 or GPL (Perl dual license)
Source: https://metacpan.org/pod/Mail::DKIM

**Rspamd** - Spam filter and DKIM/DMARC/ARC signing
License: Apache 2.0
Source: https://rspamd.com/

**Redis** - In-memory data store (used by Rspamd)
License: BSD 3-Clause (Ubuntu-packaged version)
Source: https://redis.io/

**postgrey** - Postfix greylisting policy server (optional)
License: GPL v2
Source: https://postgrey.schweikert.ch/

**dovecot-antispam** - Dovecot spam learning plugin (Ubuntu 22.04 / Dovecot 2.3 only)
License: GPL v2
Source: https://github.com/clehner/dovecot-antispam

**ClamAV** - Antivirus engine (optional)
License: GPL v2
Source: https://www.clamav.net/

---

## Web and certificates

**nginx** - Web server and reverse proxy
License: BSD 2-Clause
Source: https://nginx.org/

**Certbot** - Let's Encrypt certificate provisioning
License: Apache 2.0
Source: https://certbot.eff.org/

**idn2** - Internationalised domain name tool
License: GPL v3+ (CLI) / LGPL v3+ (library)
Source: https://gitlab.com/libidn/libidn2

---

## Webmail (one selected per install)

**Rav** - Webmail client (default)
License: MIT
Original: https://github.com/c0h1b4/oxi
Fork: https://github.com/naust-mail/rav

**Roundcube** - Webmail client (optional)
License: GPL v3+ with plugin/skin exception
Source: https://roundcube.net/

**rcmcarddav** - Roundcube CardDAV/CalDAV plugin
License: GPL v2+
Source: https://github.com/mstilkerich/rcmcarddav

**SnappyMail** - Webmail client (optional)
License: AGPL v3
Source: https://snappymail.eu/ / https://github.com/the-djmaze/snappymail
Note: AGPL v3 requires that users interacting with SnappyMail over the
network can access its source code. The source is publicly available at
the link above.

**Cypht** - Webmail client (optional)
License: LGPL v2.1
Source: https://cypht.org/ / https://github.com/cypht-org/cypht

---

## CalDAV/CardDAV

**Radicale** - CalDAV/CardDAV server (optional)
License: GPL v3
Source: https://radicale.org/ / https://github.com/Kozea/Radicale

**radicale_miab** - MIAB auth and storage plugin for Radicale
License: GPL v3+
Source: This repository (setup/components/defs/optional/radicale.py)

---

## Backups

**restic** - Backup tool
License: BSD 2-Clause
Source: https://restic.net/ / https://github.com/restic/restic

**duplicity** - Backup tool with cloud backend support (optional)
License: GPL v2
Source: https://duplicity.gitlab.io/

---

## Monitoring

**Munin** - System monitoring and graphing (optional)
License: GPL v2
Source: https://munin-monitoring.org/

**Netdata** - Real-time system monitoring (optional)
License: GPL v3 (agent core) / NCUL1 (dashboard - proprietary free-use)
Source: https://netdata.cloud/ / https://github.com/netdata/netdata
Note: The Netdata dashboard is not open source software. It is provided
free of charge for use with the Netdata agent but may not be redistributed
or modified independently.

**Beszel** - Lightweight server monitoring hub and agent (optional)
License: MIT
Source: https://github.com/henrygd/beszel

---

## Files and utilities

**FileBrowser** - Web-based file manager (optional)
License: Apache 2.0
Source: https://filebrowser.org/ / https://github.com/filebrowser/filebrowser

---

## Admin UI (frontend)

The admin panel frontend is built from `frontend/` and distributed as a
pre-built tarball fetched by the setup scripts. It bundles npm packages
whose licenses are listed in `frontend/package.json` and `frontend/package-lock.json`.
All bundled packages use permissive licenses (MIT, BSD, Apache 2.0, ISC).


