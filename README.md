<div align="center">
  <h1>Naust</h1>
  <img src=".github/dash.png" alt="Naust admin panel" width="600">
  <br>
  <p>A modern self-hosted mail server stack. Hard fork of <a href="https://github.com/mail-in-a-box/mailinabox">Mail-in-a-Box</a>.</p>
  <p>By <a href="https://github.com/boomboompower">boomboompower</a> and <a href="https://github.com/naust-mail/naust/graphs/contributors">contributors</a>.</p>
  <p>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
    <a href="https://ubuntu.com/"><img src="https://img.shields.io/badge/Ubuntu-22.04%20%2F%2024.04%20%2F%2026.04-E95420?logo=ubuntu&logoColor=white" alt="Ubuntu LTS"></a>
  </p>
</div>

---

## Table of contents

- [Why](#why)
- [Status](#status)
- [What changed from upstream](#what-changed-from-upstream)
- [What is in the box](#what-is-in-the-box)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [API](#api)
- [Contributing](#contributing)
- [Security](#security)
- [Acknowledgements](#acknowledgements)
- [License](#license)

---

## Why

Naust ("boathouse" in Norwegian: the small sturdy building where the boat is kept safe, maintained,
and relaunched) began as a fork of [Mail-in-a-Box](https://github.com/mail-in-a-box/mailinabox) with a
different set of component choices, and has since diverged into its own project. The PHP-based webmail
and groupware stack is replaced with rav (Rust), FileBrowser, and Radicale. The admin panel is
rewritten in Vue 3 with passkey support. A Docker deployment path sits alongside the bare metal
installer. The mail core - Postfix, Dovecot, NSD - is proven, boring, and kept.

Our goals:

- Self-hosted email that is simple to deploy and understand
- Promote [decentralization](http://redecentralize.org/) and privacy on the web
- Configuration that is automated, auditable, and [idempotent](https://en.wikipedia.org/wiki/Idempotence)
- Modern auth: TOTP, passkeys (WebAuthn), and hardware security keys
- No lock-in: your mail is standard Maildir, your backups restore anywhere,
  and the system supports extension rather than fighting it

## What changed from upstream

| Area               | Upstream Mail-in-a-Box | Naust                                                                         |
|--------------------|------------------------|-------------------------------------------------------------------------------|
| Webmail            | Roundcube (PHP)        | [rav](https://github.com/naust-mail/rav) (Rust, prebuilt)                     |
| File storage       | Nextcloud (PHP)        | [FileBrowser](https://filebrowser.org/) (Go)                                  |
| CalDAV/CardDAV     | Nextcloud              | [Radicale](https://radicale.org/) (Python)                                    |
| Mobile sync        | Z-Push (PHP)           | Native IMAP/CalDAV/CardDAV clients                                            |
| Admin UI           | jQuery + Bootstrap     | Vue 3 + TypeScript                                                            |
| Admin auth         | Password / TOTP        | Password + TOTP + WebAuthn passkeys                                           |
| Control plane      | Python (Flask)         | Go (`managerd` + `helperd`), privilege-separated                              |
| Setup              | Bash scripts           | Python component system (declarative, stamped, idempotent)                    |
| Ubuntu target      | 22.04 LTS              | 22.04 LTS / 24.04 LTS / 26.04 LTS                                             |
| Deployment         | Bare metal only        | Bare metal + Docker                                                           |
| PHP                | Required               | Not installed                                                                 |
| Backups            | Duplicity              | [Restic](https://github.com/restic/restic) default / Duplicity                |
| Monitoring         | Munin                  | [Netdata](https://www.netdata.cloud/) / [Beszel](https://beszel.dev/) / Munin |
| Encryption at rest | No                     | Per-user mailbox encryption (Dovecot mail_crypt, Ubuntu 26.04)                |
| SMTP relay         | No                     | Yes (configurable in admin panel)                                             |
| API tokens         | No                     | Scoped bearer tokens for automation                                           |

This is a hard fork and fixes from upstream are ported manually on a case-by-case basis.

## What is in the box

Naust turns a fresh Ubuntu machine into a working mail server by installing and configuring:

### Mail

- SMTP ([Postfix](http://www.postfix.org/)) and IMAP ([Dovecot](https://dovecot.org/))
- Spam filtering and greylisting ([rspamd](https://rspamd.com/) default, [SpamAssassin](https://spamassassin.apache.org/) optional)
- Mail filter rules (Dovecot Sieve) and email client autoconfig
- Optional per-user mailbox encryption at rest (Ubuntu 26.04)

### DNS

- Authoritative DNS ([NSD](https://nlnetlabs.nl/projects/nsd/)) with [SPF](https://en.wikipedia.org/wiki/Sender_Policy_Framework), [DKIM](https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail), [DMARC](https://en.wikipedia.org/wiki/DMARC), [DNSSEC](https://en.wikipedia.org/wiki/DNSSEC), [DANE TLSA](https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities), [MTA-STS](https://tools.ietf.org/html/rfc8461), and [SSHFP](https://tools.ietf.org/html/rfc4255) records set automatically
- Local recursive resolver with DNSSEC validation - required for DANE and for bypassing shared-IP rate limits on DNS blocklists

### Web services

- Webmail: [rav](https://github.com/naust-mail/rav) (Rust, prebuilt binary, no PHP)
- Contacts and calendar sync: [Radicale](https://radicale.org/) (CardDAV/CalDAV)
- File storage: [FileBrowser](https://filebrowser.org/)
- Reverse proxy and static site hosting: [nginx](https://nginx.org/)

### Security and operations

- TLS certificates provisioned automatically via [Let's Encrypt](https://letsencrypt.org/)
- Brute-force protection ([fail2ban](https://www.fail2ban.org/)), firewall ([ufw](https://launchpad.net/ufw))
- Backups ([restic](https://restic.net/) default, [duplicity](https://duplicity.nongnu.org/) optional) to local, rsync, S3, or B2 targets
- System monitoring: [Netdata](https://www.netdata.cloud/), [Beszel](https://beszel.dev/), or [Munin](https://munin-monitoring.org/)
- Admin control panel with TOTP and WebAuthn passkey support

### Management

- Daily health checks: services, ports, TLS validity, DNS correctness
- Web control panel for users, aliases, DNS records, SMTP relay, and backups
- REST API for control panel actions, with scoped API tokens for automation
- `boxctl` CLI: guided setup, health doctor, first-admin bootstrap

Internationalized domain names are supported.

## Requirements

- **Ubuntu LTS** (64-bit) - 22.04, 24.04, and 26.04 are supported
- A fresh machine - the installer owns the system and may overwrite existing configuration
- A domain name with glue records pointing to the box's IP

For Docker development, any Linux host with Docker and Docker Compose installed is sufficient.

## Quick start

### boxctl - the recommended entry point

`boxctl` is the interactive entry point for both Docker and bare metal:

```bash
git clone https://github.com/naust-mail/naust.git
cd naust
python3 setup/boxctl
```

Running with no arguments shows a landing screen: **Docker**, **Bare metal**, or **Manage services**.
Subcommands skip it:

```bash
python3 setup/boxctl docker      # Docker setup wizard - writes .env, prints the compose command
python3 setup/boxctl doctor      # check service health on a running box
python3 setup/boxctl bootstrap   # one-time setup code for creating the first admin via the web UI
python3 setup/boxctl update      # fetch the latest release and re-run setup (bare metal)
```

### Bare metal

Start with a completely fresh Ubuntu LTS 64-bit machine:

```bash
sudo setup/install.sh
```

The installer runs a question wizard, then the component system. Re-running it at any time is safe -
setup is fully idempotent.

### Docker

boxctl generates the compose command for you. If you prefer to run manually:

```bash
cp deploy/docker/.env.example deploy/docker/.env
# edit deploy/docker/.env - set PRIMARY_HOSTNAME at minimum

# core stack only (mail, DNS, nginx, admin panel):
docker compose -f deploy/docker/docker-compose.yml up --build

# with all optional services (pick one of munin/beszel for monitoring):
docker compose -f deploy/docker/docker-compose.yml \
  --profile rav --profile filebrowser --profile radicale --profile clamav --profile beszel \
  up --build
```

Dev ports default to unprivileged bindings (8080/8443/2525/5354 etc., all overridable via `.env`);
overlay `docker-compose.prod.yml` to bind the standard ports in production.

## API

Every action in the control panel is available through a REST API. Generate a scoped API token
(`naust_` prefix, read or read/write) in the control panel and authenticate with
`Authorization: Bearer <token>`.

## Contributing

See [CONTRIBUTING.md](.github/CONTRIBUTING.md).

## Security

See [SECURITY.md](.github/SECURITY.md) for the full threat model. To report a vulnerability privately, use [GitHub Security Advisories](https://github.com/naust-mail/naust/security/advisories/new).

## Acknowledgements

Naust stands on the shoulders of giants. This project would not exist without
[Mail-in-a-Box](https://github.com/mail-in-a-box/mailinabox) by [Joshua Tauberer](https://joshdata.me/)
and its many contributors, who did the hard work of making a mail server actually work for real people.
The original project was itself inspired by the
["NSA-proof your email in 2 hours"](https://sealedabstract.com/code/nsa-proof-your-e-mail-in-2-hours/) post by
Drew Crawford and [Sovereign](https://github.com/sovereign/sovereign) by Alex Payne.

## License

This project is licensed under the [MIT License](LICENSE). It is a fork of [Mail-in-a-Box](https://mailinabox.email), which was released into the public domain under CC0 1.0 by its contributors. New contributions in this fork are MIT-licensed.
