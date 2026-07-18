# Security Guide

This fork turns a fresh Ubuntu LTS machine into a mail server appliance. This page documents the security posture of a configured instance. The term "box" is used throughout to mean a running installation.

## Reporting Vulnerabilities

Report security vulnerabilities privately via [GitHub Security Advisories](https://github.com/naust-mail/naust/security/advisories/new). Do not open a public issue.

## Threat Model

Nothing is perfectly secure, and an adversary with sufficient resources can always penetrate a system.

The primary goal is to make deploying a good mail server easy, so security concerns are balanced with practicality. We assume adversaries:

- Do not have physical access to the box
- Have not been given Unix accounts on the box (shell access implies trust)
- May be performing passive surveillance or active man-in-the-middle attacks on the network

We do **not** protect against:

- A compromised host OS or hypervisor
- Legal compulsion targeting the hosting provider
- An admin account that has been phished or otherwise compromised

## Admin Control Panel

The control panel is served exclusively over HTTPS. It supports three authentication factors:

- **Password** - stored as a bcrypt hash (Dovecot `{BLF-CRYPT}` format, cost 12). ([source](daemon/internal/auth/password.go))
- **TOTP** - time-based one-time passwords via any authenticator app.
- **WebAuthn passkeys** - hardware security keys and platform authenticators (Touch ID, Windows Hello, etc.).

Sessions are scoped to the browser session and do not persist across restarts. Password changes and MFA changes immediately invalidate all active sessions.

The admin API uses HTTP Basic Auth with admin credentials, or a dedicated API key generated in the control panel.

## User Credentials

### Services behind TLS

All credential-carrying services require TLS:

| Service | Port | Protocol |
|---------|------|----------|
| SMTP submission | 465 | Implicit TLS |
| SMTP submission | 587 | STARTTLS (required - no auth without it) |
| IMAP | 993 | Implicit TLS |
| HTTPS | 443 | Webmail, CardDAV/CalDAV, file storage, admin panel |

TLS settings on all services:

- Minimum TLSv1.2; TLSv1.3 preferred where supported
- Certificates are provisioned automatically by Let's Encrypt; self-signed fallback until provisioning completes ([source](setup/components/defs/ssl.py))
- [Mozilla Intermediate Ciphers](https://wiki.mozilla.org/Security/Server_Side_TLS) profile - balancing security with broad mail client compatibility
- HTTPS Strict Transport Security header set; HTTP redirects to HTTPS ([source](setup/conf/nginx/nginx-ssl.conf))
- The [Qualys SSL Labs test](https://www.ssllabs.com/ssltest) should report an A+ grade

### Brute-force Protection

`fail2ban` blocks offending IP addresses at the network level after repeated failed logins. Protected services:

| Service | Log source |
|---------|-----------|
| SSH | system auth log |
| IMAP (Dovecot) | mail log |
| SMTP submission (Postfix) | mail log |
| Admin control panel | syslog |
| Rav webmail | nginx access log |
| Cypht webmail | `/var/log/cypht-auth.log` (application-level log) |
| FileBrowser | nginx access log |
| Radicale (CardDAV/CalDAV) | nginx access log |

Only the jail for the active webmail client is enabled - unused webmail jails are disabled automatically based on `WEBMAIL_CLIENT` to avoid false positives and startup failures.

A `recidive` jail escalates repeated offenders to a longer ban across all services.

### Console Access

Console/SSH access is managed by the system image, not by this project. The box will warn in the System Status Checks if password-based SSH login is enabled.

When DNSSEC is enabled at the registrar, SSHFP records are published automatically so you can verify the host key fingerprint via DNS:

```
ssh -o VerifyHostKeyDNS=yes box.example.com
```

## Outbound Mail

### DNSSEC

The box runs a local [DNSSEC](https://en.wikipedia.org/wiki/DNSSEC)-validating resolver (Unbound) for all DNS lookups. If the destination domain has DNSSEC enabled, DNS records cannot be silently tampered with en route.

### Encryption

Outbound mail uses [opportunistic TLS](https://en.wikipedia.org/wiki/Opportunistic_encryption) - connections are encrypted where the recipient server supports it, protecting against passive eavesdropping. TLSv1.2+ is used where available. ([source](setup/components/defs/postfix.py))

### DANE

If the recipient's domain publishes a [DANE TLSA](https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities) record and has DNSSEC enabled, the connection is upgraded to authenticated encryption - the recipient server must present a certificate matching the TLSA record, defeating man-in-the-middle attacks. ([source](setup/components/defs/postfix.py))

### Domain Policy (DKIM, DMARC, SPF)

All outbound mail is signed with [DKIM](https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail). [DMARC](https://en.wikipedia.org/wiki/DMARC) records are published at "quarantine" policy by default. [SPF](https://en.wikipedia.org/wiki/Sender_Policy_Framework) records are published automatically.

DKIM signing and DMARC reporting are handled by rspamd (default) or OpenDKIM (SpamAssassin path). ([source](setup/components/defs/filter/rspamd.py))

### Sender Restrictions

Users may only send mail with an envelope sender address that matches their own login address or an alias they are listed as a permitted sender of.

## Incoming Mail

### Encryption

Incoming SMTP (port 25) offers STARTTLS but cannot require it - some legitimate senders do not support it. TLSv1.2+ and modern ciphers are offered to give senders the best chance at encrypting. ([source](setup/components/defs/postfix.py))

### MTA-STS

The box publishes an [MTA-STS](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol#SMTP_MTA_Strict_Transport_Security) policy in enforce mode. Senders supporting MTA-STS will require a properly signed TLS connection and will not fall back to plaintext.

### DANE

When DNSSEC is enabled at the registrar, DANE TLSA records are published automatically. Senders supporting DANE will enforce authenticated encryption when connecting to the box. ([source](setup/components/defs/dns.py))

### Spam and Abuse Filters

Connections are screened at multiple layers:

**Postscreen (connection layer)** - runs before accepting SMTP connections:
- Rejects connections from IPs listed in [Spamhaus Zen](https://www.spamhaus.org/zen/) or [Barracuda BRBL](https://www.barracudacentral.org/rbl)
- Enforces the SMTP greeting delay (detects impatient spam bots)

**rspamd (default spam filter)** - runs on accepted messages:
- Greylisting via Redis (temporary rejection of first-time senders; legitimate servers retry, most spam bots do not)
- Bayesian classifier with Redis-backed learning
- DKIM verification and DMARC enforcement on inbound mail
- Fuzzy hash matching against known spam

**SpamAssassin (optional, `SPAM_FILTER=spamassassin`)** - alternative path with Postgrey for greylisting.
