// Package materialize renders the mail data plane's lookup tables as
// native map files: four Postfix maps (compiled with postmap) and one
// Dovecot passwd-file. Postfix and Dovecot read these on their own, so
// the manager is never in the mail hot path - mail keeps flowing when
// the manager is down, upgrading, or gone.
//
// The old SQL lookup maps resolved precedence with UNION/priority at
// query time; here precedence is resolved once at generation time and
// the files contain final answers.
package materialize

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// UserRow is one mail account as the renderers need it.
type UserRow struct {
	Email        string
	PasswordHash string
	QuotaBytes   int64
	// MailCrypt marks accounts with a committed password key slot.
	// They get the crypt_user_key_curve extra field, which is what
	// activates Dovecot's mail_crypt plugin for exactly these users;
	// for everyone else the field is absent and mail stays plaintext.
	MailCrypt bool
	// Admin, CreatedAt and TenantID feed system mail routing (system.go):
	// RFC 2142 addresses default to the owning tenant's first admin.
	Admin     bool
	CreatedAt time.Time
	TenantID  int
}

// mailCryptCurve is the key type mail_crypt generates per-folder keys
// with. Must match the curve the keygen intent uses (mailcrypt design).
const mailCryptCurve = "prime256v1"

// AliasRow is one forwarding rule as the renderers need it. Catch-alls
// use the "@domain.tld" source form.
type AliasRow struct {
	Source           string
	Destinations     []string
	PermittedSenders []string
	TenantID         int
}

// Snapshot is the full input to one rendering pass.
type Snapshot struct {
	Users   []UserRow
	Aliases []AliasRow
	// OperatorTenant owns the box itself; system mail for the primary
	// hostname (root@, postmaster@) routes to its first admin.
	OperatorTenant int
}

// renderMap emits Postfix's text map format: "key value", sorted by key
// for byte-stable output (stable output is what makes skip-if-unchanged
// work).
func renderMap(entries map[string]string) string {
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString(" ")
		b.WriteString(entries[k])
		b.WriteString("\n")
	}
	return b.String()
}

// RenderMailboxDomains lists every domain we accept mail for.
func RenderMailboxDomains(s Snapshot) string {
	entries := map[string]string{}
	for _, u := range s.Users {
		if d := domainOf(u.Email); d != "" {
			entries[d] = "1"
		}
	}
	for _, a := range s.Aliases {
		if d := domainOf(a.Source); d != "" {
			entries[d] = "1"
		}
	}
	return renderMap(entries)
}

// RenderMailboxMaps lists addresses with real mailboxes.
func RenderMailboxMaps(s Snapshot) string {
	entries := map[string]string{}
	for _, u := range s.Users {
		entries[u.Email] = "1"
	}
	return renderMap(entries)
}

// RenderAliasMaps expands aliases and catch-alls. Every user is also an
// alias to itself: virtual_alias_maps takes precedence over mailbox
// maps, so without self-entries a catch-all would swallow mail for real
// users. An alias whose source equals a user address wins over the
// self-entry (that is how a user's mail gets forwarded elsewhere).
// Aliases with no destinations (permitted-senders-only) claim nothing.
func RenderAliasMaps(s Snapshot) string {
	entries := map[string]string{}
	for _, u := range s.Users {
		entries[u.Email] = u.Email
	}
	for _, a := range s.Aliases {
		if len(a.Destinations) > 0 {
			entries[a.Source] = strings.Join(a.Destinations, ",")
		}
	}
	return renderMap(entries)
}

// RenderSenderLoginMaps answers "who may use this MAIL FROM address":
// an alias's explicit permitted senders, else its destinations, else -
// for user addresses - the user themself.
func RenderSenderLoginMaps(s Snapshot) string {
	entries := map[string]string{}
	for _, u := range s.Users {
		entries[u.Email] = u.Email
	}
	for _, a := range s.Aliases {
		switch {
		case len(a.PermittedSenders) > 0:
			entries[a.Source] = strings.Join(a.PermittedSenders, ",")
		case len(a.Destinations) > 0:
			entries[a.Source] = strings.Join(a.Destinations, ",")
		}
	}
	return renderMap(entries)
}

// RenderDovecotUsers emits a Dovecot passwd-file: one line per account,
// colon-separated user:password:uid:gid:gecos:home:shell:extra. Dovecot
// caches it in memory and re-reads on mtime change. The uid/gid are the
// literal user/group name "mail", matching the legacy SQL user_query.
func RenderDovecotUsers(s Snapshot, storageRoot string) string {
	users := make([]UserRow, len(s.Users))
	copy(users, s.Users)
	sort.Slice(users, func(i, j int) bool { return users[i].Email < users[j].Email })

	var b strings.Builder
	for _, u := range users {
		local, domain, ok := strings.Cut(u.Email, "@")
		if !ok {
			continue
		}
		home := fmt.Sprintf("%s/mail/mailboxes/%s/%s", storageRoot, domain, local)
		var extras []string
		if u.QuotaBytes > 0 {
			extras = append(extras, fmt.Sprintf("userdb_quota_storage_size=%d", u.QuotaBytes))
		}
		if u.MailCrypt {
			extras = append(extras, "userdb_crypt_user_key_curve="+mailCryptCurve)
		}
		b.WriteString(strings.Join([]string{u.Email, u.PasswordHash, "mail", "mail", "", home, "", strings.Join(extras, " ")}, ":"))
		b.WriteString("\n")
	}
	return b.String()
}

func domainOf(addr string) string {
	_, domain, ok := strings.Cut(addr, "@")
	if !ok {
		return ""
	}
	return domain
}
