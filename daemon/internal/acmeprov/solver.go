package acmeprov

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
)

// Solver satisfies one ACME challenge type: the webroot HTTP-01
// solver and the generic DNS01 solver (which any TXTProvider plugs
// into). The Selector decides which solver serves which domain.
type Solver interface {
	// ChallengeType names the ACME challenge this solver fulfills,
	// e.g. "http-01" or "dns-01".
	ChallengeType() string
	// Present publishes the challenge response value where the CA
	// will look for it. value is already in the form the challenge
	// type expects (key authorization for http-01, TXT record value
	// for dns-01).
	Present(ctx context.Context, domain, token, value string) error
	// Cleanup removes what Present published. Best effort.
	Cleanup(ctx context.Context, domain, token string) error
}

// acmeTokenRE accepts only base64url characters. The challenge token
// is a CA-supplied string the webroot solver uses as a filename;
// anything looser is an arbitrary-file-write primitive for a
// malicious or compromised CA (lego's webroot provider shipped
// exactly that, CVE-2026-40611).
var acmeTokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

// Webroot solves HTTP-01 by writing the key authorization under the
// challenge webroot that every port-80 vhost aliases at
// /.well-known/acme-challenge/ (the renderer guarantees the alias, so
// renewal keeps working no matter what the HTTPS vhost serves).
type Webroot struct {
	// Dir is the webroot directory (STORAGE_ROOT/ssl/lets_encrypt/webroot).
	Dir string
	// PublicIP and PublicIPv6 are what candidate domains must
	// resolve to for the CA's HTTP fetch to reach this box.
	PublicIP   string
	PublicIPv6 string
	// LookupIP overrides DNS resolution (tests). Nil means the
	// system resolver.
	LookupIP func(ctx context.Context, host string) ([]netip.Addr, error)
}

func (w *Webroot) ChallengeType() string { return "http-01" }

// Preflight reports whether the domain resolves to this box in public
// DNS, so the CA's HTTP fetch can reach the webroot; failures carry a
// human-readable reason. Every address the domain publishes must be
// ours: Let's Encrypt prefers IPv6 when an AAAA record exists, so a
// stray AAAA fails validation even when the A record is correct.
func (w *Webroot) Preflight(ctx context.Context, domain string) (bool, string) {
	lookup := w.LookupIP
	if lookup == nil {
		lookup = defaultLookup
	}
	addrs, err := lookup(ctx, domain)
	if err != nil || len(addrs) == 0 {
		return false, "does not resolve in public DNS"
	}
	want4, err := netip.ParseAddr(w.PublicIP)
	if err != nil {
		return false, "box public IP is unparseable: " + w.PublicIP
	}
	var want6 netip.Addr
	if w.PublicIPv6 != "" {
		want6, err = netip.ParseAddr(w.PublicIPv6)
		if err != nil {
			return false, "box public IPv6 is unparseable: " + w.PublicIPv6
		}
	}
	for _, a := range addrs {
		a = a.Unmap()
		if a.Is4() {
			if a != want4.Unmap() {
				return false, fmt.Sprintf("resolves to %s, not %s", a, w.PublicIP)
			}
			continue
		}
		if w.PublicIPv6 == "" {
			return false, fmt.Sprintf("has AAAA record %s but the box has no IPv6 address", a)
		}
		if a != want6 {
			return false, fmt.Sprintf("resolves to %s, not %s", a, w.PublicIPv6)
		}
	}
	return true, ""
}

func (w *Webroot) Present(ctx context.Context, domain, token, value string) error {
	if !acmeTokenRE.MatchString(token) {
		return errors.New("CA sent a malformed challenge token")
	}
	dir := filepath.Join(w.Dir, ".well-known", "acme-challenge")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, token), []byte(value), 0o644)
}

func (w *Webroot) Cleanup(ctx context.Context, domain, token string) error {
	if !acmeTokenRE.MatchString(token) {
		return nil // Present never wrote it
	}
	return os.Remove(filepath.Join(w.Dir, ".well-known", "acme-challenge", token))
}

// defaultLookup resolves through the system resolver: the box runs a
// recursive resolver locally, so this reflects public DNS, not our
// own authoritative zone data.
func defaultLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}
