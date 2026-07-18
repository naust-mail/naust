package acmeprov

import (
	"context"
	"fmt"
	"net"
	"time"

	"naust/daemon/internal/dnsprovider"
)

const (
	// propagationTimeout bounds waiting for the TXT record to appear
	// on the zone's authoritative servers before telling the CA to
	// validate. API providers usually publish within seconds.
	propagationTimeout = 2 * time.Minute
	propagationPoll    = 3 * time.Second
)

// DNS01 solves dns-01 challenges through any dnsprovider.Provider.
// All ACME mechanics live here, written once: the _acme-challenge
// name, the propagation wait against the zone's authoritative
// servers, and cleanup. Providers are pure API clients.
type DNS01 struct {
	Provider dnsprovider.Provider
	// Zone is the DNS zone the provider manages for this domain.
	Zone string
	// Wait overrides propagation waiting (tests). Nil polls the
	// zone's authoritative nameservers.
	Wait func(ctx context.Context, fqdn, value string) error

	// presented remembers published values so Cleanup (which gets no
	// value from the order flow) deletes exactly what Present wrote.
	// A DNS01 is built per domain and used from one goroutine.
	presented map[string]string
}

func (d *DNS01) ChallengeType() string { return "dns-01" }

func (d *DNS01) Present(ctx context.Context, domain, token, value string) error {
	fqdn := "_acme-challenge." + domain
	if err := d.Provider.SetTXT(ctx, d.Zone, fqdn, value); err != nil {
		return fmt.Errorf("publish TXT: %w", err)
	}
	if d.presented == nil {
		d.presented = map[string]string{}
	}
	d.presented[fqdn] = value
	wait := d.Wait
	if wait == nil {
		wait = func(ctx context.Context, fqdn, value string) error {
			return waitForTXT(ctx, d.Zone, fqdn, value, authoritativeTXT)
		}
	}
	if err := wait(ctx, fqdn, value); err != nil {
		return fmt.Errorf("TXT propagation: %w", err)
	}
	return nil
}

func (d *DNS01) Cleanup(ctx context.Context, domain, token string) error {
	fqdn := "_acme-challenge." + domain
	value, ok := d.presented[fqdn]
	if !ok {
		return nil
	}
	delete(d.presented, fqdn)
	return d.Provider.DeleteTXT(ctx, d.Zone, fqdn, value)
}

// waitForTXT polls query until the TXT value is visible, checking
// immediately and then at each poll interval within the timeout.
func waitForTXT(ctx context.Context, zone, fqdn, value string, query func(ctx context.Context, zone, fqdn string) ([]string, error)) error {
	ctx, cancel := context.WithTimeout(ctx, propagationTimeout)
	defer cancel()
	for {
		values, err := query(ctx, zone, fqdn)
		if err == nil {
			for _, v := range values {
				if v == value {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("record %s not visible on authoritative DNS: %w", fqdn, ctx.Err())
		case <-time.After(propagationPoll):
		}
	}
}

// authoritativeTXT queries a nameserver authoritative for the zone
// directly, bypassing the local recursive cache (which would
// negative-cache the record we just created).
func authoritativeTXT(ctx context.Context, zone, fqdn string) ([]string, error) {
	nss, err := net.DefaultResolver.LookupNS(ctx, zone)
	if err != nil || len(nss) == 0 {
		return nil, fmt.Errorf("lookup NS for %s: %w", zone, err)
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, nss[0].Host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s: %w", nss[0].Host, err)
	}
	server := net.JoinHostPort(addrs[0], "53")
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, server)
		},
	}
	return r.LookupTXT(ctx, fqdn)
}
