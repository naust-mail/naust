package acmeprov

import (
	"context"
	"net/http"
	"strings"

	"naust/daemon/internal/dnsprovider"
	"naust/daemon/internal/store/ent"
)

// Selector picks the challenge solver for one domain, or explains
// why no challenge can succeed (the domain is then skipped, not
// errored).
type Selector interface {
	Pick(ctx context.Context, domain string) (Solver, string)
}

// StandardSelector implements the provisioning policy:
//
//  1. If the domain points at this box, HTTP-01 through the webroot:
//     free, credential-less, no propagation wait. Zero-config boxes
//     never leave this path.
//  2. Otherwise, if the domain's zone has a configured DNS provider,
//     DNS-01 through the provider's API. This is what serves proxied
//     (Cloudflare orange-cloud) and externally hosted domains.
//  3. Otherwise skip, with the webroot gate's reason.
type StandardSelector struct {
	Webroot *Webroot
	// Store holds the per-zone provider configuration
	// (DNSZoneProvider rows).
	Store *ent.Client
	// HTTPClient overrides provider API transport (tests).
	HTTPClient *http.Client
	// NewProvider overrides provider construction (tests). Nil uses
	// the dnsprovider registry.
	NewProvider func(name, token string) (dnsprovider.Provider, error)
	// DNS01Wait overrides propagation waiting on built DNS01 solvers
	// (tests).
	DNS01Wait func(ctx context.Context, fqdn, value string) error
}

func (s *StandardSelector) Pick(ctx context.Context, domain string) (Solver, string) {
	ok, reason := s.Webroot.Preflight(ctx, domain)
	if ok {
		return s.Webroot, ""
	}

	rows, err := s.Store.DNSZoneProvider.Query().All(ctx)
	if err != nil {
		return nil, reason + "; provider lookup failed: " + err.Error()
	}
	var match *ent.DNSZoneProvider
	for _, row := range rows {
		if domain != row.Zone && !strings.HasSuffix(domain, "."+row.Zone) {
			continue
		}
		if match == nil || len(row.Zone) > len(match.Zone) {
			match = row
		}
	}
	if match == nil {
		return nil, reason
	}

	newProvider := s.NewProvider
	if newProvider == nil {
		newProvider = func(name, token string) (dnsprovider.Provider, error) {
			return dnsprovider.New(name, token, s.HTTPClient)
		}
	}
	provider, err := newProvider(match.Provider, match.Token)
	if err != nil {
		return nil, reason + "; " + err.Error()
	}
	return &DNS01{Provider: provider, Zone: match.Zone, Wait: s.DNS01Wait}, ""
}
