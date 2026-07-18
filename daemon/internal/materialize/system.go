package materialize

import (
	"context"
	"sort"
	"strings"

	"naust/daemon/internal/store/ent"
)

// System mail routing. Every mail domain must accept the RFC 2142 role
// addresses (postmaster@, abuse@), and the box's own hostname must
// accept operator mail (postmaster@, abuse@, root@) - Postfix and cron
// generate mail to these on their own, and a box that bounces its own
// notifications is misconfigured by default.
//
// The routing is derived, never stored: each address defaults to the
// first admin of the tenant that owns the domain, and anything the
// user defined explicitly wins (a real mailbox at that address, an
// alias, or a catch-all covering the domain). Storing these as
// protected alias rows was rejected - data that must defend itself
// from its own CRUD is config wearing a data costume.
//
// Injection happens on the snapshot, not in the renderers: synthetic
// rows flow through the same precedence and emission logic as real
// ones, so all four Postfix maps stay mutually consistent (the
// hostname domain, for example, appears in virtual-mailbox-domains
// purely because a synthetic alias source lives there).
//
// Tenancy: single-box installs have one tenant, so "owning tenant's
// first admin" degenerates to "the box's first admin". The grouping is
// still computed per tenant so multi-tenancy (v2) changes who owns a
// domain, not how routing works. v2 gate, alongside query scoping: a
// domain must not span two tenants.

// SystemRoutes derives the synthetic routes ApplySystemRouting would
// inject for the store's current contents, so the panel can show the
// automatic routing without it being stored or editable anywhere.
func SystemRoutes(ctx context.Context, client *ent.Client, hostname string) ([]AliasRow, error) {
	snap, err := loadSnapshot(ctx, client)
	if err != nil {
		return nil, err
	}
	before := len(snap.Aliases)
	snap = ApplySystemRouting(snap, hostname)
	return snap.Aliases[before:], nil
}

// systemLocals are injected for every mail domain.
var systemLocals = []string{"postmaster", "abuse"}

// hostnameLocals are injected for the box's primary hostname; root@
// is where cron and daemon mail lands.
var hostnameLocals = []string{"postmaster", "abuse", "root"}

// ApplySystemRouting returns s with synthetic alias rows appended for
// every system address not already claimed by the user's own data.
// hostname may be empty (no hostname entries are added then).
func ApplySystemRouting(s Snapshot, hostname string) Snapshot {
	admin := firstAdminByTenant(s.Users)

	// Explicit data wins: a real mailbox, a defined alias, or a
	// delivering catch-all (the user routed the whole domain).
	taken := map[string]bool{}
	catchAll := map[string]bool{}
	for _, u := range s.Users {
		taken[u.Email] = true
	}
	for _, a := range s.Aliases {
		taken[a.Source] = true
		if d, ok := strings.CutPrefix(a.Source, "@"); ok && len(a.Destinations) > 0 {
			catchAll[d] = true
		}
	}

	domains := domainTenants(s)
	if hostname != "" {
		if _, ok := domains[hostname]; !ok {
			domains[hostname] = s.OperatorTenant
		}
	}
	names := make([]string, 0, len(domains))
	for d := range domains {
		names = append(names, d)
	}
	sort.Strings(names)

	for _, d := range names {
		target, ok := admin[domains[d]]
		if !ok || catchAll[d] {
			continue
		}
		locals := systemLocals
		if d == hostname {
			locals = hostnameLocals
		}
		for _, l := range locals {
			src := l + "@" + d
			if taken[src] {
				continue
			}
			s.Aliases = append(s.Aliases, AliasRow{
				Source:       src,
				Destinations: []string{target},
				TenantID:     domains[d],
			})
		}
	}
	return s
}

// firstAdminByTenant picks each tenant's earliest-created admin, ties
// broken by email so the result is deterministic. Deleting that admin
// re-derives routing to the next one; a tenant with no admin gets no
// system routing at all (an invariant violation upstream, not a state
// the renderer should invent answers for).
func firstAdminByTenant(users []UserRow) map[int]string {
	first := map[int]UserRow{}
	for _, u := range users {
		if !u.Admin {
			continue
		}
		cur, ok := first[u.TenantID]
		if !ok || u.CreatedAt.Before(cur.CreatedAt) ||
			(u.CreatedAt.Equal(cur.CreatedAt) && u.Email < cur.Email) {
			first[u.TenantID] = u
		}
	}
	out := make(map[int]string, len(first))
	for id, u := range first {
		out[id] = u.Email
	}
	return out
}

// domainTenants maps each mail domain to its owning tenant, derived
// from the rows living on it. The lowest tenant wins on conflict for
// determinism only - a domain spanning tenants is invalid state the
// v2 scoping gate must prevent, not something this resolves.
func domainTenants(s Snapshot) map[string]int {
	out := map[string]int{}
	claim := func(addr string, tenant int) {
		d := domainOf(addr)
		if d == "" {
			return
		}
		if cur, ok := out[d]; !ok || tenant < cur {
			out[d] = tenant
		}
	}
	for _, u := range s.Users {
		claim(u.Email, u.TenantID)
	}
	for _, a := range s.Aliases {
		claim(a.Source, a.TenantID)
	}
	return out
}
