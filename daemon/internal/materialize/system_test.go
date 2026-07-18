package materialize

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSystemRoutingDefaults(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snap := Snapshot{
		OperatorTenant: 1,
		Users: []UserRow{
			// Second admin, created later: must not be the target.
			{Email: "late@example.com", Admin: true, CreatedAt: t0.Add(time.Hour), TenantID: 1},
			{Email: "ann@example.com", Admin: true, CreatedAt: t0, TenantID: 1},
			{Email: "bob@foo.org", CreatedAt: t0, TenantID: 1},
		},
	}
	out := ApplySystemRouting(snap, "box.example.com")
	aliasMaps := RenderAliasMaps(out)

	for _, want := range []string{
		"postmaster@example.com ann@example.com\n",
		"abuse@example.com ann@example.com\n",
		"postmaster@foo.org ann@example.com\n",
		"abuse@foo.org ann@example.com\n",
		"postmaster@box.example.com ann@example.com\n",
		"abuse@box.example.com ann@example.com\n",
		"root@box.example.com ann@example.com\n",
	} {
		if !strings.Contains(aliasMaps, want) {
			t.Errorf("alias maps missing %q; got:\n%s", want, aliasMaps)
		}
	}
	// root@ is hostname-only.
	if strings.Contains(aliasMaps, "root@example.com") {
		t.Error("root@ must only be injected for the hostname domain")
	}
	// The hostname domain becomes deliverable purely via the synthetics.
	if !strings.Contains(RenderMailboxDomains(out), "box.example.com 1\n") {
		t.Error("hostname domain missing from domains map")
	}
	// The target may send as the role addresses (alias semantics).
	if !strings.Contains(RenderSenderLoginMaps(out), "postmaster@example.com ann@example.com\n") {
		t.Error("sender-login missing synthetic entry")
	}
}

func TestSystemRoutingExplicitDataWins(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snap := Snapshot{
		OperatorTenant: 1,
		Users: []UserRow{
			{Email: "ann@example.com", Admin: true, CreatedAt: t0, TenantID: 1},
			// A real mailbox at a role address: no synthetic may shadow it.
			{Email: "postmaster@example.com", CreatedAt: t0, TenantID: 1},
			{Email: "carl@bar.net", CreatedAt: t0, TenantID: 1},
			{Email: "dora@cat.io", CreatedAt: t0, TenantID: 1},
		},
		Aliases: []AliasRow{
			// Explicit alias at a role address.
			{Source: "abuse@example.com", Destinations: []string{"ext@other.net"}, TenantID: 1},
			// Delivering catch-all: the user routed the whole domain.
			{Source: "@bar.net", Destinations: []string{"carl@bar.net"}, TenantID: 1},
			// Senders-only catch-all delivers nothing, so synthetics still apply.
			{Source: "@cat.io", PermittedSenders: []string{"dora@cat.io"}, TenantID: 1},
		},
	}
	out := ApplySystemRouting(snap, "")
	aliasMaps := RenderAliasMaps(out)

	if !strings.Contains(aliasMaps, "postmaster@example.com postmaster@example.com\n") {
		t.Errorf("real mailbox shadowed by synthetic:\n%s", aliasMaps)
	}
	if !strings.Contains(aliasMaps, "abuse@example.com ext@other.net\n") {
		t.Errorf("explicit alias shadowed by synthetic:\n%s", aliasMaps)
	}
	if strings.Contains(aliasMaps, "postmaster@bar.net") || strings.Contains(aliasMaps, "abuse@bar.net") {
		t.Errorf("catch-all domain must get no synthetics:\n%s", aliasMaps)
	}
	if !strings.Contains(aliasMaps, "postmaster@cat.io ann@example.com\n") {
		t.Errorf("senders-only catch-all must not suppress synthetics:\n%s", aliasMaps)
	}
}

func TestSystemRoutingPerTenant(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snap := Snapshot{
		OperatorTenant: 1,
		Users: []UserRow{
			{Email: "op@julian.cv", Admin: true, CreatedAt: t0, TenantID: 1},
			{Email: "hello@example.com", Admin: true, CreatedAt: t0, TenantID: 2},
			{Email: "worker@example.com", CreatedAt: t0, TenantID: 2},
		},
	}
	out := ApplySystemRouting(snap, "box.julian.cv")
	aliasMaps := RenderAliasMaps(out)

	// Tenant domains route to the tenant's own admin, never the operator.
	if !strings.Contains(aliasMaps, "postmaster@example.com hello@example.com\n") {
		t.Errorf("tenant domain must route to tenant admin:\n%s", aliasMaps)
	}
	if strings.Contains(aliasMaps, "postmaster@example.com op@julian.cv") {
		t.Error("tenant mail leaked to the operator")
	}
	// Infrastructure routes to the operator.
	if !strings.Contains(aliasMaps, "root@box.julian.cv op@julian.cv\n") {
		t.Errorf("hostname must route to operator admin:\n%s", aliasMaps)
	}
}

func TestSystemRoutingNoAdminNoSynthetics(t *testing.T) {
	snap := Snapshot{
		OperatorTenant: 1,
		Users: []UserRow{
			{Email: "bob@example.com", CreatedAt: time.Now(), TenantID: 1},
		},
	}
	out := ApplySystemRouting(snap, "box.example.com")
	if len(out.Aliases) != 0 {
		t.Errorf("no admin means no synthetics, got %v", out.Aliases)
	}
	if strings.Contains(RenderMailboxDomains(out), "box.example.com") {
		t.Error("hostname domain must not be accepted with nowhere to route")
	}
}

func TestSystemRoutingCreatedAtTieBreaksByEmail(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snap := Snapshot{
		OperatorTenant: 1,
		Users: []UserRow{
			{Email: "zed@example.com", Admin: true, CreatedAt: t0, TenantID: 1},
			{Email: "amy@example.com", Admin: true, CreatedAt: t0, TenantID: 1},
		},
	}
	out := ApplySystemRouting(snap, "")
	if !strings.Contains(RenderAliasMaps(out), "postmaster@example.com amy@example.com\n") {
		t.Error("equal CreatedAt must tie-break to the lexicographically first email")
	}
}

// End to end through the store: role, created_at, and the tenant edge
// must survive load(), and the hostname must reach the renderers.
func TestRebuildSystemRouting(t *testing.T) {
	m, _, client := newTestMaterializer(t)
	m.Hostname = "box.example.com"
	ctx := context.Background()
	client.User.Create().SetEmail("ann@example.com").SetPasswordHash("{BLF-CRYPT}x").
		SetRole("admin").SetTenantID(testTenantID(t, client)).SaveX(ctx)

	if err := m.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	aliasMaps, err := os.ReadFile(filepath.Join(m.Dir, "virtual-alias-maps"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"postmaster@example.com ann@example.com\n",
		"root@box.example.com ann@example.com\n",
	} {
		if !strings.Contains(string(aliasMaps), want) {
			t.Errorf("alias maps missing %q; got:\n%s", want, aliasMaps)
		}
	}
	domains, err := os.ReadFile(filepath.Join(m.Dir, "virtual-mailbox-domains"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(domains), "box.example.com 1\n") {
		t.Errorf("domains map missing hostname; got:\n%s", domains)
	}
}

func TestSystemRoutesReturnsOnlySynthetics(t *testing.T) {
	_, _, client := newTestMaterializer(t)
	ctx := context.Background()
	client.User.Create().SetEmail("ann@example.com").SetPasswordHash("{BLF-CRYPT}x").
		SetRole("admin").SetTenantID(testTenantID(t, client)).SaveX(ctx)
	// A real alias must not appear in the derived list, and its source
	// must suppress the synthetic that would have covered it.
	client.Alias.Create().SetSource("abuse@example.com").
		SetDestinations([]string{"ann@example.com"}).
		SetTenantID(testTenantID(t, client)).SaveX(ctx)

	routes, err := SystemRoutes(ctx, client, "box.example.com")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range routes {
		got[r.Source] = r.Destinations[0]
	}
	want := map[string]string{
		"postmaster@example.com":     "ann@example.com",
		"postmaster@box.example.com": "ann@example.com",
		"abuse@box.example.com":      "ann@example.com",
		"root@box.example.com":       "ann@example.com",
	}
	if len(got) != len(want) {
		t.Fatalf("routes = %v", got)
	}
	for src, dst := range want {
		if got[src] != dst {
			t.Errorf("route %s = %q, want %q", src, got[src], dst)
		}
	}
}
