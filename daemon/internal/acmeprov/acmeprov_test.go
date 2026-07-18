package acmeprov

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"naust/daemon/internal/dnsprovider"
	"naust/daemon/internal/store"
	"naust/daemon/internal/store/ent"
	entlease "naust/daemon/internal/store/ent/lease"
)

type fakeHelper struct{ calls []string }

func (f *fakeHelper) Call(_ context.Context, intent string, args map[string]string) (string, error) {
	f.calls = append(f.calls, intent+":"+args["service"])
	return "", nil
}

func testStore(t *testing.T) *ent.Client {
	t.Helper()
	client, err := store.Open(store.EngineSQLite, filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if err := client.Schema.Create(context.Background()); err != nil {
		t.Fatal(err)
	}
	tenant, err := store.EnsureDefaultTenant(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	client.User.Create().
		SetEmail("admin@example.com").SetPasswordHash("x").SetRole("admin").
		SetTenant(tenant).
		SaveX(context.Background())
	return client
}

func testTenantID(t *testing.T, client *ent.Client) int {
	t.Helper()
	tenant, err := store.EnsureDefaultTenant(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	return tenant.ID
}

// testEnv is one fully wired provisioning environment against the
// fake CA. lookups maps domains to their public DNS answers; missing
// domains do not resolve.
type testEnv struct {
	prov      *Provisioner
	selector  *StandardSelector
	fake      *fakeACME
	helper    *fakeHelper
	sslRoot   string
	sysKey    *ecdsa.PrivateKey
	kicked    int
	kickedDNS int
}

const (
	testIP      = "198.51.100.4"
	testPrimary = "box.example.com"
)

func newEnv(t *testing.T, lookups map[string][]netip.Addr) *testEnv {
	t.Helper()
	root := t.TempDir()
	sslRoot := filepath.Join(root, "ssl")
	if err := os.MkdirAll(sslRoot, 0o755); err != nil {
		t.Fatal(err)
	}

	sysKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(sysKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(filepath.Join(sslRoot, "ssl_private_key.pem"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	webroot := filepath.Join(sslRoot, "lets_encrypt", "webroot")
	fake := newFakeACME(t, webroot)
	env := &testEnv{fake: fake, helper: &fakeHelper{}, sslRoot: sslRoot, sysKey: sysKey}
	client := testStore(t)
	env.selector = &StandardSelector{
		Webroot: &Webroot{
			Dir:      webroot,
			PublicIP: testIP,
			LookupIP: func(_ context.Context, host string) ([]netip.Addr, error) {
				addrs, ok := lookups[host]
				if !ok {
					return nil, errors.New("no such host")
				}
				return addrs, nil
			},
		},
		Store: client,
	}
	env.prov = &Provisioner{
		Store:           client,
		PrimaryHostname: testPrimary,
		PublicIP:        testIP,
		StorageRoot:     root,
		DirectoryURL:    fake.directoryURL(),
		Selector:        env.selector,
		Helper:          env.helper,
		KickWeb:         func() { env.kicked++ },
		KickDNS:         func() { env.kickedDNS++ },
		Log:             log.New(os.Stderr, "", 0),
		HTTPClient:      fake.srv.Client(),
	}
	return env
}

// issueOnSystemKey installs a CA-signed certificate for domain whose
// public key is the system key, valid for the given duration.
func (e *testEnv) issueOnSystemKey(t *testing.T, base, domain string, validFor time.Duration) {
	t.Helper()
	e.fake.mu.Lock()
	e.fake.serial++
	serial := e.fake.serial
	e.fake.mu.Unlock()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validFor),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, e.fake.caCert, &e.sysKey.PublicKey, e.fake.caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(e.sslRoot, base+".pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
}

func resultFor(t *testing.T, results []Result, domain string) Result {
	t.Helper()
	for _, r := range results {
		if r.Domain == domain {
			return r
		}
	}
	t.Fatalf("no result for %s in %v", domain, results)
	return Result{}
}

func TestProvisionEndToEnd(t *testing.T) {
	our := netip.MustParseAddr(testIP)
	env := newEnv(t, map[string][]netip.Addr{
		testPrimary:              {our},
		"mta-sts.example.com":    {netip.MustParseAddr("203.0.113.9")},
		"autoconfig.example.com": {netip.MustParseAddr("2001:db8::4")},
		// autodiscover.example.com, www.example.com, example.com: no answer
	})
	env.issueOnSystemKey(t, "preissued-example.com", "example.com", 60*24*time.Hour)

	results := env.prov.Run(context.Background(), nil)

	if r := resultFor(t, results, testPrimary); r.Status != StatusInstalled {
		t.Fatalf("primary: %+v", r)
	}
	if r := resultFor(t, results, "example.com"); r.Status != StatusSkipped || !strings.Contains(r.Detail, "valid until") {
		t.Errorf("example.com: %+v", r)
	}
	if r := resultFor(t, results, "mta-sts.example.com"); r.Status != StatusSkipped || !strings.Contains(r.Detail, "203.0.113.9") {
		t.Errorf("mta-sts: %+v", r)
	}
	if r := resultFor(t, results, "autoconfig.example.com"); r.Status != StatusSkipped || !strings.Contains(r.Detail, "IPv6") {
		t.Errorf("autoconfig: %+v", r)
	}
	if r := resultFor(t, results, "autodiscover.example.com"); r.Status != StatusSkipped || !strings.Contains(r.Detail, "does not resolve") {
		t.Errorf("autodiscover: %+v", r)
	}

	// The installed chain: legacy naming, covers the domain, on the
	// system key, leaf plus issuer.
	matches, err := filepath.Glob(filepath.Join(env.sslRoot, testPrimary+"-*.pem"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("installed files = %v (%v)", matches, err)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(data)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname(testPrimary); err != nil {
		t.Error(err)
	}
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&env.sysKey.PublicKey) {
		t.Error("issued certificate is not on the system key")
	}
	if chain, _ := pem.Decode(rest); chain == nil {
		t.Error("no issuer certificate in the installed chain")
	}

	// Post-install: symlink repointed, mail services restarted, web
	// applier kicked, challenge files cleaned up.
	if target, err := os.Readlink(filepath.Join(env.sslRoot, "ssl_certificate.pem")); err != nil || target != matches[0] {
		t.Errorf("ssl_certificate.pem -> %s (%v), want %s", target, err, matches[0])
	}
	want := []string{"service.restart:postfix", "service.restart:dovecot", "service.restart:rav"}
	if strings.Join(env.helper.calls, ",") != strings.Join(want, ",") {
		t.Errorf("helper calls = %v", env.helper.calls)
	}
	if env.kicked != 1 || env.kickedDNS != 1 {
		t.Errorf("kicked = %d, kickedDNS = %d", env.kicked, env.kickedDNS)
	}
	leftover, _ := filepath.Glob(filepath.Join(env.fake.webroot, ".well-known", "acme-challenge", "*"))
	if len(leftover) != 0 {
		t.Errorf("challenge files not cleaned up: %v", leftover)
	}

	// Second run: the new certificate is seen and everything is
	// quiet - no orders, no restarts, no kicks.
	results = env.prov.Run(context.Background(), nil)
	if r := resultFor(t, results, testPrimary); r.Status != StatusSkipped {
		t.Errorf("primary after install: %+v", r)
	}
	if len(env.helper.calls) != len(want) || env.kicked != 1 || env.kickedDNS != 1 {
		t.Errorf("steady state touched the system: calls=%v kicked=%d kickedDNS=%d", env.helper.calls, env.kicked, env.kickedDNS)
	}
}

func TestRenewalReplacesExpiring(t *testing.T) {
	env := newEnv(t, map[string][]netip.Addr{
		testPrimary: {netip.MustParseAddr(testIP)},
	})
	// 10 days left: under the 30-day threshold, must renew.
	env.issueOnSystemKey(t, "expiring-box", testPrimary, 10*24*time.Hour)

	results := env.prov.Run(context.Background(), []string{testPrimary})
	if r := resultFor(t, results, testPrimary); r.Status != StatusInstalled {
		t.Fatalf("expiring cert not renewed: %+v", r)
	}
	// The symlink must point at the fresh cert, not the expiring one.
	target, err := os.Readlink(filepath.Join(env.sslRoot, "ssl_certificate.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(target, testPrimary+"-") {
		t.Errorf("symlink -> %s", target)
	}
}

// TestRenewalPassSkipsWhenLeaseHeldByAnotherProcess proves the
// scheduled sweep is actually gated by the store lease: a live lease
// held by a different process must stop this replica before it
// touches the ACME account or files, which is what prevents replicas
// from duplicating orders (and hitting Let's Encrypt's rate limits as
// a fleet) during a scheduled renewal pass.
func TestRenewalPassSkipsWhenLeaseHeldByAnotherProcess(t *testing.T) {
	env := newEnv(t, map[string][]netip.Addr{
		testPrimary: {netip.MustParseAddr(testIP)},
	})
	ctx := context.Background()

	if err := env.prov.Store.Lease.Create().
		SetName(leaseName).
		SetHolder("otherhost:9999").
		SetExpiresAt(time.Now().Add(time.Hour)).
		Exec(ctx); err != nil {
		t.Fatal(err)
	}

	env.prov.renewalPass(ctx)

	if matches, _ := filepath.Glob(filepath.Join(env.sslRoot, testPrimary+"-*.pem")); len(matches) != 0 {
		t.Errorf("certificate installed despite lease held elsewhere: %v", matches)
	}
	if len(env.helper.calls) != 0 || env.kicked != 0 || env.kickedDNS != 0 {
		t.Errorf("system touched despite lease held elsewhere: calls=%v kicked=%d kickedDNS=%d", env.helper.calls, env.kicked, env.kickedDNS)
	}
}

// TestRenewalPassRunsWhenLeaseExpired proves a crashed holder's
// lapsed lease does not permanently wedge renewals.
func TestRenewalPassRunsWhenLeaseExpired(t *testing.T) {
	env := newEnv(t, map[string][]netip.Addr{
		testPrimary: {netip.MustParseAddr(testIP)},
	})
	ctx := context.Background()

	if err := env.prov.Store.Lease.Create().
		SetName(leaseName).
		SetHolder("otherhost:9999").
		SetExpiresAt(time.Now().Add(-time.Minute)). // already lapsed
		Exec(ctx); err != nil {
		t.Fatal(err)
	}

	env.prov.renewalPass(ctx)

	if matches, _ := filepath.Glob(filepath.Join(env.sslRoot, testPrimary+"-*.pem")); len(matches) != 1 {
		t.Errorf("certificate not installed after taking over an expired lease: %v", matches)
	}
}

// TestRenewalPassReleasesLeaseOnCompletion proves the lease is
// actually released (expires_at reset to now, not left at the
// acquire-time TTL) once the sweep finishes, so the next scheduled
// pass is not blocked by a claim nobody is using anymore.
func TestRenewalPassReleasesLeaseOnCompletion(t *testing.T) {
	env := newEnv(t, map[string][]netip.Addr{
		testPrimary: {netip.MustParseAddr(testIP)},
	})
	ctx := context.Background()

	env.prov.renewalPass(ctx)

	lease, err := env.prov.Store.Lease.Query().Where(entlease.Name(leaseName)).Only(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if lease.ExpiresAt.After(time.Now().Add(time.Minute)) {
		t.Errorf("lease expires_at = %v, want released near now (not still claimed for leaseTTL)", lease.ExpiresAt)
	}
}

func TestEvilTokenRejected(t *testing.T) {
	env := newEnv(t, map[string][]netip.Addr{
		testPrimary: {netip.MustParseAddr(testIP)},
	})
	env.fake.evilToken = "../../../evil"

	results := env.prov.Run(context.Background(), []string{testPrimary})
	r := resultFor(t, results, testPrimary)
	if r.Status != StatusError || !strings.Contains(r.Detail, "malformed challenge token") {
		t.Fatalf("evil token: %+v", r)
	}
	// Nothing may have been written outside the challenge directory.
	err := filepath.WalkDir(filepath.Join(env.sslRoot, ".."), func(path string, _ os.DirEntry, err error) error {
		if err == nil && filepath.Base(path) == "evil" {
			t.Errorf("path traversal wrote %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestDNS01ViaProvider: a domain that does NOT point here but whose
// zone has a DNS provider configured gets its cert via DNS-01. The
// provider is in-memory; the real API clients have request-shape
// tests in internal/dnsprovider.
func TestDNS01ViaProvider(t *testing.T) {
	env := newEnv(t, map[string][]netip.Addr{
		// mta-sts points elsewhere: the webroot gate must fail and
		// the selector must fall through to DNS-01.
		"mta-sts.example.com": {netip.MustParseAddr("203.0.113.9")},
	})
	mem := &memProvider{}
	env.prov.Store.DNSZoneProvider.Create().
		SetZone("example.com").SetProvider("cloudflare").SetToken("cf-token").
		SetTenantID(testTenantID(t, env.prov.Store)).
		SaveX(context.Background())
	env.selector.NewProvider = func(name, token string) (dnsprovider.Provider, error) {
		if name != "cloudflare" || token != "cf-token" {
			t.Fatalf("provider %s/%s", name, token)
		}
		return mem, nil
	}
	env.selector.DNS01Wait = func(context.Context, string, string) error { return nil }
	env.fake.challengeType = "dns-01"
	env.fake.dns01Check = func(domain string) bool {
		return mem.has("_acme-challenge." + domain)
	}

	results := env.prov.Run(context.Background(), []string{"mta-sts.example.com"})
	if r := resultFor(t, results, "mta-sts.example.com"); r.Status != StatusInstalled {
		t.Fatalf("dns-01 provisioning: %+v", r)
	}
	if len(mem.created) != 1 || mem.created[0] != "_acme-challenge.mta-sts.example.com" {
		t.Errorf("created records = %v", mem.created)
	}
	if mem.zone != "example.com" {
		t.Errorf("provider zone = %s", mem.zone)
	}
	if mem.count() != 0 {
		t.Errorf("challenge TXT not cleaned up, %d records remain", mem.count())
	}
	matches, _ := filepath.Glob(filepath.Join(env.sslRoot, "mta-sts.example.com-*.pem"))
	if len(matches) != 1 {
		t.Errorf("installed files = %v", matches)
	}
}

func TestAccountKeyReuse(t *testing.T) {
	env := newEnv(t, map[string][]netip.Addr{
		testPrimary: {netip.MustParseAddr(testIP)},
	})
	ctx := context.Background()
	if r := resultFor(t, env.prov.Run(ctx, []string{testPrimary}), testPrimary); r.Status != StatusInstalled {
		t.Fatalf("first run: %+v", r)
	}
	keyPath := filepath.Join(env.sslRoot, "lets_encrypt", "account_key.pem")
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	// Force reprovisioning by removing the installed cert, then run
	// again: same account key, and the CA's "already registered"
	// response is tolerated.
	matches, _ := filepath.Glob(filepath.Join(env.sslRoot, testPrimary+"-*.pem"))
	for _, m := range matches {
		os.Remove(m)
	}
	os.Remove(filepath.Join(env.sslRoot, "ssl_certificate.pem"))

	if r := resultFor(t, env.prov.Run(ctx, []string{testPrimary}), testPrimary); r.Status != StatusInstalled {
		t.Fatalf("second run: %+v", r)
	}
	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("account key was regenerated")
	}
	if env.fake.regs != 2 {
		t.Errorf("registrations = %d", env.fake.regs)
	}
}

// TestAsyncFinalize pins the fallback for CAs that answer finalize
// with "processing" and no Location header (Pebble does; RFC 8555
// allows it): the client polls the order URL from creation instead.
func TestAsyncFinalize(t *testing.T) {
	env := newEnv(t, map[string][]netip.Addr{
		testPrimary: {netip.MustParseAddr(testIP)},
	})
	env.fake.asyncFinalize = true
	r := resultFor(t, env.prov.Run(context.Background(), []string{testPrimary}), testPrimary)
	if r.Status != StatusInstalled {
		t.Fatalf("run = %+v", r)
	}
	if _, err := os.Readlink(filepath.Join(env.sslRoot, "ssl_certificate.pem")); err != nil {
		t.Error(err)
	}
}
