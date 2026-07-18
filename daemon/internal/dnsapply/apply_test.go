package dnsapply

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"naust/daemon/internal/store"
	"naust/daemon/internal/store/ent"
	entdnsrecord "naust/daemon/internal/store/ent/dnsrecord"
)

var testNow = time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)

// fakeRunner emulates ldns-signzone (creates the .signed file with a
// fresh RRSIG) and ldns-key2ds (returns a DS line).
type fakeRunner struct {
	mu    sync.Mutex
	calls [][]string
}

func (f *fakeRunner) record(argv []string) {
	f.mu.Lock()
	f.calls = append(f.calls, argv)
	f.mu.Unlock()
}

func (f *fakeRunner) Run(_ context.Context, argv []string) error {
	f.record(argv)
	if argv[0] == "ldns-signzone" {
		zonePath := argv[4]
		expiry := testNow.Add(30 * 24 * time.Hour).Format("20060102150405")
		signed := "signed zone\nexample.com. 86400 IN RRSIG SOA 8 2 86400 " + expiry + " 20260601000000 12345 example.com. sig==\n"
		return os.WriteFile(zonePath+".signed", []byte(signed), 0o640)
	}
	return nil
}

func (f *fakeRunner) Output(_ context.Context, argv []string) (string, error) {
	f.record(argv)
	return "example.com. IN DS 12345 8 2 abcdef\n", nil
}

func (f *fakeRunner) count(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c[0] == name {
			n++
		}
	}
	return n
}

type env struct {
	a       *Applier
	runner  *fakeRunner
	client  *ent.Client
	reloads []string
	tid     int
}

func newEnv(t *testing.T) *env {
	t.Helper()
	client, err := store.Open(store.EngineSQLite, filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	ctx := context.Background()
	if err := client.Schema.Create(ctx); err != nil {
		t.Fatal(err)
	}
	tenant, err := store.EnsureDefaultTenant(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	client.User.Create().SetEmail("admin@example.com").SetPasswordHash("{BLF-CRYPT}x").SetTenantID(tenant.ID).SaveX(ctx)

	e := &env{runner: &fakeRunner{}, client: client, tid: tenant.ID}
	dir := t.TempDir()
	e.a = &Applier{
		Store:           client,
		ZonesDir:        filepath.Join(dir, "zones"),
		NSDConfPath:     filepath.Join(dir, "zones.conf"),
		DNSSECDir:       filepath.Join(dir, "dnssec"), // absent: unsigned by default
		DKIMTxtPath:     filepath.Join(dir, "mail.txt"),
		PrimaryHostname: "box.example.com",
		PublicIP:        "203.0.113.1",
		Run:             e.runner,
		Reload: func(_ context.Context, service string) error {
			e.reloads = append(e.reloads, service)
			return nil
		},
		Now: func() time.Time { return testNow },
		Log: log.New(os.Stderr, "", 0),
	}
	return e
}

func (e *env) withDNSSECKeys(t *testing.T) {
	t.Helper()
	dir := e.a.DNSSECDir
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"ECDSAP256SHA256.conf": "KSK=Kksk_domain_\nZSK=Kzsk_domain_\n",
		"Kksk_domain_.private": "ksk private for _domain_",
		"Kksk_domain_.key":     "ksk public for _domain_",
		"Kzsk_domain_.private": "zsk private for _domain_",
		"Kzsk_domain_.key":     "zsk public for _domain_",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRebuildUnsigned(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.a.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}

	zone, err := os.ReadFile(filepath.Join(e.a.ZonesDir, "example.com.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(zone), "2026070800       ; serial number") {
		t.Errorf("zone missing date serial:\n%s", zone)
	}
	conf, err := os.ReadFile(e.a.NSDConfPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(conf), "zonefile: example.com.txt\n") {
		t.Errorf("nsd.conf must serve the unsigned file:\n%s", conf)
	}
	if e.runner.count("ldns-signzone") != 0 {
		t.Error("no signing without keys")
	}
	if len(e.reloads) != 2 || e.reloads[0] != "nsd" || e.reloads[1] != "unbound" {
		t.Errorf("reloads = %v", e.reloads)
	}

	// Second run: nothing changed, nothing rewritten, no reloads.
	e.reloads = nil
	before, _ := os.Stat(filepath.Join(e.a.ZonesDir, "example.com.txt"))
	if err := e.a.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(filepath.Join(e.a.ZonesDir, "example.com.txt"))
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("unchanged zone must not be rewritten")
	}
	if len(e.reloads) != 0 {
		t.Errorf("no-op rebuild reloaded: %v", e.reloads)
	}
}

func TestRebuildSignedAndSerialBump(t *testing.T) {
	e := newEnv(t)
	e.withDNSSECKeys(t)
	ctx := context.Background()
	if err := e.a.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(e.a.ZonesDir, "example.com.txt.signed")); err != nil {
		t.Fatal("signed zone missing")
	}
	ds, err := os.ReadFile(filepath.Join(e.a.ZonesDir, "example.com.txt.ds"))
	if err != nil || !strings.Contains(string(ds), " IN DS ") {
		t.Errorf("DS records: %s, %v", ds, err)
	}
	// One KSK, three digest types.
	if e.runner.count("ldns-key2ds") != 3 {
		t.Errorf("key2ds calls = %d, want 3", e.runner.count("ldns-key2ds"))
	}
	conf, _ := os.ReadFile(e.a.NSDConfPath)
	if !strings.Contains(string(conf), "zonefile: example.com.txt.signed\n") {
		t.Errorf("nsd.conf must serve the signed file:\n%s", conf)
	}

	// No-op run signs nothing further.
	if err := e.a.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	if e.runner.count("ldns-signzone") != 1 {
		t.Errorf("signzone calls after no-op = %d, want 1", e.runner.count("ldns-signzone"))
	}

	// An alias at an existing mail domain adds nothing to the zone, so
	// nothing may be rewritten or re-signed.
	e.client.Alias.Create().SetSource("sales@example.com").SetDestinations([]string{"admin@example.com"}).SetTenantID(e.tid).SaveX(ctx)
	if err := e.a.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	if e.runner.count("ldns-signzone") != 1 {
		t.Errorf("DNS-neutral change must not re-sign: calls = %d", e.runner.count("ldns-signzone"))
	}

	// A real record change bumps the serial (same day: increment).
	e.client.DNSRecord.Create().SetQname("test.example.com").SetRtype(entdnsrecord.RtypeA).SetValue("1.2.3.4").SetTenantID(e.tid).SaveX(ctx)
	if err := e.a.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	zone, _ := os.ReadFile(filepath.Join(e.a.ZonesDir, "example.com.txt"))
	if !strings.Contains(string(zone), "2026070801       ; serial number") {
		t.Errorf("serial must increment same-day:\n%s", zone)
	}
	if e.runner.count("ldns-signzone") != 2 {
		t.Errorf("change must re-sign: calls = %d", e.runner.count("ldns-signzone"))
	}
}

func TestSignatureRenewalForcesResign(t *testing.T) {
	e := newEnv(t)
	e.withDNSSECKeys(t)
	ctx := context.Background()
	if err := e.a.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}

	// Overwrite the signed file with one whose signature is nearly
	// expired; content in the store is unchanged.
	stale := "signed zone\nexample.com. 86400 IN RRSIG SOA 8 2 86400 " +
		testNow.Add(24*time.Hour).Format("20060102150405") + " 20260601000000 12345 example.com. sig==\n"
	if err := os.WriteFile(filepath.Join(e.a.ZonesDir, "example.com.txt.signed"), []byte(stale), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := e.a.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	if e.runner.count("ldns-signzone") != 2 {
		t.Errorf("near-expiry signature must force re-sign: calls = %d", e.runner.count("ldns-signzone"))
	}
	zone, _ := os.ReadFile(filepath.Join(e.a.ZonesDir, "example.com.txt"))
	if !strings.Contains(string(zone), "2026070801       ; serial number") {
		t.Errorf("re-sign must bump the serial:\n%s", zone)
	}
}

func TestOpenDKIMTables(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	dir := t.TempDir()
	e.a.OpenDKIMDir = dir
	e.a.DKIMKeyPath = filepath.Join(dir, "mail.private")
	if err := os.WriteFile(e.a.DKIMKeyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := e.a.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	signing, err := os.ReadFile(filepath.Join(dir, "SigningTable"))
	if err != nil {
		t.Fatal(err)
	}
	if string(signing) != "*@example.com example.com\n" {
		t.Errorf("SigningTable = %q", signing)
	}
	key, _ := os.ReadFile(filepath.Join(dir, "KeyTable"))
	if !strings.Contains(string(key), "example.com example.com:mail:"+e.a.DKIMKeyPath) {
		t.Errorf("KeyTable = %q", key)
	}
	if e.reloads[len(e.reloads)-1] != "opendkim" {
		t.Errorf("reloads = %v, want opendkim last", e.reloads)
	}

	// Unchanged tables: no reload.
	e.reloads = nil
	if err := e.a.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	for _, r := range e.reloads {
		if r == "opendkim" {
			t.Error("unchanged tables must not reload opendkim")
		}
	}
}

func TestDKIMRecordFlowsIntoZone(t *testing.T) {
	e := newEnv(t)
	dkim := `mail._domainkey IN TXT ( "v=DKIM1; k=rsa; " "p=MIIBIjANBg" )` + "\n"
	if err := os.WriteFile(e.a.DKIMTxtPath, []byte(dkim), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := e.a.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	zone, _ := os.ReadFile(filepath.Join(e.a.ZonesDir, "example.com.txt"))
	if !strings.Contains(string(zone), `mail._domainkey	IN	TXT	"v=DKIM1; k=rsa; p=MIIBIjANBg"`) {
		t.Errorf("DKIM record missing from zone:\n%s", zone)
	}
}

func TestSPFIncludeFlowsIntoZone(t *testing.T) {
	e := newEnv(t)
	e.client.Setting.Create().
		SetKey(settingSMTPRelay).
		SetValue(`{"host":"smtp.sendgrid.net","port":587,"user":"apikey","spf_include":"sendgrid.net"}`).
		SaveX(context.Background())
	if err := e.a.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	zone, _ := os.ReadFile(filepath.Join(e.a.ZonesDir, "example.com.txt"))
	if !strings.Contains(string(zone), `"v=spf1 mx include:sendgrid.net -all"`) {
		t.Errorf("SPF include missing from zone:\n%s", zone)
	}
}

func TestTransferAddresses(t *testing.T) {
	e := newEnv(t)
	e.a.LookupHost = func(_ context.Context, host string) ([]string, error) {
		if host == "ns2.other.net" {
			return []string{"198.51.100.7"}, nil
		}
		return nil, os.ErrNotExist
	}
	got, err := e.a.transferAddresses(context.Background(),
		[]string{"ns2.other.net", "xfr:10.0.0.0/8", "gone.example"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.7", "10.0.0.0/8"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("addresses = %v, want %v", got, want)
	}
}

func TestFindSigningKeysDomainFilter(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"all.conf":    "KSK=Ka\nZSK=Kb\n",
		"scoped.conf": "KSK=Kc\nZSK=Kd\nDOMAINS=only.example\n",
		"none.conf":   "KSK=Ke\nZSK=Kf\nDOMAINS=none\n",
		"notes.txt":   "ignored",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := findSigningKeys(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].base != "Ka" || keys[1].base != "Kb" {
		t.Errorf("keys = %+v, want only the unscoped conf", keys)
	}
	keys, _ = findSigningKeys(dir, "only.example")
	if len(keys) != 4 {
		t.Errorf("scoped domain: %d keys, want 4", len(keys))
	}
}

func TestKeysHashStates(t *testing.T) {
	if h, err := keysHash(filepath.Join(t.TempDir(), "absent"), "example.com"); err != nil || h != "unsigned" {
		t.Errorf("absent dir: %q, %v", h, err)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.conf"), []byte("KSK=Kk\nZSK=Kz\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "Kk.private"), []byte("k1"), 0o600)
	os.WriteFile(filepath.Join(dir, "Kz.private"), []byte("z1"), 0o600)
	h1, err := keysHash(dir, "example.com")
	if err != nil || h1 == "unsigned" {
		t.Fatalf("hash: %q, %v", h1, err)
	}
	// Key rotation changes the hash.
	os.WriteFile(filepath.Join(dir, "Kz.private"), []byte("z2"), 0o600)
	if h2, _ := keysHash(dir, "example.com"); h2 == h1 {
		t.Error("rotated key must change the hash")
	}
}
