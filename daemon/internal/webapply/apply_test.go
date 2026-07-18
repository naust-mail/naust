package webapply

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"naust/daemon/internal/helper"
	"naust/daemon/internal/store"
	"naust/daemon/internal/store/ent"
	"naust/daemon/internal/web"
)

// fakeHelper records sync calls and returns an empty inventory.
type fakeHelper struct {
	intents []string
	args    []map[string]string
}

func (f *fakeHelper) Call(_ context.Context, intent string, args map[string]string) (string, error) {
	f.intents = append(f.intents, intent)
	f.args = append(f.args, args)
	return `{}`, nil
}

func confMap(m map[string]string) func(string) string {
	return func(key string) string { return m[key] }
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
	return client
}

func tenantID(t *testing.T, client *ent.Client) int {
	t.Helper()
	tenant, err := store.EnsureDefaultTenant(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	return tenant.ID
}

// seedBox creates the reference scenario: a login domain, an
// alias-only domain pointed elsewhere by a custom A record, a
// customized domain row, and a filebrowser mount override.
func seedBox(t *testing.T, client *ent.Client) {
	t.Helper()
	ctx := context.Background()
	tid := tenantID(t, client)
	client.User.Create().
		SetEmail("admin@example.com").SetPasswordHash("x").SetRole("admin").
		SetTenantID(tid).
		SaveX(ctx)
	client.Alias.Create().
		SetSource("sales@pointed.net").SetDestinations([]string{"admin@example.com"}).
		SetTenantID(tid).
		SaveX(ctx)
	client.DNSRecord.Create().
		SetQname("pointed.net").SetRtype("A").SetValue("203.0.113.9").
		SetTenantID(tid).
		SaveX(ctx)

	wd := client.WebDomain.Create().
		SetDomain("example.com").SetHsts("preload").
		SetTenantID(tid).
		SaveX(ctx)
	client.WebRule.Create().
		SetKind("proxy").SetPath("/app").SetTarget("http://127.0.0.1:9000").
		SetWebSockets(true).SetDomain(wd).
		SaveX(ctx)

	client.Setting.Create().
		SetKey(SettingMounts).SetValue(`{"filebrowser":"/data"}`).
		SaveX(ctx)
}

func testApplier(t *testing.T, client *ent.Client, conf map[string]string) (*Applier, *fakeHelper) {
	t.Helper()
	fh := &fakeHelper{}
	return &Applier{
		Store:           client,
		Conf:            confMap(conf),
		PrimaryHostname: "box.example.com",
		PublicIP:        "198.51.100.4",
		StorageRoot:     t.TempDir(),
		PHPSocket:       "/run/php/php-test.sock",
		Helper:          fh,
		Log:             log.New(os.Stderr, "", 0),
	}, fh
}

func TestBuildHosts(t *testing.T) {
	client := testStore(t)
	seedBox(t, client)
	a, _ := testApplier(t, client, map[string]string{
		"MONITORING_TOOL": "none",
		"ENABLE_RADICALE": "false",
		"WEBMAIL_HOST":    "webmail",
	})
	// Give example.com its own web root and an include file.
	if err := os.MkdirAll(filepath.Join(a.StorageRoot, "www", "example.com"), 0o755); err != nil {
		t.Fatal(err)
	}
	inc := filepath.Join(a.StorageRoot, "www", "example.com.conf")
	if err := os.WriteFile(inc, []byte("# extra\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	in, err := LoadInput(ctx, client, a.PrimaryHostname, a.PublicIP, a.PublicIPv6)
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := a.BuildHosts(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	byDomain := map[string]web.Host{}
	for _, h := range hosts {
		byDomain[h.Domain] = h
	}

	// The domain pointed elsewhere gets no vhost; its www redirect and
	// the box services for the login domain are all present.
	if _, ok := byDomain["pointed.net"]; ok {
		t.Error("pointed.net must not be served")
	}
	for _, want := range []string{
		"box.example.com", "example.com", "www.example.com",
		"autoconfig.example.com", "autodiscover.example.com",
		"mta-sts.example.com", "mta-sts.pointed.net", "www.pointed.net",
	} {
		if _, ok := byDomain[want]; !ok {
			t.Errorf("missing host %s", want)
		}
	}
	if r := byDomain["www.example.com"]; r.RedirectTo != "example.com" {
		t.Errorf("www redirect = %q", r.RedirectTo)
	}

	// Primary: default mounts (rav by default, filebrowser
	// moved to /data by the setting) and nothing disabled.
	primary := byDomain["box.example.com"]
	if !primary.Primary {
		t.Fatal("primary flag missing")
	}
	mounts := map[string]web.Mount{}
	for _, m := range primary.Mounts {
		mounts[m.App] = m
	}
	if m := mounts["webmail-rav"]; m.Path != "/" || m.BackendHost != "webmail" || m.BackendPort != 3001 {
		t.Errorf("webmail mount = %+v", m)
	}
	if m := mounts["filebrowser"]; m.Path != "/data" {
		t.Errorf("filebrowser mount = %+v", m)
	}
	if m := mounts["admin"]; m.Path != "/admin" || m.BackendHost != "127.0.0.1" {
		t.Errorf("admin mount = %+v", m)
	}
	for _, off := range []string{"radicale", "netdata", "beszel"} {
		if _, ok := mounts[off]; ok {
			t.Errorf("%s must not be mounted", off)
		}
	}

	// Customized domain: HSTS level, own root, include hatch, rule.
	ex := byDomain["example.com"]
	if ex.HSTS != "preload" {
		t.Errorf("hsts = %q", ex.HSTS)
	}
	if ex.Root != filepath.Join(a.StorageRoot, "www", "example.com") {
		t.Errorf("root = %q", ex.Root)
	}
	if ex.Include != inc {
		t.Errorf("include = %q", ex.Include)
	}
	if len(ex.Rules) != 1 || ex.Rules[0].Kind != "proxy" || !ex.Rules[0].WebSockets {
		t.Errorf("rules = %+v", ex.Rules)
	}

	// Uncustomized domain: defaults and the shared default root.
	auto := byDomain["autoconfig.example.com"]
	if auto.HSTS != "on" || auto.Root != filepath.Join(a.StorageRoot, "www", "default") {
		t.Errorf("autoconfig host = %+v", auto)
	}
}

func TestResolveMountsFallbacks(t *testing.T) {
	client := testStore(t)
	ctx := context.Background()
	client.User.Create().
		SetEmail("admin@example.com").SetPasswordHash("x").SetRole("admin").
		SetTenantID(tenantID(t, client)).
		SaveX(ctx)

	// A PHP webmail cannot leave root, and a path collision with a
	// fixed mount falls back to the service default.
	client.Setting.Create().
		SetKey(SettingMounts).SetValue(`{"webmail":"/mail","filebrowser":"/admin"}`).
		SaveX(ctx)
	a, _ := testApplier(t, client, map[string]string{
		"WEBMAIL_CLIENT":  "roundcube",
		"MONITORING_TOOL": "none",
		"ENABLE_RADICALE": "false",
	})
	mounts, err := a.resolveMounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byApp := map[string]string{}
	for _, m := range mounts {
		byApp[m.App] = m.Path
	}
	if byApp["webmail-roundcube"] != "/" {
		t.Errorf("roundcube path = %q, want / (cannot leave root)", byApp["webmail-roundcube"])
	}
	if byApp["filebrowser"] != "/files" {
		t.Errorf("filebrowser path = %q, want /files fallback", byApp["filebrowser"])
	}
}

// TestResolveMountsRejectsMalformedSetting proves a corrupted
// web_mounts row (hand-edited, or a future writer bug) fails loudly
// instead of resolveMounts silently falling back to an empty override
// map, which would look like every override was simply cleared.
func TestResolveMountsRejectsMalformedSetting(t *testing.T) {
	client := testStore(t)
	ctx := context.Background()
	client.User.Create().
		SetEmail("admin@example.com").SetPasswordHash("x").SetRole("admin").
		SetTenantID(tenantID(t, client)).
		SaveX(ctx)
	client.Setting.Create().
		SetKey(SettingMounts).SetValue(`not json`).
		SaveX(ctx)

	a, _ := testApplier(t, client, map[string]string{
		"MONITORING_TOOL": "none",
		"ENABLE_RADICALE": "false",
	})
	if _, err := a.resolveMounts(ctx); err == nil {
		t.Fatal("malformed web_mounts setting silently accepted")
	}
}

func TestRebuildSyncsRenderedFileset(t *testing.T) {
	client := testStore(t)
	seedBox(t, client)
	a, fh := testApplier(t, client, map[string]string{
		"MONITORING_TOOL": "none",
		"ENABLE_RADICALE": "false",
	})

	if err := a.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fh.intents) != 1 || fh.intents[0] != "web.sync_sites" {
		t.Fatalf("intents = %v", fh.intents)
	}
	var files map[string]string
	if err := json.Unmarshal([]byte(fh.args[0]["files"]), &files); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{web.TopFile, "box.example.com.conf", "example.com.conf", "www.example.com.conf"} {
		if _, ok := files[want]; !ok {
			t.Errorf("fileset missing %s (have %d files)", want, len(files))
		}
	}
	if _, ok := files["pointed.net.conf"]; ok {
		t.Error("pointed.net.conf must not be rendered")
	}
	// The fileset must satisfy the sync intent's own validation.
	if _, err := helper.EncodeSyncArgs(files); err != nil {
		t.Fatal(err)
	}
}

// failingHelper always errors, so Rebuild's error-wrapping around the
// sync_sites call is actually exercised rather than only its happy
// path.
type failingHelper struct{ err error }

func (f *failingHelper) Call(context.Context, string, map[string]string) (string, error) {
	return "", f.err
}

func TestRebuildErrorsWhenHelperCallFails(t *testing.T) {
	client := testStore(t)
	seedBox(t, client)
	a, _ := testApplier(t, client, map[string]string{
		"MONITORING_TOOL": "none",
		"ENABLE_RADICALE": "false",
	})
	a.Helper = &failingHelper{err: errors.New("helper socket unreachable")}

	err := a.Rebuild(context.Background())
	if err == nil || !strings.Contains(err.Error(), "helper socket unreachable") {
		t.Fatalf("err = %v, want it to wrap the helper failure", err)
	}
}

// malformedResultHelper returns a sync_sites reply the JSON decoder
// cannot parse, simulating a protocol mismatch between managerd and
// helperd.
type malformedResultHelper struct{}

func (malformedResultHelper) Call(context.Context, string, map[string]string) (string, error) {
	return "not json", nil
}

func TestRebuildErrorsOnMalformedSyncResult(t *testing.T) {
	client := testStore(t)
	seedBox(t, client)
	a, _ := testApplier(t, client, map[string]string{
		"MONITORING_TOOL": "none",
		"ENABLE_RADICALE": "false",
	})
	a.Helper = malformedResultHelper{}

	if err := a.Rebuild(context.Background()); err == nil {
		t.Fatal("malformed sync_sites result silently accepted")
	}
}
