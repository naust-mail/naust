package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"naust/daemon/internal/webrender"
)

func managedFile(body string) string {
	return webrender.ManagedMark + "\n# template-version: 1\n\n" + body
}

func readDirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// validHost is a minimal primary host that passes webrender.Render's field
// validation, for exercising the full payload -> render -> reconcile path.
func validHost() webrender.Host {
	return webrender.Host{
		Domain:   "box.example.com",
		Primary:  true,
		CertFile: "/tmp/cert.pem",
		KeyFile:  "/tmp/key.pem",
		HSTS:     "off",
	}
}

func validConfig() webrender.Config {
	return webrender.Config{ACMEWebroot: "/tmp/acme/webroot"}
}

// TestWebSyncValidation covers the intent's front door: the payload must
// decode, and webrender.Render (the trust boundary) must reject any host field
// that could inject nginx. A validation failure must run nothing.
func TestWebSyncValidation(t *testing.T) {
	run := &fakeRunner{}
	d := Deps{Run: run, Root: t.TempDir()}

	hostileBackend := validHost()
	hostileBackend.Mounts = []webrender.Mount{
		{App: "webmail-rav", Path: "/", BackendHost: "bad;host", BackendPort: 8080},
	}

	payload := func(cfg webrender.Config, hosts ...webrender.Host) map[string]string {
		args, err := EncodePayload(cfg, hosts)
		if err != nil {
			t.Fatal(err)
		}
		return args
	}

	cases := []struct {
		name string
		args map[string]string
		want string
	}{
		{"not a payload", map[string]string{"payload": "nope"}, "valid sync payload"},
		{"unsafe domain", payload(validConfig(), webrender.Host{Domain: "../evil"}), "unsafe domain"},
		{"unsafe backend host", payload(validConfig(), hostileBackend), "unsafe backend host"},
		{"unsafe acme webroot", payload(webrender.Config{ACMEWebroot: "/tmp/a;rm"}, validHost()), "unsafe ACME webroot"},
		{"missing arg", map[string]string{}, "do not match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := dispatch(t, d, "web.sync_sites", tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
	if len(run.calls) != 0 {
		t.Fatalf("validation failures must not execute anything; ran %v", run.calls)
	}
}

// TestWebSyncRendersPayloadThroughIntent proves the whole privileged
// path: a valid routing model is rendered by helperd, the managed files
// land on disk, and nginx is tested then reloaded.
func TestWebSyncRendersPayloadThroughIntent(t *testing.T) {
	root := t.TempDir()
	run := &fakeRunner{}
	d := Deps{Run: run, Root: root}

	args, err := EncodePayload(validConfig(), []webrender.Host{validHost()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Dispatch(context.Background(), d,
		Request{Intent: "web.sync_sites", Args: args}); err != nil {
		t.Fatal(err)
	}

	wantCalls := [][]string{
		{"/usr/sbin/nginx", "-t"},
		{"/usr/bin/systemctl", "reload", "nginx"},
	}
	if !reflect.DeepEqual(run.calls, wantCalls) {
		t.Fatalf("calls %v, want %v", run.calls, wantCalls)
	}
	names := readDirNames(t, filepath.Join(root, sitesDir))
	want := []string{"00-top.conf", "box.example.com.conf"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("dir %v, want %v", names, want)
	}
}

func TestWebSyncReconcilesTestsReloads(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, sitesDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Disk before: one stale managed file, one managed file to update,
	// one hand-written foreign file, one ejected copy colliding with an
	// incoming name.
	writeAll := map[string]string{
		"stale.example.com.conf": managedFile("old vhost\n"),
		"box.example.com.conf":   managedFile("old content\n"),
		"byhand.conf":            "# my own nginx config\nserver {}\n",
		"ejected.example.com.conf": strings.Replace(
			managedFile("frozen copy\n"), webrender.ManagedMark, "# ejected from naust-web", 1),
	}
	for name, content := range writeAll {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	run := &fakeRunner{}
	d := Deps{Run: run, Root: root}
	incoming := map[string]string{
		"00-top.conf":              managedFile("map {}\n"),
		"box.example.com.conf":     managedFile("new content\n"),
		"ejected.example.com.conf": managedFile("would clobber\n"),
	}
	result, err := reconcile(context.Background(), d, incoming)
	if err != nil {
		t.Fatal(err)
	}

	// nginx -t must run before the reload.
	wantCalls := [][]string{
		{"/usr/sbin/nginx", "-t"},
		{"/usr/bin/systemctl", "reload", "nginx"},
	}
	if !reflect.DeepEqual(run.calls, wantCalls) {
		t.Fatalf("calls %v, want %v", run.calls, wantCalls)
	}

	want := []string{"00-top.conf", "box.example.com.conf", "byhand.conf", "ejected.example.com.conf"}
	if got := readDirNames(t, dir); !reflect.DeepEqual(got, want) {
		t.Fatalf("dir %v, want %v", got, want)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "box.example.com.conf"))
	if string(got) != incoming["box.example.com.conf"] {
		t.Fatalf("managed file not updated: %q", got)
	}
	got, _ = os.ReadFile(filepath.Join(dir, "ejected.example.com.conf"))
	if !strings.Contains(string(got), "frozen copy") {
		t.Fatalf("user-owned collision was clobbered: %q", got)
	}
	fi, err := os.Stat(filepath.Join(dir, "00-top.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v, want 0644", fi.Mode().Perm())
	}

	// The response inventories both user-owned files; the ejected copy
	// keeps its version stamp, the hand-written one has none.
	res, err := DecodeSyncResult(result)
	if err != nil {
		t.Fatal(err)
	}
	wantSkipped := []SkippedFile{
		{File: "byhand.conf", TemplateVersion: 0},
		{File: "ejected.example.com.conf", TemplateVersion: 1},
	}
	if !reflect.DeepEqual(res.Skipped, wantSkipped) {
		t.Fatalf("skipped %v, want %v", res.Skipped, wantSkipped)
	}
}

func TestWebSyncRollbackOnTestFailure(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, sitesDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	before := map[string]string{
		"keep.example.com.conf":  managedFile("current\n"),
		"stale.example.com.conf": managedFile("stale\n"),
	}
	for name, content := range before {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	run := &fakeRunner{failOn: map[string]error{"nginx": errors.New("emerg: unknown directive")}}
	d := Deps{Run: run, Root: root}
	_, err := reconcile(context.Background(), d, map[string]string{
		"keep.example.com.conf": managedFile("broken update\n"),
		"new.example.com.conf":  managedFile("brand new\n"),
	})
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("want rollback error, got %v", err)
	}

	// Disk must be exactly the pre-sync state again.
	if got := readDirNames(t, dir); !reflect.DeepEqual(got, []string{"keep.example.com.conf", "stale.example.com.conf"}) {
		t.Fatalf("dir after rollback: %v", got)
	}
	for name, content := range before {
		got, _ := os.ReadFile(filepath.Join(dir, name))
		if string(got) != content {
			t.Fatalf("%s not restored: %q", name, got)
		}
	}
	// No reload after a failed test.
	for _, argv := range run.calls {
		if argv[len(argv)-1] == "nginx" && argv[0] == "/usr/bin/systemctl" {
			t.Fatal("reload must not run after nginx -t failure")
		}
	}
}

func TestWebSyncEmptySetDeletesManagedOnly(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, sitesDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "ours.conf"), []byte(managedFile("x\n")), 0o644)
	os.WriteFile(filepath.Join(dir, "theirs.conf"), []byte("# hand-written\n"), 0o644)

	d := Deps{Run: &fakeRunner{}, Root: root}
	if _, err := reconcile(context.Background(), d, map[string]string{}); err != nil {
		t.Fatal(err)
	}
	if got := readDirNames(t, dir); !reflect.DeepEqual(got, []string{"theirs.conf"}) {
		t.Fatalf("dir %v, want only theirs.conf", got)
	}
}

func TestWebSyncNoChangeSkipsReload(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, sitesDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"a.example.com.conf": managedFile("same\n")}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := &fakeRunner{}
	d := Deps{Run: run, Root: root}
	if _, err := reconcile(context.Background(), d, files); err != nil {
		t.Fatal(err)
	}
	if len(run.calls) != 0 {
		t.Fatalf("identical fileset must not test or reload nginx; ran %v", run.calls)
	}
}

func TestWebSyncReloadFailureKeepsFiles(t *testing.T) {
	root := t.TempDir()
	run := &fakeRunner{failOn: map[string]error{"systemctl": errors.New("not running")}}
	d := Deps{Run: run, Root: root}

	_, err := reconcile(context.Background(), d, map[string]string{
		"a.example.com.conf": managedFile("valid\n"),
	})
	if err == nil || !strings.Contains(err.Error(), "reload failed") {
		t.Fatalf("want reload error, got %v", err)
	}
	// nginx -t passed, so the valid config stays for the next start.
	if _, statErr := os.Stat(filepath.Join(root, sitesDir, "a.example.com.conf")); statErr != nil {
		t.Fatalf("valid config must stay on disk: %v", statErr)
	}
}
