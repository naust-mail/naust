package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"naust/daemon/internal/registry"
)

var testCfg = Config{
	ACMEWebroot: "/home/user-data/ssl/lets_encrypt/webroot",
	PHPSocket:   "/run/php/php8.3-fpm.sock",
}

// baseHosts covers the default box shape: primary with rav at
// root plus the standard mounts, a static secondary domain, a www
// redirect, and a fully customized domain (all rule kinds, preload
// HSTS, include hatch, static serving off).
func baseHosts() []Host {
	return []Host{
		{
			Domain:   "box.example.com",
			Primary:  true,
			CertFile: "/home/user-data/ssl/ssl_certificate.pem",
			KeyFile:  "/home/user-data/ssl/ssl_private_key.pem",
			CertHash: "abc123",
			Root:     "/home/user-data/www/default",
			HSTS:     "on",
			Mounts: []Mount{
				{App: "admin", Path: "/admin", BackendHost: "127.0.0.1", BackendPort: 10223},
				{App: "webmail-rav", Path: "/", BackendHost: "127.0.0.1", BackendPort: 3001},
				{App: "radicale", Path: "/radicale", BackendHost: "127.0.0.1", BackendPort: 5232},
				{App: "filebrowser", Path: "/files", BackendHost: "127.0.0.1", BackendPort: 8080},
				{App: "netdata", Path: "/admin/netdata", BackendHost: "127.0.0.1", BackendPort: 19999},
			},
		},
		{
			Domain:   "example.com",
			CertFile: "/home/user-data/ssl/example.com/ssl_certificate.pem",
			KeyFile:  "/home/user-data/ssl/example.com/ssl_private_key.pem",
			Root:     "/home/user-data/www/example.com",
			HSTS:     "on",
		},
		{
			Domain:     "www.example.com",
			CertFile:   "/home/user-data/ssl/www.example.com/ssl_certificate.pem",
			KeyFile:    "/home/user-data/ssl/www.example.com/ssl_private_key.pem",
			RedirectTo: "example.com",
		},
		{
			Domain:   "apps.example.com",
			CertFile: "/home/user-data/ssl/apps.example.com/ssl_certificate.pem",
			KeyFile:  "/home/user-data/ssl/apps.example.com/ssl_private_key.pem",
			HSTS:     "preload",
			Include:  "/home/user-data/www/apps.example.com.conf",
			Rules: []Rule{
				{Kind: "proxy", Path: "/", Target: "http://127.0.0.1:9000/",
					PassHostHeader: true, NoProxyRedirect: true, FrameSameOrigin: true, WebSockets: true},
				{Kind: "alias", Path: "/downloads/", Target: "/home/user-data/downloads/"},
				{Kind: "redirect", Path: "^/old/(.*)", Target: "https://example.com/new/$1"},
			},
		},
	}
}

// phpHosts covers the PHP webmail variant (roundcube) plus beszel with
// its trusted identity header, and rav mounted at a subpath.
func phpHosts() []Host {
	return []Host{
		{
			Domain:   "box2.example.net",
			Primary:  true,
			CertFile: "/home/user-data/ssl/ssl_certificate.pem",
			KeyFile:  "/home/user-data/ssl/ssl_private_key.pem",
			Root:     "/home/user-data/www/default",
			HSTS:     "on",
			Mounts: []Mount{
				{App: "admin", Path: "/admin", BackendHost: "management", BackendPort: 10223},
				{App: "webmail-roundcube", Path: "/"},
				{App: "beszel", Path: "/admin/beszel", BackendHost: "beszel-hub", BackendPort: 8090, AuthUser: "admin@example.net"},
			},
		},
	}
}

// pathMountHosts exercises openPrefix for a proxy app off root.
func pathMountHosts() []Host {
	return []Host{
		{
			Domain:   "box3.example.org",
			Primary:  true,
			CertFile: "/c.pem",
			KeyFile:  "/k.pem",
			Root:     "/home/user-data/www/default",
			HSTS:     "on",
			Mounts: []Mount{
				{App: "webmail-rav", Path: "/mail", BackendHost: "webmail", BackendPort: 3001},
				{App: "munin", Path: "/admin/munin", BackendHost: "127.0.0.1", BackendPort: 4948},
			},
		},
	}
}

func runGolden(t *testing.T, name string, hosts []Host) {
	t.Helper()
	files, err := Render(testCfg, hosts)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		old, _ := os.ReadDir(dir)
		for _, e := range old {
			os.Remove(filepath.Join(dir, e.Name()))
		}
		for fn, content := range files {
			if err := os.WriteFile(filepath.Join(dir, fn), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read golden dir (run with UPDATE_GOLDEN=1 to create): %v", err)
	}
	want := map[string]bool{}
	for _, e := range entries {
		want[e.Name()] = true
		golden, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		got, ok := files[e.Name()]
		if !ok {
			t.Errorf("golden file %s not rendered", e.Name())
			continue
		}
		if got != string(golden) {
			t.Errorf("%s differs from golden (UPDATE_GOLDEN=1 to regenerate)", e.Name())
		}
	}
	for fn := range files {
		if !want[fn] {
			t.Errorf("rendered %s has no golden file", fn)
		}
	}
}

func TestGoldenBase(t *testing.T)      { runGolden(t, "base", baseHosts()) }
func TestGoldenPHP(t *testing.T)       { runGolden(t, "php", phpHosts()) }
func TestGoldenPathMount(t *testing.T) { runGolden(t, "pathmount", pathMountHosts()) }

// Every generated file must carry the managed mark as its first line
// so the sync intent can tell our files from user-owned ones.
func TestManagedMark(t *testing.T) {
	files, err := Render(testCfg, baseHosts())
	if err != nil {
		t.Fatal(err)
	}
	for fn, content := range files {
		if !strings.HasPrefix(content, ManagedMark+"\n") {
			t.Errorf("%s missing managed mark", fn)
		}
	}
}

func TestRenderErrors(t *testing.T) {
	valid := Host{Domain: "ok.example.com", CertFile: "/c", KeyFile: "/k", HSTS: "on"}
	cases := []struct {
		name  string
		hosts []Host
	}{
		{"bad domain", []Host{{Domain: "../etc/nginx", CertFile: "/c", KeyFile: "/k", HSTS: "on"}}},
		{"duplicate host", []Host{valid, valid}},
		{"bad hsts", []Host{{Domain: "a.example.com", CertFile: "/c", KeyFile: "/k", HSTS: "yes"}}},
		{"mount on non-primary", []Host{{Domain: "a.example.com", CertFile: "/c", KeyFile: "/k", HSTS: "on",
			Mounts: []Mount{{App: "webmail-rav", Path: "/", BackendHost: "h", BackendPort: 1}}}}},
		{"unknown app", []Host{{Domain: "a.example.com", Primary: true, CertFile: "/c", KeyFile: "/k", HSTS: "on",
			Mounts: []Mount{{App: "nope", Path: "/"}}}}},
		{"app mounted twice", []Host{{Domain: "a.example.com", Primary: true, CertFile: "/c", KeyFile: "/k", HSTS: "on",
			Mounts: []Mount{
				{App: "filebrowser", Path: "/files", BackendHost: "h", BackendPort: 1},
				{App: "filebrowser", Path: "/other", BackendHost: "h", BackendPort: 1},
			}}}},
		{"php app off root", []Host{{Domain: "a.example.com", Primary: true, CertFile: "/c", KeyFile: "/k", HSTS: "on",
			Mounts: []Mount{{App: "webmail-roundcube", Path: "/mail"}}}}},
		{"directive injection in rule target", []Host{{Domain: "a.example.com", CertFile: "/c", KeyFile: "/k", HSTS: "on",
			Rules: []Rule{{Kind: "proxy", Path: "/x", Target: "http://127.0.0.1:9/; access_log off"}}}}},
		{"directive injection in rule path", []Host{{Domain: "a.example.com", CertFile: "/c", KeyFile: "/k", HSTS: "on",
			Rules: []Rule{{Kind: "alias", Path: "/x {}", Target: "/srv/y"}}}}},
	}
	for _, c := range cases {
		if _, err := Render(testCfg, c.hosts); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
	// PHP app without a socket configured.
	if _, err := Render(Config{ACMEWebroot: "/w"}, []Host{{
		Domain: "a.example.com", Primary: true, CertFile: "/c", KeyFile: "/k", HSTS: "on",
		Mounts: []Mount{{App: "webmail-roundcube", Path: "/"}},
	}}); err == nil {
		t.Error("php without socket: expected error")
	}
}

// Every service in the registry must have a location block: the
// registry is the menu of mountable apps and the renderer must be able
// to render whatever the applier picks from it.
func TestRegistryCoverage(t *testing.T) {
	for _, svc := range registry.All() {
		m := Mount{
			App:         svc.Name,
			Path:        svc.DefaultMount,
			BackendHost: "127.0.0.1",
			BackendPort: svc.Port,
			AuthUser:    "admin@example.com",
		}
		_, err := Render(testCfg, []Host{{
			Domain: "cov.example.com", Primary: true,
			CertFile: "/c", KeyFile: "/k", HSTS: "on",
			Mounts: []Mount{m},
		}})
		if err != nil {
			t.Errorf("registry app %s does not render: %v", svc.Name, err)
		}
	}
}
