package httpapi

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"naust/daemon/internal/api"
)

func webTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	s, _ := newTestServer(t)
	s.PublicIP = "198.51.100.4"
	s.StorageRoot = filepath.Join(t.TempDir(), "user-data")
	return s, login(t, s).Token
}

func getWebStatus(t *testing.T, s *Server, token string) api.WebStatusResponse {
	t.Helper()
	w := doJSON(t, s, "GET", "/api/web", token, nil)
	if w.Code != 200 {
		t.Fatalf("GET /api/web status = %d, body %s", w.Code, w.Body)
	}
	var resp api.WebStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestWebStatusDefaults(t *testing.T) {
	s, token := webTestServer(t)
	resp := getWebStatus(t, s, token)

	byDomain := map[string]api.WebDomainInfo{}
	for _, d := range resp.Domains {
		byDomain[d.Domain] = d
	}
	// The seeded admin@example.com yields example.com plus the box
	// service names; everything starts uncustomized.
	primary, ok := byDomain["box.example.com"]
	if !ok || !primary.Primary {
		t.Fatalf("primary missing or unmarked: %+v", primary)
	}
	ex, ok := byDomain["example.com"]
	if !ok || ex.Customized || ex.HSTS != "on" || !ex.ServeStatic {
		t.Fatalf("example.com defaults = %+v", ex)
	}
	if www := byDomain["www.example.com"]; www.RedirectTo != "example.com" {
		t.Errorf("www redirect = %+v", www)
	}

	byRole := map[string]api.WebMountInfo{}
	for _, m := range resp.Mounts {
		byRole[m.Role] = m
	}
	if m := byRole["admin"]; !m.Fixed || m.Path != "/admin" || !m.Enabled {
		t.Errorf("admin mount = %+v", m)
	}
	// Default conf (nil Conf = all defaults): rav enabled at root.
	if m := byRole["webmail"]; m.Fixed || m.App != "webmail-rav" || m.Path != "/" {
		t.Errorf("webmail mount = %+v", m)
	}
	// Unset MONITORING_TOOL means a legacy munin box.
	if m := byRole["monitoring"]; !m.Enabled || m.App != "munin" || m.Path != "/admin/munin" {
		t.Errorf("monitoring mount = %+v", m)
	}
}

func TestWebDomainConfigureAndReset(t *testing.T) {
	s, token := webTestServer(t)
	kicks := 0
	s.OnWebDataChange = func() { kicks++ }

	cfg := api.WebDomainConfig{
		HSTS:        "preload",
		ServeStatic: false,
		Rules: []api.WebRule{
			{Kind: "proxy", Path: "/", Target: "http://127.0.0.1:9000", WebSockets: true},
			{Kind: "redirect", Path: "^/old/(.*)", Target: "https://example.net/$1"},
			{Kind: "alias", Path: "/pub/", Target: filepath.Join(s.StorageRoot, "www", "pub") + "/"},
		},
	}
	if w := doJSON(t, s, "PUT", "/api/web/domains/EXAMPLE.com", token, cfg); w.Code != 204 {
		t.Fatalf("PUT status = %d, body %s", w.Code, w.Body)
	}
	if kicks != 1 {
		t.Errorf("kicks = %d, want 1", kicks)
	}

	resp := getWebStatus(t, s, token)
	var ex api.WebDomainInfo
	for _, d := range resp.Domains {
		if d.Domain == "example.com" {
			ex = d
		}
	}
	if !ex.Customized || ex.HSTS != "preload" || ex.ServeStatic || len(ex.Rules) != 3 {
		t.Fatalf("configured domain = %+v", ex)
	}

	// Replacing shrinks the rule set (no leftovers from the first PUT).
	cfg.Rules = cfg.Rules[:1]
	cfg.ServeStatic = true
	if w := doJSON(t, s, "PUT", "/api/web/domains/example.com", token, cfg); w.Code != 204 {
		t.Fatalf("second PUT status = %d", w.Code)
	}
	resp = getWebStatus(t, s, token)
	for _, d := range resp.Domains {
		if d.Domain == "example.com" && len(d.Rules) != 1 {
			t.Fatalf("rules after replace = %+v", d.Rules)
		}
	}

	// DELETE returns the domain to defaults.
	if w := doJSON(t, s, "DELETE", "/api/web/domains/example.com", token, nil); w.Code != 204 {
		t.Fatalf("DELETE status = %d", w.Code)
	}
	resp = getWebStatus(t, s, token)
	for _, d := range resp.Domains {
		if d.Domain == "example.com" && (d.Customized || len(d.Rules) != 0) {
			t.Fatalf("after reset = %+v", d)
		}
	}
	if kicks != 3 {
		t.Errorf("kicks = %d, want 3", kicks)
	}
}

func TestWebDomainValidation(t *testing.T) {
	s, token := webTestServer(t)
	valid := func() api.WebDomainConfig {
		return api.WebDomainConfig{HSTS: "on", ServeStatic: true}
	}

	cases := []struct {
		name string
		path string
		cfg  api.WebDomainConfig
	}{
		{"bad hsts", "/api/web/domains/example.com",
			api.WebDomainConfig{HSTS: "yes", ServeStatic: true}},
		{"bad domain", "/api/web/domains/not_a_domain", valid()},
		{"unknown kind", "/api/web/domains/example.com", api.WebDomainConfig{
			HSTS: "on", ServeStatic: true,
			Rules: []api.WebRule{{Kind: "magic", Path: "/x", Target: "/y"}}}},
		{"directive injection", "/api/web/domains/example.com", api.WebDomainConfig{
			HSTS: "on", ServeStatic: true,
			Rules: []api.WebRule{{Kind: "proxy", Path: "/x", Target: "http://127.0.0.1:9/; access_log off"}}}},
		{"public proxy ip", "/api/web/domains/example.com", api.WebDomainConfig{
			HSTS: "on", ServeStatic: true,
			Rules: []api.WebRule{{Kind: "proxy", Path: "/x", Target: "http://203.0.113.7:8080/"}}}},
		{"public proxy hostname", "/api/web/domains/example.com", api.WebDomainConfig{
			HSTS: "on", ServeStatic: true,
			Rules: []api.WebRule{{Kind: "proxy", Path: "/x", Target: "https://evil.example.net/"}}}},
		{"alias escape", "/api/web/domains/example.com", api.WebDomainConfig{
			HSTS: "on", ServeStatic: true,
			Rules: []api.WebRule{{Kind: "alias", Path: "/x/", Target: "/etc/"}}}},
		{"alias traversal", "/api/web/domains/example.com", api.WebDomainConfig{
			HSTS: "on", ServeStatic: true,
			Rules: []api.WebRule{{Kind: "alias", Path: "/x/",
				Target: filepath.Join(s.StorageRoot, "www") + "/../mail/"}}}},
		{"duplicate rule path", "/api/web/domains/example.com", api.WebDomainConfig{
			HSTS: "on", ServeStatic: true,
			Rules: []api.WebRule{
				{Kind: "redirect", Path: "/x", Target: "/a"},
				{Kind: "redirect", Path: "/x", Target: "/b"}}}},
		{"bad redirect target", "/api/web/domains/example.com", api.WebDomainConfig{
			HSTS: "on", ServeStatic: true,
			Rules: []api.WebRule{{Kind: "redirect", Path: "/x", Target: "ftp://y"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if w := doJSON(t, s, "PUT", tc.path, token, tc.cfg); w.Code != 400 {
				t.Fatalf("status = %d, body %s", w.Code, w.Body)
			}
		})
	}

	// Local proxy targets of every allowed shape pass.
	ok := valid()
	ok.Rules = []api.WebRule{
		{Kind: "proxy", Path: "/a", Target: "http://127.0.0.1:3000"},
		{Kind: "proxy", Path: "/b", Target: "http://10.0.0.7:3000/app"},
		{Kind: "proxy", Path: "/c", Target: "http://my-container:8080"},
	}
	if w := doJSON(t, s, "PUT", "/api/web/domains/example.com", token, ok); w.Code != 204 {
		t.Fatalf("valid config rejected: %d %s", w.Code, w.Body)
	}
}

func TestWebMounts(t *testing.T) {
	s, token := webTestServer(t)
	kicks := 0
	s.OnWebDataChange = func() { kicks++ }

	// Move filebrowser, keep webmail at root.
	req := api.WebMountsRequest{Mounts: map[string]string{
		"webmail":     "/",
		"filebrowser": "/data",
	}}
	if w := doJSON(t, s, "PUT", "/api/web/mounts", token, req); w.Code != 204 {
		t.Fatalf("PUT mounts status = %d, body %s", w.Code, w.Body)
	}
	if kicks != 1 {
		t.Errorf("kicks = %d", kicks)
	}
	resp := getWebStatus(t, s, token)
	for _, m := range resp.Mounts {
		if m.Role == "filebrowser" && m.Path != "/data" {
			t.Errorf("filebrowser path = %q", m.Path)
		}
	}

	bad := []struct {
		name   string
		mounts map[string]string
	}{
		{"unknown role", map[string]string{"gopher": "/g"}},
		{"admin not placeable", map[string]string{"admin": "/panel"}},
		{"reserved admin subtree", map[string]string{"filebrowser": "/admin/files"}},
		{"reserved radicale path", map[string]string{"filebrowser": "/radicale"}},
		{"trailing slash", map[string]string{"filebrowser": "/data/"}},
		{"uppercase", map[string]string{"filebrowser": "/Data"}},
		{"duplicate path", map[string]string{"filebrowser": "/", "webmail": "/"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			w := doJSON(t, s, "PUT", "/api/web/mounts", token, api.WebMountsRequest{Mounts: tc.mounts})
			if w.Code != 400 {
				t.Fatalf("status = %d, body %s", w.Code, w.Body)
			}
		})
	}
}

func TestWebRequiresAdmin(t *testing.T) {
	s, token := webTestServer(t)
	// Create a non-admin user and log in as them.
	w := doJSON(t, s, "POST", "/api/users", token, api.CreateUserRequest{
		Email: "user@example.com", Password: testPassword,
	})
	if w.Code != 201 {
		t.Fatalf("create user: %d %s", w.Code, w.Body)
	}
	userToken := loginAs(t, s, "user@example.com", testPassword)
	if w := doJSON(t, s, "GET", "/api/web", userToken, nil); w.Code != 403 {
		t.Errorf("non-admin GET /api/web = %d, want 403", w.Code)
	}
	if w := doJSON(t, s, "PUT", "/api/web/mounts", userToken,
		api.WebMountsRequest{Mounts: map[string]string{}}); w.Code != 403 {
		t.Errorf("non-admin PUT mounts = %d, want 403", w.Code)
	}
}
