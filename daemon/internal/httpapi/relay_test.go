package httpapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"naust/daemon/internal/api"
)

// fakeHelper records intents instead of talking to helperd.
type fakeHelper struct {
	calls []string // "intent key=value"
	fail  bool
}

func (f *fakeHelper) Call(_ context.Context, intent string, args map[string]string) (string, error) {
	if f.fail {
		return "", os.ErrPermission
	}
	call := intent
	if k, ok := args["key"]; ok {
		call += " " + k + "=" + args["value"]
	}
	f.calls = append(f.calls, call)
	return "", nil
}

// relayTestServer wires the relay dependencies onto a test server: a
// recording helper and a postmap fake that compiles the credential
// file the way the real tool does (a .db beside it).
func relayTestServer(t *testing.T) (*Server, *fakeHelper) {
	t.Helper()
	s, _ := newTestServer(t)
	h := &fakeHelper{}
	s.Helper = h
	s.RelayDir = filepath.Join(t.TempDir(), "relay")
	s.RunPostmap = func(_ context.Context, path string) error {
		return os.WriteFile(path+".db", []byte("compiled"), 0o600)
	}
	return s, h
}

func TestRelayConfigure(t *testing.T) {
	s, h := relayTestServer(t)
	session := login(t, s).Token
	dnsKicks := 0
	s.OnDNSDataChange = func() { dnsKicks++ }

	// Unconfigured box reports defaults.
	var cfg api.RelayConfig
	w := doJSON(t, s, "GET", "/api/system/relay", session, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "" || cfg.Port != 587 || cfg.PasswordSet {
		t.Errorf("default config = %+v", cfg)
	}

	// Configure a relay with credentials.
	w = doJSON(t, s, "PUT", "/api/system/relay", session, api.SetRelayRequest{
		Host: "smtp.sendgrid.net", Port: 587, User: "apikey",
		Password: "SG.secret", SPFInclude: "sendgrid.net",
	})
	if w.Code != 200 {
		t.Fatalf("set relay: status = %d, body %s", w.Code, w.Body)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "smtp.sendgrid.net" || !cfg.PasswordSet || cfg.SPFInclude != "sendgrid.net" {
		t.Errorf("config after set = %+v", cfg)
	}
	if dnsKicks != 1 {
		t.Errorf("dns kicks = %d, want 1 (SPF changed)", dnsKicks)
	}

	// Postfix got the full parameter set, credentials first.
	want := []string{
		"postfix.set relayhost=[smtp.sendgrid.net]:587",
		"postfix.set smtp_sasl_auth_enable=yes",
		"postfix.set smtp_sasl_password_maps=hash:" + filepath.Join(s.RelayDir, "sasl_passwd"),
		"postfix.set smtp_sasl_security_options=noanonymous",
		"postfix.set smtp_tls_security_level=verify",
	}
	if strings.Join(h.calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("helper calls:\n%s\nwant:\n%s", strings.Join(h.calls, "\n"), strings.Join(want, "\n"))
	}

	// The compiled table persists; the plaintext credentials do not.
	if _, err := os.Stat(filepath.Join(s.RelayDir, "sasl_passwd.db")); err != nil {
		t.Error("sasl_passwd.db missing")
	}
	if _, err := os.Stat(filepath.Join(s.RelayDir, "sasl_passwd")); !os.IsNotExist(err) {
		t.Error("plaintext sasl_passwd left behind")
	}

	// Updating without a password keeps the stored credential.
	h.calls = nil
	w = doJSON(t, s, "PUT", "/api/system/relay", session, api.SetRelayRequest{
		Host: "smtp.sendgrid.net", Port: 2525, User: "apikey", SPFInclude: "sendgrid.net",
	})
	if w.Code != 200 {
		t.Fatalf("update relay: status = %d, body %s", w.Code, w.Body)
	}
	json.Unmarshal(w.Body.Bytes(), &cfg)
	if !cfg.PasswordSet || cfg.Port != 2525 {
		t.Errorf("config after update = %+v", cfg)
	}

	// Removing the relay resets Postfix and deletes the credentials.
	h.calls = nil
	w = doJSON(t, s, "PUT", "/api/system/relay", session, api.SetRelayRequest{})
	if w.Code != 200 {
		t.Fatalf("remove relay: status = %d, body %s", w.Code, w.Body)
	}
	wantReset := []string{
		"postfix.set relayhost=",
		"postfix.set smtp_sasl_auth_enable=no",
		"postfix.set smtp_sasl_password_maps=",
		"postfix.set smtp_sasl_security_options=",
		"postfix.set smtp_tls_security_level=dane",
	}
	if strings.Join(h.calls, "\n") != strings.Join(wantReset, "\n") {
		t.Errorf("reset calls:\n%s", strings.Join(h.calls, "\n"))
	}
	if _, err := os.Stat(filepath.Join(s.RelayDir, "sasl_passwd.db")); !os.IsNotExist(err) {
		t.Error("sasl_passwd.db not removed")
	}
	json.Unmarshal(doJSON(t, s, "GET", "/api/system/relay", session, nil).Body.Bytes(), &cfg)
	if cfg.Host != "" || cfg.PasswordSet {
		t.Errorf("config after remove = %+v", cfg)
	}
}

func TestRelaySetValidation(t *testing.T) {
	s, h := relayTestServer(t)
	session := login(t, s).Token

	for name, req := range map[string]api.SetRelayRequest{
		"host with newline":    {Host: "evil\nhost", Port: 587},
		"host with space":      {Host: "smtp host", Port: 587},
		"port out of range":    {Host: "smtp.example.com", Port: 70000},
		"negative port":        {Host: "smtp.example.com", Port: -1},
		"bad spf include":      {Host: "smtp.example.com", Port: 587, SPFInclude: "bad host"},
		"newline in password":  {Host: "smtp.example.com", Port: 587, User: "u", Password: "p\nq"},
		"newline in user":      {Host: "smtp.example.com", Port: 587, User: "u\nv", Password: "p"},
		"leading dash in host": {Host: "-smtp.example.com", Port: 587},
		"trailing dot in host": {Host: "smtp.example.com.", Port: 587},
	} {
		if w := doJSON(t, s, "PUT", "/api/system/relay", session, req); w.Code != 400 {
			t.Errorf("%s: status = %d, want 400", name, w.Code)
		}
	}
	if len(h.calls) != 0 {
		t.Errorf("rejected requests reached the helper: %v", h.calls)
	}

	// A helper failure surfaces and leaves the setting unwritten.
	h.fail = true
	if w := doJSON(t, s, "PUT", "/api/system/relay", session, api.SetRelayRequest{
		Host: "smtp.example.com", Port: 587,
	}); w.Code != 500 {
		t.Errorf("helper failure: status = %d, want 500", w.Code)
	}
	h.fail = false
	var cfg api.RelayConfig
	json.Unmarshal(doJSON(t, s, "GET", "/api/system/relay", session, nil).Body.Bytes(), &cfg)
	if cfg.Host != "" {
		t.Errorf("failed apply persisted config: %+v", cfg)
	}
}

func TestRelayTestValidation(t *testing.T) {
	s, _ := relayTestServer(t)
	session := login(t, s).Token

	for name, req := range map[string]api.RelayTestRequest{
		"no host":         {Port: 587},
		"bad host":        {Host: "bad host", Port: 587},
		"port not listed": {Host: "smtp.example.com", Port: 8080},
	} {
		if w := doJSON(t, s, "POST", "/api/system/relay/test", session, req); w.Code != 400 {
			t.Errorf("%s: status = %d, want 400", name, w.Code)
		}
	}
}

func TestRelaySendTestRequiresConfig(t *testing.T) {
	s, _ := relayTestServer(t)
	session := login(t, s).Token

	if w := doJSON(t, s, "POST", "/api/system/relay/send-test", session, nil); w.Code != 400 {
		t.Errorf("send-test without relay: status = %d, want 400", w.Code)
	}
}
