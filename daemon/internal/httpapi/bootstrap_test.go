package httpapi

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"naust/daemon/internal/api"
)

// armBootstrap writes an active setup-code file and points the server
// at it, as "boxctl bootstrap" would.
func armBootstrap(t *testing.T, s *Server, code string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bootstrap.token")
	b, err := json.Marshal(bootstrapToken{Code: code, Expires: time.Now().Add(15 * time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s.BootstrapTokenPath = path
	return path
}

func bootstrapReq(code string) api.BootstrapRequest {
	return api.BootstrapRequest{Code: code, Email: "owner@example.com", Password: testPassword}
}

func TestBootstrapRequiresCode(t *testing.T) {
	s, _ := newEmptyTestServer(t)

	// No token file configured at all: the endpoint is inert.
	w := doJSON(t, s, "POST", "/api/bootstrap", "", bootstrapReq("ANYTHING"))
	if w.Code != 404 {
		t.Fatalf("no token path: status = %d, want 404", w.Code)
	}

	// Configured path but no file (nothing minted yet): same answer.
	s.BootstrapTokenPath = filepath.Join(t.TempDir(), "missing.token")
	w = doJSON(t, s, "POST", "/api/bootstrap", "", bootstrapReq("ANYTHING"))
	if w.Code != 404 {
		t.Fatalf("missing token file: status = %d, want 404", w.Code)
	}
}

func TestBootstrapCodeNormalization(t *testing.T) {
	s, _ := newEmptyTestServer(t)
	path := armBootstrap(t, s, "ABCD2345")

	// Hand-entered form: lowercase with spaces still matches.
	w := doJSON(t, s, "POST", "/api/bootstrap", "", bootstrapReq("abcd 2345"))
	if w.Code != 201 {
		t.Fatalf("normalized code: status = %d, body %s", w.Code, w.Body)
	}
	// The code is single-use: the file is gone after success.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("token file survived a successful bootstrap")
	}
}

func TestBootstrapWrongCodeLockout(t *testing.T) {
	s, buf := newEmptyTestServer(t)
	path := armBootstrap(t, s, "ABCD2345")

	var resp api.ErrorResponse
	for i := 1; i < bootstrapMaxAttempts; i++ {
		w := doJSON(t, s, "POST", "/api/bootstrap", "", bootstrapReq("WRONG"+strings.Repeat("X", i)))
		if w.Code != 403 {
			t.Fatalf("attempt %d: status = %d, want 403", i, w.Code)
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Hints) != 1 || resp.Hints[0] != "invalid-code" {
			t.Fatalf("attempt %d hints = %v", i, resp.Hints)
		}
	}
	// Attempts persist in the file, not process memory.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var tok bootstrapToken
	if err := json.Unmarshal(raw, &tok); err != nil {
		t.Fatal(err)
	}
	if tok.Attempts != bootstrapMaxAttempts-1 {
		t.Fatalf("persisted attempts = %d, want %d", tok.Attempts, bootstrapMaxAttempts-1)
	}

	// The final failure locks out: file deleted, then 404 forever.
	w := doJSON(t, s, "POST", "/api/bootstrap", "", bootstrapReq("WRONG"))
	if w.Code != 403 {
		t.Fatalf("lockout attempt: status = %d, want 403", w.Code)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Hints) != 1 || resp.Hints[0] != "locked" {
		t.Fatalf("lockout hints = %v", resp.Hints)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("token file survived lockout")
	}
	if w := doJSON(t, s, "POST", "/api/bootstrap", "", bootstrapReq("ABCD2345")); w.Code != 404 {
		t.Fatalf("post-lockout status = %d, want 404", w.Code)
	}

	// Wrong codes feed the same fail2ban line as failed logins.
	if !strings.Contains(buf.String(), "Failed login attempt") {
		t.Error("wrong setup code did not log the fail2ban line")
	}
}

func TestBootstrapExpiredCode(t *testing.T) {
	s, _ := newEmptyTestServer(t)
	path := filepath.Join(t.TempDir(), "bootstrap.token")
	b, _ := json.Marshal(bootstrapToken{Code: "ABCD2345", Expires: time.Now().Add(-time.Minute).Unix()})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s.BootstrapTokenPath = path

	w := doJSON(t, s, "POST", "/api/bootstrap", "", bootstrapReq("ABCD2345"))
	if w.Code != 403 {
		t.Fatalf("expired code: status = %d, want 403", w.Code)
	}
	var resp api.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Hints) != 1 || resp.Hints[0] != "expired" {
		t.Fatalf("expired hints = %v", resp.Hints)
	}
}

func TestBootstrapPythonTokenFileCompatible(t *testing.T) {
	// boxctl bootstrap (still Python) writes uuid/code/expires; the
	// extra field must not break parsing and attempts starts at zero.
	s, _ := newEmptyTestServer(t)
	path := filepath.Join(t.TempDir(), "bootstrap.token")
	raw := fmt.Sprintf(`{"uuid":"6f2c2d9e-1111-2222-3333-444455556666","code":"ABCD2345","expires":%d}`,
		time.Now().Add(15*time.Minute).Unix())
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	s.BootstrapTokenPath = path

	w := doJSON(t, s, "POST", "/api/bootstrap", "", bootstrapReq("ABCD2345"))
	if w.Code != 201 {
		t.Fatalf("python-format token: status = %d, body %s", w.Code, w.Body)
	}
}
