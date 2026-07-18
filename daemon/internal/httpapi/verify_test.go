package httpapi

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func doVerify(t *testing.T, s *Server, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"email": {email}, "password": {password}}
	req := httptest.NewRequest("POST", "/internal/auth/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func TestAuthVerify(t *testing.T) {
	s, buf := newTestServer(t)

	w := doVerify(t, s, "admin@example.com", testPassword)
	if w.Code != 200 {
		t.Fatalf("valid credentials: status = %d, body %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "admin@example.com") {
		t.Errorf("body = %s, want the user", w.Body)
	}

	// Email is case- and whitespace-normalized like the rest of the API.
	if w := doVerify(t, s, "  Admin@Example.COM ", testPassword); w.Code != 200 {
		t.Errorf("normalized email: status = %d", w.Code)
	}

	// Wrong password and unknown user answer identically.
	wrong := doVerify(t, s, "admin@example.com", "nope")
	unknown := doVerify(t, s, "ghost@example.com", "nope")
	if wrong.Code != 401 || unknown.Code != 401 {
		t.Fatalf("bad credentials: status %d/%d, want 401/401", wrong.Code, unknown.Code)
	}
	if wrong.Body.String() != unknown.Body.String() {
		t.Errorf("unknown-user body differs from wrong-password body: %s vs %s", unknown.Body, wrong.Body)
	}
	if !strings.Contains(buf.String(), "Failed login attempt") {
		t.Error("failures must emit the fail2ban line")
	}

	if w := doVerify(t, s, "", ""); w.Code != 400 {
		t.Errorf("missing params: status = %d, want 400", w.Code)
	}
}

func TestAuthVerifyRateLimit(t *testing.T) {
	s, _ := newTestServer(t)

	for i := 0; i < verifyMaxFailures; i++ {
		if w := doVerify(t, s, "admin@example.com", "nope"); w.Code != 401 {
			t.Fatalf("failure %d: status = %d", i, w.Code)
		}
	}
	w := doVerify(t, s, "admin@example.com", testPassword)
	if w.Code != 429 {
		t.Fatalf("after %d failures even the right password answers 429, got %d", verifyMaxFailures, w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("429 must carry Retry-After")
	}

	// The window is per email: other accounts are unaffected.
	if w := doVerify(t, s, "ghost@example.com", "nope"); w.Code != 401 {
		t.Errorf("other email during lockout: status = %d, want 401", w.Code)
	}
}
