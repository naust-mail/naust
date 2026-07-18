package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"naust/daemon/internal/api"
	"naust/daemon/internal/auth"
	"naust/daemon/internal/store"
	"naust/daemon/internal/store/ent"
	entuser "naust/daemon/internal/store/ent/user"
)

const testPassword = "correct horse battery staple"

// newTestServer returns a server over a fresh SQLite store seeded with
// one admin user, plus the buffer its log lines land in.
func newTestServer(t *testing.T) (*Server, *bytes.Buffer) {
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
	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	tid := testTenantID(t, client)
	client.User.Create().
		SetEmail("admin@example.com").
		SetPasswordHash(hash).
		SetRole(entuser.RoleAdmin).
		SetTenantID(tid).
		SaveX(ctx)

	var buf bytes.Buffer
	return &Server{Store: client, Log: log.New(&buf, "", 0), PrimaryHostname: "box.example.com", TenantID: tid}, &buf
}

func testTenantID(t *testing.T, client *ent.Client) int {
	t.Helper()
	tenant, err := store.EnsureDefaultTenant(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	return tenant.ID
}

func doJSON(t *testing.T, s *Server, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = strings.NewReader(string(b))
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func login(t *testing.T, s *Server) api.LoginResponse {
	t.Helper()
	w := doJSON(t, s, "POST", "/api/auth/login", "", api.LoginRequest{
		Email:    "admin@example.com",
		Password: testPassword,
	})
	if w.Code != 200 {
		t.Fatalf("login status = %d, body %s", w.Code, w.Body)
	}
	var resp api.LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func loginAs(t *testing.T, s *Server, email, password string) string {
	t.Helper()
	w := doJSON(t, s, "POST", "/api/auth/login", "", api.LoginRequest{Email: email, Password: password})
	if w.Code != 200 {
		t.Fatalf("login as %s: status = %d, body %s", email, w.Code, w.Body)
	}
	var resp api.LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Token
}

// newEmptyTestServer is newTestServer without the seeded admin, for
// exercising the bootstrap path.
func newEmptyTestServer(t *testing.T) (*Server, *bytes.Buffer) {
	t.Helper()
	client, err := store.Open(store.EngineSQLite, filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if err := client.Schema.Create(context.Background()); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	return &Server{Store: client, Log: log.New(&buf, "", 0), PrimaryHostname: "box.example.com", TenantID: testTenantID(t, client)}, &buf
}

func TestLoginAndMe(t *testing.T) {
	s, _ := newTestServer(t)
	resp := login(t, s)
	if resp.Token == "" || resp.User.Role != "admin" {
		t.Fatalf("unexpected login response: %+v", resp)
	}

	w := doJSON(t, s, "GET", "/api/auth/me", resp.Token, nil)
	if w.Code != 200 {
		t.Fatalf("me status = %d", w.Code)
	}
	var me api.User
	if err := json.Unmarshal(w.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.Email != "admin@example.com" {
		t.Errorf("me email = %q", me.Email)
	}
}

func TestFailedLoginsAreUniformAndLogged(t *testing.T) {
	s, logs := newTestServer(t)

	wrongPw := doJSON(t, s, "POST", "/api/auth/login", "", api.LoginRequest{Email: "admin@example.com", Password: "nope"})
	noUser := doJSON(t, s, "POST", "/api/auth/login", "", api.LoginRequest{Email: "ghost@example.com", Password: "nope"})

	// Wrong password and unknown account must be indistinguishable.
	if wrongPw.Code != 403 || noUser.Code != 403 {
		t.Fatalf("statuses = %d, %d, want 403, 403", wrongPw.Code, noUser.Code)
	}
	if wrongPw.Body.String() != noUser.Body.String() {
		t.Errorf("response bodies differ: %q vs %q", wrongPw.Body, noUser.Body)
	}

	// Both attempts must emit the exact line the fail2ban filter
	// matches (naust-management-daemon.conf failregex).
	failLine := regexp.MustCompile(`Naust Management Daemon: Failed login attempt from ip 192\.0\.2\.1 - timestamp \d+\.\d+`)
	if got := len(failLine.FindAllString(logs.String(), -1)); got != 2 {
		t.Errorf("fail2ban-format log lines = %d, want 2; log:\n%s", got, logs)
	}
}

func TestFailedLoginLogsForwardedFor(t *testing.T) {
	s, logs := newTestServer(t)

	b, _ := json.Marshal(api.LoginRequest{Email: "admin@example.com", Password: "nope"})
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(string(b)))
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if !strings.Contains(logs.String(), "from ip 203.0.113.9 ") {
		t.Errorf("X-Forwarded-For not used in log line:\n%s", logs)
	}
}

func TestMeRejectsMissingAndBogusTokens(t *testing.T) {
	s, _ := newTestServer(t)
	if w := doJSON(t, s, "GET", "/api/auth/me", "", nil); w.Code != 401 {
		t.Errorf("no token: status = %d, want 401", w.Code)
	}
	if w := doJSON(t, s, "GET", "/api/auth/me", "bogus", nil); w.Code != 401 {
		t.Errorf("bogus token: status = %d, want 401", w.Code)
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	s, _ := newTestServer(t)
	ctx := context.Background()
	u := s.Store.User.Query().Where(entuser.Email("admin@example.com")).OnlyX(ctx)
	token, _, err := auth.NewSession(ctx, s.Store, u, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, "GET", "/api/auth/me", token, nil); w.Code != 401 {
		t.Errorf("expired session: status = %d, want 401", w.Code)
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	s, _ := newTestServer(t)
	resp := login(t, s)

	if w := doJSON(t, s, "POST", "/api/auth/logout", resp.Token, nil); w.Code != 204 {
		t.Fatalf("logout status = %d, want 204", w.Code)
	}
	if w := doJSON(t, s, "GET", "/api/auth/me", resp.Token, nil); w.Code != 401 {
		t.Errorf("token alive after logout: status = %d, want 401", w.Code)
	}
}
