package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"naust/daemon/internal/api"
	"naust/daemon/internal/auth"
)

// doCookie performs a request authenticated by the session cookie
// instead of the Authorization header.
func doCookie(t *testing.T, s *Server, method, path, cookieValue string, body any) *httptest.ResponseRecorder {
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
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookieValue})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func sessionCookieFrom(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	return nil
}

func TestLoginSetsSessionCookie(t *testing.T) {
	s, _ := newTestServer(t)
	w := doJSON(t, s, "POST", "/api/auth/login", "", api.LoginRequest{
		Email:    "admin@example.com",
		Password: testPassword,
	})
	if w.Code != 200 {
		t.Fatalf("login status = %d", w.Code)
	}
	c := sessionCookieFrom(t, w)
	if c == nil {
		t.Fatal("login response did not set the session cookie")
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Fatalf("cookie attributes wrong: %+v", c)
	}

	// The cookie alone authenticates.
	me := doCookie(t, s, "GET", "/api/auth/me", c.Value, nil)
	if me.Code != 200 {
		t.Fatalf("me via cookie status = %d, body %s", me.Code, me.Body)
	}
}

func TestCookieCannotCarryAPIToken(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	w := doJSON(t, s, "POST", "/api/tokens", token, api.CreateAPITokenRequest{
		Name: "probe", Scope: "write",
	})
	if w.Code != 200 && w.Code != 201 {
		t.Fatalf("create token status = %d, body %s", w.Code, w.Body)
	}
	var created api.CreateAPITokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Token, auth.TokenPrefix) {
		t.Fatalf("token %q lacks the expected prefix", created.Token)
	}

	// The API token works via the Authorization header...
	if w := doJSON(t, s, "GET", "/api/users", created.Token, nil); w.Code != 200 {
		t.Fatalf("token via header status = %d", w.Code)
	}
	// ...but is rejected when planted in the cookie: an attacker
	// controls a planted cookie's attributes, so cookies may only
	// carry interactive session tokens.
	if w := doCookie(t, s, "GET", "/api/users", created.Token, nil); w.Code != 401 {
		t.Fatalf("token via cookie status = %d, want 401", w.Code)
	}
}

func TestHeaderWinsOverCookie(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	// A garbage header must not fall back to the valid cookie:
	// silently ignoring a bad explicit credential would mask client
	// bugs and confuse curl-based debugging.
	req := httptest.NewRequest("GET", "/api/auth/me", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer wrong")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("bad header + good cookie status = %d, want 401", w.Code)
	}
}

// TestAPITokenHeaderScopeNotUpgradedByStrayCookie proves a read-scoped
// API token in the Authorization header stays read-only even with a
// full-scope session cookie riding along on the same request - the
// header credential's scope must win outright, not get upgraded by
// whatever the cookie would have granted.
func TestAPITokenHeaderScopeNotUpgradedByStrayCookie(t *testing.T) {
	s, _ := newTestServer(t)
	session := login(t, s).Token

	w := doJSON(t, s, "POST", "/api/tokens", session, api.CreateAPITokenRequest{Name: "ro", Scope: "read"})
	var created api.CreateAPITokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/api/users", strings.NewReader(`{"email":"bob@example.com","password":"`+testPassword+`"}`))
	req.Header.Set("Authorization", "Bearer "+created.Token)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: session})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("read-scoped header token + full-scope cookie: status = %d, want 403", rec.Code)
	}
}

func TestLogoutClearsCookieAndSession(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	w := doCookie(t, s, "POST", "/api/auth/logout", token, nil)
	if w.Code != 204 {
		t.Fatalf("logout status = %d", w.Code)
	}
	c := sessionCookieFrom(t, w)
	if c == nil || c.MaxAge >= 0 {
		t.Fatalf("logout did not clear the cookie: %+v", c)
	}
	// The session is gone server-side, not just client-side.
	if w := doCookie(t, s, "GET", "/api/auth/me", token, nil); w.Code != 401 {
		t.Fatalf("me after logout status = %d, want 401", w.Code)
	}
}

func TestMeta(t *testing.T) {
	s, _ := newEmptyTestServer(t)
	w := doJSON(t, s, "GET", "/api/meta", "", nil)
	if w.Code != 200 {
		t.Fatalf("meta status = %d", w.Code)
	}
	var meta api.MetaResponse
	if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Hostname != "box.example.com" || !meta.NeedsBootstrap {
		t.Fatalf("empty-box meta = %+v", meta)
	}
	if meta.User != nil {
		t.Fatalf("anonymous meta carries a user: %+v", meta.User)
	}
	// The user field must be present-but-null, not omitted: the
	// frontend types it as User | null.
	if !strings.Contains(w.Body.String(), `"user":null`) {
		t.Fatalf("meta body lacks explicit null user: %s", w.Body)
	}

	seeded, _ := newTestServer(t)
	token := login(t, seeded).Token
	w = doCookie(t, seeded, "GET", "/api/meta", token, nil)
	var after api.MetaResponse
	if err := json.Unmarshal(w.Body.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	if after.NeedsBootstrap {
		t.Fatal("meta still reports needs_bootstrap with a user present")
	}
	if after.User == nil || after.User.Email != "admin@example.com" {
		t.Fatalf("session meta user = %+v", after.User)
	}

	// A garbage cookie yields user null, never an error.
	w = doCookie(t, seeded, "GET", "/api/meta", "not-a-session", nil)
	if w.Code != 200 {
		t.Fatalf("meta with bad cookie status = %d", w.Code)
	}
	var bad api.MetaResponse
	if err := json.Unmarshal(w.Body.Bytes(), &bad); err != nil {
		t.Fatal(err)
	}
	if bad.User != nil {
		t.Fatal("meta authenticated a garbage cookie")
	}
}

func TestAuthMethods(t *testing.T) {
	s, _ := newTestServer(t)

	methods := func(email string) []string {
		t.Helper()
		w := doJSON(t, s, "GET", "/api/auth/methods?email="+email, "", nil)
		if w.Code != 200 {
			t.Fatalf("methods status = %d", w.Code)
		}
		var resp api.AuthMethodsResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp.Methods
	}
	equal := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	// Nothing enrolled and unknown account answer identically.
	if got := methods("admin@example.com"); !equal(got, []string{"password"}) {
		t.Fatalf("plain account methods = %v", got)
	}
	if got := methods("ghost@example.com"); !equal(got, []string{"password"}) {
		t.Fatalf("unknown account methods = %v", got)
	}

	// TOTP enrolled.
	admin := s.Store.User.Query().OnlyX(context.Background())
	s.Store.TOTPCredential.Create().
		SetUser(admin).
		SetSecret("JBSWY3DPEHPK3PXP").
		SaveX(context.Background())
	if got := methods("admin@example.com"); !equal(got, []string{"password+totp"}) {
		t.Fatalf("totp account methods = %v", got)
	}

	// Passkey too: both ceremonies available.
	s.Store.WebAuthnCredential.Create().
		SetUser(admin).
		SetCredentialID([]byte("cred")).
		SetData("{}").
		SaveX(context.Background())
	if got := methods("admin@example.com"); !equal(got, []string{"passkey", "password+totp"}) {
		t.Fatalf("passkey+totp account methods = %v", got)
	}

	// Passkey only: password login is refused, so it is not offered.
	s.Store.TOTPCredential.Delete().ExecX(context.Background())
	if got := methods("admin@example.com"); !equal(got, []string{"passkey"}) {
		t.Fatalf("passkey-only account methods = %v", got)
	}
}
