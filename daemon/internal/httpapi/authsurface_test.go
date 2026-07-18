package httpapi

import (
	"encoding/base32"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"naust/daemon/internal/api"
	"naust/daemon/internal/auth"
)

func TestBootstrapFlow(t *testing.T) {
	s, _ := newTestServer(t)
	// The seeded admin means the box is set up: bootstrap refuses.
	w := doJSON(t, s, "POST", "/api/bootstrap", "", api.BootstrapRequest{
		Email: "eve@example.com", Password: testPassword,
	})
	if w.Code != 403 {
		t.Fatalf("bootstrap on set-up box: status = %d, want 403", w.Code)
	}

	// On an empty box with an active setup code it creates the first
	// admin - even at a DCV-style address - and returns a working
	// session.
	s2, _ := newEmptyTestServer(t)
	armBootstrap(t, s2, "TESTCODE")
	w = doJSON(t, s2, "POST", "/api/bootstrap", "", api.BootstrapRequest{
		Code: "TESTCODE", Email: "admin@example.com", Password: testPassword,
	})
	if w.Code != 201 {
		t.Fatalf("bootstrap status = %d, body %s", w.Code, w.Body)
	}
	var resp api.LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.User.Role != "admin" {
		t.Errorf("first user role = %q, want admin", resp.User.Role)
	}
	if w := doJSON(t, s2, "GET", "/api/users", resp.Token, nil); w.Code != 200 {
		t.Errorf("bootstrap session must work: status = %d", w.Code)
	}
	// And exactly once - even a fresh code does not reopen it.
	armBootstrap(t, s2, "NEWCODE2")
	if w := doJSON(t, s2, "POST", "/api/bootstrap", "", api.BootstrapRequest{
		Code: "NEWCODE2", Email: "eve@example.com", Password: testPassword,
	}); w.Code != 403 {
		t.Errorf("second bootstrap: status = %d, want 403", w.Code)
	}
}

func TestAPITokenLifecycleAndScopes(t *testing.T) {
	s, _ := newTestServer(t)
	session := login(t, s).Token

	// Mint a read token and a write token.
	makeToken := func(scope string) string {
		w := doJSON(t, s, "POST", "/api/tokens", session, api.CreateAPITokenRequest{
			Name: scope + " token", Scope: scope,
		})
		if w.Code != 201 {
			t.Fatalf("create %s token: status = %d, body %s", scope, w.Code, w.Body)
		}
		var resp api.CreateAPITokenResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(resp.Token, "naust_") {
			t.Fatalf("token format: %q", resp.Token)
		}
		return resp.Token
	}
	readToken := makeToken("read")
	writeToken := makeToken("write")

	// Read token: GET works, mutation blocked.
	if w := doJSON(t, s, "GET", "/api/users", readToken, nil); w.Code != 200 {
		t.Errorf("read token GET: status = %d", w.Code)
	}
	if w := doJSON(t, s, "POST", "/api/users", readToken, api.CreateUserRequest{
		Email: "bob@example.com", Password: testPassword,
	}); w.Code != 403 {
		t.Errorf("read token POST: status = %d, want 403", w.Code)
	}

	// Write token: mutations work, credential surface stays closed.
	if w := doJSON(t, s, "POST", "/api/users", writeToken, api.CreateUserRequest{
		Email: "bob@example.com", Password: testPassword,
	}); w.Code != 201 {
		t.Errorf("write token POST: status = %d", w.Code)
	}
	for _, path := range []string{"/api/tokens", "/api/auth/totp/setup"} {
		if w := doJSON(t, s, "POST", path, writeToken, api.CreateAPITokenRequest{Name: "x", Scope: "read"}); w.Code != 403 {
			t.Errorf("write token on %s: status = %d, want 403", path, w.Code)
		}
	}

	// Garbage and revoked tokens are rejected.
	if w := doJSON(t, s, "GET", "/api/users", "naust_deadbeef", nil); w.Code != 401 {
		t.Errorf("bogus token: status = %d, want 401", w.Code)
	}
	var list api.APITokensResponse
	w := doJSON(t, s, "GET", "/api/tokens", session, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Tokens) != 2 {
		t.Fatalf("token list = %+v", list.Tokens)
	}
	for _, tok := range list.Tokens {
		if tok.Scope == "read" {
			if w := doJSON(t, s, "DELETE", "/api/tokens/"+itoa(tok.ID), session, nil); w.Code != 204 {
				t.Fatalf("revoke: status = %d", w.Code)
			}
		}
	}
	if w := doJSON(t, s, "GET", "/api/users", readToken, nil); w.Code != 401 {
		t.Errorf("revoked token: status = %d, want 401", w.Code)
	}
}

// TestWriteScopedTokenOwnedByNonAdminRejectedOnAdminRoute proves the
// scope check and the role check are independent gates: a write-scope
// API token (which passes requireAuth's scope check on any method)
// owned by a non-admin user must still be turned away by requireAdmin,
// not waved through because its scope happens to be "write".
func TestWriteScopedTokenOwnedByNonAdminRejectedOnAdminRoute(t *testing.T) {
	s, _ := newTestServer(t)
	admin := login(t, s).Token
	if w := doJSON(t, s, "POST", "/api/users", admin, api.CreateUserRequest{
		Email: "bob@example.com", Password: testPassword,
	}); w.Code != 201 {
		t.Fatalf("create bob = %d %s", w.Code, w.Body)
	}
	bobSession := loginAs(t, s, "bob@example.com", testPassword)

	w := doJSON(t, s, "POST", "/api/tokens", bobSession, api.CreateAPITokenRequest{Name: "bot", Scope: "write"})
	var created api.CreateAPITokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	if w := doJSON(t, s, "POST", "/api/users", created.Token, api.CreateUserRequest{
		Email: "eve@example.com", Password: testPassword,
	}); w.Code != 403 {
		t.Fatalf("non-admin's write token on admin route: status = %d, want 403", w.Code)
	}
}

func TestDemotedAdminTokensRevoked(t *testing.T) {
	s, _ := newTestServer(t)
	session := login(t, s).Token

	// Second admin gets a token, then is demoted; the token dies too.
	doJSON(t, s, "POST", "/api/users", session, api.CreateUserRequest{
		Email: "bob@example.com", Password: testPassword, Role: "admin",
	})
	bobSession := loginAs(t, s, "bob@example.com", testPassword)
	w := doJSON(t, s, "POST", "/api/tokens", bobSession, api.CreateAPITokenRequest{Name: "bot", Scope: "write"})
	var created api.CreateAPITokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	role := "user"
	if w := doJSON(t, s, "PATCH", "/api/users/bob@example.com", session, api.UpdateUserRequest{Role: &role}); w.Code != 200 {
		t.Fatalf("demote: status = %d, body %s", w.Code, w.Body)
	}
	if w := doJSON(t, s, "GET", "/api/users", created.Token, nil); w.Code != 401 {
		t.Errorf("demoted admin's token: status = %d, want 401", w.Code)
	}
}

func TestTOTPLoginFlow(t *testing.T) {
	s, _ := newTestServer(t)
	session := login(t, s).Token

	// Enroll: setup offers a secret, enable requires a matching code.
	w := doJSON(t, s, "POST", "/api/auth/totp/setup", session, nil)
	var setup api.TOTPSetupResponse
	if err := json.Unmarshal(w.Body.Bytes(), &setup); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(setup.OTPAuthURI, "otpauth://totp/") {
		t.Errorf("URI = %q", setup.OTPAuthURI)
	}
	if w := doJSON(t, s, "POST", "/api/auth/totp/enable", session, api.EnableTOTPRequest{
		Secret: setup.Secret, Code: "000000",
	}); w.Code != 400 {
		t.Errorf("enable with wrong code: status = %d, want 400", w.Code)
	}
	code := totpNow(t, setup.Secret, 0)
	if w := doJSON(t, s, "POST", "/api/auth/totp/enable", session, api.EnableTOTPRequest{
		Secret: setup.Secret, Code: code, Label: "phone",
	}); w.Code != 201 {
		t.Fatalf("enable: status = %d, body %s", w.Code, w.Body)
	}

	// Password alone now fails with the hint...
	w = doJSON(t, s, "POST", "/api/auth/login", "", api.LoginRequest{
		Email: "admin@example.com", Password: testPassword,
	})
	if w.Code != 403 {
		t.Fatalf("login without code: status = %d", w.Code)
	}
	var errResp api.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatal(err)
	}
	if len(errResp.Hints) != 1 || errResp.Hints[0] != "missing-totp-code" {
		t.Errorf("hints = %v", errResp.Hints)
	}

	// ...a wrong code fails...
	if w := doJSON(t, s, "POST", "/api/auth/login", "", api.LoginRequest{
		Email: "admin@example.com", Password: testPassword, TOTPCode: "000000",
	}); w.Code != 403 {
		t.Errorf("login with wrong code: status = %d", w.Code)
	}

	// ...the next step's code succeeds (enrollment consumed the current
	// step), and replaying it fails.
	next := totpNow(t, setup.Secret, 1)
	w = doJSON(t, s, "POST", "/api/auth/login", "", api.LoginRequest{
		Email: "admin@example.com", Password: testPassword, TOTPCode: next,
	})
	if w.Code != 200 {
		t.Fatalf("login with code: status = %d, body %s", w.Code, w.Body)
	}
	if w := doJSON(t, s, "POST", "/api/auth/login", "", api.LoginRequest{
		Email: "admin@example.com", Password: testPassword, TOTPCode: next,
	}); w.Code != 403 {
		t.Errorf("replayed code: status = %d, want 403", w.Code)
	}

	// Disable restores password-only login.
	var state api.MFAStateResponse
	w = doJSON(t, s, "GET", "/api/auth/mfa", session, nil)
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Credentials) != 1 || state.Credentials[0].Label != "phone" {
		t.Fatalf("MFA state = %+v", state.Credentials)
	}
	if w := doJSON(t, s, "DELETE", "/api/auth/mfa/totp/"+itoa(state.Credentials[0].ID), session, nil); w.Code != 204 {
		t.Fatalf("disable: status = %d", w.Code)
	}
	if w := doJSON(t, s, "POST", "/api/auth/login", "", api.LoginRequest{
		Email: "admin@example.com", Password: testPassword,
	}); w.Code != 200 {
		t.Errorf("login after disable: status = %d", w.Code)
	}
}

// enrollTOTP is the setup+enable round trip, returning the secret.
func enrollTOTP(t *testing.T, s *Server, session, label string) string {
	t.Helper()
	w := doJSON(t, s, "POST", "/api/auth/totp/setup", session, nil)
	var setup api.TOTPSetupResponse
	if err := json.Unmarshal(w.Body.Bytes(), &setup); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, s, "POST", "/api/auth/totp/enable", session, api.EnableTOTPRequest{
		Secret: setup.Secret, Code: totpNow(t, setup.Secret, 0), Label: label,
	})
	if w.Code != 201 {
		t.Fatalf("enroll %s: status = %d, body %s", label, w.Code, w.Body)
	}
	return setup.Secret
}

// TestMFADisableRejectsDeletingAnotherUsersCredential proves the
// HasUserWith ownership filter in handleMFADisable actually stops one
// account from stripping another's second factor by guessing its
// credential id - the direct MFA-bypass path if that filter were ever
// dropped.
func TestMFADisableRejectsDeletingAnotherUsersCredential(t *testing.T) {
	s, _ := newTestServer(t)
	admin := login(t, s).Token
	enrollTOTP(t, s, admin, "admin phone")

	var state api.MFAStateResponse
	w := doJSON(t, s, "GET", "/api/auth/mfa", admin, nil)
	json.Unmarshal(w.Body.Bytes(), &state)
	adminCredID := state.Credentials[0].ID

	if w := doJSON(t, s, "POST", "/api/users", admin, api.CreateUserRequest{
		Email: "bob@example.com", Password: testPassword,
	}); w.Code != 201 {
		t.Fatalf("create bob = %d %s", w.Code, w.Body)
	}
	bob := loginAs(t, s, "bob@example.com", testPassword)

	if w := doJSON(t, s, "DELETE", "/api/auth/mfa/totp/"+itoa(adminCredID), bob, nil); w.Code != 404 {
		t.Fatalf("bob deleting admin's TOTP credential: status = %d, want 404", w.Code)
	}

	// admin's credential must have survived.
	w = doJSON(t, s, "GET", "/api/auth/mfa", admin, nil)
	json.Unmarshal(w.Body.Bytes(), &state)
	if len(state.Credentials) != 1 {
		t.Fatalf("admin's credentials after bob's attempt = %+v", state.Credentials)
	}
}

// TestTOTPLoginFallsThroughToSecondCredential proves checkTOTP's loop
// over multiple enrolled credentials actually tries every one: a code
// valid only for the second credential must still authenticate even
// though the first credential's own comparison fails for it.
func TestTOTPLoginFallsThroughToSecondCredential(t *testing.T) {
	s, _ := newTestServer(t)
	session := login(t, s).Token
	enrollTOTP(t, s, session, "phone one")
	secretTwo := enrollTOTP(t, s, session, "phone two")

	// Enrollment consumes the current step, so the next step is what's
	// still valid - matching TestTOTPLoginFlow's pattern above.
	code := totpNow(t, secretTwo, 1)
	w := doJSON(t, s, "POST", "/api/auth/login", "", api.LoginRequest{
		Email: "admin@example.com", Password: testPassword, TOTPCode: code,
	})
	if w.Code != 200 {
		t.Fatalf("login with second credential's code: status = %d, body %s", w.Code, w.Body)
	}
}

// totpNow computes the code for the enrolled secret at now+offset
// steps, using the same implementation the server trusts (pinned
// separately against RFC 6238 vectors).
func totpNow(t *testing.T, secret string, offsetSteps int64) string {
	t.Helper()
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return auth.TOTPCodeForTest(key, time.Now().Unix()/30+offsetSteps)
}

func itoa(n int) string { return strconv.Itoa(n) }
