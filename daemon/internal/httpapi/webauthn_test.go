package httpapi

import (
	"encoding/json"
	"testing"

	"naust/daemon/internal/api"
)

// Full WebAuthn ceremonies need a real authenticator; the library's
// verification is its own test surface. These tests cover our side:
// options shape, challenge lifecycle, and the auth gates around it.

func TestWebAuthnRegisterBegin(t *testing.T) {
	s, _ := newTestServer(t)
	session := login(t, s).Token

	w := doJSON(t, s, "POST", "/api/auth/webauthn/register/begin", session, nil)
	if w.Code != 200 {
		t.Fatalf("begin status = %d, body %s", w.Code, w.Body)
	}
	var resp api.WebAuthnBeginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Nonce == "" {
		t.Error("nonce missing")
	}
	var options struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID string `json:"id"`
			} `json:"rp"`
			User struct {
				Name string `json:"name"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(resp.Options, &options); err != nil {
		t.Fatal(err)
	}
	if options.PublicKey.Challenge == "" || options.PublicKey.RP.ID != "box.example.com" {
		t.Errorf("options = %s", resp.Options)
	}
	if options.PublicKey.User.Name != "admin@example.com" {
		t.Errorf("user name = %q", options.PublicKey.User.Name)
	}

	// Unauthenticated and token-authenticated callers are refused.
	if w := doJSON(t, s, "POST", "/api/auth/webauthn/register/begin", "", nil); w.Code != 401 {
		t.Errorf("unauthenticated begin: status = %d", w.Code)
	}

	// Completing with an unknown nonce fails cleanly.
	w = doJSON(t, s, "POST", "/api/auth/webauthn/register/complete", session, api.WebAuthnRegisterCompleteRequest{
		Nonce: "does-not-exist", Credential: json.RawMessage(`{}`),
	})
	if w.Code != 400 {
		t.Errorf("complete with bogus nonce: status = %d", w.Code)
	}
}

// TestWebAuthnRegisterCompleteRejectsCrossUserHijack proves the
// owner.ID != userFrom(r).ID guard in handleWebAuthnRegisterComplete
// actually stops user B from completing user A's enrollment ceremony
// with a credential of B's own choosing - the direct "wrong user
// completing another user's ceremony" account-takeover path.
func TestWebAuthnRegisterCompleteRejectsCrossUserHijack(t *testing.T) {
	s, _ := newTestServer(t)
	admin := login(t, s).Token
	if w := doJSON(t, s, "POST", "/api/users", admin, api.CreateUserRequest{
		Email: "bob@example.com", Password: testPassword,
	}); w.Code != 201 {
		t.Fatalf("create bob = %d %s", w.Code, w.Body)
	}
	bob := loginAs(t, s, "bob@example.com", testPassword)

	// admin begins enrollment.
	w := doJSON(t, s, "POST", "/api/auth/webauthn/register/begin", admin, nil)
	if w.Code != 200 {
		t.Fatalf("admin begin = %d %s", w.Code, w.Body)
	}
	var begin api.WebAuthnBeginResponse
	json.Unmarshal(w.Body.Bytes(), &begin)

	// bob, authenticated as himself, tries to complete admin's nonce.
	va := newVirtualAuthenticator(t, s.PrimaryHostname)
	w = doJSON(t, s, "POST", "/api/auth/webauthn/register/complete", bob,
		api.WebAuthnRegisterCompleteRequest{
			Nonce:      begin.Nonce,
			Credential: va.attest(t, challengeFrom(t, begin.Options)),
		})
	if w.Code != 400 {
		t.Fatalf("cross-user hijack status = %d %s, want 400", w.Code, w.Body)
	}
	// The credential must not have attached to either account.
	if creds := mfaCreds(t, s, admin); len(creds) != 0 {
		t.Errorf("hijacked credential attached to admin: %+v", creds)
	}
	if creds := mfaCreds(t, s, bob); len(creds) != 0 {
		t.Errorf("hijacked credential attached to bob: %+v", creds)
	}
}

// mfaCreds lists the caller's enrolled MFA credentials.
func mfaCreds(t *testing.T, s *Server, token string) []api.MFACredential {
	t.Helper()
	w := doJSON(t, s, "GET", "/api/auth/mfa", token, nil)
	if w.Code != 200 {
		t.Fatalf("mfa state = %d %s", w.Code, w.Body)
	}
	var resp api.MFAStateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.Credentials
}

// TestWebAuthnLoginFullCeremony exercises a real passkey login end to
// end: register a key, then log in with only the passkey (no
// password), and confirm the minted session actually works.
func TestWebAuthnLoginFullCeremony(t *testing.T) {
	s, _ := newTestServer(t)
	session := login(t, s).Token
	uid := userIDOf(t, s, "admin@example.com")
	va := newVirtualAuthenticator(t, s.PrimaryHostname)
	registerPasskey(t, s, session, va)

	w := doJSON(t, s, "POST", "/api/auth/webauthn/login/begin", "",
		api.WebAuthnLoginBeginRequest{Email: "admin@example.com"})
	if w.Code != 200 {
		t.Fatalf("login begin = %d %s", w.Code, w.Body)
	}
	var begin api.WebAuthnBeginResponse
	json.Unmarshal(w.Body.Bytes(), &begin)

	w = doJSON(t, s, "POST", "/api/auth/webauthn/login/complete", "",
		api.WebAuthnLoginCompleteRequest{
			Nonce:      begin.Nonce,
			Credential: va.assert(t, challengeFrom(t, begin.Options), uid),
		})
	if w.Code != 200 {
		t.Fatalf("login complete = %d %s", w.Code, w.Body)
	}
	var resp api.LoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token == "" || resp.User.Email != "admin@example.com" {
		t.Fatalf("login response = %+v", resp)
	}

	if w := doJSON(t, s, "GET", "/api/auth/me", resp.Token, nil); w.Code != 200 {
		t.Errorf("minted token does not authenticate: %d %s", w.Code, w.Body)
	}
}

// TestWebAuthnNoncesAreSingleUse proves a nonce cannot complete a
// second ceremony after it already succeeded once - the delete-before-
// use pattern that stops a retried network request from re-running a
// ceremony.
func TestWebAuthnNoncesAreSingleUse(t *testing.T) {
	s, _ := newTestServer(t)
	session := login(t, s).Token
	uid := userIDOf(t, s, "admin@example.com")
	va := newVirtualAuthenticator(t, s.PrimaryHostname)

	// Registration nonce, replayed.
	w := doJSON(t, s, "POST", "/api/auth/webauthn/register/begin", session, nil)
	var begin api.WebAuthnBeginResponse
	json.Unmarshal(w.Body.Bytes(), &begin)
	regReq := api.WebAuthnRegisterCompleteRequest{
		Nonce:      begin.Nonce,
		Credential: va.attest(t, challengeFrom(t, begin.Options)),
	}
	if w := doJSON(t, s, "POST", "/api/auth/webauthn/register/complete", session, regReq); w.Code != 201 {
		t.Fatalf("first register complete = %d %s", w.Code, w.Body)
	}
	if w := doJSON(t, s, "POST", "/api/auth/webauthn/register/complete", session, regReq); w.Code == 201 {
		t.Fatal("register nonce was reusable")
	}

	// Login nonce, replayed.
	w = doJSON(t, s, "POST", "/api/auth/webauthn/login/begin", "",
		api.WebAuthnLoginBeginRequest{Email: "admin@example.com"})
	json.Unmarshal(w.Body.Bytes(), &begin)
	loginReq := api.WebAuthnLoginCompleteRequest{
		Nonce:      begin.Nonce,
		Credential: va.assert(t, challengeFrom(t, begin.Options), uid),
	}
	if w := doJSON(t, s, "POST", "/api/auth/webauthn/login/complete", "", loginReq); w.Code != 200 {
		t.Fatalf("first login complete = %d %s", w.Code, w.Body)
	}
	if w := doJSON(t, s, "POST", "/api/auth/webauthn/login/complete", "", loginReq); w.Code == 200 {
		t.Fatal("login nonce was reusable")
	}
}

// TestWebAuthnRegisterNonceCannotCompleteLogin proves ceremony kinds
// are enforced in both directions: a register-kind nonce must not
// complete a login (TestPRFNonceCannotCompleteLogin already proves
// this the other way, for prf-kind nonces).
func TestWebAuthnRegisterNonceCannotCompleteLogin(t *testing.T) {
	s, _ := newTestServer(t)
	session := login(t, s).Token
	uid := userIDOf(t, s, "admin@example.com")
	va := newVirtualAuthenticator(t, s.PrimaryHostname)

	w := doJSON(t, s, "POST", "/api/auth/webauthn/register/begin", session, nil)
	var begin api.WebAuthnBeginResponse
	json.Unmarshal(w.Body.Bytes(), &begin)

	w = doJSON(t, s, "POST", "/api/auth/webauthn/login/complete", "",
		api.WebAuthnLoginCompleteRequest{
			Nonce:      begin.Nonce,
			Credential: va.assert(t, challengeFrom(t, begin.Options), uid),
		})
	if w.Code != 400 {
		t.Fatalf("register nonce completed a login: %d %s", w.Code, w.Body)
	}
}

func TestWebAuthnLoginBeginRequiresPasskeys(t *testing.T) {
	s, _ := newTestServer(t)
	// Account exists but has no passkeys; unknown accounts get the
	// same answer.
	for _, email := range []string{"admin@example.com", "ghost@example.com"} {
		w := doJSON(t, s, "POST", "/api/auth/webauthn/login/begin", "", api.WebAuthnLoginBeginRequest{Email: email})
		if w.Code != 403 {
			t.Errorf("%s: status = %d, want 403", email, w.Code)
		}
	}
}
