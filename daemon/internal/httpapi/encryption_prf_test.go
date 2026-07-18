package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"testing"

	"naust/daemon/internal/api"
	"naust/daemon/internal/auth"
	entuser "naust/daemon/internal/store/ent/user"
)

// registerPasskey walks the full register ceremony with the virtual
// authenticator and returns the credential's MFA row id.
func registerPasskey(t *testing.T, s *Server, token string, va *virtualAuthenticator) int {
	t.Helper()
	w := doJSON(t, s, "POST", "/api/auth/webauthn/register/begin", token, nil)
	if w.Code != 200 {
		t.Fatalf("register begin = %d %s", w.Code, w.Body)
	}
	var begin api.WebAuthnBeginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &begin); err != nil {
		t.Fatal(err)
	}
	w = doJSON(t, s, "POST", "/api/auth/webauthn/register/complete", token,
		api.WebAuthnRegisterCompleteRequest{
			Nonce:      begin.Nonce,
			Credential: va.attest(t, challengeFrom(t, begin.Options)),
			Name:       "test key",
		})
	if w.Code != 201 {
		t.Fatalf("register complete = %d %s", w.Code, w.Body)
	}
	var cred api.MFACredential
	if err := json.Unmarshal(w.Body.Bytes(), &cred); err != nil {
		t.Fatal(err)
	}
	return cred.ID
}

// prfOptions pulls the prf extension inputs out of assertion options.
type prfOptions struct {
	PublicKey struct {
		Extensions struct {
			PRF struct {
				Eval struct {
					First string `json:"first"`
				} `json:"eval"`
				EvalByCredential map[string]struct {
					First string `json:"first"`
				} `json:"evalByCredential"`
			} `json:"prf"`
		} `json:"extensions"`
	} `json:"publicKey"`
}

func decodePRFOptions(t *testing.T, options []byte) prfOptions {
	t.Helper()
	var o prfOptions
	if err := json.Unmarshal(options, &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func userIDOf(t *testing.T, s *Server, email string) int {
	t.Helper()
	return s.Store.User.Query().
		Where(entuser.Email(email)).
		OnlyX(context.Background()).ID
}

func TestPRFEnrollRequiresEncryption(t *testing.T) {
	s, _, token := encTestServer(t)
	if w := doJSON(t, s, "POST", "/api/user/encryption/prf/enroll/begin", token, nil); w.Code != 400 {
		t.Errorf("enroll without encryption = %d %s", w.Code, w.Body)
	}
	if w := doJSON(t, s, "POST", "/api/user/encryption/prf/relink/begin", token, nil); w.Code != 400 {
		t.Errorf("relink without prf slots = %d %s", w.Code, w.Body)
	}
}

func TestPRFEnrollRelinkLifecycle(t *testing.T) {
	s, h, token := encTestServer(t)
	unwrapKey := writeUnwrapKey(t, s)
	enableEncryption(t, s, token)
	uid := userIDOf(t, s, "admin@example.com")

	va := newVirtualAuthenticator(t, s.PrimaryHostname)
	credRowID := registerPasskey(t, s, token, va)

	// Enroll: the begin options carry a fresh eval salt.
	w := doJSON(t, s, "POST", "/api/user/encryption/prf/enroll/begin", token, nil)
	if w.Code != 200 {
		t.Fatalf("enroll begin = %d %s", w.Code, w.Body)
	}
	var begin api.WebAuthnBeginResponse
	json.Unmarshal(w.Body.Bytes(), &begin)
	saltB64 := decodePRFOptions(t, begin.Options).PublicKey.Extensions.PRF.Eval.First
	if saltB64 == "" {
		t.Fatalf("no prf eval salt in options: %s", begin.Options)
	}
	salt, err := base64.RawURLEncoding.DecodeString(saltB64)
	if err != nil {
		t.Fatal(err)
	}

	w = doJSON(t, s, "POST", "/api/user/encryption/prf/enroll/complete", token,
		api.EncryptionPRFCompleteRequest{
			Nonce:      begin.Nonce,
			Credential: va.assert(t, challengeFrom(t, begin.Options), uid),
			PRFOutput:  b64u(va.prf(salt)),
			Password:   testPassword,
		})
	if w.Code != 200 {
		t.Fatalf("enroll complete = %d %s", w.Code, w.Body)
	}
	if st := encStatus(t, s, token); !st.HasPRFSlot {
		t.Fatalf("has_prf_slot after enroll: %+v", st)
	}

	// Simulate an admin reset (hash swapped, slot orphaned).
	newHash, err := auth.HashPassword("reset by admin 77")
	if err != nil {
		t.Fatal(err)
	}
	s.Store.User.Update().
		Where(entuser.Email("admin@example.com")).
		SetPasswordHash(newHash).
		ExecX(context.Background())
	// The existing session stays valid (in real life the user signs
	// back in with the passkey; password login now requires it).
	if _, resp := unwrap(t, s, unwrapKey, "admin@example.com", "reset by admin 77"); resp.MailKey != nil {
		t.Fatal("orphaned slot unwrapped")
	}

	// Relink via passkey: options must carry the SAME eval salt keyed
	// by credential, so the authenticator reproduces the enroll output.
	w = doJSON(t, s, "POST", "/api/user/encryption/prf/relink/begin", token, nil)
	if w.Code != 200 {
		t.Fatalf("relink begin = %d %s", w.Code, w.Body)
	}
	json.Unmarshal(w.Body.Bytes(), &begin)
	byCred := decodePRFOptions(t, begin.Options).PublicKey.Extensions.PRF.EvalByCredential
	got, ok := byCred[b64u(va.credID)]
	if !ok || got.First != saltB64 {
		t.Fatalf("evalByCredential = %v, want %s under %s", byCred, saltB64, b64u(va.credID))
	}

	// A wrong PRF output is rejected and burns only the ceremony.
	w = doJSON(t, s, "POST", "/api/user/encryption/prf/relink/complete", token,
		api.EncryptionPRFCompleteRequest{
			Nonce:      begin.Nonce,
			Credential: va.assert(t, challengeFrom(t, begin.Options), uid),
			PRFOutput:  b64u(make([]byte, 32)),
			Password:   "reset by admin 77",
		})
	if w.Code != 400 {
		t.Fatalf("relink with wrong prf output = %d %s", w.Code, w.Body)
	}

	// Fresh ceremony, correct output: the password slot comes back and
	// delivers the same dovecot key as the original setup.
	w = doJSON(t, s, "POST", "/api/user/encryption/prf/relink/begin", token, nil)
	json.Unmarshal(w.Body.Bytes(), &begin)
	w = doJSON(t, s, "POST", "/api/user/encryption/prf/relink/complete", token,
		api.EncryptionPRFCompleteRequest{
			Nonce:      begin.Nonce,
			Credential: va.assert(t, challengeFrom(t, begin.Options), uid),
			PRFOutput:  b64u(va.prf(salt)),
			Password:   "reset by admin 77",
		})
	if w.Code != 200 {
		t.Fatalf("relink complete = %d %s", w.Code, w.Body)
	}
	_, resp := unwrap(t, s, unwrapKey, "admin@example.com", "reset by admin 77")
	if resp.MailKey == nil || *resp.MailKey != h.args[0]["key_hex"] {
		t.Fatal("relinked slot delivers a different dovecot key")
	}

	// Deleting the passkey deletes its slot.
	if w := doJSON(t, s, "DELETE", "/api/auth/mfa/webauthn/"+strconv.Itoa(credRowID), token, nil); w.Code != 204 {
		t.Fatalf("mfa delete = %d %s", w.Code, w.Body)
	}
	if st := encStatus(t, s, token); st.HasPRFSlot {
		t.Fatalf("prf slot survived credential deletion: %+v", st)
	}
}

func TestPRFNonceCannotCompleteLogin(t *testing.T) {
	// A prf ceremony is assertion-shaped but must never mint a
	// session: the kinds are distinct on purpose.
	s, _, token := encTestServer(t)
	enableEncryption(t, s, token)
	uid := userIDOf(t, s, "admin@example.com")
	va := newVirtualAuthenticator(t, s.PrimaryHostname)
	registerPasskey(t, s, token, va)

	w := doJSON(t, s, "POST", "/api/user/encryption/prf/enroll/begin", token, nil)
	var begin api.WebAuthnBeginResponse
	json.Unmarshal(w.Body.Bytes(), &begin)

	w = doJSON(t, s, "POST", "/api/auth/webauthn/login/complete", "",
		api.WebAuthnLoginCompleteRequest{
			Nonce:      begin.Nonce,
			Credential: va.assert(t, challengeFrom(t, begin.Options), uid),
		})
	if w.Code != 400 {
		t.Fatalf("prf nonce completed a login: %d %s", w.Code, w.Body)
	}
}
