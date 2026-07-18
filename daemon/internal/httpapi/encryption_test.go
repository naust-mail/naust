package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"naust/daemon/internal/api"
	"naust/daemon/internal/auth"
	"naust/daemon/internal/mailcrypt"
	"naust/daemon/internal/store"
	entuser "naust/daemon/internal/store/ent/user"
)

// authFailures reads the store-backed counter logFailedLogin and
// logEncFailure increment.
func authFailures(t *testing.T, s *Server) int64 {
	t.Helper()
	v, err := store.CounterValue(context.Background(), s.Store, store.CounterAuthFailures)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// encHelper records full intent args (fakeHelper only records postfix
// key/value pairs) and can fail keypair generation on demand.
type encHelper struct {
	intents []string
	args    []map[string]string
	fail    bool
}

func (f *encHelper) Call(_ context.Context, intent string, args map[string]string) (string, error) {
	if f.fail {
		return "", errors.New("doveadm exploded")
	}
	f.intents = append(f.intents, intent)
	f.args = append(f.args, args)
	return "", nil
}

func encTestServer(t *testing.T) (*Server, *encHelper, string) {
	t.Helper()
	s, _ := newTestServer(t)
	s.Conf = func(key string) string {
		if key == "ENCRYPTION_AT_REST" {
			return "true"
		}
		return ""
	}
	h := &encHelper{}
	s.Helper = h
	return s, h, login(t, s).Token
}

func encStatus(t *testing.T, s *Server, token string) api.EncryptionStatusResponse {
	t.Helper()
	w := doJSON(t, s, "GET", "/api/user/encryption/status", token, nil)
	if w.Code != 200 {
		t.Fatalf("status = %d %s", w.Code, w.Body)
	}
	var resp api.EncryptionStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// enableEncryption walks the full ceremony and returns the recovery
// codes.
func enableEncryption(t *testing.T, s *Server, token string) []string {
	t.Helper()
	w := doJSON(t, s, "POST", "/api/user/encryption/setup", token,
		api.EncryptionSetupRequest{Password: testPassword})
	if w.Code != 200 {
		t.Fatalf("setup = %d %s", w.Code, w.Body)
	}
	var resp api.EncryptionSetupResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, "POST", "/api/user/encryption/challenge", token,
		api.EncryptionChallengeRequest{Code: resp.RecoveryCodes[1], CodeIndex: 1}); w.Code != 200 {
		t.Fatalf("challenge = %d %s", w.Code, w.Body)
	}
	return resp.RecoveryCodes
}

// unwrap posts the form-encoded internal unwrap request.
func unwrap(t *testing.T, s *Server, apiKey, user, password string) (int, api.MailcryptUnwrapResponse) {
	t.Helper()
	form := url.Values{"user": {user}, "password": {password}}
	req := httptest.NewRequest("POST", "/internal/mailcrypt/unwrap",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if apiKey != "" {
		req.Header.Set("X-Api-Key", apiKey)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	var resp api.MailcryptUnwrapResponse
	if w.Code == 200 {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
	}
	return w.Code, resp
}

func writeUnwrapKey(t *testing.T, s *Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mailcrypt.key")
	if err := os.WriteFile(path, []byte("sekrit-unwrap-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.MailcryptKeyPath = path
	return "sekrit-unwrap-key"
}

func TestEncryptionFeatureGate(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token
	// Conf is nil: the feature is off and the routes hide themselves.
	if w := doJSON(t, s, "GET", "/api/user/encryption/status", token, nil); w.Code != 404 {
		t.Errorf("status with feature off = %d", w.Code)
	}
	if w := doJSON(t, s, "POST", "/api/user/encryption/setup", token,
		api.EncryptionSetupRequest{Password: testPassword}); w.Code != 404 {
		t.Errorf("setup with feature off = %d", w.Code)
	}
}

func TestEncryptionSetupCeremony(t *testing.T) {
	s, h, token := encTestServer(t)

	if st := encStatus(t, s, token); st.Enabled {
		t.Fatal("enabled before setup")
	}

	// Wrong password refuses.
	if w := doJSON(t, s, "POST", "/api/user/encryption/setup", token,
		api.EncryptionSetupRequest{Password: "wrong"}); w.Code != 403 {
		t.Fatalf("wrong password = %d", w.Code)
	}

	w := doJSON(t, s, "POST", "/api/user/encryption/setup", token,
		api.EncryptionSetupRequest{Password: testPassword})
	if w.Code != 200 {
		t.Fatalf("setup = %d %s", w.Code, w.Body)
	}
	var resp api.EncryptionSetupResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.RecoveryCodes) != 4 {
		t.Fatalf("codes = %v", resp.RecoveryCodes)
	}

	// Nothing committed until the challenge passes.
	if st := encStatus(t, s, token); st.Enabled || len(st.SlotTypes) != 0 {
		t.Fatalf("slots exist before challenge: %+v", st)
	}

	// Wrong index, malformed code (counts an attempt), then success.
	if w := doJSON(t, s, "POST", "/api/user/encryption/challenge", token,
		api.EncryptionChallengeRequest{Code: resp.RecoveryCodes[0], CodeIndex: 9}); w.Code != 400 {
		t.Errorf("bad index = %d", w.Code)
	}
	if w := doJSON(t, s, "POST", "/api/user/encryption/challenge", token,
		api.EncryptionChallengeRequest{Code: "NOT-AREA-LCOD-EXXX", CodeIndex: 0}); w.Code != 400 {
		t.Errorf("bad CRC = %d", w.Code)
	}
	if w := doJSON(t, s, "POST", "/api/user/encryption/challenge", token,
		api.EncryptionChallengeRequest{Code: resp.RecoveryCodes[2], CodeIndex: 2}); w.Code != 200 {
		t.Fatalf("challenge = %d %s", w.Code, w.Body)
	}

	// The keypair was generated via the helper intent with a 64-hex
	// key that never equals the raw recovery input.
	if len(h.intents) != 1 || h.intents[0] != "mailcrypt.keygen" {
		t.Fatalf("intents = %v", h.intents)
	}
	if h.args[0]["email"] != "admin@example.com" || len(h.args[0]["key_hex"]) != 64 {
		t.Fatalf("keygen args = %v", h.args[0])
	}

	st := encStatus(t, s, token)
	if !st.Enabled || len(st.SlotTypes) != 2 {
		t.Fatalf("after ceremony: %+v", st)
	}

	// Second setup refused.
	if w := doJSON(t, s, "POST", "/api/user/encryption/setup", token,
		api.EncryptionSetupRequest{Password: testPassword}); w.Code != 400 {
		t.Errorf("re-setup = %d", w.Code)
	}
}

func TestEncryptionChallengeAttemptLimit(t *testing.T) {
	s, _, token := encTestServer(t)
	w := doJSON(t, s, "POST", "/api/user/encryption/setup", token,
		api.EncryptionSetupRequest{Password: testPassword})
	var resp api.EncryptionSetupResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	// A validly-formatted but wrong code burns attempts.
	wrong, _ := freshCode(t, resp.RecoveryCodes)
	for i := 0; i < 3; i++ {
		if w := doJSON(t, s, "POST", "/api/user/encryption/challenge", token,
			api.EncryptionChallengeRequest{Code: wrong, CodeIndex: 0}); w.Code != 400 {
			t.Fatalf("attempt %d = %d", i, w.Code)
		}
	}
	if w := doJSON(t, s, "POST", "/api/user/encryption/challenge", token,
		api.EncryptionChallengeRequest{Code: wrong, CodeIndex: 0}); w.Code != 429 {
		t.Fatalf("4th attempt = %d", w.Code)
	}
	// The pending ceremony is gone; even the right code cannot land.
	if w := doJSON(t, s, "POST", "/api/user/encryption/challenge", token,
		api.EncryptionChallengeRequest{Code: resp.RecoveryCodes[0], CodeIndex: 0}); w.Code != 400 {
		t.Fatalf("after purge = %d", w.Code)
	}
}

// freshCode generates a valid code that is not in the given set.
func freshCode(t *testing.T, avoid []string) (string, int) {
	t.Helper()
	for i := 0; i < 20; i++ {
		codes, err := mailcrypt.GenerateRecoveryCodes()
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range codes {
			collides := false
			for _, a := range avoid {
				if c == a {
					collides = true
				}
			}
			if !collides {
				return c, 0
			}
		}
	}
	t.Fatal("could not generate a fresh code")
	return "", 0
}

func TestEncryptionKeypairFailureLeavesCleanState(t *testing.T) {
	s, h, token := encTestServer(t)
	h.fail = true

	w := doJSON(t, s, "POST", "/api/user/encryption/setup", token,
		api.EncryptionSetupRequest{Password: testPassword})
	var resp api.EncryptionSetupResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if w := doJSON(t, s, "POST", "/api/user/encryption/challenge", token,
		api.EncryptionChallengeRequest{Code: resp.RecoveryCodes[0], CodeIndex: 0}); w.Code != 500 {
		t.Fatalf("challenge with broken doveadm = %d", w.Code)
	}
	if st := encStatus(t, s, token); st.Enabled || len(st.SlotTypes) != 0 {
		t.Fatalf("slots committed despite keypair failure: %+v", st)
	}
	// The pending state is purged: the user starts over cleanly.
	if w := doJSON(t, s, "POST", "/api/user/encryption/challenge", token,
		api.EncryptionChallengeRequest{Code: resp.RecoveryCodes[0], CodeIndex: 0}); w.Code != 400 {
		t.Fatalf("retry without new setup = %d", w.Code)
	}
}

func TestMailcryptUnwrap(t *testing.T) {
	s, h, token := encTestServer(t)

	// No key file configured: fails closed even with the ceremony done.
	if code, _ := unwrap(t, s, "anything", "admin@example.com", testPassword); code != 403 {
		t.Fatalf("no key file = %d", code)
	}
	key := writeUnwrapKey(t, s)
	if code, _ := unwrap(t, s, "wrong-key", "admin@example.com", testPassword); code != 403 {
		t.Fatalf("wrong api key = %d", code)
	}

	// Encryption not set up: null key, 200.
	code, resp := unwrap(t, s, key, "admin@example.com", testPassword)
	if code != 200 || resp.MailKey != nil {
		t.Fatalf("before setup = %d %+v", code, resp)
	}
	// Unknown user: identical response.
	code, resp = unwrap(t, s, key, "ghost@example.com", "pw")
	if code != 200 || resp.MailKey != nil {
		t.Fatalf("unknown user = %d %+v", code, resp)
	}

	enableEncryption(t, s, token)

	// Wrong password: null key, and the failure is counted.
	before := authFailures(t, s)
	code, resp = unwrap(t, s, key, "admin@example.com", "wrong password")
	if code != 200 || resp.MailKey != nil {
		t.Fatalf("wrong password = %d %+v", code, resp)
	}
	if authFailures(t, s) != before+1 {
		t.Error("failed unwrap not counted as auth failure")
	}

	// Correct password: the delivered key IS the keypair password the
	// helper received during setup - the invariant that makes mail
	// readable.
	code, resp = unwrap(t, s, key, "admin@example.com", testPassword)
	if code != 200 || resp.MailKey == nil {
		t.Fatalf("unwrap = %d %+v", code, resp)
	}
	if *resp.MailKey != h.args[0]["key_hex"] {
		t.Fatal("unwrap key does not match the generated keypair password")
	}
}

func TestEncryptionRelink(t *testing.T) {
	s, h, token := encTestServer(t)
	key := writeUnwrapKey(t, s)
	codes := enableEncryption(t, s, token)

	// Simulate an admin reset: the hash changes, the slot does not.
	newHash, err := auth.HashPassword("brand new password 9")
	if err != nil {
		t.Fatal(err)
	}
	s.Store.User.Update().
		Where(entuser.Email("admin@example.com")).
		SetPasswordHash(newHash).
		ExecX(context.Background())
	token = loginAs(t, s, "admin@example.com", "brand new password 9")

	// The orphaned slot no longer unwraps.
	if _, resp := unwrap(t, s, key, "admin@example.com", "brand new password 9"); resp.MailKey != nil {
		t.Fatal("orphaned slot unwrapped with the new password")
	}

	// Wrong current password refuses.
	if w := doJSON(t, s, "POST", "/api/user/encryption/relink", token,
		api.EncryptionRelinkRequest{Code: codes[0], Password: "not it"}); w.Code != 403 {
		t.Fatalf("wrong password = %d", w.Code)
	}
	// Wrong (but valid-format) code refuses.
	wrong, _ := freshCode(t, codes)
	if w := doJSON(t, s, "POST", "/api/user/encryption/relink", token,
		api.EncryptionRelinkRequest{Code: wrong, Password: "brand new password 9"}); w.Code != 400 {
		t.Fatalf("wrong code = %d", w.Code)
	}

	if w := doJSON(t, s, "POST", "/api/user/encryption/relink", token,
		api.EncryptionRelinkRequest{Code: codes[3], Password: "brand new password 9"}); w.Code != 200 {
		t.Fatalf("relink = %d %s", w.Code, w.Body)
	}

	// The new password now delivers the SAME dovecot key as setup: the
	// root key survived, mail stays readable, no keypair regeneration.
	_, resp := unwrap(t, s, key, "admin@example.com", "brand new password 9")
	if resp.MailKey == nil || *resp.MailKey != h.args[0]["key_hex"] {
		t.Fatal("relinked slot delivers a different key")
	}
}

func TestEncryptionRelinkRateLimit(t *testing.T) {
	s, _, token := encTestServer(t)
	codes := enableEncryption(t, s, token)
	wrong, _ := freshCode(t, codes)

	for i := 0; i < 5; i++ {
		if w := doJSON(t, s, "POST", "/api/user/encryption/relink", token,
			api.EncryptionRelinkRequest{Code: wrong, Password: testPassword}); w.Code != 400 {
			t.Fatalf("failure %d = %d", i, w.Code)
		}
	}
	// The 6th attempt is refused even with the RIGHT code.
	if w := doJSON(t, s, "POST", "/api/user/encryption/relink", token,
		api.EncryptionRelinkRequest{Code: codes[0], Password: testPassword}); w.Code != 429 {
		t.Fatalf("rate limited = %d", w.Code)
	}
}

func TestEncryptionRotateRecovery(t *testing.T) {
	s, _, token := encTestServer(t)
	oldCodes := enableEncryption(t, s, token)

	w := doJSON(t, s, "POST", "/api/user/encryption/rotate-recovery", token,
		api.EncryptionSetupRequest{Password: testPassword})
	if w.Code != 200 {
		t.Fatalf("rotate = %d %s", w.Code, w.Body)
	}
	var resp api.EncryptionSetupResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.RecoveryCodes) != 4 || resp.RecoveryCodes[0] == oldCodes[0] {
		t.Fatalf("new codes = %v", resp.RecoveryCodes)
	}

	// Old codes remain live until the confirm lands.
	if w := doJSON(t, s, "POST", "/api/user/encryption/relink", token,
		api.EncryptionRelinkRequest{Code: oldCodes[0], Password: testPassword}); w.Code != 200 {
		t.Fatalf("old code during rotation = %d", w.Code)
	}

	if w := doJSON(t, s, "POST", "/api/user/encryption/rotate-recovery-confirm", token,
		api.EncryptionChallengeRequest{Code: resp.RecoveryCodes[1], CodeIndex: 1}); w.Code != 200 {
		t.Fatalf("confirm = %d %s", w.Code, w.Body)
	}

	// Old codes are dead, new codes work.
	if w := doJSON(t, s, "POST", "/api/user/encryption/relink", token,
		api.EncryptionRelinkRequest{Code: oldCodes[0], Password: testPassword}); w.Code != 400 {
		t.Fatalf("old code after rotation = %d", w.Code)
	}
	if w := doJSON(t, s, "POST", "/api/user/encryption/relink", token,
		api.EncryptionRelinkRequest{Code: resp.RecoveryCodes[2], Password: testPassword}); w.Code != 200 {
		t.Fatalf("new code after rotation = %d", w.Code)
	}

	// Rotation without encryption enabled is refused.
	s2, _, token2 := encTestServer(t)
	if w := doJSON(t, s2, "POST", "/api/user/encryption/rotate-recovery", token2,
		api.EncryptionSetupRequest{Password: testPassword}); w.Code != 400 {
		t.Errorf("rotate without setup = %d", w.Code)
	}
}

func TestAdminResetRequiresAcknowledgement(t *testing.T) {
	s, _, token := encTestServer(t)
	enableEncryption(t, s, token)

	// Unacknowledged reset on an encrypted account: refused, hash
	// untouched (the old password still logs in).
	w := doJSON(t, s, "PUT", "/api/users/admin@example.com/password", token,
		api.SetPasswordRequest{Password: "replacement password 1"})
	if w.Code != 409 {
		t.Fatalf("unacknowledged reset = %d %s", w.Code, w.Body)
	}
	loginAs(t, s, "admin@example.com", testPassword)

	// Acknowledged: proceeds; the slot survives (stranded) so status
	// still reports encryption enabled and relink can replace it.
	w = doJSON(t, s, "PUT", "/api/users/admin@example.com/password", token,
		api.SetPasswordRequest{Password: "replacement password 1", AcknowledgeEncryption: true})
	if w.Code != 204 {
		t.Fatalf("acknowledged reset = %d %s", w.Code, w.Body)
	}
	token = loginAs(t, s, "admin@example.com", "replacement password 1")
	if st := encStatus(t, s, token); !st.Enabled {
		t.Fatalf("slot deleted by reset: %+v", st)
	}

	// Accounts without encryption reset exactly as before, no ack.
	doJSON(t, s, "POST", "/api/users", token, api.CreateUserRequest{
		Email: "plain@example.com", Password: "plain user password 2"})
	if w := doJSON(t, s, "PUT", "/api/users/plain@example.com/password", token,
		api.SetPasswordRequest{Password: "changed by admin 3"}); w.Code != 204 {
		t.Fatalf("plain reset = %d %s", w.Code, w.Body)
	}
}

func TestSelfServicePasswordChangeRotatesSlot(t *testing.T) {
	s, h, token := encTestServer(t)
	key := writeUnwrapKey(t, s)
	enableEncryption(t, s, token)

	// Wrong current password refused.
	if w := doJSON(t, s, "POST", "/api/user/password", token,
		api.ChangePasswordRequest{CurrentPassword: "nope", NewPassword: "next password 44"}); w.Code != 403 {
		t.Fatalf("wrong current = %d", w.Code)
	}

	if w := doJSON(t, s, "POST", "/api/user/password", token,
		api.ChangePasswordRequest{CurrentPassword: testPassword, NewPassword: "next password 44"}); w.Code != 204 {
		t.Fatalf("change = %d %s", w.Code, w.Body)
	}

	// The new password logs in AND unwraps the same dovecot key: the
	// slot rotated with the hash, nothing stranded.
	loginAs(t, s, "admin@example.com", "next password 44")
	_, resp := unwrap(t, s, key, "admin@example.com", "next password 44")
	if resp.MailKey == nil || *resp.MailKey != h.args[0]["key_hex"] {
		t.Fatal("slot did not rotate with the password change")
	}
	if _, resp := unwrap(t, s, key, "admin@example.com", testPassword); resp.MailKey != nil {
		t.Fatal("old password still unwraps after change")
	}
}

func TestSelfServicePasswordChangeOnStrandedSlot(t *testing.T) {
	s, _, token := encTestServer(t)
	enableEncryption(t, s, token)

	// Admin reset strands the slot.
	if w := doJSON(t, s, "PUT", "/api/users/admin@example.com/password", token,
		api.SetPasswordRequest{Password: "reset password 55", AcknowledgeEncryption: true}); w.Code != 204 {
		t.Fatalf("reset = %d", w.Code)
	}
	token = loginAs(t, s, "admin@example.com", "reset password 55")

	// A further self-service change is refused until the user
	// re-links: changing again would bury the recovery path deeper.
	if w := doJSON(t, s, "POST", "/api/user/password", token,
		api.ChangePasswordRequest{CurrentPassword: "reset password 55", NewPassword: "even newer 66"}); w.Code != 409 {
		t.Fatalf("change on stranded slot = %d %s", w.Code, w.Body)
	}
}

func TestSelfServicePasswordChangeWithoutEncryption(t *testing.T) {
	// The endpoint exists independent of the encryption feature.
	s, _ := newTestServer(t)
	token := login(t, s).Token
	if w := doJSON(t, s, "POST", "/api/user/password", token,
		api.ChangePasswordRequest{CurrentPassword: testPassword, NewPassword: "the plain path 77"}); w.Code != 204 {
		t.Fatalf("plain change = %d %s", w.Code, w.Body)
	}
	loginAs(t, s, "admin@example.com", "the plain path 77")
}
