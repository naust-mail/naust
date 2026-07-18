package httpapi

// Encryption-at-rest ceremony routes (self-service, any signed-in
// user) plus the internal unwrap endpoint Dovecot's Lua passdb calls
// at login. All user-facing routes 404 when ENCRYPTION_AT_REST is off
// so key slots can never exist that Dovecot is not configured to use.
//
// Setup and rotation are two-phase: the first call issues recovery
// codes and parks the wrapped slots in an EncryptionSetup row; nothing
// becomes a real MailKeySlot until the challenge proves the user
// copied a code. The Dovecot keypair is generated before the commit,
// so a keypair failure leaves the account cleanly not-enabled.

import (
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"naust/daemon/internal/api"
	"naust/daemon/internal/auth"
	"naust/daemon/internal/mailcrypt"
	"naust/daemon/internal/store/ent"
	entencryptionsetup "naust/daemon/internal/store/ent/encryptionsetup"
	entuser "naust/daemon/internal/store/ent/user"
)

const (
	encryptionSetupTTL   = 10 * time.Minute
	maxChallengeAttempts = 3

	// Sliding-window rate limit for relink attempts (the endpoint that
	// accepts recovery codes against committed slots). Failures are
	// database rows, so the limit holds across restarts and replicas.
	relinkMaxFailures = 5
	relinkWindow      = 15 * time.Minute
)

// encryptionEnabled reports the box-level feature flag.
func (s *Server) encryptionEnabled() bool {
	return s.Conf != nil && s.Conf("ENCRYPTION_AT_REST") == "true"
}

// requireEncryption hides the ceremony routes when the feature is off.
func (s *Server) requireEncryption(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.encryptionEnabled() {
			writeError(w, http.StatusNotFound, "encryption at rest is not enabled on this server")
			return
		}
		next(w, r)
	}
}

// logEncFailure feeds failed ceremony attempts into the same counter
// and log stream as failed logins (fail2ban and the login-failure
// heuristic watch both the same way).
func (s *Server) logEncFailure(r *http.Request) {
	s.countAuthFailure(r.Context())
	s.Log.Printf("Naust Management Daemon: Encryption auth failure from ip %s - timestamp %.6f",
		clientIP(r), float64(time.Now().UnixMicro())/1e6)
}

func (s *Server) handleEncryptionStatus(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	types, err := mailcrypt.SlotTypes(r.Context(), s.Store, u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key slot query failed")
		return
	}
	enabled := false
	hasPRF := false
	for _, t := range types {
		switch t {
		case mailcrypt.SlotPassword:
			enabled = true
		case mailcrypt.SlotPasskeyPRF:
			hasPRF = true
		}
	}
	writeJSON(w, http.StatusOK, api.EncryptionStatusResponse{
		Enabled:    enabled,
		SlotTypes:  types,
		HasPRFSlot: hasPRF,
	})
}

func (s *Server) handleEncryptionSetup(w http.ResponseWriter, r *http.Request) {
	var req api.EncryptionSetupRequest
	if !decodeBody(w, r, &req) {
		return
	}
	u := userFrom(r)
	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "your current password is required to enable encryption")
		return
	}
	// Re-authenticate: the password wraps the key slot, so a wrong
	// password here would silently create an unusable slot.
	if !auth.VerifyPassword(u.PasswordHash, req.Password) {
		s.logEncFailure(r)
		writeError(w, http.StatusForbidden, "password is incorrect")
		return
	}
	has, err := mailcrypt.HasSlot(r.Context(), s.Store, u.ID, mailcrypt.SlotPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key slot query failed")
		return
	}
	if has {
		writeError(w, http.StatusBadRequest, "encryption at rest is already enabled for this account")
		return
	}

	rootKey, err := mailcrypt.GenerateRootKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	codes, err := mailcrypt.GenerateRecoveryCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	pwSlot, err := mailcrypt.BuildPasswordSlot(u.ID, req.Password, rootKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	recSlots, err := mailcrypt.BuildRecoverySlots(u.ID, codes, rootKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}

	if err := s.storePendingSetup(r, u, entencryptionsetup.ModeSetup,
		append([]mailcrypt.PreparedSlot{pwSlot}, recSlots...)); err != nil {
		writeError(w, http.StatusInternalServerError, "could not store pending setup")
		return
	}
	// Recovery codes are returned exactly once and never stored.
	writeJSON(w, http.StatusOK, api.EncryptionSetupResponse{RecoveryCodes: codes})
}

// storePendingSetup replaces any pending ceremony for the user with a
// fresh one.
func (s *Server) storePendingSetup(r *http.Request, u *ent.User, mode entencryptionsetup.Mode, slots []mailcrypt.PreparedSlot) error {
	prepared, err := mailcrypt.EncodePrepared(slots)
	if err != nil {
		return err
	}
	ctx := r.Context()
	if _, err := s.Store.EncryptionSetup.Delete().
		Where(entencryptionsetup.HasUserWith(entuser.ID(u.ID))).
		Exec(ctx); err != nil {
		return err
	}
	return s.Store.EncryptionSetup.Create().
		SetUserID(u.ID).
		SetMode(mode).
		SetPrepared(prepared).
		SetExpiresAt(time.Now().Add(encryptionSetupTTL)).
		Exec(ctx)
}

// pendingSetup loads the user's pending ceremony of the wanted mode,
// purging it when expired.
func (s *Server) pendingSetup(r *http.Request, u *ent.User, mode entencryptionsetup.Mode) (*ent.EncryptionSetup, error) {
	ctx := r.Context()
	row, err := s.Store.EncryptionSetup.Query().
		Where(entencryptionsetup.HasUserWith(entuser.ID(u.ID))).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if row.Mode != mode {
		return nil, nil
	}
	if time.Now().After(row.ExpiresAt) {
		s.Store.EncryptionSetup.DeleteOne(row).Exec(ctx)
		return nil, nil
	}
	return row, nil
}

// challengeVerify runs the shared part of the setup and rotation
// challenges: attempt accounting, CRC fast-fail, and unwrapping the
// prepared recovery slot the client claims to have copied. On success
// it returns the root key and the full prepared set; on failure it has
// already written the response.
func (s *Server) challengeVerify(w http.ResponseWriter, r *http.Request, u *ent.User, row *ent.EncryptionSetup, code string, codeIndex int) ([]byte, []mailcrypt.PreparedSlot, bool) {
	ctx := r.Context()
	if row.Attempts >= maxChallengeAttempts {
		s.Store.EncryptionSetup.DeleteOne(row).Exec(ctx)
		writeError(w, http.StatusTooManyRequests, "too many incorrect attempts, start again")
		return nil, nil, false
	}
	countAttempt := func(msg string) {
		s.logEncFailure(r)
		s.Store.EncryptionSetup.UpdateOne(row).AddAttempts(1).Exec(ctx)
		writeError(w, http.StatusBadRequest, msg)
	}
	if !mailcrypt.ValidRecoveryCodeCRC(code) {
		countAttempt("that does not look like a valid recovery code")
		return nil, nil, false
	}
	slots, err := mailcrypt.DecodePrepared(row.Prepared)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "pending setup is corrupt, start again")
		return nil, nil, false
	}
	var target *mailcrypt.PreparedSlot
	for i := range slots {
		if slots[i].SlotType == mailcrypt.SlotRecoveryCode && slots[i].Label == strconv.Itoa(codeIndex) {
			target = &slots[i]
			break
		}
	}
	if target == nil {
		writeError(w, http.StatusBadRequest, "invalid code index")
		return nil, nil, false
	}
	rootKey, err := mailcrypt.UnwrapPreparedRecovery(u.ID, *target, code)
	if err != nil {
		countAttempt("incorrect recovery code")
		return nil, nil, false
	}
	return rootKey, slots, true
}

func (s *Server) handleEncryptionChallenge(w http.ResponseWriter, r *http.Request) {
	var req api.EncryptionChallengeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	u := userFrom(r)
	row, err := s.pendingSetup(r, u, entencryptionsetup.ModeSetup)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "pending setup lookup failed")
		return
	}
	if row == nil {
		writeError(w, http.StatusBadRequest, "no pending encryption setup, start again")
		return
	}
	rootKey, slots, ok := s.challengeVerify(w, r, u, row, req.Code, req.CodeIndex)
	if !ok {
		return
	}

	// Generate the Dovecot keypair FIRST, protected by the dovecot
	// subkey. Only if that succeeds are the slots committed, so a
	// failure leaves a clean not-enabled state the user can retry.
	if err := s.generateKeypair(r, u.Email, rootKey); err != nil {
		s.Store.EncryptionSetup.DeleteOne(row).Exec(r.Context())
		s.Log.Printf("mailcrypt: keypair generation failed for %s: %v", u.Email, err)
		writeError(w, http.StatusInternalServerError, "could not initialise encryption keys, please try again")
		return
	}

	if err := mailcrypt.InsertSlots(r.Context(), s.Store, u.ID, slots); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save key slots")
		return
	}
	s.Store.EncryptionSetup.DeleteOne(row).Exec(r.Context())
	s.Log.Printf("mailcrypt: encryption enabled for %s", u.Email)
	writeJSON(w, http.StatusOK, api.EncryptionEnabledResponse{Enabled: true})
}

// generateKeypair asks helperd to run doveadm cryptokey generate with
// the user's dovecot subkey as the keypair password.
func (s *Server) generateKeypair(r *http.Request, email string, rootKey []byte) error {
	sub, err := mailcrypt.Subkey(rootKey, mailcrypt.SubkeyDovecot)
	if err != nil {
		return err
	}
	_, err = s.Helper.Call(r.Context(), "mailcrypt.keygen", map[string]string{
		"email":   email,
		"key_hex": hex.EncodeToString(sub),
	})
	return err
}

func (s *Server) handleEncryptionRelink(w http.ResponseWriter, r *http.Request) {
	var req api.EncryptionRelinkRequest
	if !decodeBody(w, r, &req) {
		return
	}
	u := userFrom(r)
	exceeded, err := s.authFailuresExceeded(r.Context(), failureKindRelink, u.Email, relinkMaxFailures, relinkWindow)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rate limit check failed")
		return
	}
	if exceeded {
		writeError(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return
	}
	if req.Code == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "recovery code and current password are required")
		return
	}
	if !mailcrypt.ValidRecoveryCodeCRC(req.Code) {
		s.logEncFailure(r)
		s.recordAuthFailure(r.Context(), failureKindRelink, u.Email, relinkWindow)
		writeError(w, http.StatusBadRequest, "that does not look like a valid recovery code")
		return
	}
	// The new slot must wrap under the real login password, otherwise
	// future logins still would not decrypt.
	if !auth.VerifyPassword(u.PasswordHash, req.Password) {
		s.logEncFailure(r)
		s.recordAuthFailure(r.Context(), failureKindRelink, u.Email, relinkWindow)
		writeError(w, http.StatusForbidden, "current password is incorrect")
		return
	}
	rootKey, err := mailcrypt.UnwrapViaRecoveryCode(r.Context(), s.Store, u.ID, req.Code)
	if errors.Is(err, mailcrypt.ErrNoSlot) {
		writeError(w, http.StatusBadRequest, "encryption is not enabled for this account")
		return
	}
	if errors.Is(err, mailcrypt.ErrWrongSecret) {
		s.logEncFailure(r)
		s.recordAuthFailure(r.Context(), failureKindRelink, u.Email, relinkWindow)
		writeError(w, http.StatusBadRequest, "recovery code did not match, check it and try again")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key slot query failed")
		return
	}
	if err := mailcrypt.ReplacePasswordSlot(r.Context(), s.Store, u.ID, req.Password, rootKey); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update the password slot")
		return
	}
	s.clearAuthFailures(r.Context(), failureKindRelink, u.Email)
	s.Log.Printf("mailcrypt: password slot re-linked for %s", u.Email)
	writeJSON(w, http.StatusOK, api.OKResponse{Status: "ok"})
}

func (s *Server) handleEncryptionRotateRecovery(w http.ResponseWriter, r *http.Request) {
	var req api.EncryptionSetupRequest
	if !decodeBody(w, r, &req) {
		return
	}
	u := userFrom(r)
	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "your current password is required")
		return
	}
	if !auth.VerifyPassword(u.PasswordHash, req.Password) {
		s.logEncFailure(r)
		writeError(w, http.StatusForbidden, "password is incorrect")
		return
	}
	rootKey, err := mailcrypt.UnwrapViaPassword(r.Context(), s.Store, u.ID, req.Password)
	if errors.Is(err, mailcrypt.ErrNoSlot) {
		writeError(w, http.StatusBadRequest, "encryption is not enabled for this account")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not unlock your mail key, try again")
		return
	}

	codes, err := mailcrypt.GenerateRecoveryCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	slots, err := mailcrypt.BuildRecoverySlots(u.ID, codes, rootKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	if err := s.storePendingSetup(r, u, entencryptionsetup.ModeRotation, slots); err != nil {
		writeError(w, http.StatusInternalServerError, "could not store pending rotation")
		return
	}
	writeJSON(w, http.StatusOK, api.EncryptionSetupResponse{RecoveryCodes: codes})
}

func (s *Server) handleEncryptionRotateConfirm(w http.ResponseWriter, r *http.Request) {
	var req api.EncryptionChallengeRequest
	if !decodeBody(w, r, &req) {
		return
	}
	u := userFrom(r)
	row, err := s.pendingSetup(r, u, entencryptionsetup.ModeRotation)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "pending rotation lookup failed")
		return
	}
	if row == nil {
		writeError(w, http.StatusBadRequest, "no pending code rotation, start again")
		return
	}
	_, slots, ok := s.challengeVerify(w, r, u, row, req.Code, req.CodeIndex)
	if !ok {
		return
	}
	// Old codes stay valid until this atomic replacement.
	if err := mailcrypt.ReplaceRecoverySlots(r.Context(), s.Store, u.ID, slots); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save key slots")
		return
	}
	s.Store.EncryptionSetup.DeleteOne(row).Exec(r.Context())
	s.Log.Printf("mailcrypt: recovery slots rotated for %s", u.Email)
	writeJSON(w, http.StatusOK, api.OKResponse{Status: "ok"})
}

// handleMailcryptUnwrap serves Dovecot's Lua passdb at login. It is
// registered under /internal/, which nginx never proxies, and is
// additionally gated by a dedicated shared secret file - NOT an admin
// credential: a caller holding it gets an unwrap oracle that still
// needs each user's correct password, nothing more.
//
// Always answers 200 with mail_key null for unknown users, users
// without encryption, or a wrong password: login must never break and
// the endpoint must not be a user-enumeration oracle. The value
// returned is the dovecot subkey, never the root key.
func (s *Server) handleMailcryptUnwrap(w http.ResponseWriter, r *http.Request) {
	if !s.unwrapCallerAuthorized(r) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	// Dovecot's Lua http client speaks form encoding; keeping the
	// internal endpoint form-based keeps the Lua side trivial.
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	user := r.PostFormValue("user")
	password := r.PostFormValue("password")
	if user == "" || password == "" {
		writeError(w, http.StatusBadRequest, "missing parameters")
		return
	}
	nullReply := api.MailcryptUnwrapResponse{}

	if !s.encryptionEnabled() {
		writeJSON(w, http.StatusOK, nullReply)
		return
	}
	u, err := s.Store.User.Query().Where(entuser.Email(strings.ToLower(user))).Only(r.Context())
	if err != nil {
		if !ent.IsNotFound(err) {
			s.Log.Printf("mailcrypt unwrap: user lookup failed: %v", err)
		}
		writeJSON(w, http.StatusOK, nullReply)
		return
	}
	rootKey, err := mailcrypt.UnwrapViaPassword(r.Context(), s.Store, u.ID, password)
	if errors.Is(err, mailcrypt.ErrNoSlot) {
		writeJSON(w, http.StatusOK, nullReply)
		return
	}
	if err != nil {
		// Wrong password against an encrypted account: count it like a
		// failed login so brute force is visible to the heuristics.
		s.logEncFailure(r)
		s.Log.Printf("mailcrypt unwrap: password did not unlock key for %s", u.Email)
		writeJSON(w, http.StatusOK, nullReply)
		return
	}
	sub, err := mailcrypt.Subkey(rootKey, mailcrypt.SubkeyDovecot)
	if err != nil {
		writeJSON(w, http.StatusOK, nullReply)
		return
	}
	s.Log.Printf("mailcrypt unwrap: key delivered for %s", u.Email)
	key := hex.EncodeToString(sub)
	writeJSON(w, http.StatusOK, api.MailcryptUnwrapResponse{MailKey: &key})
}

// unwrapCallerAuthorized checks the X-Api-Key header against the
// scoped secret file. No file or empty file means nothing can
// authorize (fails closed).
func (s *Server) unwrapCallerAuthorized(r *http.Request) bool {
	if s.MailcryptKeyPath == "" {
		return false
	}
	data, err := os.ReadFile(s.MailcryptKeyPath)
	if err != nil {
		return false
	}
	want := strings.TrimSpace(string(data))
	if want == "" {
		return false
	}
	return hmac.Equal([]byte(r.Header.Get("X-Api-Key")), []byte(want))
}
