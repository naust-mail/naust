package httpapi

// Passkey PRF slots. A WebAuthn credential that supports the prf
// extension can wrap the mail root key: the authenticator derives a
// stable 32-byte secret from (credential, eval salt), the browser
// hands it to us, and it becomes a slot exactly like a recovery code.
// That gives passkey holders password-reset-safe encryption: after an
// admin reset they re-link with a passkey assertion instead of typing
// a recovery code.
//
// Facts that shape the flow: authenticators only emit PRF output
// during assertions (not registration), so enrollment is its own
// small assertion ceremony; and the PRF result is read by client JS
// from getClientExtensionResults() and sent explicitly in the request
// body - it is not part of the signed assertion.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"naust/daemon/internal/api"
	"naust/daemon/internal/auth"
	"naust/daemon/internal/mailcrypt"
	"naust/daemon/internal/store/ent"
	entwachallenge "naust/daemon/internal/store/ent/webauthnchallenge"
)

// prfSession is the session_data payload for kind=prf challenge rows:
// the library session plus what the ceremony needs on completion.
type prfSession struct {
	SD *webauthn.SessionData `json:"sd"`
	// Purpose is "enroll" or "relink"; a begin of one purpose cannot
	// complete as the other.
	Purpose string `json:"purpose"`
	// EnrollSalt is the fresh eval salt for enroll ceremonies. Relink
	// uses the salts already stored on the user's PRF slots.
	EnrollSalt []byte `json:"enroll_salt,omitempty"`
}

// prfExtension builds the assertion extension input. Values are
// base64url per the WebAuthn JSON encoding; client JS converts them
// to ArrayBuffers before calling navigator.credentials.get.
func prfExtension(eval map[string]string) protocol.AuthenticationExtensions {
	body := map[string]any{}
	if salt, ok := eval[""]; ok {
		// One salt for whichever credential answers.
		body["eval"] = map[string]string{"first": salt}
	} else {
		body["evalByCredential"] = func() map[string]any {
			m := make(map[string]any, len(eval))
			for credID, salt := range eval {
				m[credID] = map[string]string{"first": salt}
			}
			return m
		}()
	}
	return protocol.AuthenticationExtensions{"prf": body}
}

// beginPRF starts an assertion ceremony carrying prf extension inputs
// and stores the wrapped session under kind=prf.
func (s *Server) beginPRF(w http.ResponseWriter, r *http.Request, u *ent.User, sess prfSession, eval map[string]string) {
	wa, err := s.wa()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webauthn unavailable")
		return
	}
	wu, _, err := s.waUserFor(r, u)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential query failed")
		return
	}
	if len(wu.creds) == 0 {
		writeError(w, http.StatusBadRequest, "no passkeys on this account")
		return
	}
	options, sd, err := wa.BeginLogin(wu, webauthn.WithAssertionExtensions(prfExtension(eval)))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "assertion setup failed")
		return
	}
	sess.SD = sd
	encoded, err := json.Marshal(sess)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "challenge storage failed")
		return
	}
	nonce, err := s.storeRawChallenge(r, u, entwachallenge.KindPrf, string(encoded))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "challenge storage failed")
		return
	}
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "options encoding failed")
		return
	}
	writeJSON(w, http.StatusOK, api.WebAuthnBeginResponse{Nonce: nonce, Options: optionsJSON})
}

// completePRF consumes a kind=prf challenge for the session user,
// validates the assertion, and returns the verified credential plus
// the ceremony payload.
func (s *Server) completePRF(w http.ResponseWriter, r *http.Request, nonce, purpose string, credentialJSON []byte) (*webauthn.Credential, *prfSession, bool) {
	wa, err := s.wa()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webauthn unavailable")
		return nil, nil, false
	}
	owner, raw, err := s.takeRawChallenge(r, nonce, entwachallenge.KindPrf)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "challenge lookup failed")
		return nil, nil, false
	}
	var sess prfSession
	if owner != nil {
		if err := json.Unmarshal([]byte(raw), &sess); err != nil {
			writeError(w, http.StatusInternalServerError, "challenge state corrupt")
			return nil, nil, false
		}
	}
	if owner == nil || owner.ID != userFrom(r).ID || sess.Purpose != purpose {
		writeError(w, http.StatusBadRequest, "unknown or expired ceremony; start again")
		return nil, nil, false
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(credentialJSON)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed credential response")
		return nil, nil, false
	}
	wu, _, err := s.waUserFor(r, owner)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential query failed")
		return nil, nil, false
	}
	cred, err := wa.ValidateLogin(wu, *sess.SD, parsed)
	if err != nil {
		s.logEncFailure(r)
		writeError(w, http.StatusForbidden, "passkey verification failed")
		return nil, nil, false
	}
	return cred, &sess, true
}

func decodePRFOutput(w http.ResponseWriter, s string) ([]byte, bool) {
	out, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(out) != 32 {
		writeError(w, http.StatusBadRequest, "prf output must be 32 base64url bytes")
		return nil, false
	}
	return out, true
}

func (s *Server) handlePRFEnrollBegin(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	has, err := mailcrypt.HasSlot(r.Context(), s.Store, u.ID, mailcrypt.SlotPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key slot query failed")
		return
	}
	if !has {
		writeError(w, http.StatusBadRequest, "encryption is not enabled for this account")
		return
	}
	salt, err := mailcrypt.GenerateSalt()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	s.beginPRF(w, r, u, prfSession{Purpose: "enroll", EnrollSalt: salt},
		map[string]string{"": base64.RawURLEncoding.EncodeToString(salt)})
}

func (s *Server) handlePRFEnrollComplete(w http.ResponseWriter, r *http.Request) {
	var req api.EncryptionPRFCompleteRequest
	if !decodeBody(w, r, &req) {
		return
	}
	u := userFrom(r)
	cred, sess, ok := s.completePRF(w, r, req.Nonce, "enroll", req.Credential)
	if !ok {
		return
	}
	prfOutput, ok := decodePRFOutput(w, req.PRFOutput)
	if !ok {
		return
	}
	// The server needs the root key to wrap the new slot; the password
	// is the proof-of-knowledge that unwraps it.
	if !auth.VerifyPassword(u.PasswordHash, req.Password) {
		s.logEncFailure(r)
		writeError(w, http.StatusForbidden, "password is incorrect")
		return
	}
	rootKey, err := mailcrypt.UnwrapViaPassword(r.Context(), s.Store, u.ID, req.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not unlock your mail key; if your password was recently reset, re-link it first")
		return
	}
	credID := mailcrypt.EncodeCredentialID(cred.ID)
	slot, salt, err := mailcrypt.BuildPRFSlot(u.ID, credID, prfOutput, sess.EnrollSalt, rootKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	if err := mailcrypt.InsertPRFSlot(r.Context(), s.Store, u.ID, slot, salt); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save key slot")
		return
	}
	s.Log.Printf("mailcrypt: prf slot enrolled for %s", u.Email)
	writeJSON(w, http.StatusOK, api.OKResponse{Status: "ok"})
}

func (s *Server) handlePRFRelinkBegin(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	// Eval salts come from the stored slots: one entry per credential
	// that has one, keyed by base64url credential ID.
	slots, err := s.prfSlotSalts(r, u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key slot query failed")
		return
	}
	if len(slots) == 0 {
		writeError(w, http.StatusBadRequest, "no passkey is enrolled for encryption on this account")
		return
	}
	s.beginPRF(w, r, u, prfSession{Purpose: "relink"}, slots)
}

func (s *Server) handlePRFRelinkComplete(w http.ResponseWriter, r *http.Request) {
	var req api.EncryptionPRFCompleteRequest
	if !decodeBody(w, r, &req) {
		return
	}
	u := userFrom(r)
	cred, _, ok := s.completePRF(w, r, req.Nonce, "relink", req.Credential)
	if !ok {
		return
	}
	prfOutput, ok := decodePRFOutput(w, req.PRFOutput)
	if !ok {
		return
	}
	// The new slot must wrap under the real login password.
	if !auth.VerifyPassword(u.PasswordHash, req.Password) {
		s.logEncFailure(r)
		writeError(w, http.StatusForbidden, "current password is incorrect")
		return
	}
	credID := mailcrypt.EncodeCredentialID(cred.ID)
	rootKey, err := mailcrypt.UnwrapViaPRF(r.Context(), s.Store, u.ID, credID, prfOutput)
	if errors.Is(err, mailcrypt.ErrNoSlot) {
		writeError(w, http.StatusBadRequest, "that passkey is not enrolled for encryption")
		return
	}
	if err != nil {
		s.logEncFailure(r)
		writeError(w, http.StatusBadRequest, "passkey could not unlock the encryption key")
		return
	}
	if err := mailcrypt.ReplacePasswordSlot(r.Context(), s.Store, u.ID, req.Password, rootKey); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update the password slot")
		return
	}
	s.Log.Printf("mailcrypt: password slot re-linked via passkey for %s", u.Email)
	writeJSON(w, http.StatusOK, api.OKResponse{Status: "ok"})
}

// prfSlotSalts maps credential ID -> base64url eval salt for every
// PRF slot the user has.
func (s *Server) prfSlotSalts(r *http.Request, userID int) (map[string]string, error) {
	rows, err := mailcrypt.PRFSlots(r.Context(), s.Store, userID)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(rows))
	for _, row := range rows {
		m[row.Label] = base64.RawURLEncoding.EncodeToString(row.PrfSalt)
	}
	return m, nil
}
