package httpapi

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"naust/daemon/internal/api"
	"naust/daemon/internal/auth"
	"naust/daemon/internal/store/ent"
	entuser "naust/daemon/internal/store/ent/user"
	entwachallenge "naust/daemon/internal/store/ent/webauthnchallenge"
	entwacred "naust/daemon/internal/store/ent/webauthncredential"
)

// challengeTTL bounds how long a begun ceremony stays completable.
const challengeTTL = 10 * time.Minute

// wa builds the relying-party instance once per server. The RP ID is
// the box's hostname; the admin panel is only served from there over
// HTTPS.
func (s *Server) wa() (*webauthn.WebAuthn, error) {
	s.waOnce.Do(func() {
		s.waInst, s.waErr = webauthn.New(&webauthn.Config{
			RPID:          s.PrimaryHostname,
			RPDisplayName: s.PrimaryHostname,
			RPOrigins:     []string{"https://" + s.PrimaryHostname},
		})
	})
	return s.waInst, s.waErr
}

// waUser adapts an account and its stored passkeys to the library's
// user interface.
type waUser struct {
	u     *ent.User
	creds []webauthn.Credential
}

func (w waUser) WebAuthnID() []byte                         { return []byte(strconv.Itoa(w.u.ID)) }
func (w waUser) WebAuthnName() string                       { return w.u.Email }
func (w waUser) WebAuthnDisplayName() string                { return w.u.Email }
func (w waUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

// waUserFor loads the library-format credentials for u.
func (s *Server) waUserFor(r *http.Request, u *ent.User) (waUser, []*ent.WebAuthnCredential, error) {
	rows, err := s.Store.WebAuthnCredential.Query().
		Where(entwacred.HasUserWith(entuser.ID(u.ID))).
		Order(entwacred.ByID()).
		All(r.Context())
	if err != nil {
		return waUser{}, nil, err
	}
	wu := waUser{u: u, creds: make([]webauthn.Credential, 0, len(rows))}
	for _, row := range rows {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(row.Data), &c); err != nil {
			return waUser{}, nil, err
		}
		wu.creds = append(wu.creds, c)
	}
	return wu, rows, nil
}

// storeChallenge persists ceremony state and returns the client nonce.
func (s *Server) storeChallenge(r *http.Request, u *ent.User, kind entwachallenge.Kind, sd *webauthn.SessionData) (string, error) {
	encoded, err := json.Marshal(sd)
	if err != nil {
		return "", err
	}
	return s.storeRawChallenge(r, u, kind, string(encoded))
}

// storeRawChallenge persists arbitrary ceremony state (prf ceremonies
// wrap SessionData with their own payload) and returns the client
// nonce. Expired leftovers purge here, keeping the table minutes-sized.
func (s *Server) storeRawChallenge(r *http.Request, u *ent.User, kind entwachallenge.Kind, sessionData string) (string, error) {
	_, _ = s.Store.WebAuthnChallenge.Delete().
		Where(entwachallenge.ExpiresAtLT(time.Now())).
		Exec(r.Context())

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(raw)
	err := s.Store.WebAuthnChallenge.Create().
		SetUser(u).
		SetNonceHash(hashNonce(nonce)).
		SetSessionData(sessionData).
		SetKind(kind).
		SetExpiresAt(time.Now().Add(challengeTTL)).
		Exec(r.Context())
	if err != nil {
		return "", err
	}
	return nonce, nil
}

// takeChallenge resolves and consumes a nonce: the row is deleted
// before use, so a ceremony completes at most once.
func (s *Server) takeChallenge(r *http.Request, nonce string, kind entwachallenge.Kind) (*ent.User, *webauthn.SessionData, error) {
	owner, raw, err := s.takeRawChallenge(r, nonce, kind)
	if err != nil || owner == nil {
		return nil, nil, err
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal([]byte(raw), &sd); err != nil {
		return nil, nil, err
	}
	return owner, &sd, nil
}

// takeRawChallenge is takeChallenge without the SessionData decode.
func (s *Server) takeRawChallenge(r *http.Request, nonce string, kind entwachallenge.Kind) (*ent.User, string, error) {
	row, err := s.Store.WebAuthnChallenge.Query().
		Where(
			entwachallenge.NonceHash(hashNonce(nonce)),
			entwachallenge.KindEQ(kind),
			entwachallenge.ExpiresAtGT(time.Now()),
		).
		WithUser().
		Only(r.Context())
	if ent.IsNotFound(err) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	n, err := s.Store.WebAuthnChallenge.Delete().
		Where(entwachallenge.ID(row.ID)).
		Exec(r.Context())
	if err != nil {
		return nil, "", err
	}
	if n == 0 {
		return nil, "", nil // concurrent complete won the race
	}
	owner, err := row.Edges.UserOrErr()
	if err != nil {
		return nil, "", err
	}
	return owner, row.SessionData, nil
}

func hashNonce(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return hex.EncodeToString(sum[:])
}

func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	wa, err := s.wa()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webauthn unavailable")
		return
	}
	wu, _, err := s.waUserFor(r, userFrom(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential query failed")
		return
	}
	options, sd, err := wa.BeginRegistration(wu)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "registration setup failed")
		return
	}
	s.writeWebAuthnBegin(w, r, userFrom(r), entwachallenge.KindRegister, options, sd)
}

func (s *Server) handleWebAuthnRegisterComplete(w http.ResponseWriter, r *http.Request) {
	var req api.WebAuthnRegisterCompleteRequest
	if !decodeBody(w, r, &req) {
		return
	}
	wa, err := s.wa()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webauthn unavailable")
		return
	}
	owner, sd, err := s.takeChallenge(r, req.Nonce, entwachallenge.KindRegister)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "challenge lookup failed")
		return
	}
	// The ceremony must belong to the session that asked for it.
	if owner == nil || owner.ID != userFrom(r).ID {
		writeError(w, http.StatusBadRequest, "unknown or expired enrollment; start again")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(req.Credential)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed credential response")
		return
	}
	wu, _, err := s.waUserFor(r, owner)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential query failed")
		return
	}
	cred, err := wa.CreateCredential(wu, *sd, parsed)
	if err != nil {
		writeError(w, http.StatusBadRequest, "credential verification failed")
		return
	}
	encoded, err := json.Marshal(cred)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential save failed")
		return
	}
	row, err := s.Store.WebAuthnCredential.Create().
		SetUser(owner).
		SetCredentialID(cred.ID).
		SetData(string(encoded)).
		SetName(req.Name).
		Save(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential save failed")
		return
	}
	writeJSON(w, http.StatusCreated, api.MFACredential{ID: row.ID, Type: "webauthn", Label: row.Name})
}

func (s *Server) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req api.WebAuthnLoginBeginRequest
	if !decodeBody(w, r, &req) {
		return
	}
	wa, err := s.wa()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webauthn unavailable")
		return
	}
	u, err := s.Store.User.Query().Where(entuser.Email(req.Email)).Only(r.Context())
	if ent.IsNotFound(err) {
		writeError(w, http.StatusForbidden, "no passkeys for that account")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user lookup failed")
		return
	}
	wu, _, err := s.waUserFor(r, u)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential query failed")
		return
	}
	if len(wu.creds) == 0 {
		writeError(w, http.StatusForbidden, "no passkeys for that account")
		return
	}
	options, sd, err := wa.BeginLogin(wu)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "login setup failed")
		return
	}
	s.writeWebAuthnBegin(w, r, u, entwachallenge.KindLogin, options, sd)
}

func (s *Server) handleWebAuthnLoginComplete(w http.ResponseWriter, r *http.Request) {
	var req api.WebAuthnLoginCompleteRequest
	if !decodeBody(w, r, &req) {
		return
	}
	wa, err := s.wa()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "webauthn unavailable")
		return
	}
	owner, sd, err := s.takeChallenge(r, req.Nonce, entwachallenge.KindLogin)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "challenge lookup failed")
		return
	}
	if owner == nil {
		writeError(w, http.StatusBadRequest, "unknown or expired login attempt; start again")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(req.Credential)
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed credential response")
		return
	}
	wu, rows, err := s.waUserFor(r, owner)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential query failed")
		return
	}
	cred, err := wa.ValidateLogin(wu, *sd, parsed)
	if err != nil {
		s.logFailedLogin(r)
		writeError(w, http.StatusForbidden, "passkey verification failed")
		return
	}

	// Persist the updated record (sign count moved) and last_used.
	for _, row := range rows {
		if string(row.CredentialID) == string(cred.ID) {
			if encoded, err := json.Marshal(cred); err == nil {
				_ = s.Store.WebAuthnCredential.UpdateOne(row).
					SetData(string(encoded)).
					SetLastUsed(time.Now()).
					Exec(r.Context())
			}
			break
		}
	}

	token, expires, err := auth.NewSession(r.Context(), s.Store, owner, auth.DefaultSessionTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session creation failed")
		return
	}
	setSessionCookie(w, token, expires)
	writeJSON(w, http.StatusOK, api.LoginResponse{
		Token:     token,
		ExpiresAt: expires,
		User:      apiUser(owner),
	})
}

func (s *Server) writeWebAuthnBegin(w http.ResponseWriter, r *http.Request, u *ent.User, kind entwachallenge.Kind, options any, sd *webauthn.SessionData) {
	nonce, err := s.storeChallenge(r, u, kind, sd)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "challenge storage failed")
		return
	}
	encoded, err := json.Marshal(options)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "options encoding failed")
		return
	}
	writeJSON(w, http.StatusOK, api.WebAuthnBeginResponse{Nonce: nonce, Options: encoded})
}
