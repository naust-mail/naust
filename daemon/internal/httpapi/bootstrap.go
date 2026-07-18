package httpapi

import (
	"crypto/hmac"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"naust/daemon/internal/api"
	"naust/daemon/internal/auth"
	entuser "naust/daemon/internal/store/ent/user"
)

// bootstrapToken is the on-disk setup-code state written by
// "boxctl bootstrap". Attempts is managed here and persists across
// restarts, unlike the Python daemon's in-memory counter. Unknown
// fields in the file (the Python writer's uuid) are ignored.
type bootstrapToken struct {
	Code     string `json:"code"`
	Expires  int64  `json:"expires"`
	Attempts int    `json:"attempts"`
}

const bootstrapMaxAttempts = 5

// checkBootstrapCode enforces the setup-code gate: the endpoint is
// inert without an unexpired token file, wrong codes burn attempts
// (persisted to the file), and the fifth failure deletes the file so
// lockout survives restarts. The operator recovers from any dead end
// the same way: sudo boxctl bootstrap mints a fresh code. Reports
// whether the caller may proceed; on false the response is written.
func (s *Server) checkBootstrapCode(w http.ResponseWriter, r *http.Request, code string) bool {
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()

	noSession := func() {
		writeJSON(w, http.StatusNotFound, api.ErrorResponse{
			Error: "no bootstrap session active; run: sudo boxctl bootstrap",
			Hints: []string{"not-found"},
		})
	}
	if s.BootstrapTokenPath == "" {
		noSession()
		return false
	}
	raw, err := os.ReadFile(s.BootstrapTokenPath)
	if err != nil {
		noSession()
		return false
	}
	var tok bootstrapToken
	if err := json.Unmarshal(raw, &tok); err != nil || tok.Code == "" {
		noSession()
		return false
	}
	if time.Now().Unix() > tok.Expires {
		writeJSON(w, http.StatusForbidden, api.ErrorResponse{
			Error: "the setup code expired; run: sudo boxctl bootstrap",
			Hints: []string{"expired"},
		})
		return false
	}

	// Codes are entered by hand: strip spaces, ignore case.
	normalized := strings.ToUpper(strings.ReplaceAll(code, " ", ""))
	if !hmac.Equal([]byte(normalized), []byte(tok.Code)) {
		s.logFailedLogin(r)
		tok.Attempts++
		if tok.Attempts >= bootstrapMaxAttempts {
			_ = os.Remove(s.BootstrapTokenPath)
			writeJSON(w, http.StatusForbidden, api.ErrorResponse{
				Error: "too many failed attempts; run: sudo boxctl bootstrap for a new code",
				Hints: []string{"locked"},
			})
			return false
		}
		if updated, err := json.Marshal(tok); err == nil {
			_ = os.WriteFile(s.BootstrapTokenPath, updated, 0o600)
		}
		remaining := bootstrapMaxAttempts - tok.Attempts
		noun := "attempts"
		if remaining == 1 {
			noun = "attempt"
		}
		writeJSON(w, http.StatusForbidden, api.ErrorResponse{
			Error: "incorrect setup code; " + strconv.Itoa(remaining) + " " + noun + " remaining",
			Hints: []string{"invalid-code"},
		})
		return false
	}
	return true
}

// handleBootstrap creates the very first admin account and logs it in.
// Unauthenticated by necessity - there is nobody to authenticate as -
// but gated on the setup code from "boxctl bootstrap" so a scanner
// cannot claim a freshly installed box, and inert the moment any user
// exists. The DCV-address rule is not enforced here: setup may
// legitimately start with admin@domain, and the operator learns the
// rule before creating further accounts.
func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	var req api.BootstrapRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if err := validateUserEmail(req.Email); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	n, err := s.Store.User.Query().Count(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user query failed")
		return
	}
	if n > 0 {
		writeError(w, http.StatusForbidden, "this box is already set up")
		return
	}
	if !s.checkBootstrapCode(w, r, req.Code) {
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password hashing failed")
		return
	}
	u, err := s.Store.User.Create().
		SetEmail(req.Email).
		SetPasswordHash(hash).
		SetRole(entuser.RoleAdmin).
		SetTenantID(s.TenantID).
		Save(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user creation failed")
		return
	}
	// Two racing bootstraps can both pass the count check and both
	// insert. The oldest row wins; any later row deletes itself, so
	// exactly one first admin survives (never zero: the winner keeps
	// itself unconditionally).
	oldest, err := s.Store.User.Query().Order(entuser.ByID()).First(r.Context())
	if err != nil || oldest.ID != u.ID {
		_ = s.Store.User.DeleteOne(u).Exec(r.Context())
		writeError(w, http.StatusForbidden, "this box is already set up")
		return
	}
	// The code is single-use: consumed by the account it created.
	if s.BootstrapTokenPath != "" {
		_ = os.Remove(s.BootstrapTokenPath)
	}
	s.mailDataChanged()
	s.sendWelcome(u.Email)

	token, expires, err := auth.NewSession(r.Context(), s.Store, u, auth.DefaultSessionTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session creation failed")
		return
	}
	setSessionCookie(w, token, expires)
	writeJSON(w, http.StatusCreated, api.LoginResponse{
		Token:     token,
		ExpiresAt: expires,
		User:      apiUser(u),
	})
}
