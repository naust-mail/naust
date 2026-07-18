package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"naust/daemon/internal/auth"
	"naust/daemon/internal/store/ent"
	entuser "naust/daemon/internal/store/ent/user"
)

// Verify's window is tighter than relink's: a mail client with a stale
// stored password retries continuously, and a short lockout both stops
// the bcrypt burn and clears quickly once the client is fixed.
const (
	verifyMaxFailures = 5
	verifyWindow      = time.Minute
)

// handleAuthVerify authenticates a mail user's credentials for other
// on-box services (Radicale CalDAV/CardDAV, FileBrowser). Registered
// under /internal/, which nginx never proxies; deliberately not gated
// by a shared secret - a local caller could ask Dovecot's loopback
// IMAP the same question, so a secret would add ceremony, not
// protection. Password only, no MFA: this is the mail-password check,
// same posture as IMAP itself.
//
// Form-encoded to keep the callers trivial; answers 200 with the user,
// 401 on bad credentials (identical timing and message for unknown
// users), 429 when the email's window is exhausted.
func (s *Server) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	password := r.PostFormValue("password")
	if email == "" || password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	exceeded, err := s.authFailuresExceeded(r.Context(), failureKindVerify, email, verifyMaxFailures, verifyWindow)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rate limit query failed")
		return
	}
	if exceeded {
		w.Header().Set("Retry-After", strconv.Itoa(int(verifyWindow.Seconds())))
		writeError(w, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return
	}

	u, err := s.Store.User.Query().Where(entuser.Email(email)).Only(r.Context())
	if ent.IsNotFound(err) {
		auth.FakeVerify(password)
		s.recordAuthFailure(r.Context(), failureKindVerify, email, verifyWindow)
		s.logFailedLogin(r)
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user lookup failed")
		return
	}
	if !auth.VerifyPassword(u.PasswordHash, password) {
		s.recordAuthFailure(r.Context(), failureKindVerify, email, verifyWindow)
		s.logFailedLogin(r)
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	s.clearAuthFailures(r.Context(), failureKindVerify, email)
	writeJSON(w, http.StatusOK, apiUser(u))
}
