package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"naust/daemon/internal/api"
	"naust/daemon/internal/auth"
	"naust/daemon/internal/mailcrypt"
	"naust/daemon/internal/store/ent"
	enttotp "naust/daemon/internal/store/ent/totpcredential"
	entuser "naust/daemon/internal/store/ent/user"
	entwacred "naust/daemon/internal/store/ent/webauthncredential"
)

// handleAuthMethods tells the login page how an account signs in.
// Unknown accounts get the ["password"] default, the same answer as
// an account with nothing enrolled, so the response does not reveal
// which addresses exist. It reveals a real account's MFA posture to
// anyone who asks, which is the accepted cost of routing users to the
// right ceremony up front; the credential checks stay on the login
// endpoints.
func (s *Server) handleAuthMethods(w http.ResponseWriter, r *http.Request) {
	methods := []string{"password"}
	u, err := s.Store.User.Query().
		Where(entuser.Email(r.URL.Query().Get("email"))).
		Only(r.Context())
	if err != nil && !ent.IsNotFound(err) {
		writeError(w, http.StatusInternalServerError, "user lookup failed")
		return
	}
	// The credential counts run for unknown accounts too (against user
	// ID 0, which never exists), so both paths cost the same queries
	// and response timing does not separate "no such account" from "no
	// MFA enrolled" - the two cases the response body deliberately
	// merges.
	userID := 0
	if u != nil {
		userID = u.ID
	}
	totp, err1 := s.Store.TOTPCredential.Query().
		Where(enttotp.HasUserWith(entuser.ID(userID))).
		Count(r.Context())
	passkeys, err2 := s.Store.WebAuthnCredential.Query().
		Where(entwacred.HasUserWith(entuser.ID(userID))).
		Count(r.Context())
	if err1 != nil || err2 != nil {
		writeError(w, http.StatusInternalServerError, "credential lookup failed")
		return
	}
	switch {
	case passkeys > 0 && totp > 0:
		methods = []string{"passkey", "password+totp"}
	case passkeys > 0:
		// Passkey-only: password login is refused outright.
		methods = []string{"passkey"}
	case totp > 0:
		methods = []string{"password+totp"}
	}
	writeJSON(w, http.StatusOK, api.AuthMethodsResponse{Methods: methods})
}

// checkTOTP enforces a user's enrolled second factors during a
// password login. Returns ok=true when no factor is enrolled or a
// TOTP code matches; otherwise hints tell the client what to do next.
// A passkey-only account cannot log in by password at all - the
// passkey ceremony is the login - but an enrolled TOTP factor still
// satisfies MFA for accounts that have both.
func (s *Server) checkTOTP(r *http.Request, u *ent.User, code string) (bool, []string, error) {
	creds, err := s.Store.TOTPCredential.Query().
		Where(enttotp.HasUserWith(entuser.ID(u.ID))).
		All(r.Context())
	if err != nil {
		return false, nil, err
	}
	if len(creds) == 0 {
		n, err := s.Store.WebAuthnCredential.Query().
			Where(entwacred.HasUserWith(entuser.ID(u.ID))).
			Count(r.Context())
		if err != nil {
			return false, nil, err
		}
		if n > 0 {
			return false, []string{"use-passkey"}, nil
		}
		return true, nil, nil
	}
	if code == "" {
		return false, []string{"missing-totp-code"}, nil
	}
	for _, cred := range creds {
		step, ok := auth.VerifyTOTP(cred.Secret, code, time.Now())
		if !ok {
			continue
		}
		// Consume the step atomically: the conditional update only
		// moves the stored step forward, so a replayed code (or a
		// concurrent login with the same code) loses the race.
		n, err := s.Store.TOTPCredential.Update().
			Where(
				enttotp.ID(cred.ID),
				enttotp.Or(
					enttotp.MruTokenIsNil(),
					enttotp.MruTokenLT(auth.FormatTOTPStep(step)),
				),
			).
			SetMruToken(auth.FormatTOTPStep(step)).
			Save(r.Context())
		if err != nil {
			return false, nil, err
		}
		if n > 0 {
			return true, nil, nil
		}
	}
	return false, []string{"invalid-totp-code"}, nil
}

func (s *Server) handleMFAState(w http.ResponseWriter, r *http.Request) {
	creds, err := s.Store.TOTPCredential.Query().
		Where(enttotp.HasUserWith(entuser.ID(userFrom(r).ID))).
		Order(enttotp.ByID()).
		All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential query failed")
		return
	}
	passkeys, err := s.Store.WebAuthnCredential.Query().
		Where(entwacred.HasUserWith(entuser.ID(userFrom(r).ID))).
		Order(entwacred.ByID()).
		All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential query failed")
		return
	}
	resp := api.MFAStateResponse{Credentials: make([]api.MFACredential, 0, len(creds)+len(passkeys))}
	for _, c := range creds {
		resp.Credentials = append(resp.Credentials, api.MFACredential{
			ID:    c.ID,
			Type:  "totp",
			Label: c.Label,
		})
	}
	for _, c := range passkeys {
		resp.Credentials = append(resp.Credentials, api.MFACredential{
			ID:    c.ID,
			Type:  "webauthn",
			Label: c.Name,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleTOTPSetup hands out a fresh secret and provisioning URI.
// Nothing is stored: enrollment only completes when the enable call
// proves the authenticator produces matching codes, so an abandoned
// setup cannot lock anyone out.
func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "secret generation failed")
		return
	}
	issuer := s.PrimaryHostname + " Control Panel"
	writeJSON(w, http.StatusOK, api.TOTPSetupResponse{
		Secret:     secret,
		OTPAuthURI: auth.TOTPURI(secret, userFrom(r).Email, issuer),
	})
}

func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	var req api.EnableTOTPRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if err := auth.ValidateTOTPSecret(req.Secret); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	step, ok := auth.VerifyTOTP(req.Secret, req.Code, time.Now())
	if !ok {
		writeError(w, http.StatusBadRequest, "the code does not match; check the authenticator app and try again")
		return
	}
	cred, err := s.Store.TOTPCredential.Create().
		SetUser(userFrom(r)).
		SetSecret(req.Secret).
		SetMruToken(auth.FormatTOTPStep(step)).
		SetLabel(req.Label).
		Save(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential save failed")
		return
	}
	writeJSON(w, http.StatusCreated, api.MFACredential{ID: cred.ID, Type: "totp", Label: cred.Label})
}

// handleMFADisable removes one second factor. The path carries the
// type because TOTP and passkey rows number independently - a bare id
// would be ambiguous. Scoped to the caller: one admin cannot strip
// another's MFA here.
func (s *Server) handleMFADisable(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid credential id")
		return
	}
	var n int
	switch r.PathValue("type") {
	case "totp":
		n, err = s.Store.TOTPCredential.Delete().
			Where(enttotp.ID(id), enttotp.HasUserWith(entuser.ID(userFrom(r).ID))).
			Exec(r.Context())
	case "webauthn":
		// A deleted passkey takes its encryption slot with it: the
		// authenticator that could derive the PRF secret is gone.
		row, qerr := s.Store.WebAuthnCredential.Query().
			Where(entwacred.ID(id), entwacred.HasUserWith(entuser.ID(userFrom(r).ID))).
			Only(r.Context())
		if qerr == nil {
			if derr := mailcrypt.DeletePRFSlot(r.Context(), s.Store, userFrom(r).ID,
				mailcrypt.EncodeCredentialID(row.CredentialID)); derr != nil {
				writeError(w, http.StatusInternalServerError, "credential deletion failed")
				return
			}
		}
		n, err = s.Store.WebAuthnCredential.Delete().
			Where(entwacred.ID(id), entwacred.HasUserWith(entuser.ID(userFrom(r).ID))).
			Exec(r.Context())
	default:
		writeError(w, http.StatusBadRequest, "credential type must be \"totp\" or \"webauthn\"")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential deletion failed")
		return
	}
	if n == 0 {
		writeError(w, http.StatusNotFound, "no such credential")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
