package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"naust/daemon/internal/api"
	"naust/daemon/internal/auth"
	"naust/daemon/internal/mailcrypt"
	"naust/daemon/internal/store/ent"
	entapitoken "naust/daemon/internal/store/ent/apitoken"
	entmailkeyslot "naust/daemon/internal/store/ent/mailkeyslot"
	entsession "naust/daemon/internal/store/ent/session"
	entuser "naust/daemon/internal/store/ent/user"
)

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.Store.User.Query().
		Order(entuser.ByEmail()).
		All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user query failed")
		return
	}
	resp := api.UsersResponse{Users: make([]api.User, 0, len(users))}
	for _, u := range users {
		resp.Users = append(resp.Users, apiUser(u))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req api.CreateUserRequest
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
	role, err := parseRole(req.Role, entuser.RoleUser)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.QuotaBytes < 0 {
		writeError(w, http.StatusBadRequest, "quota_bytes may not be negative")
		return
	}
	// DCV addresses may not be user accounts - except the very first
	// account, created during setup before the operator knows the rule.
	n, err := s.Store.User.Query().Count(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user query failed")
		return
	}
	if n > 0 && isDCVAddress(req.Email) {
		writeError(w, http.StatusBadRequest, "that address is frequently used for domain control validation and cannot be a user account; use an alias instead")
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
		SetRole(role).
		SetQuotaBytes(req.QuotaBytes).
		SetTenantID(s.TenantID).
		Save(r.Context())
	if ent.IsConstraintError(err) {
		writeError(w, http.StatusConflict, "a user with that email already exists")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user creation failed")
		return
	}
	s.mailDataChanged()
	writeJSON(w, http.StatusCreated, apiUser(u))
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	var req api.UpdateUserRequest
	if !decodeBody(w, r, &req) {
		return
	}
	u, ok := s.userByPath(w, r)
	if !ok {
		return
	}

	upd := u.Update()
	if req.Role != nil {
		role, err := parseRole(*req.Role, "")
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if u.Role == entuser.RoleAdmin && role != entuser.RoleAdmin {
			last, err := s.isLastAdmin(r, u)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "user query failed")
				return
			}
			if last {
				writeError(w, http.StatusBadRequest, "cannot demote the last admin")
				return
			}
			// A demoted admin loses all access immediately: sessions
			// and API tokens die with the privilege.
			if err := s.revokeCredentials(r, u); err != nil {
				writeError(w, http.StatusInternalServerError, "credential revocation failed")
				return
			}
		}
		upd.SetRole(role)
	}
	if req.QuotaBytes != nil {
		if *req.QuotaBytes < 0 {
			writeError(w, http.StatusBadRequest, "quota_bytes may not be negative")
			return
		}
		upd.SetQuotaBytes(*req.QuotaBytes)
	}

	u, err := upd.Save(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user update failed")
		return
	}
	s.mailDataChanged()
	writeJSON(w, http.StatusOK, apiUser(u))
}

func (s *Server) handleSetUserPassword(w http.ResponseWriter, r *http.Request) {
	var req api.SetPasswordRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if err := validatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	u, ok := s.userByPath(w, r)
	if !ok {
		return
	}
	// An admin reset cannot re-wrap an encrypted account's mail key
	// (no old password), so it strands the password slot. Never do
	// that silently: the admin must acknowledge, and the user then
	// re-links with a recovery code or passkey. The slot stays - it
	// marks encryption as enabled and the re-link flow replaces it.
	encrypted, err := mailcrypt.HasSlot(r.Context(), s.Store, u.ID, mailcrypt.SlotPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key slot query failed")
		return
	}
	if encrypted && !req.AcknowledgeEncryption {
		writeError(w, http.StatusConflict, "this account uses encryption at rest: resetting the password will lock its mail until the user re-links with a recovery code or passkey; repeat with acknowledge_encryption to proceed")
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password hashing failed")
		return
	}
	if err := u.Update().SetPasswordHash(hash).Exec(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "password update failed")
		return
	}
	if encrypted {
		s.Log.Printf("mailcrypt: password reset stranded the key slot for %s (acknowledged)", u.Email)
	}
	s.mailDataChanged()
	w.WriteHeader(http.StatusNoContent)
}

// handleChangeOwnPassword is the self-service password change: the
// caller proves the current password, which also lets the encryption
// key slot rotate in the same transaction - the path whose absence
// made admin resets the only (and slot-stranding) way to change a
// password.
func (s *Server) handleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	var req api.ChangePasswordRequest
	if !decodeBody(w, r, &req) {
		return
	}
	u := userFrom(r)
	if !auth.VerifyPassword(u.PasswordHash, req.CurrentPassword) {
		s.logFailedLogin(r)
		writeError(w, http.StatusForbidden, "current password is incorrect")
		return
	}
	if err := validatePassword(req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Unwrap before touching anything: expensive KDF work stays
	// outside the transaction, and a wrong-state failure aborts the
	// whole change.
	var newSlot *mailcrypt.PreparedSlot
	rootKey, err := mailcrypt.UnwrapViaPassword(r.Context(), s.Store, u.ID, req.CurrentPassword)
	switch {
	case err == nil:
		slot, err := mailcrypt.BuildPasswordSlot(u.ID, req.NewPassword, rootKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "key generation failed")
			return
		}
		newSlot = &slot
	case errors.Is(err, mailcrypt.ErrNoSlot):
		// No encryption on this account; just the hash changes.
	case errors.Is(err, mailcrypt.ErrWrongSecret):
		// The slot is stranded from an earlier reset. Changing the
		// password now would not make it worse, but refusing points
		// the user at the re-link flow while they still know a
		// working password.
		writeError(w, http.StatusConflict, "your encryption key is out of sync with your password: re-link it with a recovery code or passkey first")
		return
	default:
		writeError(w, http.StatusInternalServerError, "key slot query failed")
		return
	}

	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password hashing failed")
		return
	}
	tx, err := s.Store.Tx(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password update failed")
		return
	}
	err = func() error {
		if err := tx.User.UpdateOneID(u.ID).SetPasswordHash(hash).Exec(r.Context()); err != nil {
			return err
		}
		if newSlot == nil {
			return nil
		}
		if _, err := tx.MailKeySlot.Delete().
			Where(
				entmailkeyslot.HasUserWith(entuser.ID(u.ID)),
				entmailkeyslot.SlotTypeEQ(entmailkeyslot.SlotTypePassword),
			).
			Exec(r.Context()); err != nil {
			return err
		}
		return mailcrypt.InsertSlots(r.Context(), tx.Client(), u.ID, []mailcrypt.PreparedSlot{*newSlot})
	}()
	if err != nil {
		tx.Rollback()
		writeError(w, http.StatusInternalServerError, "password update failed")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "password update failed")
		return
	}
	s.mailDataChanged()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	u, ok := s.userByPath(w, r)
	if !ok {
		return
	}
	if u.Role == entuser.RoleAdmin {
		last, err := s.isLastAdmin(r, u)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "user query failed")
			return
		}
		if last {
			writeError(w, http.StatusBadRequest, "cannot delete the last admin")
			return
		}
	}
	// Sessions, API tokens, and MFA credentials cascade with the row.
	if err := s.Store.User.DeleteOne(u).Exec(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "user deletion failed")
		return
	}
	s.mailDataChanged()
	w.WriteHeader(http.StatusNoContent)
}

// userByPath resolves the {email} path segment; on failure it has
// already written the 404.
func (s *Server) userByPath(w http.ResponseWriter, r *http.Request) (*ent.User, bool) {
	u, err := s.Store.User.Query().
		Where(entuser.Email(r.PathValue("email"))).
		Only(r.Context())
	if ent.IsNotFound(err) {
		writeError(w, http.StatusNotFound, "no such user")
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user query failed")
		return nil, false
	}
	return u, true
}

func (s *Server) isLastAdmin(r *http.Request, u *ent.User) (bool, error) {
	n, err := s.Store.User.Query().
		Where(entuser.RoleEQ(entuser.RoleAdmin), entuser.IDNEQ(u.ID)).
		Count(r.Context())
	return n == 0, err
}

// revokeCredentials deletes all sessions and API tokens for u.
func (s *Server) revokeCredentials(r *http.Request, u *ent.User) error {
	if _, err := s.Store.Session.Delete().
		Where(entsession.HasUserWith(entuser.ID(u.ID))).
		Exec(r.Context()); err != nil {
		return err
	}
	_, err := s.Store.APIToken.Delete().
		Where(entapitoken.HasUserWith(entuser.ID(u.ID))).
		Exec(r.Context())
	return err
}

func parseRole(s string, dflt entuser.Role) (entuser.Role, error) {
	if s == "" && dflt != "" {
		return dflt, nil
	}
	role := entuser.Role(s)
	if err := entuser.RoleValidator(role); err != nil {
		return "", err
	}
	return role, nil
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	body := http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return false
	}
	return true
}
