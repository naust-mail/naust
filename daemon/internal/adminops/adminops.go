// Package adminops implements the break-glass admin operations behind
// `boxctl recover ...`. It is the Go replacement for the recovery subset of the
// retired Python cli.py: the shell path an operator uses when locked out of the
// admin panel (reset a password, grant admin, disable MFA), which by definition
// cannot go through the authenticated API.
//
// These functions write the store directly through the same ent client managerd
// uses - same {BLF-CRYPT} bcrypt format, no schema drift. They run as the naust
// user (the caller, cmd/boxctl, invokes via runuser), and the trust anchor is
// Unix: you must already be root->naust on the box. They deliberately sit BELOW
// the httpapi guards (those protect panel flows); the one guard kept here is the
// last-admin block on RemoveAdmin, because removing the last admin is itself a
// lockout, the exact thing recover exists to undo.
//
// Operations that touch materialized data (SetPassword changes the Dovecot
// passwd-file) only write the store; the caller triggers a materialize rebuild
// so the change reaches Dovecot immediately rather than on the next hourly tick.
package adminops

import (
	"context"
	"errors"
	"fmt"

	"naust/daemon/internal/auth"
	"naust/daemon/internal/store/ent"
	entmailkeyslot "naust/daemon/internal/store/ent/mailkeyslot"
	entsession "naust/daemon/internal/store/ent/session"
	enttotp "naust/daemon/internal/store/ent/totpcredential"
	entuser "naust/daemon/internal/store/ent/user"
	entwebauthn "naust/daemon/internal/store/ent/webauthncredential"
)

// ErrUserNotFound is returned when no account matches the given email.
var ErrUserNotFound = errors.New("account not found")

// ErrLastAdmin is returned when removing admin from the account would leave the
// box with no admins - a self-inflicted lockout recover must not create.
var ErrLastAdmin = errors.New("refusing to remove the last admin: the box would have no admins left")

// ErrEmptyPassword guards against writing an empty password hash.
var ErrEmptyPassword = errors.New("password must not be empty")

// Admin summarizes an admin account for `recover list-admins`, enough to pick
// the right account to act on and copy its exact email for confirmation.
type Admin struct {
	Email    string
	TOTP     bool
	Passkeys int
}

// SlotInfo describes one at-rest encryption key slot for `recover encryption`.
type SlotInfo struct {
	Type  string
	Label string
}

// UserSlots pairs an account with its encryption slots for `recover encryption list`.
type UserSlots struct {
	Email string
	Slots []SlotInfo
}

// lookup resolves an account by email, mapping ent's not-found to ErrUserNotFound.
func lookup(ctx context.Context, client *ent.Client, email string) (*ent.User, error) {
	u, err := client.User.Query().Where(entuser.Email(email)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// ListAdmins returns every admin account with a short MFA summary.
func ListAdmins(ctx context.Context, client *ent.Client) ([]Admin, error) {
	users, err := client.User.Query().
		Where(entuser.RoleEQ(entuser.RoleAdmin)).
		Order(ent.Asc(entuser.FieldEmail)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	admins := make([]Admin, 0, len(users))
	for _, u := range users {
		totp, err := client.TOTPCredential.Query().Where(enttotp.HasUserWith(entuser.ID(u.ID))).Exist(ctx)
		if err != nil {
			return nil, err
		}
		passkeys, err := client.WebAuthnCredential.Query().Where(entwebauthn.HasUserWith(entuser.ID(u.ID))).Count(ctx)
		if err != nil {
			return nil, err
		}
		admins = append(admins, Admin{Email: u.Email, TOTP: totp, Passkeys: passkeys})
	}
	return admins, nil
}

// MakeAdmin grants the admin role. Idempotent: already-admin is not an error.
func MakeAdmin(ctx context.Context, client *ent.Client, email string) error {
	u, err := lookup(ctx, client, email)
	if err != nil {
		return err
	}
	return client.User.UpdateOne(u).SetRole(entuser.RoleAdmin).Exec(ctx)
}

// RemoveAdmin revokes the admin role, refusing if it would leave no admins.
func RemoveAdmin(ctx context.Context, client *ent.Client, email string) error {
	u, err := lookup(ctx, client, email)
	if err != nil {
		return err
	}
	if u.Role != entuser.RoleAdmin {
		return nil
	}
	admins, err := client.User.Query().Where(entuser.RoleEQ(entuser.RoleAdmin)).Count(ctx)
	if err != nil {
		return err
	}
	if admins <= 1 {
		return ErrLastAdmin
	}
	return client.User.UpdateOne(u).SetRole(entuser.RoleUser).Exec(ctx)
}

// SetPassword replaces the account's password and revokes its active sessions,
// returning how many were revoked. It writes the store only; the caller must
// trigger a materialize rebuild so Dovecot sees the new hash immediately.
func SetPassword(ctx context.Context, client *ent.Client, email, password string) (revoked int, err error) {
	if password == "" {
		return 0, ErrEmptyPassword
	}
	u, err := lookup(ctx, client, email)
	if err != nil {
		return 0, err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return 0, fmt.Errorf("hash password: %w", err)
	}
	if err := client.User.UpdateOne(u).SetPasswordHash(hash).Exec(ctx); err != nil {
		return 0, err
	}
	revoked, err = client.Session.Delete().Where(entsession.HasUserWith(entuser.ID(u.ID))).Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("revoke sessions: %w", err)
	}
	return revoked, nil
}

// DisableMFA removes every second factor from the account, returning the count
// of TOTP secrets and passkeys removed. Leaves the password intact.
func DisableMFA(ctx context.Context, client *ent.Client, email string) (totp, passkeys int, err error) {
	u, err := lookup(ctx, client, email)
	if err != nil {
		return 0, 0, err
	}
	totp, err = client.TOTPCredential.Delete().Where(enttotp.HasUserWith(entuser.ID(u.ID))).Exec(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("remove totp: %w", err)
	}
	passkeys, err = client.WebAuthnCredential.Delete().Where(entwebauthn.HasUserWith(entuser.ID(u.ID))).Exec(ctx)
	if err != nil {
		return totp, 0, fmt.Errorf("remove passkeys: %w", err)
	}
	return totp, passkeys, nil
}

// EncryptionStatus returns the account's at-rest key slots (empty = encryption off).
func EncryptionStatus(ctx context.Context, client *ent.Client, email string) ([]SlotInfo, error) {
	u, err := lookup(ctx, client, email)
	if err != nil {
		return nil, err
	}
	return slotsForUser(ctx, client, u.ID)
}

// EncryptionList returns every account that has at-rest encryption slots.
func EncryptionList(ctx context.Context, client *ent.Client) ([]UserSlots, error) {
	users, err := client.User.Query().
		Where(entuser.HasMailKeySlots()).
		Order(ent.Asc(entuser.FieldEmail)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]UserSlots, 0, len(users))
	for _, u := range users {
		slots, err := slotsForUser(ctx, client, u.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, UserSlots{Email: u.Email, Slots: slots})
	}
	return out, nil
}

// EncryptionDisable removes all at-rest key slots for the account, returning the
// count removed. Destructive: any mail already encrypted becomes unrecoverable -
// the caller is responsible for the confirmation gate.
func EncryptionDisable(ctx context.Context, client *ent.Client, email string) (removed int, err error) {
	u, err := lookup(ctx, client, email)
	if err != nil {
		return 0, err
	}
	removed, err = client.MailKeySlot.Delete().Where(entmailkeyslot.HasUserWith(entuser.ID(u.ID))).Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("remove key slots: %w", err)
	}
	return removed, nil
}

// slotsForUser lists a user's key slots ordered by type then label.
func slotsForUser(ctx context.Context, client *ent.Client, userID int) ([]SlotInfo, error) {
	slots, err := client.MailKeySlot.Query().
		Where(entmailkeyslot.HasUserWith(entuser.ID(userID))).
		Order(ent.Asc(entmailkeyslot.FieldSlotType), ent.Asc(entmailkeyslot.FieldLabel)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]SlotInfo, 0, len(slots))
	for _, s := range slots {
		out = append(out, SlotInfo{Type: string(s.SlotType), Label: s.Label})
	}
	return out, nil
}
