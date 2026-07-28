package adminops

import (
	"context"
	"errors"
	"fmt"

	"naust/daemon/internal/auth"
	"naust/daemon/internal/mailaddr"
	"naust/daemon/internal/store/ent"
	entalias "naust/daemon/internal/store/ent/alias"
	entuser "naust/daemon/internal/store/ent/user"
)

// lockedHash is a password-hash sentinel that is deliberately not a valid
// {BLF-CRYPT} value, so both auth doors refuse it: managerd's
// auth.VerifyPassword fails the scheme-prefix check, and Dovecot's
// passwd-file lookup (default_pass_scheme=BLF-CRYPT) finds no valid bcrypt
// to match. It marks an account as "exists and receives mail, but cannot
// log in until a real password is set" - the state account migration
// leaves every imported account in.
const lockedHash = "!"

// ValidationError is a caller-input error (bad email, password, quota, or
// a reserved address). Callers map it to a 400-class response and surface
// its message; it is distinct from ErrUserExists (a conflict) and from
// internal errors (which map to 500).
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

func invalid(format string, args ...any) error { return &ValidationError{fmt.Sprintf(format, args...)} }

// wrapValidation turns a mailaddr validation error into a ValidationError,
// preserving its message.
func wrapValidation(err error) error {
	if err == nil {
		return nil
	}
	return &ValidationError{err.Error()}
}

// ErrUserExists is returned by CreateUser when the email is already taken.
var ErrUserExists = errors.New("a user with that email already exists")

// ErrAliasExists is returned by UpsertAlias(overwrite=false) when the
// source already has an alias, so migration stays additive and never
// clobbers a hand-made or system-generated route.
var ErrAliasExists = errors.New("an alias with that source already exists")

// CreateUserParams describes an account to create. Password and Locked are
// mutually exclusive: a normal account carries a password to hash; a
// locked account (Locked=true, empty Password) is created with the
// lockedHash sentinel - used by account migration, where the operator
// sets a real password afterward.
//
// Role is taken as-is: session/privilege policy (e.g. "granting admin
// needs an interactive session") is the HTTP layer's concern, not this
// store-level primitive.
type CreateUserParams struct {
	Email      string
	Role       entuser.Role
	QuotaBytes int64
	Password   string
	Locked     bool
}

// CreateUser validates and creates one account, applying the same address,
// password, quota, and DCV-reservation rules the panel enforces (so the
// panel and the migration path cannot drift). It writes the store only;
// the caller triggers a materialize rebuild so Dovecot sees the new row.
func CreateUser(ctx context.Context, client *ent.Client, tenantID int, p CreateUserParams) (*ent.User, error) {
	if err := mailaddr.UserEmail(p.Email); err != nil {
		return nil, wrapValidation(err)
	}
	if p.QuotaBytes < 0 {
		return nil, invalid("quota_bytes may not be negative")
	}

	// DCV addresses may not be user accounts - except the very first
	// account, created before any account exists to enforce the rule.
	n, err := client.User.Query().Count(ctx)
	if err != nil {
		return nil, err
	}
	if n > 0 && mailaddr.IsDCV(p.Email) {
		return nil, invalid("that address is frequently used for domain control validation and cannot be a user account; use an alias instead")
	}

	hash := lockedHash
	if !p.Locked {
		if err := mailaddr.Password(p.Password); err != nil {
			return nil, wrapValidation(err)
		}
		hash, err = auth.HashPassword(p.Password)
		if err != nil {
			return nil, fmt.Errorf("hash password: %w", err)
		}
	} else if p.Password != "" {
		return nil, invalid("a locked account must not carry a password")
	}

	u, err := client.User.Create().
		SetEmail(p.Email).
		SetPasswordHash(hash).
		SetRole(p.Role).
		SetQuotaBytes(p.QuotaBytes).
		SetTenantID(tenantID).
		Save(ctx)
	if ent.IsConstraintError(err) {
		return nil, ErrUserExists
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// AliasParams describes a forwarding rule to create or replace.
type AliasParams struct {
	Source           string
	Destinations     []string
	PermittedSenders []string
}

// UpsertAlias validates and writes an alias. With overwrite it replaces any
// existing row for the source (the panel's set-this-alias semantics, which
// also turns a system-generated auto alias into a manual one). Without
// overwrite an existing source is left untouched and ErrAliasExists is
// returned, so migration is additive. It writes the store only; the caller
// triggers a materialize rebuild.
func UpsertAlias(ctx context.Context, client *ent.Client, tenantID int, p AliasParams, overwrite bool) (*ent.Alias, error) {
	p.Source = mailaddr.NormalizeDomain(p.Source)
	if err := mailaddr.AliasSource(p.Source); err != nil {
		return nil, wrapValidation(err)
	}
	if len(p.Destinations) == 0 {
		return nil, invalid("at least one destination is required")
	}
	for i, d := range p.Destinations {
		p.Destinations[i] = mailaddr.NormalizeDomain(d)
		if err := mailaddr.EmailBasic(p.Destinations[i]); err != nil {
			return nil, wrapValidation(err)
		}
	}
	for i, ps := range p.PermittedSenders {
		p.PermittedSenders[i] = mailaddr.NormalizeDomain(ps)
		if err := mailaddr.EmailBasic(p.PermittedSenders[i]); err != nil {
			return nil, wrapValidation(err)
		}
	}

	if !overwrite {
		exists, err := client.Alias.Query().Where(entalias.Source(p.Source)).Exist(ctx)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, ErrAliasExists
		}
	}

	create := client.Alias.Create().
		SetSource(p.Source).
		SetDestinations(p.Destinations).
		SetPermittedSenders(p.PermittedSenders).
		SetAuto(false).
		SetTenantID(tenantID)
	if overwrite {
		if err := create.
			OnConflictColumns(entalias.FieldSource).
			UpdateNewValues().
			Exec(ctx); err != nil {
			return nil, err
		}
	} else if err := create.Exec(ctx); err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrAliasExists
		}
		return nil, err
	}

	a, err := client.Alias.Query().Where(entalias.Source(p.Source)).Only(ctx)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// ListUsers returns every account ordered by email.
func ListUsers(ctx context.Context, client *ent.Client) ([]*ent.User, error) {
	return client.User.Query().Order(entuser.ByEmail()).All(ctx)
}

// ListAliases returns every stored alias ordered by source. Auto flag is
// left on each row; migration filters system-generated (auto) aliases at
// the adapter, since the destination box regenerates its own.
func ListAliases(ctx context.Context, client *ent.Client) ([]*ent.Alias, error) {
	return client.Alias.Query().Order(entalias.BySource()).All(ctx)
}
