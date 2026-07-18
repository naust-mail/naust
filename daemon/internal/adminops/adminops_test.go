package adminops

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"naust/daemon/internal/store"
	"naust/daemon/internal/store/ent"
	entmailkeyslot "naust/daemon/internal/store/ent/mailkeyslot"
	entuser "naust/daemon/internal/store/ent/user"
)

// newClient opens a fresh sqlite-backed store with the default tenant ready.
func newClient(t *testing.T) *ent.Client {
	t.Helper()
	client, err := store.Open(store.EngineSQLite, filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if err := client.Schema.Create(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureDefaultTenant(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	return client
}

// mkUser creates an account with the given email and role.
func mkUser(t *testing.T, client *ent.Client, email string, role entuser.Role) *ent.User {
	t.Helper()
	ctx := context.Background()
	tenant, err := store.EnsureDefaultTenant(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	u, err := client.User.Create().
		SetEmail(email).
		SetPasswordHash("{BLF-CRYPT}$2b$12$original").
		SetRole(role).
		SetTenant(tenant).
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestMakeAdminIsIdempotent(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	mkUser(t, client, "u@example.com", entuser.RoleUser)

	if err := MakeAdmin(ctx, client, "u@example.com"); err != nil {
		t.Fatal(err)
	}
	got := client.User.Query().Where(entuser.Email("u@example.com")).OnlyX(ctx)
	if got.Role != entuser.RoleAdmin {
		t.Fatalf("role = %v, want admin", got.Role)
	}
	// A second call must not error.
	if err := MakeAdmin(ctx, client, "u@example.com"); err != nil {
		t.Fatalf("second MakeAdmin: %v", err)
	}
}

func TestRemoveAdminBlocksLastAdmin(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	mkUser(t, client, "solo@example.com", entuser.RoleAdmin)

	if err := RemoveAdmin(ctx, client, "solo@example.com"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("RemoveAdmin on last admin = %v, want ErrLastAdmin", err)
	}

	// With a second admin present, removal succeeds.
	mkUser(t, client, "other@example.com", entuser.RoleAdmin)
	if err := RemoveAdmin(ctx, client, "solo@example.com"); err != nil {
		t.Fatalf("RemoveAdmin with two admins: %v", err)
	}
	got := client.User.Query().Where(entuser.Email("solo@example.com")).OnlyX(ctx)
	if got.Role != entuser.RoleUser {
		t.Fatalf("role = %v, want user", got.Role)
	}
}

func TestSetPasswordHashesAndRevokesSessions(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	u := mkUser(t, client, "u@example.com", entuser.RoleUser)
	for i := 0; i < 3; i++ {
		client.Session.Create().SetUser(u).SetTokenHash(fmt.Sprintf("sess-%d", i)).
			SetExpiresAt(time.Now().Add(time.Hour)).SaveX(ctx)
	}

	revoked, err := SetPassword(ctx, client, "u@example.com", "a-new-password")
	if err != nil {
		t.Fatal(err)
	}
	if revoked != 3 {
		t.Fatalf("revoked = %d, want 3", revoked)
	}
	got := client.User.Query().Where(entuser.Email("u@example.com")).OnlyX(ctx)
	if !strings.HasPrefix(got.PasswordHash, "{BLF-CRYPT}") {
		t.Fatalf("hash = %q, want {BLF-CRYPT} prefix", got.PasswordHash)
	}
	if got.PasswordHash == "{BLF-CRYPT}$2b$12$original" {
		t.Fatal("password hash was not changed")
	}
	if n := client.Session.Query().CountX(ctx); n != 0 {
		t.Fatalf("sessions remaining = %d, want 0", n)
	}
}

func TestSetPasswordRejectsEmpty(t *testing.T) {
	client := newClient(t)
	mkUser(t, client, "u@example.com", entuser.RoleUser)
	if _, err := SetPassword(context.Background(), client, "u@example.com", ""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("SetPassword empty = %v, want ErrEmptyPassword", err)
	}
}

func TestDisableMFARemovesBothFactors(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	u := mkUser(t, client, "u@example.com", entuser.RoleUser)
	client.TOTPCredential.Create().SetUser(u).SetSecret("JBSWY3DP").SaveX(ctx)
	client.WebAuthnCredential.Create().SetUser(u).SetCredentialID([]byte{1, 2, 3}).SetData(`{"id":"AQID"}`).SaveX(ctx)
	client.WebAuthnCredential.Create().SetUser(u).SetCredentialID([]byte{4, 5, 6}).SetData(`{"id":"BAUG"}`).SaveX(ctx)

	totp, passkeys, err := DisableMFA(ctx, client, "u@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if totp != 1 || passkeys != 2 {
		t.Fatalf("removed totp=%d passkeys=%d, want 1 and 2", totp, passkeys)
	}
	if n := client.TOTPCredential.Query().CountX(ctx) + client.WebAuthnCredential.Query().CountX(ctx); n != 0 {
		t.Fatalf("credentials remaining = %d, want 0", n)
	}
}

func TestEncryptionStatusListDisable(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	u := mkUser(t, client, "enc@example.com", entuser.RoleUser)
	mkUser(t, client, "plain@example.com", entuser.RoleUser)
	mkSlot(t, client, u, entmailkeyslot.SlotTypePassword, "primary")
	mkSlot(t, client, u, entmailkeyslot.SlotTypeRecoveryCode, "backup")

	slots, err := EncryptionStatus(ctx, client, "enc@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 2 {
		t.Fatalf("status slots = %d, want 2", len(slots))
	}
	if none, err := EncryptionStatus(ctx, client, "plain@example.com"); err != nil || len(none) != 0 {
		t.Fatalf("plain status = %v (err %v), want empty", none, err)
	}

	list, err := EncryptionList(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Email != "enc@example.com" {
		t.Fatalf("list = %+v, want only enc@example.com", list)
	}

	removed, err := EncryptionDisable(ctx, client, "enc@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2", removed)
	}
	if n := client.MailKeySlot.Query().CountX(ctx); n != 0 {
		t.Fatalf("slots remaining = %d, want 0", n)
	}
}

func TestListAdmins(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	a := mkUser(t, client, "a-admin@example.com", entuser.RoleAdmin)
	mkUser(t, client, "b-admin@example.com", entuser.RoleAdmin)
	mkUser(t, client, "regular@example.com", entuser.RoleUser)
	client.TOTPCredential.Create().SetUser(a).SetSecret("JBSWY3DP").SaveX(ctx)

	admins, err := ListAdmins(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(admins) != 2 {
		t.Fatalf("admins = %d, want 2", len(admins))
	}
	// Ordered by email: a-admin first, and it has TOTP.
	if admins[0].Email != "a-admin@example.com" || !admins[0].TOTP {
		t.Fatalf("admins[0] = %+v, want a-admin with TOTP", admins[0])
	}
	if admins[1].TOTP {
		t.Fatalf("admins[1] = %+v, want no TOTP", admins[1])
	}
}

func TestUnknownAccount(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	for _, err := range []error{
		MakeAdmin(ctx, client, "nope@example.com"),
		mustErr(DisableMFA(ctx, client, "nope@example.com")),
		mustErr2(SetPassword(ctx, client, "nope@example.com", "x")),
	} {
		if !errors.Is(err, ErrUserNotFound) {
			t.Fatalf("got %v, want ErrUserNotFound", err)
		}
	}
}

// mkSlot creates one encryption key slot for a user with valid required fields.
func mkSlot(t *testing.T, client *ent.Client, u *ent.User, typ entmailkeyslot.SlotType, label string) {
	t.Helper()
	client.MailKeySlot.Create().
		SetUser(u).
		SetSlotType(typ).
		SetLabel(label).
		SetVersion(1).
		SetWrappedKey([]byte{1, 2, 3, 4}).
		SetNonce([]byte{5, 6, 7, 8}).
		SetKdfSalt([]byte{9, 10, 11, 12}).
		SaveX(context.Background())
}

// mustErr/mustErr2 discard non-error returns so table rows above stay one-liners.
func mustErr(_, _ int, err error) error { return err }
func mustErr2(_ int, err error) error   { return err }
