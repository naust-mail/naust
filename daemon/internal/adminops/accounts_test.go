package adminops

import (
	"context"
	"errors"
	"testing"

	"naust/daemon/internal/auth"
	"naust/daemon/internal/store"
	"naust/daemon/internal/store/ent"
	entalias "naust/daemon/internal/store/ent/alias"
	entuser "naust/daemon/internal/store/ent/user"
)

// tenantID resolves the default tenant's id for the create helpers.
func tenantID(t *testing.T, client *ent.Client) int {
	t.Helper()
	tenant, err := store.EnsureDefaultTenant(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	return tenant.ID
}

func TestCreateUserNormalIsLoginable(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	u, err := CreateUser(ctx, client, tenantID(t, client), CreateUserParams{
		Email:    "alice@example.com",
		Role:     entuser.RoleUser,
		Password: "correcthorse",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if !auth.VerifyPassword(u.PasswordHash, "correcthorse") {
		t.Fatalf("password should verify for a normal account")
	}
}

func TestCreateUserLockedRefusesLogin(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	u, err := CreateUser(ctx, client, tenantID(t, client), CreateUserParams{
		Email:  "bob@example.com",
		Role:   entuser.RoleUser,
		Locked: true,
	})
	if err != nil {
		t.Fatalf("CreateUser locked: %v", err)
	}
	if u.PasswordHash != lockedHash {
		t.Fatalf("locked account hash = %q, want %q", u.PasswordHash, lockedHash)
	}
	// Both auth doors must refuse: managerd verifies here, Dovecot reads
	// the same sentinel from the passwd-file and finds no valid bcrypt.
	if auth.VerifyPassword(u.PasswordHash, "") || auth.VerifyPassword(u.PasswordHash, lockedHash) {
		t.Fatalf("locked account must never verify any password")
	}
	// The account still exists (and so receives mail).
	if n, _ := client.User.Query().Count(ctx); n != 1 {
		t.Fatalf("locked account should be stored")
	}
}

func TestCreateUserLockedWithPasswordRejected(t *testing.T) {
	client := newClient(t)
	_, err := CreateUser(context.Background(), client, tenantID(t, client), CreateUserParams{
		Email:    "carol@example.com",
		Role:     entuser.RoleUser,
		Locked:   true,
		Password: "shouldnotbehere",
	})
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationError, got %v", err)
	}
}

func TestCreateUserDCVRejectedAfterFirst(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	tid := tenantID(t, client)

	// First account may be a DCV address (created before the rule applies).
	if _, err := CreateUser(ctx, client, tid, CreateUserParams{
		Email: "admin@example.com", Role: entuser.RoleUser, Locked: true,
	}); err != nil {
		t.Fatalf("first DCV account should be allowed: %v", err)
	}
	// A later DCV address is rejected.
	_, err := CreateUser(ctx, client, tid, CreateUserParams{
		Email: "postmaster@example.com", Role: entuser.RoleUser, Locked: true,
	})
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationError for DCV address, got %v", err)
	}
}

func TestCreateUserDuplicate(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	tid := tenantID(t, client)
	p := CreateUserParams{Email: "dave@example.com", Role: entuser.RoleUser, Locked: true}
	if _, err := CreateUser(ctx, client, tid, p); err != nil {
		t.Fatal(err)
	}
	_, err := CreateUser(ctx, client, tid, p)
	if !errors.Is(err, ErrUserExists) {
		t.Fatalf("want ErrUserExists, got %v", err)
	}
}

func TestCreateUserInvalidInputs(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	tid := tenantID(t, client)
	cases := []CreateUserParams{
		{Email: "not-an-email", Role: entuser.RoleUser, Locked: true},
		{Email: "eve@example.com", Role: entuser.RoleUser, QuotaBytes: -1, Locked: true},
		{Email: "eve@example.com", Role: entuser.RoleUser, Password: "short"}, // < 8 chars
	}
	for i, p := range cases {
		_, err := CreateUser(ctx, client, tid, p)
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Fatalf("case %d: want ValidationError, got %v", i, err)
		}
	}
}

func TestUpsertAliasCreateIfAbsent(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	tid := tenantID(t, client)
	a, err := UpsertAlias(ctx, client, tid, AliasParams{
		Source:       "info@example.com",
		Destinations: []string{"alice@example.com"},
	}, false)
	if err != nil {
		t.Fatalf("UpsertAlias: %v", err)
	}
	if a.Source != "info@example.com" || a.Auto {
		t.Fatalf("unexpected alias %+v", a)
	}
}

func TestUpsertAliasAdditiveSkipsExisting(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	tid := tenantID(t, client)

	// A pre-existing system-generated (auto) alias.
	if _, err := client.Alias.Create().
		SetSource("postmaster@example.com").
		SetDestinations([]string{"root@example.com"}).
		SetAuto(true).
		SetTenantID(tid).
		Save(ctx); err != nil {
		t.Fatal(err)
	}
	// Additive create must refuse and leave the auto alias untouched.
	_, err := UpsertAlias(ctx, client, tid, AliasParams{
		Source:       "postmaster@example.com",
		Destinations: []string{"someone@example.com"},
	}, false)
	if !errors.Is(err, ErrAliasExists) {
		t.Fatalf("want ErrAliasExists, got %v", err)
	}
	got := client.Alias.Query().Where(entalias.Source("postmaster@example.com")).OnlyX(ctx)
	if !got.Auto || got.Destinations[0] != "root@example.com" {
		t.Fatalf("additive upsert must not clobber the auto alias: %+v", got)
	}
}

func TestUpsertAliasOverwriteReplaces(t *testing.T) {
	client := newClient(t)
	ctx := context.Background()
	tid := tenantID(t, client)
	if _, err := client.Alias.Create().
		SetSource("info@example.com").
		SetDestinations([]string{"old@example.com"}).
		SetAuto(true).
		SetTenantID(tid).
		Save(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := UpsertAlias(ctx, client, tid, AliasParams{
		Source:       "info@example.com",
		Destinations: []string{"new@example.com"},
	}, true)
	if err != nil {
		t.Fatalf("overwrite upsert: %v", err)
	}
	if a.Auto || a.Destinations[0] != "new@example.com" {
		t.Fatalf("overwrite should replace and clear auto: %+v", a)
	}
}

func TestUpsertAliasRequiresDestination(t *testing.T) {
	client := newClient(t)
	_, err := UpsertAlias(context.Background(), client, tenantID(t, client), AliasParams{
		Source: "info@example.com",
	}, false)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationError, got %v", err)
	}
}
