package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"naust/daemon/internal/store/ent"
	"naust/daemon/internal/store/ent/alias"
	"naust/daemon/internal/store/ent/session"
	"naust/daemon/internal/store/ent/user"
)

// forEachEngine runs the same test body against every reachable engine:
// SQLite always (fresh file per subtest), Postgres when TEST_POSTGRES_DSN
// is set. This is the dialect test matrix - every store behavior test in
// this package must go through it, never through a single hardcoded engine.
func forEachEngine(t *testing.T, fn func(t *testing.T, client *ent.Client)) {
	t.Run("sqlite", func(t *testing.T) {
		client, err := Open(EngineSQLite, filepath.Join(t.TempDir(), "test.sqlite"))
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		if err := client.Schema.Create(context.Background()); err != nil {
			t.Fatal(err)
		}
		fn(t, client)
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("TEST_POSTGRES_DSN not set")
		}
		client, err := Open(EnginePostgres, dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		ctx := context.Background()
		if err := client.Schema.Create(ctx); err != nil {
			t.Fatal(err)
		}
		// The Postgres database persists between runs; start each test
		// from empty tables. User deletion cascades to credentials.
		if _, err := client.User.Delete().Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Alias.Delete().Exec(ctx); err != nil {
			t.Fatal(err)
		}
		fn(t, client)
	})
}

func testTenant(t *testing.T, client *ent.Client) *ent.Tenant {
	t.Helper()
	tenant, err := EnsureDefaultTenant(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	return tenant
}

func TestUserLifecycle(t *testing.T) {
	forEachEngine(t, func(t *testing.T, client *ent.Client) {
		ctx := context.Background()

		u, err := client.User.Create().
			SetEmail("me@example.com").
			SetPasswordHash("$2b$fake").
			SetRole(user.RoleAdmin).
			SetQuotaBytes(1 << 30).
			SetTenant(testTenant(t, client)).
			Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if u.HomeNode != "" {
			t.Errorf("home_node default = %q, want empty", u.HomeNode)
		}

		got, err := client.User.Query().Where(user.Email("me@example.com")).Only(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got.Role != user.RoleAdmin || got.QuotaBytes != 1<<30 {
			t.Errorf("got role=%v quota=%d", got.Role, got.QuotaBytes)
		}

		// Unique email must be enforced by every engine.
		_, err = client.User.Create().
			SetEmail("me@example.com").
			SetPasswordHash("x").
			SetTenant(testTenant(t, client)).
			Save(ctx)
		if !ent.IsConstraintError(err) {
			t.Errorf("duplicate email: got %v, want constraint error", err)
		}

		if err := client.User.DeleteOne(u).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAliasUpsert(t *testing.T) {
	forEachEngine(t, func(t *testing.T, client *ent.Client) {
		ctx := context.Background()

		// Same portable upsert the reconciler will use: dialect-specific
		// conflict SQL is emitted per engine by ent.
		for _, dest := range [][]string{{"a@example.com"}, {"b@example.com", "c@example.com"}} {
			err := client.Alias.Create().
				SetSource("postmaster@example.com").
				SetDestinations(dest).
				SetAuto(true).
				SetTenant(testTenant(t, client)).
				OnConflictColumns(alias.FieldSource).
				UpdateNewValues().
				Exec(ctx)
			if err != nil {
				t.Fatal(err)
			}
		}

		got, err := client.Alias.Query().Where(alias.Source("postmaster@example.com")).Only(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Destinations) != 2 || got.Destinations[0] != "b@example.com" {
			t.Errorf("destinations after upsert = %v", got.Destinations)
		}
		if n := client.Alias.Query().CountX(ctx); n != 1 {
			t.Errorf("alias count = %d, want 1", n)
		}
	})
}

func TestDeletingUserCascadesToCredentials(t *testing.T) {
	forEachEngine(t, func(t *testing.T, client *ent.Client) {
		ctx := context.Background()

		u := client.User.Create().
			SetEmail("me@example.com").
			SetPasswordHash("x").
			SetTenant(testTenant(t, client)).
			SaveX(ctx)
		client.Session.Create().
			SetUser(u).
			SetTokenHash("sess1").
			SetExpiresAt(time.Now().Add(time.Hour)).
			SaveX(ctx)
		client.APIToken.Create().
			SetUser(u).
			SetName("ci").
			SetTokenHash("tok1").
			SaveX(ctx)
		client.TOTPCredential.Create().
			SetUser(u).
			SetSecret("JBSWY3DP").
			SaveX(ctx)
		client.WebAuthnCredential.Create().
			SetUser(u).
			SetCredentialID([]byte{1, 2, 3}).
			SetData(`{"id":"AQID"}`).
			SaveX(ctx)
		client.WebAuthnChallenge.Create().
			SetUser(u).
			SetNonceHash("nonce1").
			SetSessionData(`{}`).
			SetKind("login").
			SetExpiresAt(time.Now().Add(time.Minute)).
			SaveX(ctx)

		if err := client.User.DeleteOne(u).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		for name, count := range map[string]int{
			"sessions":   client.Session.Query().CountX(ctx),
			"tokens":     client.APIToken.Query().CountX(ctx),
			"totp":       client.TOTPCredential.Query().CountX(ctx),
			"webauthn":   client.WebAuthnCredential.Query().CountX(ctx),
			"challenges": client.WebAuthnChallenge.Query().CountX(ctx),
		} {
			if count != 0 {
				t.Errorf("%s not cascade-deleted: %d rows remain", name, count)
			}
		}
	})
}

func TestOpenRejectsUnknownEngine(t *testing.T) {
	if _, err := Open(Engine("mysql"), "whatever"); err == nil {
		t.Fatal("unknown database engine silently accepted")
	}
}

func TestSessionExpiryFiltering(t *testing.T) {
	forEachEngine(t, func(t *testing.T, client *ent.Client) {
		ctx := context.Background()

		u := client.User.Create().
			SetEmail("me@example.com").
			SetPasswordHash("x").
			SetTenant(testTenant(t, client)).
			SaveX(ctx)
		client.Session.Create().
			SetUser(u).
			SetTokenHash("live").
			SetExpiresAt(time.Now().Add(time.Hour)).
			SaveX(ctx)
		client.Session.Create().
			SetUser(u).
			SetTokenHash("expired").
			SetExpiresAt(time.Now().Add(-time.Hour)).
			SaveX(ctx)

		live := client.Session.Query().
			Where(session.ExpiresAtGT(time.Now())).
			AllX(ctx)
		if len(live) != 1 {
			t.Fatalf("live sessions = %d, want 1", len(live))
		}
	})
}
