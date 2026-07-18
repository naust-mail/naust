package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"naust/daemon/internal/store"
	"naust/daemon/internal/store/ent"
	entsession "naust/daemon/internal/store/ent/session"
)

func testClient(t *testing.T) *ent.Client {
	t.Helper()
	client, err := store.Open(store.EngineSQLite, filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if err := client.Schema.Create(context.Background()); err != nil {
		t.Fatal(err)
	}
	return client
}

func testUser(t *testing.T, client *ent.Client, email string) *ent.User {
	t.Helper()
	tenant, err := store.EnsureDefaultTenant(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	u, err := client.User.Create().
		SetEmail(email).SetPasswordHash("x").SetRole("user").
		SetTenant(tenant).
		Save(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestNewSessionAndUserForToken(t *testing.T) {
	client := testClient(t)
	u := testUser(t, client, "bob@example.com")
	ctx := context.Background()

	token, expires, err := NewSession(ctx, client, u, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || expires.Before(time.Now()) {
		t.Fatalf("token=%q expires=%v", token, expires)
	}

	got, err := UserForToken(ctx, client, token)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Email != u.Email {
		t.Fatalf("resolved user = %+v", got)
	}
}

func TestUserForTokenUnknownTokenReturnsNilNil(t *testing.T) {
	client := testClient(t)
	got, err := UserForToken(context.Background(), client, "never-issued")
	if err != nil || got != nil {
		t.Fatalf("got=%v err=%v, want nil,nil", got, err)
	}
}

// TestUserForTokenRejectsExpiredSession is the single scariest gap an
// auth package can have: if the expiry filter ever regresses, an
// expired bearer token would still authenticate. This proves an
// already-expired session row is treated exactly like no session at
// all, not as a valid one.
func TestUserForTokenRejectsExpiredSession(t *testing.T) {
	client := testClient(t)
	u := testUser(t, client, "bob@example.com")
	ctx := context.Background()

	const token = "expired-token-plaintext"
	_, err := client.Session.Create().
		SetUser(u).
		SetTokenHash(hashToken(token)).
		SetExpiresAt(time.Now().Add(-time.Minute)). // already lapsed
		Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	got, err := UserForToken(ctx, client, token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expired session authenticated as %+v", got)
	}
}

func TestDeleteSessionRevokes(t *testing.T) {
	client := testClient(t)
	u := testUser(t, client, "bob@example.com")
	ctx := context.Background()

	token, _, err := NewSession(ctx, client, u, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := DeleteSession(ctx, client, token); err != nil {
		t.Fatal(err)
	}
	got, err := UserForToken(ctx, client, token)
	if err != nil || got != nil {
		t.Fatalf("revoked session still resolves: got=%v err=%v", got, err)
	}
}

// TestUserForTokenStampsLastUsed proves the activity timestamp is
// actually written on a successful lookup, so the best-effort update
// path is not silently dead code.
func TestUserForTokenStampsLastUsed(t *testing.T) {
	client := testClient(t)
	u := testUser(t, client, "bob@example.com")
	ctx := context.Background()

	token, _, err := NewSession(ctx, client, u, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	got, err := UserForToken(ctx, client, token)
	if err != nil || got == nil {
		t.Fatalf("got=%v err=%v", got, err)
	}

	sess, err := client.Session.Query().Where(entsession.TokenHash(hashToken(token))).Only(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sess.LastUsed == nil {
		t.Error("last_used was not stamped on use")
	}
}
