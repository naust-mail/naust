package auth

import (
	"context"
	"testing"

	entapitoken "naust/daemon/internal/store/ent/apitoken"
)

func TestNewAPITokenAndUserForAPIToken(t *testing.T) {
	client := testClient(t)
	u := testUser(t, client, "automation@example.com")
	ctx := context.Background()

	plaintext, row, err := NewAPIToken(ctx, client, u, "ci", entapitoken.ScopeRead)
	if err != nil {
		t.Fatal(err)
	}
	if row.LastUsed != nil {
		t.Error("fresh token already has a last-used stamp")
	}

	gotRow, gotUser, err := UserForAPIToken(ctx, client, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if gotRow == nil || gotRow.ID != row.ID || gotUser == nil || gotUser.Email != u.Email {
		t.Fatalf("row=%+v user=%+v", gotRow, gotUser)
	}
}

func TestUserForAPITokenRejectsMissingPrefix(t *testing.T) {
	client := testClient(t)
	row, u, err := UserForAPIToken(context.Background(), client, "not-a-naust-token")
	if err != nil || row != nil || u != nil {
		t.Fatalf("row=%v user=%v err=%v, want nil,nil,nil", row, u, err)
	}
}

func TestUserForAPITokenRejectsEmptySecret(t *testing.T) {
	client := testClient(t)
	row, u, err := UserForAPIToken(context.Background(), client, TokenPrefix)
	if err != nil || row != nil || u != nil {
		t.Fatalf("row=%v user=%v err=%v, want nil,nil,nil", row, u, err)
	}
}

func TestUserForAPITokenUnknownSecretReturnsNilNilNil(t *testing.T) {
	client := testClient(t)
	row, u, err := UserForAPIToken(context.Background(), client, TokenPrefix+"0000000000000000000000000000000000000000000000000000000000000")
	if err != nil || row != nil || u != nil {
		t.Fatalf("row=%v user=%v err=%v, want nil,nil,nil", row, u, err)
	}
}

// TestUserForAPITokenLastUsedThrottled proves last_used only writes
// at most once a minute, matching the comment's promise that
// automation traffic must not write the database on every request.
func TestUserForAPITokenLastUsedThrottled(t *testing.T) {
	client := testClient(t)
	u := testUser(t, client, "automation@example.com")
	ctx := context.Background()

	plaintext, row, err := NewAPIToken(ctx, client, u, "ci", entapitoken.ScopeRead)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := UserForAPIToken(ctx, client, plaintext); err != nil {
		t.Fatal(err)
	}
	first, err := client.APIToken.Get(ctx, row.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first.LastUsed == nil {
		t.Fatal("last_used not stamped on first use")
	}

	if _, _, err := UserForAPIToken(ctx, client, plaintext); err != nil {
		t.Fatal(err)
	}
	second, err := client.APIToken.Get(ctx, row.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !second.LastUsed.Equal(*first.LastUsed) {
		t.Errorf("last_used moved from %v to %v within the same minute", first.LastUsed, second.LastUsed)
	}
}
