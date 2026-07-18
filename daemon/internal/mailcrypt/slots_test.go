package mailcrypt

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"naust/daemon/internal/store"
	"naust/daemon/internal/store/ent"
	entmailkeyslot "naust/daemon/internal/store/ent/mailkeyslot"
	entuser "naust/daemon/internal/store/ent/user"
)

func testStore(t *testing.T) *ent.Client {
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

func testUser(t *testing.T, client *ent.Client, email string) int {
	t.Helper()
	tenant, err := store.EnsureDefaultTenant(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	u, err := client.User.Create().
		SetEmail(email).
		SetPasswordHash("x").
		SetTenant(tenant).
		Save(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// enable sets up committed password + recovery slots for a user and
// returns the root key and codes, mimicking a completed ceremony.
func enable(t *testing.T, client *ent.Client, userID int, password string) ([]byte, []string) {
	t.Helper()
	ctx := context.Background()
	root, err := GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	codes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	pw, err := BuildPasswordSlot(userID, password, root)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := BuildRecoverySlots(userID, codes, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertSlots(ctx, client, userID, append([]PreparedSlot{pw}, rec...)); err != nil {
		t.Fatal(err)
	}
	return root, codes
}

func TestSlotRoundTrips(t *testing.T) {
	client := testStore(t)
	ctx := context.Background()
	userID := testUser(t, client, "a@example.com")
	root, codes := enable(t, client, userID, "hunter2 but longer")

	got, err := UnwrapViaPassword(ctx, client, userID, "hunter2 but longer")
	if err != nil || !bytes.Equal(got, root) {
		t.Fatalf("password unwrap: %v", err)
	}
	if _, err := UnwrapViaPassword(ctx, client, userID, "wrong"); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("wrong password = %v", err)
	}

	for _, c := range codes {
		got, err := UnwrapViaRecoveryCode(ctx, client, userID, c)
		if err != nil || !bytes.Equal(got, root) {
			t.Fatalf("recovery unwrap %q: %v", c, err)
		}
	}
	other, _ := GenerateRecoveryCodes()
	if _, err := UnwrapViaRecoveryCode(ctx, client, userID, other[0]); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("foreign code = %v", err)
	}

	types, err := SlotTypes(ctx, client, userID)
	if err != nil || len(types) != 2 {
		t.Errorf("slot types = %v (%v)", types, err)
	}
	has, err := HasSlot(ctx, client, userID, SlotPassword)
	if err != nil || !has {
		t.Errorf("HasSlot password = %v %v", has, err)
	}
}

func TestNoSlotErrors(t *testing.T) {
	client := testStore(t)
	ctx := context.Background()
	userID := testUser(t, client, "b@example.com")

	if _, err := UnwrapViaPassword(ctx, client, userID, "pw"); !errors.Is(err, ErrNoSlot) {
		t.Errorf("password = %v", err)
	}
	if _, err := UnwrapViaRecoveryCode(ctx, client, userID, "AAAA-AAAA-AAAA-AAAA"); !errors.Is(err, ErrNoSlot) {
		t.Errorf("recovery = %v", err)
	}
	if _, err := UnwrapViaPRF(ctx, client, userID, "cred", []byte("x")); !errors.Is(err, ErrNoSlot) {
		t.Errorf("prf = %v", err)
	}
}

func TestSlotsAreUserBound(t *testing.T) {
	// A slot row belonging to one user must never unwrap for another,
	// even if an attacker with database access copies the row over.
	client := testStore(t)
	ctx := context.Background()
	alice := testUser(t, client, "alice@example.com")
	bob := testUser(t, client, "bob@example.com")
	root, _ := enable(t, client, alice, "alices password")

	// Rebuild Alice's password slot bytes as if copied to Bob's row.
	slot, err := client.MailKeySlot.Query().Where().First(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.MailKeySlot.Create().
		SetUserID(bob).
		SetSlotType(slot.SlotType).
		SetLabel(slot.Label).
		SetVersion(slot.Version).
		SetWrappedKey(slot.WrappedKey).
		SetNonce(slot.Nonce).
		SetKdfSalt(slot.KdfSalt).
		Exec(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapViaPassword(ctx, client, bob, "alices password")
	if err == nil && bytes.Equal(got, root) {
		t.Fatal("copied slot unwrapped for another user: AAD not binding")
	}
}

// TestWithTxRollsBackOnError proves a failure partway through a
// delete-then-insert rotation (ReplacePasswordSlot,
// ReplaceRecoverySlots, InsertPRFSlot all share this helper) leaves
// the original slot intact instead of committing the delete alone,
// which would lock the user out with no password slot at all.
func TestWithTxRollsBackOnError(t *testing.T) {
	client := testStore(t)
	ctx := context.Background()
	userID := testUser(t, client, "e@example.com")
	root, _ := enable(t, client, userID, "original password")

	boom := errors.New("boom")
	err := withTx(ctx, client, func(tx *ent.Client) error {
		if _, err := tx.MailKeySlot.Delete().
			Where(entmailkeyslot.HasUserWith(entuser.ID(userID)), entmailkeyslot.SlotTypeEQ(entmailkeyslot.SlotTypePassword)).
			Exec(ctx); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}

	got, err := UnwrapViaPassword(ctx, client, userID, "original password")
	if err != nil || !bytes.Equal(got, root) {
		t.Fatalf("password slot lost after a rolled-back transaction: %v", err)
	}
}

func TestDecodePreparedRejectsMalformedJSON(t *testing.T) {
	if _, err := DecodePrepared("not json"); err == nil {
		t.Fatal("malformed prepared-slot JSON silently accepted")
	}
	if _, err := DecodePrepared(""); err == nil {
		t.Fatal("empty prepared-slot payload silently accepted")
	}
}

func TestReplacePasswordSlot(t *testing.T) {
	client := testStore(t)
	ctx := context.Background()
	userID := testUser(t, client, "c@example.com")
	root, codes := enable(t, client, userID, "old password")

	if err := ReplacePasswordSlot(ctx, client, userID, "new password", root); err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapViaPassword(ctx, client, userID, "old password"); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("old password still unwraps: %v", err)
	}
	got, err := UnwrapViaPassword(ctx, client, userID, "new password")
	if err != nil || !bytes.Equal(got, root) {
		t.Fatalf("new password: %v", err)
	}
	// Recovery codes untouched.
	if _, err := UnwrapViaRecoveryCode(ctx, client, userID, codes[0]); err != nil {
		t.Errorf("recovery after replace: %v", err)
	}
}

func TestReplaceRecoverySlots(t *testing.T) {
	client := testStore(t)
	ctx := context.Background()
	userID := testUser(t, client, "d@example.com")
	root, oldCodes := enable(t, client, userID, "pw pw pw")

	newCodes, _ := GenerateRecoveryCodes()
	prepared, err := BuildRecoverySlots(userID, newCodes, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := ReplaceRecoverySlots(ctx, client, userID, prepared); err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapViaRecoveryCode(ctx, client, userID, oldCodes[0]); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("old code still valid: %v", err)
	}
	if _, err := UnwrapViaRecoveryCode(ctx, client, userID, newCodes[3]); err != nil {
		t.Errorf("new code: %v", err)
	}
}

func TestPRFSlotLifecycle(t *testing.T) {
	client := testStore(t)
	ctx := context.Background()
	userID := testUser(t, client, "e@example.com")
	root, _ := enable(t, client, userID, "some password")

	credID := EncodeCredentialID([]byte{1, 2, 3, 4})
	prfOutput := bytes.Repeat([]byte{7}, 32)
	evalSalt := bytes.Repeat([]byte{9}, 32)
	slot, salt, err := BuildPRFSlot(userID, credID, prfOutput, evalSalt, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertPRFSlot(ctx, client, userID, slot, salt); err != nil {
		t.Fatal(err)
	}

	gotSalt, err := PRFSaltFor(ctx, client, userID, credID)
	if err != nil || !bytes.Equal(gotSalt, evalSalt) {
		t.Fatalf("prf salt: %v", err)
	}
	got, err := UnwrapViaPRF(ctx, client, userID, credID, prfOutput)
	if err != nil || !bytes.Equal(got, root) {
		t.Fatalf("prf unwrap: %v", err)
	}
	if _, err := UnwrapViaPRF(ctx, client, userID, credID, bytes.Repeat([]byte{8}, 32)); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("wrong prf output = %v", err)
	}

	// Re-enrolling the same credential replaces, not duplicates.
	slot2, salt2, err := BuildPRFSlot(userID, credID, prfOutput, evalSalt, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := InsertPRFSlot(ctx, client, userID, slot2, salt2); err != nil {
		t.Fatal(err)
	}

	if err := DeletePRFSlot(ctx, client, userID, credID); err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapViaPRF(ctx, client, userID, credID, prfOutput); !errors.Is(err, ErrNoSlot) {
		t.Errorf("after delete = %v", err)
	}
	// Deleting again is not an error.
	if err := DeletePRFSlot(ctx, client, userID, credID); err != nil {
		t.Error(err)
	}
}

func TestPreparedEncodingRoundTrip(t *testing.T) {
	root, _ := GenerateRootKey()
	codes, _ := GenerateRecoveryCodes()
	prepared, err := BuildRecoverySlots(42, codes, root)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodePrepared(prepared)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePrepared(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != len(prepared) {
		t.Fatalf("len = %d", len(decoded))
	}
	// The decoded prepared slot still verifies and unwraps.
	got, err := UnwrapPreparedRecovery(42, decoded[2], codes[2])
	if err != nil || !bytes.Equal(got, root) {
		t.Fatalf("decoded unwrap: %v", err)
	}
	if _, err := UnwrapPreparedRecovery(42, decoded[2], codes[1]); !errors.Is(err, ErrWrongSecret) {
		t.Errorf("wrong code on prepared = %v", err)
	}
}
