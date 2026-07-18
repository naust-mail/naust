package auth

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashPasswordAndVerifyRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Error("correct password rejected")
	}
	if VerifyPassword(hash, "wrong password") {
		t.Error("wrong password accepted")
	}
}

// TestVerifyPasswordRejectsMissingPrefix is the auth-bypass case: a
// hash that is not in the expected {BLF-CRYPT} format (corrupt row,
// or a legacy scheme this daemon no longer honors) must be rejected
// outright, never compared as if the whole string were the bcrypt
// hash.
func TestVerifyPasswordRejectsMissingPrefix(t *testing.T) {
	rawHash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyPassword(string(rawHash), "hunter2") {
		t.Error("hash without the {BLF-CRYPT} prefix must not verify")
	}
}

func TestVerifyPasswordRejectsGarbageHash(t *testing.T) {
	for _, hash := range []string{"", "{BLF-CRYPT}", "{BLF-CRYPT}not-a-bcrypt-hash", "{SHA512-CRYPT}$6$whatever"} {
		if VerifyPassword(hash, "anything") {
			t.Errorf("garbage hash %q must not verify", hash)
		}
	}
}

// TestFakeVerifyUsesRealBcryptCost locks in the actual invariant that
// keeps FakeVerify a timing decoy: it must burn the same bcrypt cost
// as a real verification. A change that swaps in a cheap placeholder
// hash would silently reopen the user-enumeration timing side channel
// this function exists to close, and a wall-clock timing assertion
// here would just be flaky, so this checks the cost bcrypt itself
// records in the dummy hash instead.
func TestFakeVerifyUsesRealBcryptCost(t *testing.T) {
	FakeVerify("anything") // ensures dummyHash is initialized
	cost, err := bcrypt.Cost(dummyHash)
	if err != nil {
		t.Fatal(err)
	}
	if cost != bcryptCost {
		t.Errorf("FakeVerify dummy hash cost = %d, want %d (matching real VerifyPassword)", cost, bcryptCost)
	}
}
