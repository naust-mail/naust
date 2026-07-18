package mailcrypt

import (
	"bytes"
	"strings"
	"testing"
)

func TestRecoveryCodeFormatAndCRC(t *testing.T) {
	codes, err := GenerateRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("got %d codes", len(codes))
	}
	for _, c := range codes {
		if len(c) != 19 || strings.Count(c, "-") != 3 {
			t.Errorf("bad format: %q", c)
		}
		for _, g := range strings.Split(c, "-") {
			if len(g) != 4 {
				t.Errorf("bad group in %q", c)
			}
		}
		if !ValidRecoveryCodeCRC(c) {
			t.Errorf("CRC failed for issued code %q", c)
		}
		if !ValidRecoveryCodeCRC(strings.ToLower(c)) {
			t.Errorf("lowercase rejected: %q", c)
		}
	}

	// Single-character corruption must fail the CRC.
	raw := strings.ReplaceAll(codes[0], "-", "")
	i := strings.IndexByte(crockford, raw[0])
	corrupted := string(crockford[(i+1)%32]) + raw[1:]
	if ValidRecoveryCodeCRC(corrupted) {
		t.Error("CRC did not catch corruption")
	}

	// Adjacent transposition must fail (the reason for mod 37).
	swapped := []byte(raw)
	for j := 0; j < recoveryDataLen-1; j++ {
		if swapped[j] != swapped[j+1] {
			swapped[j], swapped[j+1] = swapped[j+1], swapped[j]
			break
		}
	}
	if string(swapped) != raw && ValidRecoveryCodeCRC(string(swapped)) {
		t.Error("CRC did not catch transposition")
	}

	if ValidRecoveryCodeCRC("SHRT") || ValidRecoveryCodeCRC("") {
		t.Error("short input accepted")
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	if got := NormalizeRecoveryCode(" a3k7-9mnp-2qrt-x5bc "); got != "A3K79MNP2QRTX5BC" {
		t.Errorf("normalize = %q", got)
	}
	// Crockford input aliasing: O->0, I/L->1.
	if got := NormalizeRecoveryCode("OIL0"); got != "0110" {
		t.Errorf("aliasing = %q", got)
	}
}

func TestWrapUnwrapWithAAD(t *testing.T) {
	root, err := GenerateRootKey()
	if err != nil {
		t.Fatal(err)
	}
	salt, _ := GenerateSalt()
	wk, err := DeriveKeyFromSecret([]byte("high entropy secret"), salt)
	if err != nil {
		t.Fatal(err)
	}

	ct, nonce, err := Wrap(root, wk, 7, "password", "", SlotVersion)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unwrap(ct, nonce, wk, 7, "password", "", SlotVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, root) {
		t.Error("round-trip mismatch")
	}

	// Any context change must fail authentication.
	cases := []struct {
		name            string
		userID          int
		slotType, label string
		version         int
	}{
		{"other user", 8, "password", "", SlotVersion},
		{"other type", 7, "recovery_code", "", SlotVersion},
		{"other label", 7, "password", "0", SlotVersion},
		{"other version", 7, "password", "", SlotVersion + 1},
	}
	for _, c := range cases {
		if _, err := Unwrap(ct, nonce, wk, c.userID, c.slotType, c.label, c.version); err == nil {
			t.Errorf("%s: unwrap succeeded with wrong AAD", c.name)
		}
	}

	// Wrong wrapping key fails.
	otherKey, _ := DeriveKeyFromSecret([]byte("wrong"), salt)
	if _, err := Unwrap(ct, nonce, otherKey, 7, "password", "", SlotVersion); err == nil {
		t.Error("unwrap succeeded with wrong key")
	}
}

func TestPasswordKDFDeterminism(t *testing.T) {
	salt, _ := GenerateSalt()
	k1 := DeriveKeyFromPassword("correct horse", salt)
	k2 := DeriveKeyFromPassword("correct horse", salt)
	if !bytes.Equal(k1, k2) {
		t.Error("Argon2id not deterministic for same input")
	}
	if bytes.Equal(k1, DeriveKeyFromPassword("wrong horse", salt)) {
		t.Error("different passwords derived the same key")
	}
	otherSalt, _ := GenerateSalt()
	if bytes.Equal(k1, DeriveKeyFromPassword("correct horse", otherSalt)) {
		t.Error("different salts derived the same key")
	}
}

func TestSubkeyDerivation(t *testing.T) {
	root, _ := GenerateRootKey()
	dove, err := Subkey(root, SubkeyDovecot)
	if err != nil {
		t.Fatal(err)
	}
	dove2, _ := Subkey(root, SubkeyDovecot)
	if !bytes.Equal(dove, dove2) {
		t.Error("subkey not deterministic")
	}
	if bytes.Equal(dove, root) {
		t.Error("subkey equals root key")
	}
	other, _ := Subkey(root, "pgp")
	if bytes.Equal(dove, other) {
		t.Error("purposes share key material")
	}
	if len(dove) != 32 {
		t.Errorf("subkey length = %d", len(dove))
	}
}
