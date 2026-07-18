package dnsapply

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFindSigningKeysRejectsConfMissingAKeyType proves a misconfigured
// signing-key conf (e.g. a KSK entry with no matching ZSK) fails
// loudly instead of silently signing with only half the key pair,
// which would produce a zone the resolver treats as bogus.
func TestFindSigningKeysRejectsConfMissingAKeyType(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.conf"), []byte("KSK=Ka\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := findSigningKeys(dir, "example.com")
	if err == nil || !strings.Contains(err.Error(), "missing ZSK") {
		t.Fatalf("err = %v, want a missing-ZSK error", err)
	}
}

func TestFindSigningKeysRejectsUnreadableDir(t *testing.T) {
	_, err := findSigningKeys(filepath.Join(t.TempDir(), "does-not-exist"), "example.com")
	if err == nil {
		t.Fatal("missing key directory silently returned no keys")
	}
}

// TestPatchKeysStopsOnMissingKeyFile proves that when a listed key's
// on-disk file is missing (e.g. a conf naming a base that was never
// generated), patchKeys errors out before signing rather than
// producing a partially patched key set that gets fed into signing.
func TestPatchKeysStopsOnMissingKeyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.conf"), []byte("KSK=Kk\nZSK=Kz\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Kk's files exist; Kz's do not (as if generation was interrupted).
	for _, ext := range []string{".private", ".key"} {
		if err := os.WriteFile(filepath.Join(dir, "Kk"+ext), []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// signZone always creates tmpDir fresh with os.MkdirTemp and
	// defer os.RemoveAll(tmpDir) regardless of outcome, so a partial
	// write here (KSK patched before ZSK's missing file is hit) is
	// harmless - the whole scratch dir is discarded. What matters is
	// that the error propagates and no key list is returned to sign.
	tmpDir := t.TempDir()
	all, ksks, err := patchKeys(dir, "example.com", tmpDir)
	if err == nil {
		t.Fatal("missing ZSK key file silently accepted")
	}
	if all != nil || ksks != nil {
		t.Errorf("partial result returned on error: all=%v ksks=%v", all, ksks)
	}
}
