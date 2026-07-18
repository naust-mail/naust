package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBootstrapCodeShape(t *testing.T) {
	for i := 0; i < 50; i++ {
		code, err := bootstrapCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != bootstrapCodeLen {
			t.Fatalf("code %q length %d, want %d", code, len(code), bootstrapCodeLen)
		}
		for _, c := range code {
			if !strings.ContainsRune(bootstrapCodeChars, c) {
				t.Fatalf("code %q contains %q, outside the alphabet", code, c)
			}
		}
	}
}

func TestNewBootstrapToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tok := newBootstrapToken("ABCD2345", now)
	if tok.Code != "ABCD2345" {
		t.Errorf("code = %q, want ABCD2345", tok.Code)
	}
	if tok.Attempts != 0 {
		t.Errorf("attempts = %d, want 0 (managerd owns the counter)", tok.Attempts)
	}
	if want := now.Add(15 * time.Minute).Unix(); tok.Expires != want {
		t.Errorf("expires = %d, want %d (now + 15m)", tok.Expires, want)
	}
}

// TestWriteBootstrapTokenContract is the load-bearing test: the file this writes
// must parse into exactly the fields managerd's reader expects (code, expires,
// attempts). Mirrors internal/httpapi/bootstrap.go's bootstrapToken struct.
func TestWriteBootstrapTokenContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap.token")
	tok := newBootstrapToken("HJKM6789", time.Unix(1_700_000_000, 0))
	if err := writeBootstrapToken(path, tok); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", info.Mode().Perm())
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Code     string `json:"code"`
		Expires  int64  `json:"expires"`
		Attempts int    `json:"attempts"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("managerd could not parse the token: %v", err)
	}
	if got.Code != tok.Code || got.Expires != tok.Expires || got.Attempts != 0 {
		t.Errorf("round-trip = %+v, want %+v", got, tok)
	}

	// No .tmp left behind.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file survived: %v", err)
	}
}

// TestBootstrapCodeUnique guards against the entropy source going constant: a
// batch of freshly minted codes should be all-distinct. A collision in the
// unambiguous 31^8 space is astronomically unlikely, so any repeat here means
// bootstrapCode stopped drawing real randomness.
func TestBootstrapCodeUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 500; i++ {
		code, err := bootstrapCode()
		if err != nil {
			t.Fatal(err)
		}
		if seen[code] {
			t.Fatalf("duplicate code %q after %d draws - randomness is broken", code, i)
		}
		seen[code] = true
	}
}

// TestWriteBootstrapTokenReMint covers the recovery path the whole command exists
// for: an operator whose code expired runs bootstrap again. The second write must
// fully replace the first (managerd must never read a stale code) and keep 0600.
func TestWriteBootstrapTokenReMint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap.token")
	first := newBootstrapToken("AAAA2345", time.Unix(1_700_000_000, 0))
	if err := writeBootstrapToken(path, first); err != nil {
		t.Fatal(err)
	}
	second := newBootstrapToken("BBBB6789", time.Unix(1_700_000_900, 0))
	if err := writeBootstrapToken(path, second); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got bootstrapToken
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Code != second.Code || got.Expires != second.Expires {
		t.Errorf("re-mint left stale token %+v, want %+v", got, second)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Errorf("re-mint mode = %v, want 0600", info.Mode().Perm())
	}
}

// TestWriteBootstrapTokenMissingDir: if control/ does not exist, the write must
// fail loudly rather than silently drop the token, and must not leave a .tmp
// turd behind for a reader to trip over.
func TestWriteBootstrapTokenMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	path := filepath.Join(dir, "bootstrap.token")
	if err := writeBootstrapToken(path, newBootstrapToken("CCCC2345", time.Unix(1_700_000_000, 0))); err == nil {
		t.Fatal("expected an error writing into a missing directory, got nil")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("token file should not exist after a failed write: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file should not survive a failed write: %v", err)
	}
}

// TestCertFingerprintMalformed: a non-PEM or truncated certificate file is a
// display nicety failing, not a crash or a gate - it must yield "".
func TestCertFingerprintMalformed(t *testing.T) {
	for _, content := range []string{
		"",
		"not a certificate at all",
		"-----BEGIN CERTIFICATE-----\nnot base64 pem body\n-----END CERTIFICATE-----\n",
	} {
		root := t.TempDir()
		sslDir := filepath.Join(root, "ssl")
		if err := os.MkdirAll(sslDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sslDir, "ssl_certificate.pem"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := certFingerprint(root); got != "" {
			t.Errorf("malformed cert %q yielded %q, want empty", content, got)
		}
	}
}

// TestCertFingerprintMatchesDER pins the exact format: the uppercase colon-hex
// SHA-256 of the certificate DER, matching openssl x509 -fingerprint -sha256.
func TestCertFingerprintMatchesDER(t *testing.T) {
	root := t.TempDir()
	sslDir := filepath.Join(root, "ssl")
	if err := os.MkdirAll(sslDir, 0o755); err != nil {
		t.Fatal(err)
	}
	der := selfSignedDER(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(sslDir, "ssl_certificate.pem"), pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, by := range sum {
		parts[i] = fmt.Sprintf("%02X", by)
	}
	want := strings.Join(parts, ":")

	if got := certFingerprint(root); got != want {
		t.Errorf("fingerprint = %q, want %q (uppercase colon-hex sha256 of DER)", got, want)
	}
}

func TestCertFingerprint(t *testing.T) {
	root := t.TempDir()
	if got := certFingerprint(root); got != "" {
		t.Errorf("missing cert should yield empty fingerprint, got %q", got)
	}

	der := selfSignedDER(t)
	sslDir := filepath.Join(root, "ssl")
	if err := os.MkdirAll(sslDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(sslDir, "ssl_certificate.pem"), pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	fp := certFingerprint(root)
	// 32 SHA-256 bytes -> 32 hex pairs joined by 31 colons.
	if n := strings.Count(fp, ":"); n != 31 {
		t.Errorf("fingerprint %q has %d colons, want 31", fp, n)
	}
	if fp != strings.ToUpper(fp) {
		t.Errorf("fingerprint %q should be uppercase hex", fp)
	}
}

func selfSignedDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "box.example.com"},
		NotBefore:    time.Unix(1_700_000_000, 0),
		NotAfter:     time.Unix(1_900_000_000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
