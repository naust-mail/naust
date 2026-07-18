package acmeprov

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func selfSignedDER(t *testing.T, domain string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestInstallCertRejectsHostnameMismatch proves a certificate issued
// for the wrong name is never installed, even though nothing upstream
// double-checks this - a CA (or a compromised/misbehaving one) handing
// back a mismatched cert must not end up silently serving TLS for the
// wrong domain.
func TestInstallCertRejectsHostnameMismatch(t *testing.T) {
	p := &Provisioner{Log: log.New(os.Stderr, "", 0)}
	sslRoot := t.TempDir()
	der := selfSignedDER(t, "attacker.example")

	err := p.installCert([][]byte{der}, "victim.example.com", sslRoot)
	if err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("err = %v, want a hostname-mismatch error", err)
	}
	entries, _ := os.ReadDir(sslRoot)
	if len(entries) != 0 {
		t.Errorf("mismatched certificate was written to disk: %v", entries)
	}
}

func TestInstallCertRejectsEmptyChain(t *testing.T) {
	p := &Provisioner{Log: log.New(os.Stderr, "", 0)}
	if err := p.installCert(nil, "example.com", t.TempDir()); err == nil {
		t.Fatal("empty chain accepted")
	}
}

func TestInstallCertAcceptsMatchingHostname(t *testing.T) {
	p := &Provisioner{Log: log.New(os.Stderr, "", 0)}
	sslRoot := t.TempDir()
	der := selfSignedDER(t, "example.com")

	if err := p.installCert([][]byte{der}, "example.com", sslRoot); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(sslRoot, "example.com-*.pem"))
	if len(matches) != 1 {
		t.Errorf("installed files = %v", matches)
	}
}

// TestLoadOrCreateAccountKeyRejectsCorruptFile proves a corrupt
// account_key.pem fails loudly instead of being silently replaced,
// which would desync the ACME account's client-side identity from
// whatever key the CA still has on file.
func TestLoadOrCreateAccountKeyRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account_key.pem")
	if err := os.WriteFile(path, []byte("not a pem file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateAccountKey(path); err == nil {
		t.Fatal("corrupt account key file silently accepted or regenerated")
	}
}

func TestLoadOrCreateAccountKeyRejectsUndecodablePKCS8(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account_key.pem")
	block := "-----BEGIN PRIVATE KEY-----\nbm90IHJlYWxseSBhIGtleQ==\n-----END PRIVATE KEY-----\n"
	if err := os.WriteFile(path, []byte(block), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateAccountKey(path); err == nil {
		t.Fatal("undecodable PKCS8 payload silently accepted")
	}
}

func TestLoadOrCreateAccountKeyGeneratesAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account_key.pem")
	first, err := loadOrCreateAccountKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateAccountKey(path)
	if err != nil {
		t.Fatal(err)
	}
	fk, ok1 := first.Public().(*ecdsa.PublicKey)
	sk, ok2 := second.Public().(*ecdsa.PublicKey)
	if !ok1 || !ok2 || !fk.Equal(sk) {
		t.Error("reloading the account key produced a different key instead of the persisted one")
	}
}
