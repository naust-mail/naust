package sslcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var now = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             now.AddDate(-1, 0, 0),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

var serial int64 = 100

// issue writes a cert (and optionally its key) into dir. ca == nil
// means self-signed.
func issue(t *testing.T, ca *testCA, dir, base, cn string, sans []string, notBefore, notAfter time.Time, writeKey bool) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     sans,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	parent, signKey := tmpl, key
	if ca != nil {
		parent, signKey = ca.cert, ca.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, base+".pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if writeKey {
		writeKeyFile(t, key, filepath.Join(dir, base+"_key.pem"))
	}
	return key
}

func writeKeyFile(t *testing.T, key *ecdsa.PrivateKey, path string) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestScanAndResolve(t *testing.T) {
	root := t.TempDir()
	ca := newCA(t)

	// System pair: self-signed for the primary, key at the fixed path.
	sysKey := issue(t, nil, root, "primary_selfsigned",
		"box.example.com", []string{"box.example.com"},
		now.AddDate(0, -1, 0), now.AddDate(1, 0, 0), false)
	writeKeyFile(t, sysKey, filepath.Join(root, "ssl_private_key.pem"))
	// The ssl_certificate.pem symlink must never be scanned as a
	// candidate.
	if err := os.Symlink(filepath.Join(root, "primary_selfsigned.pem"),
		filepath.Join(root, "ssl_certificate.pem")); err != nil {
		t.Fatal(err)
	}

	// A CA-signed cert for the primary hostname on the SYSTEM key:
	// eligible for the primary (and preferred over self-signed).
	sysSignedDir := filepath.Join(root, "box.example.com-20270101")
	issueDER := func() {
		serial++
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "box.example.com"},
			DNSNames:     []string{"box.example.com"},
			NotBefore:    now.AddDate(0, -1, 0),
			NotAfter:     now.AddDate(0, 3, 0),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &sysKey.PublicKey, ca.key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(sysSignedDir, 0o755); err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		if err := os.WriteFile(filepath.Join(sysSignedDir, "cert.pem"), certPEM, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	issueDER()

	// example.com: an expired cert and a valid one - valid must win
	// even though the expired one expires... earlier; also a wildcard.
	issue(t, ca, filepath.Join(root, "example.com-old"), "cert",
		"example.com", []string{"example.com", "mail.example.com"},
		now.AddDate(-2, 0, 0), now.AddDate(-1, 9, 0), true)
	issue(t, ca, filepath.Join(root, "example.com-new"), "cert",
		"example.com", []string{"example.com", "mail.example.com"},
		now.AddDate(0, -1, 0), now.AddDate(0, 2, 0), true)
	issue(t, ca, filepath.Join(root, "wild"), "cert",
		"*.example.net", []string{"*.example.net"},
		now.AddDate(0, -1, 0), now.AddDate(0, 2, 0), true)
	// A cert with no key on disk: unusable, must never be chosen.
	issue(t, ca, filepath.Join(root, "keyless"), "cert",
		"orphan.example.org", []string{"orphan.example.org"},
		now.AddDate(0, -1, 0), now.AddDate(5, 0, 0), false)
	// A cert for the primary hostname on a NON-system key: ineligible
	// for the primary even though it expires later.
	issue(t, ca, filepath.Join(root, "rogue"), "cert",
		"box.example.com", []string{"box.example.com"},
		now.AddDate(0, -1, 0), now.AddDate(9, 0, 0), true)

	certs, err := Scan(root, "box.example.com", now)
	if err != nil {
		t.Fatal(err)
	}

	// Primary: the CA-signed cert on the system key wins over both the
	// self-signed one and the later-expiring rogue-key one.
	p, ok := certs["box.example.com"]
	if !ok {
		t.Fatal("no cert chosen for primary")
	}
	if p.CertFile != filepath.Join(sysSignedDir, "cert.pem") {
		t.Errorf("primary cert = %s", p.CertFile)
	}
	if p.KeyFile != filepath.Join(root, "ssl_private_key.pem") {
		t.Errorf("primary key = %s", p.KeyFile)
	}
	if p.SelfSigned {
		t.Error("chosen primary cert marked self-signed")
	}

	// example.com and its SAN sibling: the valid cert wins.
	for _, d := range []string{"example.com", "mail.example.com"} {
		c, ok := certs[d]
		if !ok {
			t.Fatalf("no cert for %s", d)
		}
		if c.CertFile != filepath.Join(root, "example.com-new", "cert.pem") {
			t.Errorf("%s cert = %s", d, c.CertFile)
		}
		if !c.Valid(now) {
			t.Errorf("%s chosen cert not valid", d)
		}
	}
	if _, ok := certs["orphan.example.org"]; ok {
		t.Error("keyless cert must not be usable")
	}

	// Resolve: exact, wildcard, primary pinned to system pair,
	// unknown falls back to system pair.
	sysCert := filepath.Join(root, "ssl_certificate.pem")
	sysKeyFile := filepath.Join(root, "ssl_private_key.pem")
	cases := []struct {
		domain   string
		wantCert string
		wantKey  string
	}{
		{"example.com", filepath.Join(root, "example.com-new", "cert.pem"), filepath.Join(root, "example.com-new", "cert_key.pem")},
		{"app.example.net", filepath.Join(root, "wild", "cert.pem"), filepath.Join(root, "wild", "cert_key.pem")},
		{"box.example.com", sysCert, sysKeyFile},
		{"nothing.example.org", sysCert, sysKeyFile},
	}
	for _, tc := range cases {
		gotCert, gotKey := Resolve(certs, root, "box.example.com", tc.domain)
		if gotCert != tc.wantCert || gotKey != tc.wantKey {
			t.Errorf("Resolve(%s) = %s, %s; want %s, %s", tc.domain, gotCert, gotKey, tc.wantCert, tc.wantKey)
		}
	}
}

func TestScanMissingDirIsEmpty(t *testing.T) {
	certs, err := Scan(filepath.Join(t.TempDir(), "nope"), "box.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 0 {
		t.Fatalf("certs = %v", certs)
	}
}

func TestJunkFilesIgnored(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "notes.txt"), []byte("hello"), 0o644)
	os.WriteFile(filepath.Join(root, "broken.pem"), []byte("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n"), 0o644)
	os.MkdirAll(filepath.Join(root, "sub", "deeper"), 0o755) // two levels: ignored
	certs, err := Scan(root, "box.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 0 {
		t.Fatalf("certs = %v", certs)
	}
}
