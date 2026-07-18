package dnsapply

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

type tlsFixture struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	serial int64
}

func newTLSFixture(t *testing.T) *tlsFixture {
	t.Helper()
	key := genKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             testNow.AddDate(-1, 0, 0),
		NotAfter:              testNow.AddDate(10, 0, 0),
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
	return &tlsFixture{caCert: cert, caKey: key, serial: 1}
}

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// issue writes base.pem into dir for cn, signed by the CA (or
// self-signed when selfSigned), on the given key.
func (f *tlsFixture) issue(t *testing.T, dir, base, cn string, key *ecdsa.PrivateKey, selfSigned bool) {
	t.Helper()
	f.serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(f.serial),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    testNow.AddDate(0, 0, -1),
		NotAfter:     testNow.AddDate(0, 3, 0),
	}
	parent, signKey := f.caCert, any(f.caKey)
	if selfSigned {
		parent, signKey = tmpl, any(key)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, base+".pem"), "CERTIFICATE", der)
}

func writeKey(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, path, "PRIVATE KEY", der)
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTLSInputs(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	f := newTLSFixture(t)
	sslRoot := t.TempDir()
	e.a.SSLRoot = sslRoot
	e.a.MTASTSPolicyPath = filepath.Join(t.TempDir(), "mta-sts.txt")

	// System pair: CA-signed cert for the primary hostname on the
	// system key, both as the served symlink target stand-in
	// (ssl_certificate.pem, which Scan skips) and as a scanned file.
	systemKey := genKey(t)
	writeKey(t, filepath.Join(sslRoot, "ssl_private_key.pem"), systemKey)
	f.issue(t, sslRoot, "ssl_certificate", "box.example.com", systemKey, false)
	f.issue(t, sslRoot, "box.example.com-cert", "box.example.com", systemKey, false)

	// No policy file yet: TLSA only.
	in, err := e.a.loadInput(ctx)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(sslRoot, "ssl_certificate.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	spki := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if want := "3 1 1 " + hex.EncodeToString(spki[:]); in.TLSARecord != want {
		t.Errorf("TLSARecord = %q, want %q", in.TLSARecord, want)
	}
	if in.MTASTSPolicyID != "" || in.MTASTSDomains != nil {
		t.Errorf("MTA-STS inputs set without a policy file: %q %v", in.MTASTSPolicyID, in.MTASTSDomains)
	}

	// Policy file present, but example.com's mta-sts host has no
	// certificate yet: id computed, domain not vouched for.
	if err := os.WriteFile(e.a.MTASTSPolicyPath, []byte("version: STSv1\nmode: enforce\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	in, err = e.a.loadInput(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9]{20}$`).MatchString(in.MTASTSPolicyID) {
		t.Errorf("MTASTSPolicyID = %q, want 20 alphanumerics", in.MTASTSPolicyID)
	}
	firstID := in.MTASTSPolicyID
	if in.MTASTSDomains["example.com"] {
		t.Error("example.com vouched for without an mta-sts certificate")
	}

	// A valid signed certificate covering mta-sts.example.com flips
	// it; a wildcard counts because nginx would serve it (unlike the
	// legacy exact-name check).
	stsKey := genKey(t)
	writeKey(t, filepath.Join(sslRoot, "wildcard-example-key.pem"), stsKey)
	f.issue(t, sslRoot, "wildcard-example-cert", "*.example.com", stsKey, false)
	in, err = e.a.loadInput(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !in.MTASTSDomains["example.com"] {
		t.Error("example.com not vouched for despite valid certificates")
	}
	if in.MTASTSPolicyID != firstID {
		t.Errorf("policy id changed without a policy change: %q -> %q", firstID, in.MTASTSPolicyID)
	}
	if err := os.WriteFile(e.a.MTASTSPolicyPath, []byte("version: STSv1\nmode: testing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	in, err = e.a.loadInput(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if in.MTASTSPolicyID == firstID {
		t.Error("policy id must change with the policy file")
	}
}

func TestTLSInputsSelfSignedPrimaryBlocksMTASTS(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	f := newTLSFixture(t)
	sslRoot := t.TempDir()
	e.a.SSLRoot = sslRoot
	e.a.MTASTSPolicyPath = filepath.Join(t.TempDir(), "mta-sts.txt")
	if err := os.WriteFile(e.a.MTASTSPolicyPath, []byte("version: STSv1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Fresh-box state: self-signed cert on the system key. The mta-sts
	// host even has a valid signed cert, but the MX itself does not.
	systemKey := genKey(t)
	writeKey(t, filepath.Join(sslRoot, "ssl_private_key.pem"), systemKey)
	f.issue(t, sslRoot, "ssl_certificate", "box.example.com", systemKey, true)
	f.issue(t, sslRoot, "box.example.com-cert", "box.example.com", systemKey, true)
	stsKey := genKey(t)
	writeKey(t, filepath.Join(sslRoot, "mta-sts.example.com-key.pem"), stsKey)
	f.issue(t, sslRoot, "mta-sts.example.com-cert", "mta-sts.example.com", stsKey, false)

	in, err := e.a.loadInput(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// TLSA is key-pinned, so even the self-signed cert yields it.
	if in.TLSARecord == "" {
		t.Error("TLSA record missing for the self-signed system pair")
	}
	if len(in.MTASTSDomains) != 0 {
		t.Errorf("MTASTSDomains = %v, want none while the MX cert is self-signed", in.MTASTSDomains)
	}
}
