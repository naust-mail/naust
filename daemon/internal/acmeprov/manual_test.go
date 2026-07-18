package acmeprov

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCSR(t *testing.T) {
	env := newEnv(t, nil)
	ctx := context.Background()

	pemCSR, err := env.prov.CSR(ctx, testPrimary, "DE")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(pemCSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("csr = %q", pemCSR)
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.CheckSignature(); err != nil {
		t.Errorf("signature: %v", err)
	}
	if req.Subject.CommonName != testPrimary || len(req.Subject.Country) != 1 || req.Subject.Country[0] != "DE" {
		t.Errorf("subject = %+v", req.Subject)
	}
	pub, ok := req.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(env.sysKey.Public()) {
		t.Error("CSR is not on the system key")
	}

	// No country code: C= omitted entirely.
	pemCSR, err = env.prov.CSR(ctx, testPrimary, "")
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode([]byte(pemCSR))
	if req, err = x509.ParseCertificateRequest(block.Bytes); err != nil || len(req.Subject.Country) != 0 {
		t.Errorf("country = %+v (%v)", req.Subject, err)
	}

	if _, err := env.prov.CSR(ctx, "not-hosted.net", ""); err == nil ||
		!strings.Contains(err.Error(), "unknown domain") {
		t.Errorf("unknown domain err = %v", err)
	}
	if _, err := env.prov.CSR(ctx, testPrimary, "deutschland"); err == nil ||
		!strings.Contains(err.Error(), "country code") {
		t.Errorf("bad country err = %v", err)
	}
}

// caSignedPEM issues a certificate over pub from the fake CA.
func caSignedPEM(t *testing.T, env *testEnv, domain string, pub any, notAfter time.Time) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, env.fake.caCert, pub, env.fake.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestInstallManual(t *testing.T) {
	env := newEnv(t, nil)
	ctx := context.Background()
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: env.fake.caCert.Raw}))
	good := caSignedPEM(t, env, testPrimary, env.sysKey.Public(), time.Now().Add(90*24*time.Hour))

	if err := env.prov.InstallManual(ctx, testPrimary, good, caPEM); err != nil {
		t.Fatal(err)
	}
	// Installed under the legacy naming scheme and activated: the
	// symlink points at it and the mail services were restarted.
	link, err := os.Readlink(filepath.Join(env.sslRoot, "ssl_certificate.pem"))
	if err != nil {
		t.Fatalf("symlink: %v", err)
	}
	data, err := os.ReadFile(link)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), strings.TrimSpace(good)) {
		t.Error("installed file does not contain the leaf")
	}
	if !strings.Contains(string(data), strings.TrimSpace(caPEM)) {
		t.Error("installed file does not contain the chain")
	}
	if len(env.helper.calls) == 0 || env.helper.calls[0] != "service.restart:postfix" {
		t.Errorf("helper calls = %v", env.helper.calls)
	}
	if env.kicked == 0 || env.kickedDNS == 0 {
		t.Errorf("appliers not kicked: web=%d dns=%d", env.kicked, env.kickedDNS)
	}

	// A certificate on a foreign key is refused.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreign := caSignedPEM(t, env, testPrimary, otherKey.Public(), time.Now().Add(90*24*time.Hour))
	if err := env.prov.InstallManual(ctx, testPrimary, foreign, ""); err == nil ||
		!strings.Contains(err.Error(), "private key") {
		t.Errorf("foreign key err = %v", err)
	}

	// Expired, garbage, multi-cert paste, and unknown domain.
	expired := caSignedPEM(t, env, testPrimary, env.sysKey.Public(), time.Now().Add(-time.Hour))
	if err := env.prov.InstallManual(ctx, testPrimary, expired, ""); err == nil ||
		!strings.Contains(err.Error(), "not currently valid") {
		t.Errorf("expired err = %v", err)
	}
	if err := env.prov.InstallManual(ctx, testPrimary, "not pem", ""); err == nil {
		t.Error("garbage accepted")
	}
	if err := env.prov.InstallManual(ctx, testPrimary, good+good, ""); err == nil ||
		!strings.Contains(err.Error(), "exactly one certificate") {
		t.Errorf("multi-cert err = %v", err)
	}
	if err := env.prov.InstallManual(ctx, "not-hosted.net", good, ""); err == nil ||
		!strings.Contains(err.Error(), "unknown domain") {
		t.Errorf("unknown domain err = %v", err)
	}
}
