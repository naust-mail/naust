package acmeprov

import (
	"context"
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

func statusFor(t *testing.T, list []DomainStatus, domain string) DomainStatus {
	t.Helper()
	for _, d := range list {
		if d.Domain == domain {
			return d
		}
	}
	t.Fatalf("no status for %s in %v", domain, list)
	return DomainStatus{}
}

func TestDomainStatuses(t *testing.T) {
	env := newEnv(t, nil)
	ctx := context.Background()

	// Bare box: a system key but no certificates at all.
	list, err := env.prov.DomainStatuses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := statusFor(t, list, testPrimary); got.Cert != CertMissing || !got.NotAfter.IsZero() {
		t.Errorf("bare primary = %+v", got)
	}

	env.issueOnSystemKey(t, "box-valid", testPrimary, 90*24*time.Hour)
	env.issueOnSystemKey(t, "example-expiring", "example.com", 10*24*time.Hour)
	env.issueOnSystemKey(t, "www-expired", "www.example.com", -30*time.Minute)

	// Self-signed certificate for the mta-sts host.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9999),
		Subject:      pkix.Name{CommonName: "mta-sts.example.com"},
		DNSNames:     []string{"mta-sts.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &env.sysKey.PublicKey, env.sysKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(env.sslRoot, "mta-sts-selfsigned.pem"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	list, err = env.prov.DomainStatuses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for domain, want := range map[string]CertState{
		testPrimary:              CertValid,
		"example.com":            CertExpiring,
		"www.example.com":        CertExpired,
		"mta-sts.example.com":    CertSelfSigned,
		"autoconfig.example.com": CertMissing,
	} {
		if got := statusFor(t, list, domain); got.Cert != want {
			t.Errorf("%s = %s, want %s", domain, got.Cert, want)
		}
	}
	if got := statusFor(t, list, testPrimary); got.NotAfter.IsZero() {
		t.Error("valid primary has zero NotAfter")
	}
}

func TestStartRun(t *testing.T) {
	env := newEnv(t, nil)
	// A limit matching no hosted domain: the run loads inputs, visits
	// nothing, and finishes without CA or DNS traffic.
	env.prov.StartRun([]string{"no-such-domain.example.net"})
	deadline := time.Now().Add(5 * time.Second)
	for env.prov.Busy() {
		if time.Now().After(deadline) {
			t.Fatal("StartRun did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ranAt := env.prov.Status(); ranAt.IsZero() {
		t.Error("Status ranAt not set after StartRun")
	}
}
