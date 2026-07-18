package checks

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	dnszone "naust/daemon/internal/dns"
)

// testCert makes a self-signed certificate and its PEM encoding.
func testCert(t *testing.T, cn string, notAfter time.Time) (tls.Certificate, *x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, parsed, pemBytes
}

// tlsFixture serves the four mail ports on local listeners: implicit
// TLS on 465/993, SMTP STARTTLS on 25/587. Dial maps the public
// address to the listeners.
type tlsFixture struct {
	addrs map[string]string // "public-ip:port" -> listener addr
}

func startTLSFixture(t *testing.T, publicIP string, cert tls.Certificate) *tlsFixture {
	t.Helper()
	f := &tlsFixture{addrs: map[string]string{}}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	serve := func(port int, starttls bool) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		f.addrs[net.JoinHostPort(publicIP, fmt.Sprint(port))] = ln.Addr().String()
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					if starttls {
						if err := answerSTARTTLS(conn); err != nil {
							return
						}
					}
					tc := tls.Server(conn, cfg)
					if err := tc.Handshake(); err != nil {
						return
					}
					tc.Read(make([]byte, 1)) // hold until the client closes
				}(conn)
			}
		}()
	}
	serve(25, true)
	serve(465, false)
	serve(587, true)
	serve(993, false)
	return f
}

func answerSTARTTLS(conn net.Conn) error {
	br := bufio.NewReader(conn)
	fmt.Fprintf(conn, "220 test ESMTP\r\n")
	if _, err := br.ReadString('\n'); err != nil { // EHLO
		return err
	}
	fmt.Fprintf(conn, "250-test\r\n250 STARTTLS\r\n")
	if _, err := br.ReadString('\n'); err != nil { // STARTTLS
		return err
	}
	fmt.Fprintf(conn, "220 go ahead\r\n")
	return nil
}

func (f *tlsFixture) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	real, ok := f.addrs[addr]
	if !ok {
		return nil, fmt.Errorf("connection refused: %s", addr)
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, real)
}

func tlsDeps(t *testing.T, f *tlsFixture, installedPEM []byte, tlsa string) *Deps {
	t.Helper()
	var zones []dnszone.Zone
	if tlsa != "" {
		zones = []dnszone.Zone{{Apex: "box.example.com", Records: []dnszone.ZoneRecord{
			{Name: "_25._tcp", Type: "TLSA", Value: tlsa, Category: dnszone.CatRecommended},
		}}}
	}
	return &Deps{
		PrimaryHostname: "box.example.com",
		PublicIP:        "203.0.113.5",
		StorageRoot:     "/data",
		ReadFile:        fakeFS(map[string]string{"/data/ssl/ssl_certificate.pem": string(installedPEM)}),
		Dial:            f.dial,
		Zones: func(ctx context.Context) ([]dnszone.Zone, error) {
			return zones, nil
		},
		// Matches StorageRoot above, so the "Postfix serves the installed
		// certificate, not a fallback" step reports OK by default. Tests
		// exercising that step override Run after calling tlsDeps.
		Run: func(ctx context.Context, argv ...string) (string, error) {
			return "/data/ssl/ssl_certificate.pem\n", nil
		},
		Now: func() time.Time { return time.Now() },
	}
}

func spkiTLSA(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "3 1 1 " + hex.EncodeToString(sum[:])
}

func TestMailTLSAllMatch(t *testing.T) {
	cert, parsed, pemBytes := testCert(t, "box.example.com", time.Now().Add(60*24*time.Hour))
	f := startTLSFixture(t, "203.0.113.5", cert)
	d := tlsDeps(t, f, pemBytes, spkiTLSA(parsed))

	steps := runDomainCheck(d, checkMailTLS, "")
	if len(steps) != 10 {
		t.Fatalf("steps = %+v", steps)
	}
	for _, s := range steps {
		if s.Status != StatusOK {
			t.Errorf("step %q = %s: %s", s.Name, s.Status, s.Message)
		}
	}
}

func TestMailTLSStaleCertificate(t *testing.T) {
	// Services serve the old certificate; the disk has the renewed one.
	oldCert, _, _ := testCert(t, "box.example.com", time.Now().Add(5*24*time.Hour))
	_, newParsed, newPEM := testCert(t, "box.example.com", time.Now().Add(90*24*time.Hour))
	f := startTLSFixture(t, "203.0.113.5", oldCert)
	d := tlsDeps(t, f, newPEM, spkiTLSA(newParsed))

	steps := runDomainCheck(d, checkMailTLS, "")
	for _, name := range []string{"Incoming mail", "Outgoing mail", "Mail submission", "IMAP"} {
		s := stepByName(t, steps, name)
		if s.Status != StatusError || !strings.Contains(s.Message, "not reloaded") || s.FixHint == "" {
			t.Errorf("step %q = %+v", name, s)
		}
	}
	// The old key differs, so DANE must fail too.
	if s := stepByName(t, steps, "DANE TLSA"); s.Status != StatusError {
		t.Errorf("dane = %+v", s)
	}
}

func TestMailTLSSnakeoilConfigured(t *testing.T) {
	// Postfix's main.cf never points smtpd_tls_cert_file at the installed
	// certificate, so it falls back to Ubuntu's default self-signed cert.
	cert, parsed, pemBytes := testCert(t, "box.example.com", time.Now().Add(60*24*time.Hour))
	f := startTLSFixture(t, "203.0.113.5", cert)
	d := tlsDeps(t, f, pemBytes, spkiTLSA(parsed))
	d.Run = func(ctx context.Context, argv ...string) (string, error) {
		return "/etc/ssl/certs/ssl-cert-snakeoil.pem\n", nil
	}

	steps := runDomainCheck(d, checkMailTLS, "")
	s := stepByName(t, steps, "Postfix is configured to serve the installed certificate, not a fallback")
	if s.Status != StatusError || !strings.Contains(s.Message, "snakeoil") || s.FixHint == "" {
		t.Errorf("snakeoil step = %+v", s)
	}
}

func TestMailTLSExpiredMismatchReportsBoth(t *testing.T) {
	// Services serve an expired old certificate while the disk has a
	// valid renewed one: both the mismatch and the expiry must fail.
	oldCert, _, _ := testCert(t, "box.example.com", time.Now().Add(-30*time.Minute))
	_, newParsed, newPEM := testCert(t, "box.example.com", time.Now().Add(90*24*time.Hour))
	f := startTLSFixture(t, "203.0.113.5", oldCert)
	d := tlsDeps(t, f, newPEM, spkiTLSA(newParsed))

	steps := runDomainCheck(d, checkMailTLS, "")
	for _, p := range tlsProbes {
		served := stepByName(t, steps, p.label+" serves the installed certificate")
		if served.Status != StatusError || !strings.Contains(served.Message, "not reloaded") {
			t.Errorf("served %q = %+v", p.label, served)
		}
		expired := stepByName(t, steps, p.label+"'s certificate has not expired")
		if expired.Status != StatusError || !strings.Contains(expired.Message, "expired") {
			t.Errorf("expired %q = %+v", p.label, expired)
		}
	}
}

func TestMailTLSUnreachableWarns(t *testing.T) {
	_, parsed, pemBytes := testCert(t, "box.example.com", time.Now().Add(60*24*time.Hour))
	f := &tlsFixture{addrs: map[string]string{}} // nothing listens
	d := tlsDeps(t, f, pemBytes, spkiTLSA(parsed))

	steps := runDomainCheck(d, checkMailTLS, "")
	if s := stepByName(t, steps, "Incoming mail"); s.Status != StatusWarning {
		t.Errorf("unreachable = %+v", s)
	}
	// No handshake means the expiry step has nothing to judge: skip.
	if s := stepByName(t, steps, "Incoming mail (SMTP port 25, STARTTLS)'s certificate"); s.Status != StatusSkipped {
		t.Errorf("expiry = %+v", s)
	}
	// No handshake on 25 means DANE has nothing to compare: skip.
	if s := stepByName(t, steps, "DANE TLSA"); s.Status != StatusSkipped {
		t.Errorf("dane = %+v", s)
	}
}

func TestMailTLSNoInstalledCert(t *testing.T) {
	f := &tlsFixture{addrs: map[string]string{}}
	d := tlsDeps(t, f, nil, "")
	d.ReadFile = fakeFS(map[string]string{})

	steps := runDomainCheck(d, checkMailTLS, "")
	if len(steps) != 1 || steps[0].Status != StatusSkipped {
		t.Fatalf("steps = %+v", steps)
	}
}
