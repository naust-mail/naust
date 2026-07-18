package checks

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"
)

func tlsChecks() []Check {
	return []Check{{
		// Live handshakes against the mail ports, compared to the
		// certificate installed on disk: the one failure mode the file
		// based SSL status cannot see is a service still serving the
		// old certificate after a renewal.
		Name:        "mail-tls",
		Title:       "Mail certificate served",
		Description: "Connects to the mail services for receiving and sending mail and checks each one is presenting the current certificate rather than an old copy left behind after the last renewal, and that the certificate has not expired. If a service serves the wrong or expired certificate, mail programs show security warnings and some senders refuse to deliver.",
		Category:    "mail", Locus: LocusNode, Tier: TierHourly,
		Timeout: time.Minute,
		Run:     checkMailTLS,
	}}
}

type tlsProbe struct {
	label    string
	port     int
	starttls bool // negotiate SMTP STARTTLS before the handshake
	hint     string
}

var tlsProbes = []tlsProbe{
	{"Incoming mail (SMTP port 25, STARTTLS)", 25, true, "service.restart postfix"},
	{"Outgoing mail (SMTPS port 465)", 465, false, "service.restart postfix"},
	{"Mail submission (port 587, STARTTLS)", 587, true, "service.restart postfix"},
	{"IMAP (port 993)", 993, false, "service.restart dovecot"},
}

func checkMailTLS(ctx context.Context, d *Deps, _ string, r *Reporter) {
	expected, err := expectedServedCert(d)
	if err != nil {
		r.Step("The installed certificate can be read", func(s *StepCtx) {
			s.Skipf("cannot read the installed certificate: %v", err)
		})
		return
	}
	expectedFP := sha256.Sum256(expected.Raw)

	r.Step("Postfix is configured to serve the installed certificate, not a fallback", func(s *StepCtx) {
		if d.InDocker {
			// postconf here would read the management container's own
			// local Postfix install (present only for its CLI tools),
			// not the mail container's real, materialized main.cf -
			// a confidently wrong answer rather than no answer.
			s.Skipf("main.cf is not shared with the mail container in Docker")
			return
		}
		wantPath := filepath.Join(d.StorageRoot, "ssl", "ssl_certificate.pem")
		out, err := d.Run(ctx, "postconf", "-h", "smtpd_tls_cert_file")
		if err != nil {
			s.Warnf("could not read Postfix's configured certificate path: %v", err)
			return
		}
		got := strings.TrimSpace(out)
		s.Expect(wantPath, got)
		switch {
		case got == "":
			s.Failf("Postfix has no smtpd_tls_cert_file configured - it is serving a package default, and mail clients will see security warnings.")
			s.Hint("service.restart postfix")
		case strings.Contains(got, "snakeoil"):
			s.Failf("Postfix is configured to serve Ubuntu's default self-signed snakeoil certificate (%s) instead of the installed one - this almost always means smtpd_tls_cert_file/smtpd_tls_key_file were never set in main.cf, and TLS-verifying senders will reject mail.", got)
			s.Hint("service.restart postfix")
		case got != wantPath:
			s.Failf("Postfix's configured certificate path (%s) does not match the installed certificate (%s).", got, wantPath)
			s.Hint("service.restart postfix")
		}
	})

	var served25 *x509.Certificate
	for _, p := range tlsProbes {
		p := p
		var leaf *x509.Certificate
		var fetchErr error
		r.Step(p.label+" serves the installed certificate", func(s *StepCtx) {
			leaf, fetchErr = fetchServedCert(ctx, d, p)
			if fetchErr != nil {
				s.Warnf("could not complete a TLS handshake on port %d: %v", p.port, fetchErr)
				return
			}
			if p.port == 25 {
				served25 = leaf
			}
			if sha256.Sum256(leaf.Raw) != expectedFP {
				s.Expect(certLine(expected), certLine(leaf))
				s.Failf("%s is serving a different certificate than the one installed on disk - it was probably not reloaded after the last renewal.", p.label)
				s.Hint(p.hint)
			}
		})
		r.Step(p.label+"'s certificate has not expired", func(s *StepCtx) {
			if fetchErr != nil {
				s.Skipf("no certificate was observed on port %d", p.port)
				return
			}
			if d.Now().After(leaf.NotAfter) {
				s.Failf("%s is serving an expired certificate (expired %s).",
					p.label, leaf.NotAfter.UTC().Format("2006-01-02"))
				s.Hint(p.hint)
			}
		})
	}

	r.Step("DANE TLSA record matches the certificate served on port 25", func(s *StepCtx) {
		if d.Zones == nil {
			s.Skipf("no zone data available")
			return
		}
		if served25 == nil {
			s.Skipf("no certificate was observed on port 25")
			return
		}
		want, err := generatedTLSA(ctx, d)
		if err != nil {
			s.Warnf("could not load the generated zones: %v", err)
			return
		}
		if want == "" {
			s.Skipf("no TLSA record is generated yet")
			return
		}
		spki := sha256.Sum256(served25.RawSubjectPublicKeyInfo)
		got := "3 1 1 " + hex.EncodeToString(spki[:])
		s.Expect(want, got)
		if !strings.EqualFold(want, got) {
			s.Failf("The generated TLSA record does not match the key served on port 25 - DANE-validating senders will refuse to deliver mail. The certificate key changed without DNS following; check the DNS applier and the served certificate.")
		}
	})
}

// expectedServedCert parses the leaf of the certificate file every
// mail service is configured to serve.
func expectedServedCert(d *Deps) (*x509.Certificate, error) {
	data, err := d.ReadFile(filepath.Join(d.StorageRoot, "ssl", "ssl_certificate.pem"))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no certificate in ssl_certificate.pem")
	}
	return x509.ParseCertificate(block.Bytes)
}

// generatedTLSA returns the TLSA value generated for _25._tcp of the
// primary hostname, or "".
func generatedTLSA(ctx context.Context, d *Deps) (string, error) {
	zones, err := d.Zones(ctx)
	if err != nil {
		return "", err
	}
	want := "_25._tcp." + d.PrimaryHostname + "."
	for _, z := range zones {
		for _, rec := range z.Records {
			if rec.Type == "TLSA" && fqdnOf(rec.Name, z.Apex) == want {
				return rec.Value, nil
			}
		}
	}
	return "", nil
}

// fetchServedCert connects to one mail port and returns the leaf
// certificate it presents. Verification is deliberately skipped: the
// point is comparing the leaf against the installed file, not judging
// PKI validity (the SSL status owns that).
func fetchServedCert(ctx context.Context, d *Deps, p tlsProbe) (*x509.Certificate, error) {
	// In Docker, d.PublicIP is a placeholder unreachable from the
	// management container; dial the mail container directly instead,
	// same as the HostVar-based probes in checks_services.go.
	host := d.PublicIP
	if d.InDocker {
		host = d.flag("MAIL_HOST", "127.0.0.1")
	}
	conn, err := d.Dial(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(p.port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(15 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetDeadline(deadline)

	if p.starttls {
		if err := smtpStartTLS(conn, d.PrimaryHostname); err != nil {
			return nil, err
		}
	}
	tc := tls.Client(conn, &tls.Config{ServerName: d.PrimaryHostname, InsecureSkipVerify: true})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate presented")
	}
	return certs[0], nil
}

// smtpStartTLS drives the minimal SMTP dialogue up to an accepted
// STARTTLS, leaving the connection ready for the TLS handshake.
func smtpStartTLS(conn net.Conn, helo string) error {
	br := bufio.NewReader(conn)
	if err := readSMTPReply(br, "220"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(conn, "EHLO %s\r\n", helo); err != nil {
		return err
	}
	if err := readSMTPReply(br, "250"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return err
	}
	return readSMTPReply(br, "220")
}

// readSMTPReply consumes one possibly multiline SMTP reply and checks
// its code.
func readSMTPReply(br *bufio.Reader, code string) error {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		if len(line) < 4 || !strings.HasPrefix(line, code) {
			return fmt.Errorf("unexpected SMTP reply %q", strings.TrimSpace(line))
		}
		if line[3] == ' ' {
			return nil // a hyphen at [3] means a continuation line
		}
	}
}

func certLine(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%s, SHA256 %s, expires %s",
		cert.Subject.CommonName, hex.EncodeToString(sum[:8]), cert.NotAfter.UTC().Format("2006-01-02"))
}
