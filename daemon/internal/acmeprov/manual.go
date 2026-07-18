package acmeprov

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"time"

	"naust/daemon/internal/webapply"

	cryptorand "crypto/rand"
)

// Manual certificate handling: the operator buys a certificate from a
// commercial CA instead of using ACME. The CSR is generated from the
// box's single system key, so the resulting certificate drops into the
// same install path as an ACME one and DANE TLSA records stay stable.

var countryCodeRe = regexp.MustCompile(`^[A-Z]{2}$`)

// CSR returns a PEM certificate signing request for domain, signed
// with the system private key. countryCode is optional ("" omits C=).
func (p *Provisioner) CSR(ctx context.Context, domain, countryCode string) (string, error) {
	if err := p.checkHosted(ctx, domain); err != nil {
		return "", err
	}
	if countryCode != "" && !countryCodeRe.MatchString(countryCode) {
		return "", errors.New("invalid country code: use two uppercase letters")
	}
	key, err := loadSigner(filepath.Join(p.StorageRoot, "ssl", "ssl_private_key.pem"))
	if err != nil {
		return "", fmt.Errorf("load system key: %w", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}
	if countryCode != "" {
		tmpl.Subject.Country = []string{countryCode}
	}
	der, err := x509.CreateCertificateRequest(cryptorand.Reader, tmpl, key)
	if err != nil {
		return "", fmt.Errorf("create CSR: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// InstallManual validates and installs an operator-provided
// certificate (plus its intermediate chain) for domain. The leaf must
// cover the domain, be currently valid, and be issued for the system
// private key - certificates for foreign keys would break every
// service sharing ssl_private_key.pem and the published TLSA record.
func (p *Provisioner) InstallManual(ctx context.Context, domain, certPEM, chainPEM string) error {
	if err := p.checkHosted(ctx, domain); err != nil {
		return err
	}
	leafDER, err := decodeCerts(certPEM)
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	if len(leafDER) != 1 {
		return errors.New("certificate: paste exactly one certificate (intermediates go in the chain field)")
	}
	var chainDER [][]byte
	if chainPEM != "" {
		if chainDER, err = decodeCerts(chainPEM); err != nil {
			return fmt.Errorf("chain: %w", err)
		}
	}

	leaf, err := x509.ParseCertificate(leafDER[0])
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return fmt.Errorf("certificate is not currently valid (%s to %s)",
			leaf.NotBefore.UTC().Format("2006-01-02"), leaf.NotAfter.UTC().Format("2006-01-02"))
	}
	key, err := loadSigner(filepath.Join(p.StorageRoot, "ssl", "ssl_private_key.pem"))
	if err != nil {
		return fmt.Errorf("load system key: %w", err)
	}
	wantPub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	havePub, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return errors.New("certificate: unsupported public key type")
	}
	if !bytes.Equal(wantPub, havePub) {
		return errors.New("the certificate was not issued for this box's private key - request it with a CSR generated here")
	}
	for i, der := range chainDER {
		if _, err := x509.ParseCertificate(der); err != nil {
			return fmt.Errorf("chain certificate %d: %w", i+1, err)
		}
	}

	sslRoot := filepath.Join(p.StorageRoot, "ssl")
	if err := p.installCert(append(leafDER, chainDER...), domain, sslRoot); err != nil {
		return err
	}
	p.postInstall(ctx, sslRoot)
	return nil
}

// checkHosted rejects domains the web tier does not serve, mirroring
// the domain set DomainStatuses reports.
func (p *Provisioner) checkHosted(ctx context.Context, domain string) error {
	in, err := webapply.LoadInput(ctx, p.Store, p.PrimaryHostname, p.PublicIP, p.PublicIPv6)
	if err != nil {
		return err
	}
	for _, site := range webapply.Derive(in) {
		if site.Domain == domain {
			return nil
		}
	}
	return fmt.Errorf("unknown domain: %s", domain)
}

// decodeCerts extracts every CERTIFICATE block from pemText.
func decodeCerts(pemText string) ([][]byte, error) {
	var out [][]byte
	rest := []byte(pemText)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected %q PEM block", block.Type)
		}
		out = append(out, block.Bytes)
	}
	if len(out) == 0 {
		return nil, errors.New("no PEM certificate found")
	}
	return out, nil
}
