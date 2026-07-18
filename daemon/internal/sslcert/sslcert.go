// Package sslcert scans the installed TLS certificates under
// STORAGE_ROOT/ssl and picks the best certificate for each domain.
// Port of the Python selection logic (management/services/
// ssl_certificates/selection.py): same directory layout, same
// preference order, so a box migrated mid-flight resolves identically.
//
// The system pair - ssl/ssl_certificate.pem (a symlink maintained by
// provisioning) and ssl/ssl_private_key.pem - always serves the
// primary hostname, because those paths are hardcoded in the Postfix
// and Dovecot configuration. Everything else matches by SAN, with
// wildcard fallback, then falls back to the system pair.
package sslcert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Pair is the chosen certificate for one domain.
type Pair struct {
	CertFile string
	KeyFile  string
	// PrimaryDomain is the certificate's own subject CN (or first
	// SAN), for display in the panel.
	PrimaryDomain string
	NotBefore     time.Time
	NotAfter      time.Time
	SelfSigned    bool
}

// Valid reports whether the certificate covers the instant.
func (p Pair) Valid(now time.Time) bool {
	return !now.Before(p.NotBefore) && !now.After(p.NotAfter)
}

type scannedCert struct {
	file string
	cert *x509.Certificate
}

// Scan walks sslRoot (files plus one directory level, matching where
// provisioning installs certs) and returns domain -> best pair. A
// missing directory is an empty result, not an error: fresh boxes
// have no certs yet.
func Scan(sslRoot, primaryHostname string, now time.Time) (map[string]Pair, error) {
	var certs []scannedCert
	keys := map[string]string{} // fingerprint of public key -> key file

	for _, fn := range listFiles(sslRoot) {
		data, err := os.ReadFile(fn)
		if err != nil {
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			continue
		}
		switch {
		case block.Type == "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			certs = append(certs, scannedCert{file: fn, cert: cert})
		case strings.HasSuffix(block.Type, "PRIVATE KEY"):
			pub := publicKeyOf(block)
			if pub != "" {
				keys[pub] = fn
			}
		}
	}

	systemKey := filepath.Join(sslRoot, "ssl_private_key.pem")
	byDomain := map[string][]int{}
	keyFiles := make([]string, len(certs))
	for i, sc := range certs {
		keyFile, ok := keys[fingerprint(sc.cert.PublicKey)]
		if !ok {
			continue // certificate without its private key is unusable
		}
		keyFiles[i] = keyFile
		for _, domain := range certDomains(sc.cert) {
			// The primary hostname may only use certificates for the
			// system private key (hardcoded in mail service configs).
			if domain == primaryHostname && keyFile != systemKey {
				continue
			}
			byDomain[domain] = append(byDomain[domain], i)
		}
	}

	out := map[string]Pair{}
	for domain, idxs := range byDomain {
		best := idxs[0]
		for _, i := range idxs[1:] {
			if better(certs[i], certs[best], now) {
				best = i
			}
		}
		sc := certs[best]
		out[domain] = Pair{
			CertFile:      sc.file,
			KeyFile:       keyFiles[best],
			PrimaryDomain: certPrimaryDomain(sc.cert),
			NotBefore:     sc.cert.NotBefore,
			NotAfter:      sc.cert.NotAfter,
			SelfSigned:    bytes.Equal(sc.cert.RawIssuer, sc.cert.RawSubject),
		}
	}
	return out, nil
}

// Resolve picks the certificate files for a domain: the system pair
// for the primary hostname (always), an exact SAN match, a wildcard
// match, else the system pair as the fallback of last resort (the
// browser warns, but nginx can start).
func Resolve(certs map[string]Pair, sslRoot, primaryHostname, domain string) (certFile, keyFile string) {
	if domain != primaryHostname {
		if p, ok := certs[domain]; ok {
			return p.CertFile, p.KeyFile
		}
		if i := strings.IndexByte(domain, '.'); i > 0 {
			if p, ok := certs["*"+domain[i:]]; ok {
				return p.CertFile, p.KeyFile
			}
		}
	}
	return filepath.Join(sslRoot, "ssl_certificate.pem"),
		filepath.Join(sslRoot, "ssl_private_key.pem")
}

// better reports whether a should be preferred over b, mirroring the
// Python sort: currently valid, then not self-signed, then latest
// expiry (so nightly provisioning sees its new cert actually chosen),
// then lexicographically last filename as the tiebreak.
func better(a, b scannedCert, now time.Time) bool {
	av := !now.Before(a.cert.NotBefore) && !now.After(a.cert.NotAfter)
	bv := !now.Before(b.cert.NotBefore) && !now.After(b.cert.NotAfter)
	if av != bv {
		return av
	}
	as := bytes.Equal(a.cert.RawIssuer, a.cert.RawSubject)
	bs := bytes.Equal(b.cert.RawIssuer, b.cert.RawSubject)
	if as != bs {
		return bs // prefer the one that is NOT self-signed
	}
	if !a.cert.NotAfter.Equal(b.cert.NotAfter) {
		return a.cert.NotAfter.After(b.cert.NotAfter)
	}
	return a.file > b.file
}

// listFiles yields regular files in root and one level deeper,
// skipping the ssl_certificate.pem symlink: it points at the chosen
// primary cert, and treating it as a candidate could select a
// symlink to itself.
func listFiles(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.Name() == "ssl_certificate.pem" {
			continue
		}
		p := filepath.Join(root, e.Name())
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.Mode().IsRegular() {
			out = append(out, p)
			continue
		}
		if !fi.IsDir() {
			continue
		}
		subs, err := os.ReadDir(p)
		if err != nil {
			continue
		}
		for _, sub := range subs {
			sp := filepath.Join(p, sub.Name())
			if sfi, err := os.Stat(sp); err == nil && sfi.Mode().IsRegular() {
				out = append(out, sp)
			}
		}
	}
	sort.Strings(out)
	return out
}

// certDomains returns every name the certificate is good for: the
// subject CN (legacy) plus all DNS SANs, lowercased. Certificates
// carry punycode already, matching how domains are stored.
func certDomains(cert *x509.Certificate) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		name = strings.ToLower(name)
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	add(cert.Subject.CommonName)
	for _, name := range cert.DNSNames {
		add(name)
	}
	return out
}

func certPrimaryDomain(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return strings.ToLower(cert.Subject.CommonName)
	}
	if len(cert.DNSNames) > 0 {
		return strings.ToLower(cert.DNSNames[0])
	}
	return ""
}

// publicKeyOf parses a private key PEM block (PKCS#8, PKCS#1, or SEC1)
// and fingerprints its public half; "" when unparseable.
func publicKeyOf(block *pem.Block) string {
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return ""
	}
	if err != nil {
		return ""
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return ""
	}
	return fingerprint(signer.Public())
}

// fingerprint canonicalizes a public key for cert<->key matching.
func fingerprint(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return ""
		}
		return string(der)
	default:
		return ""
	}
}
