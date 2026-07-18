package acmeprov

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"naust/daemon/internal/sslcert"

	"golang.org/x/crypto/acme"
)

// newClient loads (or creates) the ACME account key and ensures the
// account is registered. A key that is already registered is fine:
// the CA returns the existing account and the client caches its URL.
func (p *Provisioner) newClient(ctx context.Context) (*acme.Client, error) {
	dir := filepath.Join(p.StorageRoot, "ssl", "lets_encrypt")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	key, err := loadOrCreateAccountKey(filepath.Join(dir, "account_key.pem"))
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}
	cl := &acme.Client{Key: key, DirectoryURL: p.DirectoryURL, HTTPClient: p.HTTPClient}
	if cl.DirectoryURL == "" {
		cl.DirectoryURL = LetsEncryptDirectory
	}
	if _, err := cl.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil &&
		!errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("register ACME account: %w", err)
	}
	return cl, nil
}

// provisionOne runs one order end to end: authorize, satisfy the
// solver's challenge, finalize with a CSR over the system key,
// install the chain.
func (p *Provisioner) provisionOne(ctx context.Context, cl *acme.Client, sysKey crypto.Signer, solver Solver, domain, sslRoot string) error {
	ctx, cancel := context.WithTimeout(ctx, perDomainTimeout)
	defer cancel()

	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return fmt.Errorf("order: %w", err)
	}

	chalType := solver.ChallengeType()
	for _, zurl := range order.AuthzURLs {
		authz, err := cl.GetAuthorization(ctx, zurl)
		if err != nil {
			return fmt.Errorf("authorization: %w", err)
		}
		if authz.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == chalType {
				chal = c
				break
			}
		}
		if chal == nil {
			return fmt.Errorf("CA offered no %s challenge", chalType)
		}
		value, err := challengeValue(cl, chalType, chal.Token)
		if err != nil {
			return err
		}
		if err := solver.Present(ctx, domain, chal.Token, value); err != nil {
			return fmt.Errorf("present challenge: %w", err)
		}
		defer solver.Cleanup(ctx, domain, chal.Token)
		if _, err := cl.Accept(ctx, chal); err != nil {
			return fmt.Errorf("accept challenge: %w", err)
		}
		if _, err := cl.WaitAuthorization(ctx, authz.URI); err != nil {
			return fmt.Errorf("validation: %w", err)
		}
	}

	if _, err := cl.WaitOrder(ctx, order.URI); err != nil {
		return fmt.Errorf("order: %w", err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, sysKey)
	if err != nil {
		return fmt.Errorf("csr: %w", err)
	}
	der, _, err := cl.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		// CAs may answer finalize with "processing" and no Location
		// header (RFC 8555 does not require one; Pebble does exactly
		// this), which CreateOrderCert's internal wait cannot follow.
		// Poll the order URL we already hold instead; if the order
		// never turns valid the original error stands.
		ord, werr := cl.WaitOrder(ctx, order.URI)
		if werr != nil || ord.CertURL == "" {
			return fmt.Errorf("finalize: %w", err)
		}
		if der, err = cl.FetchCert(ctx, ord.CertURL, true); err != nil {
			return fmt.Errorf("fetch certificate: %w", err)
		}
	}
	return p.installCert(der, domain, sslRoot)
}

// challengeValue derives the response the solver must publish, in
// the form the challenge type expects.
func challengeValue(cl *acme.Client, chalType, token string) (string, error) {
	switch chalType {
	case "http-01":
		return cl.HTTP01ChallengeResponse(token)
	case "dns-01":
		return cl.DNS01ChallengeRecord(token)
	default:
		return "", fmt.Errorf("unsupported challenge type %q", chalType)
	}
}

// installCert writes the issued chain into sslRoot using the legacy
// naming scheme (<domain>-<expiry>-<fingerprint>.pem) so migrated
// boxes and sslcert.Scan see one consistent layout.
func (p *Provisioner) installCert(der [][]byte, domain, sslRoot string) error {
	if len(der) == 0 {
		return errors.New("CA returned an empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return fmt.Errorf("parse issued certificate: %w", err)
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return fmt.Errorf("issued certificate does not cover %s: %w", domain, err)
	}
	var buf bytes.Buffer
	for _, d := range der {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: d}); err != nil {
			return err
		}
	}
	fpr := sha256.Sum256(leaf.Raw)
	name := fmt.Sprintf("%s-%s-%s.pem", safeName(domain),
		leaf.NotAfter.UTC().Format("20060102"), hex.EncodeToString(fpr[:4]))
	if warn, err := writeCertFile(filepath.Join(sslRoot, name), buf.Bytes()); err != nil {
		return err
	} else if warn != nil {
		p.Log.Printf("acmeprov: %v", warn)
	}
	p.Log.Printf("acmeprov: installed %s", name)
	return nil
}

// certRestartServices are the services that hold the primary
// certificate open and need a restart when the symlink repoints.
// Every name must be in the helper's service vocabulary
// (TestCertRestartServicesKnownToHelper pins that).
var certRestartServices = []string{"postfix", "dovecot", "rav"}

// postInstall re-resolves the primary hostname's best certificate,
// repoints the ssl_certificate.pem symlink (the path hardcoded in the
// Postfix and Dovecot configs) when it changed, restarts the mail
// services, and kicks the web applier. The DANE TLSA record stays
// valid throughout because the private key is reused.
func (p *Provisioner) postInstall(ctx context.Context, sslRoot string) {
	certs, err := sslcert.Scan(sslRoot, p.PrimaryHostname, time.Now())
	if err != nil {
		p.Log.Printf("acmeprov: rescan after install: %v", err)
	} else if pair, ok := certs[p.PrimaryHostname]; !ok {
		p.Log.Printf("acmeprov: no usable certificate for %s", p.PrimaryHostname)
	} else {
		link := filepath.Join(sslRoot, "ssl_certificate.pem")
		if target, err := os.Readlink(link); err != nil || target != pair.CertFile {
			if err := replaceSymlink(pair.CertFile, link); err != nil {
				p.Log.Printf("acmeprov: update %s: %v", link, err)
			} else {
				for _, svc := range certRestartServices {
					if _, err := p.Helper.Call(ctx, "service.restart", map[string]string{"service": svc}); err != nil {
						p.Log.Printf("acmeprov: restart %s: %v", svc, err)
					}
				}
			}
		}
	}
	if p.KickWeb != nil {
		p.KickWeb()
	}
	if p.KickDNS != nil {
		p.KickDNS()
	}
}

func replaceSymlink(target, link string) error {
	tmp := link + ".tmp"
	os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, link)
}

// writeCertFile writes atomically with the certificate readable by
// the ssl-cert group, so loopback TLS clients can verify against the
// live chain. The group change is best effort: dev environments run
// managerd outside that group, so a failure here doesn't fail the
// whole issuance - it's returned as a warning so the caller can log
// it instead of the failure vanishing silently.
func writeCertFile(path string, content []byte) (warn error, err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".cert-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if g, lerr := user.LookupGroup("ssl-cert"); lerr == nil {
		if gid, aerr := strconv.Atoi(g.Gid); aerr == nil {
			if cerr := os.Chown(tmp.Name(), -1, gid); cerr != nil {
				warn = fmt.Errorf("could not set ssl-cert group on %s (naust user may not be in that group): %w", path, cerr)
			}
		}
	}
	return warn, os.Rename(tmp.Name(), path)
}

// loadOrCreateAccountKey reads the ACME account key, generating an
// ECDSA P-256 key on first use. Losing this key is harmless (a new
// account gets registered); it is stored only to stay a polite,
// stable client to the CA.
func loadOrCreateAccountKey(path string) (crypto.Signer, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("%s: no PEM block", path)
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%s: not a signing key", path)
		}
		return signer, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// loadSigner parses the system private key (PKCS#8, PKCS#1, or SEC1),
// which signs every CSR so issued certificates keep the DANE-pinned
// key.
func loadSigner(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	var key any
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%s: unsupported key type %q", path, block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: not a signing key", path)
	}
	return signer, nil
}

// safeName makes a domain safe to embed in a filename. Domains from
// the store are already IDNA-encoded and lowercase; this only guards
// a malformed name from sneaking into a path.
func safeName(domain string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		}
		return '_'
	}, strings.ToLower(domain))
}
