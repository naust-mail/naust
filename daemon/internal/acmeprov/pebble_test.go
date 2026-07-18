package acmeprov

// Integration test against Pebble, Let's Encrypt's chaos-mode test CA.
// Skipped unless PEBBLE_BIN and CHALLTESTSRV_BIN point at the two
// binaries from a pebble release (ephemeral /tmp installs):
//
//	PEBBLE_BIN=/tmp/pebble CHALLTESTSRV_BIN=/tmp/pebble-challtestsrv \
//	  go test -run TestPebble ./internal/acmeprov/
//
// Fixed localhost ports (the test is opt-in, so collisions are the
// operator's to manage): 14000/15000 Pebble ACME/management, 8053
// challtestsrv DNS, 8055 its management API, 5002 the webroot HTTP
// server Pebble validates against.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestPebble(t *testing.T) {
	pebbleBin := os.Getenv("PEBBLE_BIN")
	challBin := os.Getenv("CHALLTESTSRV_BIN")
	if pebbleBin == "" || challBin == "" {
		t.Skip("set PEBBLE_BIN and CHALLTESTSRV_BIN to run the Pebble integration test")
	}

	dir := t.TempDir()
	caCert, pool := pebbleTLSPair(t, dir)
	cfg := fmt.Sprintf(`{"pebble": {
		"listenAddress": "127.0.0.1:14000",
		"managementListenAddress": "127.0.0.1:15000",
		"certificate": %q, "privateKey": %q,
		"httpPort": 5002, "tlsPort": 5001,
		"ocspResponderURL": "",
		"externalAccountBindingRequired": false}}`,
		filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	cfgPath := filepath.Join(dir, "pebble.json")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	// challtestsrv answers Pebble's DNS lookups with 127.0.0.1 for
	// everything; all its challenge responders are disabled since the
	// webroot server below plays that part.
	var logs bytes.Buffer
	startProc(t, &logs, challBin,
		"-dnsserver", "127.0.0.1:8053", "-management", "127.0.0.1:8055",
		"-defaultIPv6", "", "-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", "")
	pebble := exec.Command(pebbleBin, "-config", cfgPath, "-dnsserver", "127.0.0.1:8053", "-strict")
	// Deterministic run: no authorization delays, no synthetic
	// badNonce rejections (the client's retry path has upstream tests).
	pebble.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0")
	startCmd(t, &logs, pebble)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("pebble/challtestsrv output:\n%s", logs.String())
		}
	})
	_ = caCert

	env := newEnv(t, map[string][]netip.Addr{
		testPrimary: {netip.MustParseAddr(testIP)}, // webroot preflight gate
	})
	env.prov.DirectoryURL = "https://127.0.0.1:14000/dir"
	env.prov.HTTPClient = &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}

	// Serve the solver's webroot where Pebble's validator will fetch
	// challenge files: http://<domain resolved to 127.0.0.1>:5002/.
	webroot := filepath.Join(env.sslRoot, "lets_encrypt", "webroot")
	if err := os.MkdirAll(webroot, 0o755); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:5002")
	if err != nil {
		t.Fatalf("webroot listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go http.Serve(ln, http.FileServer(http.Dir(webroot)))

	waitForPebble(t, env.prov.HTTPClient, env.prov.DirectoryURL)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if r := resultFor(t, env.prov.Run(ctx, []string{testPrimary}), testPrimary); r.Status != StatusInstalled {
		t.Fatalf("run = %+v", r)
	}

	// The installed chain must be live: symlinked, covering the
	// domain, and on the DANE-pinned system key.
	data, err := os.ReadFile(filepath.Join(env.sslRoot, "ssl_certificate.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname(testPrimary); err != nil {
		t.Error(err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(env.sysKey.Public()) {
		t.Error("issued certificate is not on the system key")
	}
}

// pebbleTLSPair writes a self-signed localhost certificate for
// Pebble's HTTPS listener and returns it with a pool trusting it.
func pebbleTLSPair(t *testing.T, dir string) (*x509.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writeFile := func(name, typ string, b []byte) {
		data := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b})
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("cert.pem", "CERTIFICATE", der)
	writeFile("key.pem", "PRIVATE KEY", keyDER)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return cert, pool
}

func startProc(t *testing.T, logs *bytes.Buffer, bin string, args ...string) {
	t.Helper()
	startCmd(t, logs, exec.Command(bin, args...))
}

func startCmd(t *testing.T, logs *bytes.Buffer, cmd *exec.Cmd) {
	t.Helper()
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", cmd.Path, err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
}

func waitForPebble(t *testing.T, client *http.Client, url string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("pebble not ready: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
