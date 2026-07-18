package acmeprov

// A minimal RFC 8555 CA for tests: enough of the protocol for the
// x/crypto/acme client to register, order, be challenged, finalize,
// and fetch a chain. Challenge validation reads the webroot directly
// (standing in for nginx serving it). JWS signatures are not
// verified; payloads are just decoded.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeOrder struct {
	domain    string
	token     string
	valid     bool
	finalized bool
	certDER   [][]byte
}

type fakeACME struct {
	t       *testing.T
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	srv     *httptest.Server
	webroot string

	mu     sync.Mutex
	orders map[int]*fakeOrder
	nextID int
	serial int64
	regs   int
	// evilToken, when set, is handed out as every challenge token:
	// the client must refuse to use it as a filename.
	evilToken string
	// challengeType switches the offered challenge (default http-01).
	challengeType string
	// dns01Check stands in for the CA's DNS lookup when offering
	// dns-01: it reports whether the challenge TXT is published.
	dns01Check func(domain string) bool
	// asyncFinalize mimics Pebble: finalize answers "processing" with
	// no Location header and no certificate, so the client must poll
	// the order URL it learned at creation.
	asyncFinalize bool
}

func newFakeACME(t *testing.T, webroot string) *fakeACME {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fake ACME CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeACME{
		t: t, caCert: caCert, caKey: caKey, webroot: webroot,
		orders: map[int]*fakeOrder{}, serial: 100,
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeACME) directoryURL() string { return f.srv.URL + "/dir" }

func (f *fakeACME) handle(w http.ResponseWriter, r *http.Request) {
	nonce := make([]byte, 8)
	rand.Read(nonce)
	w.Header().Set("Replay-Nonce", hex.EncodeToString(nonce))

	path := r.URL.Path
	switch {
	case path == "/dir":
		f.writeJSON(w, http.StatusOK, map[string]string{
			"newNonce":   f.srv.URL + "/nonce",
			"newAccount": f.srv.URL + "/new-acct",
			"newOrder":   f.srv.URL + "/new-order",
			"revokeCert": f.srv.URL + "/revoke",
			"keyChange":  f.srv.URL + "/keychange",
		})
	case path == "/nonce":
		w.WriteHeader(http.StatusOK)
	case path == "/new-acct":
		f.mu.Lock()
		f.regs++
		first := f.regs == 1
		f.mu.Unlock()
		w.Header().Set("Location", f.srv.URL+"/acct/1")
		code := http.StatusOK
		if first {
			code = http.StatusCreated
		}
		f.writeJSON(w, code, map[string]string{"status": "valid"})
	case path == "/new-order":
		f.newOrder(w, r)
	case strings.HasPrefix(path, "/authz/"):
		f.authz(w, f.order(path))
	case strings.HasPrefix(path, "/chal/"):
		f.challenge(w, f.order(path))
	case strings.HasPrefix(path, "/order/"):
		f.orderStatus(w, path, f.order(path))
	case strings.HasPrefix(path, "/finalize/"):
		f.finalize(w, r, path, f.order(path))
	case strings.HasPrefix(path, "/cert/"):
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		var buf strings.Builder
		for _, der := range f.order(path).certDER {
			pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		}
		fmt.Fprint(w, buf.String())
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeACME) newOrder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifiers []struct{ Type, Value string } `json:"identifiers"`
	}
	if err := json.Unmarshal(f.payload(r), &req); err != nil || len(req.Identifiers) != 1 {
		f.t.Errorf("new-order: bad identifiers: %v", err)
		http.Error(w, "bad order", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.nextID++
	id := f.nextID
	token := "tok-" + strconv.Itoa(id)
	if f.evilToken != "" {
		token = f.evilToken
	}
	f.orders[id] = &fakeOrder{domain: req.Identifiers[0].Value, token: token}
	f.mu.Unlock()
	w.Header().Set("Location", fmt.Sprintf("%s/order/%d", f.srv.URL, id))
	f.writeJSON(w, http.StatusCreated, f.orderJSON(id))
}

// order resolves the trailing numeric id of any endpoint path.
func (f *fakeACME) order(path string) *fakeOrder {
	id, err := strconv.Atoi(path[strings.LastIndexByte(path, '/')+1:])
	if err != nil {
		f.t.Fatalf("bad order path %s", path)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.orders[id]
	if o == nil {
		f.t.Fatalf("unknown order %d", id)
	}
	return o
}

func (f *fakeACME) orderJSON(id int) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.orders[id]
	status := "pending"
	if o.valid {
		status = "ready"
	}
	out := map[string]any{
		"status":         status,
		"authorizations": []string{fmt.Sprintf("%s/authz/%d", f.srv.URL, id)},
		"finalize":       fmt.Sprintf("%s/finalize/%d", f.srv.URL, id),
	}
	if o.finalized {
		out["status"] = "valid"
		out["certificate"] = fmt.Sprintf("%s/cert/%d", f.srv.URL, id)
	}
	return out
}

func (f *fakeACME) orderStatus(w http.ResponseWriter, path string, _ *fakeOrder) {
	id, _ := strconv.Atoi(path[strings.LastIndexByte(path, '/')+1:])
	f.writeJSON(w, http.StatusOK, f.orderJSON(id))
}

func (f *fakeACME) authz(w http.ResponseWriter, o *fakeOrder) {
	id := f.idOf(o)
	status := "pending"
	if o.valid {
		status = "valid"
	}
	f.writeJSON(w, http.StatusOK, map[string]any{
		"status":     status,
		"identifier": map[string]string{"type": "dns", "value": o.domain},
		"challenges": []map[string]string{{
			"type":   f.chalType(),
			"url":    fmt.Sprintf("%s/chal/%d", f.srv.URL, id),
			"token":  o.token,
			"status": status,
		}},
	})
}

func (f *fakeACME) chalType() string {
	if f.challengeType != "" {
		return f.challengeType
	}
	return "http-01"
}

// challenge validates like the CA would: an HTTP fetch (reading the
// webroot directly, standing in for nginx) or a DNS lookup (asking
// the test's dns01Check).
func (f *fakeACME) challenge(w http.ResponseWriter, o *fakeOrder) {
	fulfilled := false
	if f.chalType() == "dns-01" {
		fulfilled = f.dns01Check != nil && f.dns01Check(o.domain)
	} else {
		data, err := os.ReadFile(filepath.Join(f.webroot, ".well-known", "acme-challenge", o.token))
		fulfilled = err == nil && strings.HasPrefix(string(data), o.token+".")
	}
	if !fulfilled {
		f.t.Errorf("challenge for %s not fulfilled", o.domain)
		http.Error(w, "challenge not fulfilled", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	o.valid = true
	f.mu.Unlock()
	f.writeJSON(w, http.StatusOK, map[string]string{"type": f.chalType(), "token": o.token, "status": "valid"})
}

func (f *fakeACME) finalize(w http.ResponseWriter, r *http.Request, path string, o *fakeOrder) {
	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(f.payload(r), &req); err != nil {
		f.t.Errorf("finalize: %v", err)
		http.Error(w, "bad finalize", http.StatusBadRequest)
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		f.t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	f.serial++
	serial := f.serial
	f.mu.Unlock()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 3, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, f.caCert, csr.PublicKey, f.caKey)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	o.finalized = true
	o.certDER = [][]byte{leafDER, f.caCert.Raw}
	f.mu.Unlock()
	id, _ := strconv.Atoi(path[strings.LastIndexByte(path, '/')+1:])
	if f.asyncFinalize {
		f.writeJSON(w, http.StatusOK, map[string]any{
			"status":         "processing",
			"authorizations": []string{fmt.Sprintf("%s/authz/%d", f.srv.URL, id)},
			"finalize":       fmt.Sprintf("%s/finalize/%d", f.srv.URL, id),
		})
		return
	}
	f.writeJSON(w, http.StatusOK, f.orderJSON(id))
}

func (f *fakeACME) idOf(o *fakeOrder) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, ord := range f.orders {
		if ord == o {
			return id
		}
	}
	f.t.Fatal("order not registered")
	return 0
}

// payload extracts the base64url payload from a JWS request body.
// Signatures are not checked.
func (f *fakeACME) payload(r *http.Request) []byte {
	var body struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		f.t.Fatalf("decode JWS: %v", err)
	}
	data, err := base64.RawURLEncoding.DecodeString(body.Payload)
	if err != nil {
		f.t.Fatalf("decode JWS payload: %v", err)
	}
	return data
}

func (f *fakeACME) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
