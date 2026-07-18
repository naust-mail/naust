package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"naust/daemon/internal/acmeprov"
	"naust/daemon/internal/api"
)

type fakeCerts struct {
	statuses  []acmeprov.DomainStatus
	err       error
	last      []acmeprov.Result
	ranAt     time.Time
	busy      bool
	started   [][]string
	csrErr    error
	installed []api.SSLInstallRequest
	instErr   error
}

func (f *fakeCerts) DomainStatuses(context.Context) ([]acmeprov.DomainStatus, error) {
	return f.statuses, f.err
}
func (f *fakeCerts) Status() ([]acmeprov.Result, time.Time) { return f.last, f.ranAt }
func (f *fakeCerts) StartRun(domains []string)              { f.started = append(f.started, domains) }
func (f *fakeCerts) Busy() bool                             { return f.busy }
func (f *fakeCerts) CSR(_ context.Context, domain, cc string) (string, error) {
	if f.csrErr != nil {
		return "", f.csrErr
	}
	return "-----BEGIN CERTIFICATE REQUEST-----\n" + domain + "/" + cc, nil
}
func (f *fakeCerts) InstallManual(_ context.Context, domain, cert, chain string) error {
	if f.instErr != nil {
		return f.instErr
	}
	f.installed = append(f.installed, api.SSLInstallRequest{Domain: domain, Cert: cert, Chain: chain})
	return nil
}

func TestSSLStatus(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token
	notAfter := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	s.Certs = &fakeCerts{
		statuses: []acmeprov.DomainStatus{
			{Domain: "box.example.com", Cert: acmeprov.CertValid, NotAfter: notAfter},
			{Domain: "example.com", Cert: acmeprov.CertMissing},
		},
		last: []acmeprov.Result{
			{Domain: "box.example.com", Status: acmeprov.StatusInstalled},
			{Domain: "example.com", Status: acmeprov.StatusSkipped, Detail: "does not resolve to this box"},
			{Status: acmeprov.StatusError, Detail: "load domains: boom"},
		},
		ranAt: time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC),
		busy:  true,
	}

	if w := doJSON(t, s, "GET", "/api/ssl", "", nil); w.Code != 401 {
		t.Errorf("unauthenticated status = %d, want 401", w.Code)
	}

	w := doJSON(t, s, "GET", "/api/ssl", token, nil)
	if w.Code != 200 {
		t.Fatalf("GET /api/ssl = %d %s", w.Code, w.Body)
	}
	var resp api.SSLStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Running {
		t.Error("running not reported")
	}
	if resp.LastError != "load domains: boom" {
		t.Errorf("last_error = %q", resp.LastError)
	}
	if resp.LastRunAt == nil || !resp.LastRunAt.Equal(time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("last_run_at = %v", resp.LastRunAt)
	}
	if len(resp.Domains) != 2 {
		t.Fatalf("domains = %+v", resp.Domains)
	}
	box := resp.Domains[0]
	if box.Cert != "valid" || box.NotAfter == nil || !box.NotAfter.Equal(notAfter) || box.LastStatus != "installed" {
		t.Errorf("box.example.com = %+v", box)
	}
	ex := resp.Domains[1]
	if ex.Cert != "missing" || ex.NotAfter != nil || ex.LastStatus != "skipped" ||
		ex.LastDetail != "does not resolve to this box" {
		t.Errorf("example.com = %+v", ex)
	}
}

func TestSSLProvision(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token
	fake := &fakeCerts{statuses: []acmeprov.DomainStatus{{Domain: "example.com", Cert: acmeprov.CertMissing}}}
	s.Certs = fake

	// Empty body: a full run over every hosted domain.
	if w := doJSON(t, s, "POST", "/api/ssl/provision", token, nil); w.Code != 202 {
		t.Fatalf("empty-body provision = %d %s", w.Code, w.Body)
	}
	if len(fake.started) != 1 || len(fake.started[0]) != 0 {
		t.Errorf("started = %v", fake.started)
	}

	// Scoped to one hosted domain.
	w := doJSON(t, s, "POST", "/api/ssl/provision", token,
		api.SSLProvisionRequest{Domains: []string{"example.com"}})
	if w.Code != 202 {
		t.Fatalf("scoped provision = %d %s", w.Code, w.Body)
	}
	if len(fake.started) != 2 || len(fake.started[1]) != 1 || fake.started[1][0] != "example.com" {
		t.Errorf("started = %v", fake.started)
	}

	// Unknown domains are rejected before anything starts.
	w = doJSON(t, s, "POST", "/api/ssl/provision", token,
		api.SSLProvisionRequest{Domains: []string{"evil.example.net"}})
	if w.Code != 400 {
		t.Errorf("unknown domain = %d %s", w.Code, w.Body)
	}
	if len(fake.started) != 2 {
		t.Errorf("run started despite rejection: %v", fake.started)
	}

	if w := doJSON(t, s, "POST", "/api/ssl/provision", "", nil); w.Code != 401 {
		t.Errorf("unauthenticated provision = %d, want 401", w.Code)
	}
}

func TestSSLCSRAndInstall(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token
	fake := &fakeCerts{}
	s.Certs = fake

	w := doJSON(t, s, "POST", "/api/ssl/csr", token,
		api.SSLCSRRequest{Domain: "example.com", CountryCode: "DE"})
	if w.Code != 200 {
		t.Fatalf("csr = %d %s", w.Code, w.Body)
	}
	var csrResp api.SSLCSRResponse
	if err := json.Unmarshal(w.Body.Bytes(), &csrResp); err != nil {
		t.Fatal(err)
	}
	if csrResp.CSR != "-----BEGIN CERTIFICATE REQUEST-----\nexample.com/DE" {
		t.Errorf("csr = %q", csrResp.CSR)
	}
	if w := doJSON(t, s, "POST", "/api/ssl/csr", token, api.SSLCSRRequest{}); w.Code != 400 {
		t.Errorf("empty domain = %d", w.Code)
	}
	fake.csrErr = errors.New("unknown domain: nope.net")
	if w := doJSON(t, s, "POST", "/api/ssl/csr", token, api.SSLCSRRequest{Domain: "nope.net"}); w.Code != 400 {
		t.Errorf("provisioner error = %d", w.Code)
	}

	w = doJSON(t, s, "POST", "/api/ssl/install", token,
		api.SSLInstallRequest{Domain: "example.com", Cert: "CERTPEM", Chain: "CHAINPEM"})
	if w.Code != 204 {
		t.Fatalf("install = %d %s", w.Code, w.Body)
	}
	if len(fake.installed) != 1 || fake.installed[0].Chain != "CHAINPEM" {
		t.Errorf("installed = %+v", fake.installed)
	}
	if w := doJSON(t, s, "POST", "/api/ssl/install", token,
		api.SSLInstallRequest{Domain: "example.com"}); w.Code != 400 {
		t.Errorf("missing cert = %d", w.Code)
	}
	fake.instErr = errors.New("the certificate was not issued for this box's private key")
	w = doJSON(t, s, "POST", "/api/ssl/install", token,
		api.SSLInstallRequest{Domain: "example.com", Cert: "WRONG"})
	if w.Code != 400 || !strings.Contains(w.Body.String(), "private key") {
		t.Errorf("bad cert = %d %s", w.Code, w.Body)
	}
}
