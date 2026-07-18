package httpapi

import (
	"context"
	"net/http"
	"time"

	"naust/daemon/internal/acmeprov"
	"naust/daemon/internal/api"
)

// CertProvisioner is the slice of *acmeprov.Provisioner the API uses:
// on-disk certificate state, the last run's results, the manual
// provisioning trigger, and the commercial-CA path (CSR + install).
type CertProvisioner interface {
	DomainStatuses(ctx context.Context) ([]acmeprov.DomainStatus, error)
	Status() ([]acmeprov.Result, time.Time)
	StartRun(domains []string)
	Busy() bool
	CSR(ctx context.Context, domain, countryCode string) (string, error)
	InstallManual(ctx context.Context, domain, certPEM, chainPEM string) error
}

func (s *Server) handleSSLStatus(w http.ResponseWriter, r *http.Request) {
	domains, err := s.Certs.DomainStatuses(r.Context())
	if err != nil {
		s.Log.Printf("ssl status: %v", err)
		writeError(w, http.StatusInternalServerError, "certificate scan failed")
		return
	}
	last, ranAt := s.Certs.Status()
	byDomain := map[string]acmeprov.Result{}
	resp := api.SSLStatusResponse{Running: s.Certs.Busy()}
	for _, res := range last {
		if res.Domain == "" {
			resp.LastError = res.Detail
			continue
		}
		byDomain[res.Domain] = res
	}
	if !ranAt.IsZero() {
		resp.LastRunAt = &ranAt
	}
	resp.Domains = make([]api.SSLDomainInfo, 0, len(domains))
	for _, d := range domains {
		info := api.SSLDomainInfo{Domain: d.Domain, Cert: string(d.Cert)}
		if !d.NotAfter.IsZero() {
			na := d.NotAfter
			info.NotAfter = &na
		}
		if res, ok := byDomain[d.Domain]; ok {
			info.LastStatus = string(res.Status)
			info.LastDetail = res.Detail
		}
		resp.Domains = append(resp.Domains, info)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSSLProvision(w http.ResponseWriter, r *http.Request) {
	var req api.SSLProvisionRequest
	if r.ContentLength != 0 && !decodeBody(w, r, &req) {
		return
	}
	if len(req.Domains) > 0 {
		domains, err := s.Certs.DomainStatuses(r.Context())
		if err != nil {
			s.Log.Printf("ssl provision: %v", err)
			writeError(w, http.StatusInternalServerError, "certificate scan failed")
			return
		}
		known := map[string]bool{}
		for _, d := range domains {
			known[d.Domain] = true
		}
		for _, d := range req.Domains {
			if !known[d] {
				writeError(w, http.StatusBadRequest, "not a hosted domain: "+d)
				return
			}
		}
	}
	s.Certs.StartRun(req.Domains)
	w.WriteHeader(http.StatusAccepted)
}

// handleSSLCSR and handleSSLInstall are the commercial-CA path. Every
// failure is reported to the caller: the inputs (domain, country
// code, pasted PEM) are all operator-supplied and correctable.
func (s *Server) handleSSLCSR(w http.ResponseWriter, r *http.Request) {
	var req api.SSLCSRRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	csr, err := s.Certs.CSR(r.Context(), req.Domain, req.CountryCode)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, api.SSLCSRResponse{CSR: csr})
}

func (s *Server) handleSSLInstall(w http.ResponseWriter, r *http.Request) {
	var req api.SSLInstallRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Domain == "" || req.Cert == "" {
		writeError(w, http.StatusBadRequest, "domain and cert are required")
		return
	}
	if err := s.Certs.InstallManual(r.Context(), req.Domain, req.Cert, req.Chain); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
