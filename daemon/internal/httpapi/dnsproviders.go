package httpapi

// Per-zone DNS provider configuration: which external DNS host
// (Cloudflare, DigitalOcean, Hetzner) serves a zone's public DNS, so
// certificate provisioning can fulfill DNS-01 challenges through the
// provider's API for domains that do not point at this box. Zones
// with no row keep the default HTTP-01 behavior.

import (
	"encoding/json"
	"net/http"
	"slices"
	"sort"
	"unicode"

	"naust/daemon/internal/api"
	"naust/daemon/internal/dnsprovider"
	"naust/daemon/internal/store/ent"
	entdnszoneprovider "naust/daemon/internal/store/ent/dnszoneprovider"
)

const maxProviderTokenLen = 512

func (s *Server) handleDNSProvidersList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.DNSZoneProvider.Query().All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing providers failed")
		return
	}
	resp := api.DNSProvidersResponse{Available: dnsprovider.Names()}
	for _, row := range rows {
		resp.Zones = append(resp.Zones, api.DNSZoneProviderInfo{Zone: row.Zone, Provider: row.Provider})
	}
	sort.Slice(resp.Zones, func(i, j int) bool { return resp.Zones[i].Zone < resp.Zones[j].Zone })
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDNSProviderSet(w http.ResponseWriter, r *http.Request) {
	zone, err := normalizeDomain(r.PathValue("zone"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req api.DNSZoneProviderSetRequest
	body := http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if !slices.Contains(dnsprovider.Names(), req.Provider) {
		writeError(w, http.StatusBadRequest, "unknown provider")
		return
	}
	if req.Token == "" || len(req.Token) > maxProviderTokenLen {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	for _, r := range req.Token {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			writeError(w, http.StatusBadRequest, "token contains whitespace or control characters")
			return
		}
	}

	if err := s.Store.DNSZoneProvider.Create().
		SetZone(zone).
		SetProvider(req.Provider).
		SetToken(req.Token).
		SetTenantID(s.TenantID).
		OnConflictColumns(entdnszoneprovider.FieldZone).
		Update(func(u *ent.DNSZoneProviderUpsert) {
			u.SetProvider(req.Provider)
			u.SetToken(req.Token)
		}).
		Exec(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "saving provider failed")
		return
	}
	// A newly usable provider usually means "go get my certificates
	// now", not tomorrow.
	if s.OnCertConfigChange != nil {
		s.OnCertConfigChange()
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDNSProviderDelete(w http.ResponseWriter, r *http.Request) {
	zone, err := normalizeDomain(r.PathValue("zone"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	n, err := s.Store.DNSZoneProvider.Delete().
		Where(entdnszoneprovider.Zone(zone)).
		Exec(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "deleting provider failed")
		return
	}
	if n == 0 {
		writeError(w, http.StatusNotFound, "no provider configured for zone")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
