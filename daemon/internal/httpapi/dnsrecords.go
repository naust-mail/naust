package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"naust/daemon/internal/adminops"
	"naust/daemon/internal/api"
	"naust/daemon/internal/dns"
	"naust/daemon/internal/store/ent"
	entdnsrecord "naust/daemon/internal/store/ent/dnsrecord"
	entsetting "naust/daemon/internal/store/ent/setting"
)

// settingSecondaryNS holds the secondary-nameserver list as a JSON
// array of strings.
const settingSecondaryNS = "dns_secondary_nameservers"

// maxDNSValuesPerName caps how many values one qname/rtype may hold. The
// per-zone cap lives in adminops (adminops.MaxDNSRecordsPerZone), shared
// with the migration create path.
const maxDNSValuesPerName = 50

// dnsZones derives the zone apexes this box hosts. It delegates to adminops
// so the API and the migration path agree on what DNS this box owns.
func (s *Server) dnsZones(r *http.Request) ([]string, error) {
	return adminops.HostedZones(r.Context(), s.Store, s.PrimaryHostname)
}

// resolveDNSName normalizes a record name (including punycoding of
// internationalized labels) and checks it against the hosted zones; on
// failure it has already written the error response.
func (s *Server) resolveDNSName(w http.ResponseWriter, r *http.Request, qname string) (name, zone string, ok bool) {
	qname, nameErr := dns.NormalizeName(qname)
	if nameErr != nil {
		writeError(w, http.StatusBadRequest, "the name is not a valid domain name")
		return "", "", false
	}
	zones, err := s.dnsZones(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "zone lookup failed")
		return "", "", false
	}
	zone, found := dns.ZoneFor(qname, zones)
	if !found {
		writeError(w, http.StatusBadRequest, "that name is not a domain or subdomain managed by this box")
		return "", "", false
	}
	// Zone apexes already proved themselves; anything below must look
	// like a DNS name (single-label zones would fail this check).
	if qname != zone && !dns.ValidRecordName(qname) {
		writeError(w, http.StatusBadRequest, "the name is not valid; use letters, numbers, hyphens, and dots only")
		return "", "", false
	}
	return qname, zone, true
}

func parseRType(s string) (entdnsrecord.Rtype, error) {
	rtype := entdnsrecord.Rtype(strings.ToUpper(strings.TrimSpace(s)))
	return rtype, entdnsrecord.RtypeValidator(rtype)
}

func (s *Server) handleDNSZones(w http.ResponseWriter, r *http.Request) {
	zones, err := s.dnsZones(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "zone lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, api.DNSZonesResponse{Zones: zones})
}

func (s *Server) handleListDNSRecords(w http.ResponseWriter, r *http.Request) {
	records, err := adminops.ListDNSRecords(r.Context(), s.Store)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "record query failed")
		return
	}
	zones, err := s.dnsZones(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "zone lookup failed")
		return
	}
	resp := api.DNSRecordsResponse{Records: make([]api.DNSRecord, 0, len(records))}
	for _, rec := range records {
		// Zone is empty when the record's domain is no longer hosted
		// (its last user or alias was removed).
		zone, _ := dns.ZoneFor(rec.Qname, zones)
		resp.Records = append(resp.Records, api.DNSRecord{
			QName: rec.Qname,
			RType: string(rec.Rtype),
			Value: rec.Value,
			Zone:  zone,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCreateDNSRecord(w http.ResponseWriter, r *http.Request) {
	var req api.CreateDNSRecordRequest
	if !decodeBody(w, r, &req) {
		return
	}
	value := strings.TrimSpace(req.Value)
	// The dynamic-DNS idiom: an empty A/AAAA value means "my address". This
	// stays in the HTTP layer because it needs the request's client IP.
	if value == "" {
		if rt := strings.ToUpper(strings.TrimSpace(req.RType)); rt == "A" || rt == "AAAA" {
			value = clientIP(r)
		}
	}
	rec, zone, err := adminops.CreateDNSRecord(r.Context(), s.Store, s.TenantID, s.PrimaryHostname, req.QName, req.RType, value)
	if err != nil {
		writeDNSError(w, err)
		return
	}
	s.dnsDataChanged()
	writeJSON(w, http.StatusCreated, api.DNSRecord{
		QName: rec.Qname,
		RType: string(rec.Rtype),
		Value: rec.Value,
		Zone:  zone,
	})
}

// writeDNSError maps an adminops DNS error to its HTTP status.
func writeDNSError(w http.ResponseWriter, err error) {
	var ve *adminops.ValidationError
	switch {
	case errors.As(err, &ve):
		writeError(w, http.StatusBadRequest, ve.Error())
	case errors.Is(err, adminops.ErrZoneNotHosted):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, adminops.ErrDNSRecordExists):
		writeError(w, http.StatusConflict, "that record already exists")
	default:
		writeError(w, http.StatusInternalServerError, "record creation failed")
	}
}

func (s *Server) handleReplaceDNSRecords(w http.ResponseWriter, r *http.Request) {
	var req api.ReplaceDNSRecordsRequest
	if !decodeBody(w, r, &req) {
		return
	}
	rtype, err := parseRType(r.PathValue("rtype"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "unknown record type")
		return
	}
	qname, zone, ok := s.resolveDNSName(w, r, r.PathValue("qname"))
	if !ok {
		return
	}
	if len(req.Values) > maxDNSValuesPerName {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("at most %d values per record", maxDNSValuesPerName))
		return
	}
	values := make([]string, 0, len(req.Values))
	seen := map[string]bool{}
	for _, v := range req.Values {
		v, err := dns.ValidateValue(qname, zone, string(rtype), strings.TrimSpace(v))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !seen[v] {
			seen[v] = true
			values = append(values, v)
		}
	}

	zoneCount, err := s.Store.DNSRecord.Query().
		Where(entdnsrecord.Or(entdnsrecord.Qname(zone), entdnsrecord.QnameHasSuffix("."+zone))).
		Count(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "record count failed")
		return
	}
	existing, err := s.Store.DNSRecord.Query().
		Where(entdnsrecord.Qname(qname), entdnsrecord.RtypeEQ(rtype)).
		Count(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "record count failed")
		return
	}
	if zoneCount-existing+len(values) > adminops.MaxDNSRecordsPerZone {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("at most %d custom DNS records per zone", adminops.MaxDNSRecordsPerZone))
		return
	}

	tx, err := s.Store.Tx(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "record update failed")
		return
	}
	_, err = tx.DNSRecord.Delete().
		Where(entdnsrecord.Qname(qname), entdnsrecord.RtypeEQ(rtype)).
		Exec(r.Context())
	for _, v := range values {
		if err != nil {
			break
		}
		err = tx.DNSRecord.Create().SetQname(qname).SetRtype(rtype).SetValue(v).SetTenantID(s.TenantID).Exec(r.Context())
	}
	if err != nil {
		tx.Rollback()
		writeError(w, http.StatusInternalServerError, "record update failed")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "record update failed")
		return
	}
	s.dnsDataChanged()

	resp := api.DNSRecordsResponse{Records: make([]api.DNSRecord, 0, len(values))}
	for _, v := range values {
		resp.Records = append(resp.Records, api.DNSRecord{QName: qname, RType: string(rtype), Value: v, Zone: zone})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDeleteDNSRecords(w http.ResponseWriter, r *http.Request) {
	rtype, err := parseRType(r.PathValue("rtype"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "unknown record type")
		return
	}
	// No zone check on delete: records whose domain is no longer hosted
	// must remain deletable.
	qname, err := dns.NormalizeName(r.PathValue("qname"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "the name is not a valid domain name")
		return
	}

	del := s.Store.DNSRecord.Delete().
		Where(entdnsrecord.Qname(qname), entdnsrecord.RtypeEQ(rtype))
	// Optional ?value= narrows the delete to one exact record.
	if value := r.URL.Query().Get("value"); value != "" {
		del = del.Where(entdnsrecord.Value(value))
	}
	n, err := del.Exec(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "record deletion failed")
		return
	}
	if n == 0 {
		writeError(w, http.StatusNotFound, "no matching records")
		return
	}
	s.dnsDataChanged()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetSecondaryNS(w http.ResponseWriter, r *http.Request) {
	hostnames, err := s.secondaryNameservers(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "setting lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, api.SecondaryNameservers{Hostnames: hostnames})
}

func (s *Server) handleSetSecondaryNS(w http.ResponseWriter, r *http.Request) {
	var req api.SecondaryNameservers
	if !decodeBody(w, r, &req) {
		return
	}
	hostnames := make([]string, 0, len(req.Hostnames))
	for _, h := range req.Hostnames {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		h, err := dns.ValidateSecondaryNameserver(h)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		hostnames = append(hostnames, h)
	}
	encoded, err := json.Marshal(hostnames)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "setting update failed")
		return
	}
	err = s.Store.Setting.Create().
		SetKey(settingSecondaryNS).
		SetValue(string(encoded)).
		OnConflictColumns(entsetting.FieldKey).
		UpdateNewValues().
		Exec(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "setting update failed")
		return
	}
	s.dnsDataChanged()
	writeJSON(w, http.StatusOK, api.SecondaryNameservers{Hostnames: hostnames})
}

func (s *Server) secondaryNameservers(r *http.Request) ([]string, error) {
	row, err := s.Store.Setting.Query().
		Where(entsetting.Key(settingSecondaryNS)).
		Only(r.Context())
	if ent.IsNotFound(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var hostnames []string
	if err := json.Unmarshal([]byte(row.Value), &hostnames); err != nil {
		return nil, err
	}
	return hostnames, nil
}
