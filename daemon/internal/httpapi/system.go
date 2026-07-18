package httpapi

import (
	"net/http"
	"os"

	"naust/daemon/internal/api"
	dnszone "naust/daemon/internal/dns"
)

// handleReboot reboots the box through the helper. Whether a reboot
// is needed is a status-check fact (the software-updates check); this
// endpoint re-verifies it server-side so a remote caller cannot
// reboot a box that has no reason to go down.
func (s *Server) handleReboot(w http.ResponseWriter, r *http.Request) {
	path := s.RebootRequiredPath
	if path == "" {
		path = "/var/run/reboot-required"
	}
	if _, err := os.Stat(path); err != nil {
		writeError(w, http.StatusConflict, "no reboot is required")
		return
	}
	if _, err := s.Helper.Call(r.Context(), "host.reboot", nil); err != nil {
		s.Log.Printf("reboot: %v", err)
		writeError(w, http.StatusInternalServerError, "reboot failed")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// handleDNSExternal returns the full desired record set for operators
// hosting DNS outside this box: exactly what the box would serve
// itself, minus the records that only matter when it does (ns1/ns2
// bookkeeping). The same zone build feeds the applier and the
// dns-zone status check, so this view can never drift from either.
func (s *Server) handleDNSExternal(w http.ResponseWriter, r *http.Request) {
	zones, err := s.Zones(r.Context())
	if err != nil {
		s.Log.Printf("dns external: %v", err)
		writeError(w, http.StatusInternalServerError, "zone build failed")
		return
	}
	resp := api.ExternalDNSResponse{Zones: []api.ExternalDNSZone{}}
	for _, z := range zones {
		zone := api.ExternalDNSZone{Zone: z.Apex, Records: []api.ExternalDNSRecord{}}
		for _, rec := range z.Records {
			if rec.Category == dnszone.CatInternal {
				continue
			}
			qname := z.Apex
			if rec.Name != "" {
				qname = rec.Name + "." + z.Apex
			}
			zone.Records = append(zone.Records, api.ExternalDNSRecord{
				QName: qname, Type: rec.Type, Value: rec.Value, Category: string(rec.Category),
			})
		}
		if len(zone.Records) > 0 {
			resp.Zones = append(resp.Zones, zone)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
