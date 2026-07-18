package httpapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"naust/daemon/internal/api"
	dnszone "naust/daemon/internal/dns"
)

func TestReboot(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token
	h := &fakeHelper{}
	s.Helper = h
	s.RebootRequiredPath = filepath.Join(t.TempDir(), "reboot-required")

	// No reboot pending: refused, helper untouched.
	if w := doJSON(t, s, "POST", "/api/system/reboot", token, nil); w.Code != 409 {
		t.Fatalf("not required = %d %s", w.Code, w.Body)
	}
	if len(h.calls) != 0 {
		t.Errorf("helper called: %v", h.calls)
	}

	if err := os.WriteFile(s.RebootRequiredPath, []byte("*** System restart required ***\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if w := doJSON(t, s, "POST", "/api/system/reboot", token, nil); w.Code != 202 {
		t.Fatalf("required = %d %s", w.Code, w.Body)
	}
	if len(h.calls) != 1 || h.calls[0] != "host.reboot" {
		t.Errorf("helper calls = %v", h.calls)
	}
	// Helper failure surfaces as an error.
	h.fail = true
	if w := doJSON(t, s, "POST", "/api/system/reboot", token, nil); w.Code != 500 {
		t.Errorf("helper failure = %d", w.Code)
	}

	if w := doJSON(t, s, "POST", "/api/system/reboot", "", nil); w.Code != 401 {
		t.Errorf("unauthenticated = %d", w.Code)
	}
}

func TestDNSExternal(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token
	s.Zones = func(context.Context) ([]dnszone.Zone, error) {
		return []dnszone.Zone{
			{Apex: "example.com", Records: []dnszone.ZoneRecord{
				{Name: "", Type: "NS", Value: "ns1.box.example.com.", Category: dnszone.CatInternal},
				{Name: "", Type: "A", Value: "203.0.113.5", Category: dnszone.CatRequired},
				{Name: "", Type: "MX", Value: "10 box.example.com.", Category: dnszone.CatRequired},
				{Name: "www", Type: "A", Value: "203.0.113.5", Category: dnszone.CatOptional},
			}},
			{Apex: "internal-only.net", Records: []dnszone.ZoneRecord{
				{Name: "", Type: "NS", Value: "ns1.box.example.com.", Category: dnszone.CatInternal},
			}},
		}, nil
	}

	w := doJSON(t, s, "GET", "/api/dns/external", token, nil)
	if w.Code != 200 {
		t.Fatalf("GET = %d %s", w.Code, w.Body)
	}
	var resp api.ExternalDNSResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	// The internal-only zone vanishes; internal records are filtered.
	if len(resp.Zones) != 1 || resp.Zones[0].Zone != "example.com" {
		t.Fatalf("zones = %+v", resp.Zones)
	}
	recs := resp.Zones[0].Records
	if len(recs) != 3 {
		t.Fatalf("records = %+v", recs)
	}
	if recs[0].QName != "example.com" || recs[0].Type != "A" || recs[0].Category != "required" {
		t.Errorf("first = %+v", recs[0])
	}
	if recs[2].QName != "www.example.com" || recs[2].Category != "optional" {
		t.Errorf("www = %+v", recs[2])
	}

	if w := doJSON(t, s, "GET", "/api/dns/external", "", nil); w.Code != 401 {
		t.Errorf("unauthenticated = %d", w.Code)
	}
}
