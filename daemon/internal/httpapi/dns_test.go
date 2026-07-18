package httpapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	"naust/daemon/internal/api"
)

// The seeded admin@example.com plus PrimaryHostname box.example.com
// make example.com the single hosted zone (box.example.com folds in).

func TestDNSZones(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	w := doJSON(t, s, "GET", "/api/dns/zones", token, nil)
	if w.Code != 200 {
		t.Fatalf("zones status = %d, body %s", w.Code, w.Body)
	}
	var resp api.DNSZonesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Zones) != 1 || resp.Zones[0] != "example.com" {
		t.Errorf("zones = %v, want [example.com]", resp.Zones)
	}
}

func TestDNSRecordLifecycle(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	// Add two records for the same pair.
	for _, value := range []string{"1.2.3.4", "5.6.7.8"} {
		w := doJSON(t, s, "POST", "/api/dns/custom", token, api.CreateDNSRecordRequest{
			QName: "www.example.com", RType: "A", Value: value,
		})
		if w.Code != 201 {
			t.Fatalf("create %s status = %d, body %s", value, w.Code, w.Body)
		}
	}

	// Exact duplicate is a conflict.
	w := doJSON(t, s, "POST", "/api/dns/custom", token, api.CreateDNSRecordRequest{
		QName: "www.example.com", RType: "A", Value: "1.2.3.4",
	})
	if w.Code != 409 {
		t.Errorf("duplicate status = %d, want 409", w.Code)
	}

	// Both listed, in creation order, with the zone annotated.
	w = doJSON(t, s, "GET", "/api/dns/custom", token, nil)
	var list api.DNSRecordsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Records) != 2 || list.Records[0].Value != "1.2.3.4" || list.Records[1].Value != "5.6.7.8" {
		t.Fatalf("records = %+v", list.Records)
	}
	if list.Records[0].Zone != "example.com" {
		t.Errorf("zone = %q, want example.com", list.Records[0].Zone)
	}

	// PUT replaces the whole set (duplicates in the request collapse).
	w = doJSON(t, s, "PUT", "/api/dns/custom/www.example.com/A", token, api.ReplaceDNSRecordsRequest{
		Values: []string{"9.9.9.9", "9.9.9.9"},
	})
	if w.Code != 200 {
		t.Fatalf("replace status = %d, body %s", w.Code, w.Body)
	}
	w = doJSON(t, s, "GET", "/api/dns/custom", token, nil)
	list = api.DNSRecordsResponse{}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Records) != 1 || list.Records[0].Value != "9.9.9.9" {
		t.Fatalf("after replace: %+v", list.Records)
	}

	// Delete by exact value, then the pair is gone and 404s.
	w = doJSON(t, s, "DELETE", "/api/dns/custom/www.example.com/A?value="+url.QueryEscape("9.9.9.9"), token, nil)
	if w.Code != 204 {
		t.Fatalf("delete status = %d, body %s", w.Code, w.Body)
	}
	w = doJSON(t, s, "DELETE", "/api/dns/custom/www.example.com/A", token, nil)
	if w.Code != 404 {
		t.Errorf("delete empty pair status = %d, want 404", w.Code)
	}
}

func TestDNSRecordRejections(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	cases := []struct {
		name string
		req  api.CreateDNSRecordRequest
	}{
		{"foreign domain", api.CreateDNSRecordRequest{QName: "www.other.net", RType: "A", Value: "1.2.3.4"}},
		{"bad type", api.CreateDNSRecordRequest{QName: "www.example.com", RType: "PTR", Value: "x"}},
		{"ipv6 in A", api.CreateDNSRecordRequest{QName: "www.example.com", RType: "A", Value: "::1"}},
		{"NS at apex", api.CreateDNSRecordRequest{QName: "example.com", RType: "NS", Value: "ns.other.net"}},
		{"newline in TXT", api.CreateDNSRecordRequest{QName: "example.com", RType: "TXT", Value: "a\nb"}},
		{"bad name", api.CreateDNSRecordRequest{QName: "-bad.example.com", RType: "A", Value: "1.2.3.4"}},
	}
	for _, c := range cases {
		w := doJSON(t, s, "POST", "/api/dns/custom", token, c.req)
		if w.Code != 400 {
			t.Errorf("%s: status = %d, want 400 (body %s)", c.name, w.Code, w.Body)
		}
	}
}

func TestDNSRecordDynamicDNSDefaultsToClientIP(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	// httptest requests come from 192.0.2.1 (see httptest.NewRequest).
	w := doJSON(t, s, "POST", "/api/dns/custom", token, api.CreateDNSRecordRequest{
		QName: "home.example.com", RType: "A",
	})
	if w.Code != 201 {
		t.Fatalf("status = %d, body %s", w.Code, w.Body)
	}
	var rec api.DNSRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Value != "192.0.2.1" {
		t.Errorf("value = %q, want the client IP 192.0.2.1", rec.Value)
	}
}

func TestDNSRecordLocalSentinel(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	w := doJSON(t, s, "POST", "/api/dns/custom", token, api.CreateDNSRecordRequest{
		QName: "example.com", RType: "A", Value: "local",
	})
	if w.Code != 201 {
		t.Fatalf("status = %d, body %s", w.Code, w.Body)
	}
	var rec api.DNSRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Value != "local" {
		t.Errorf("value = %q, want the local sentinel stored verbatim", rec.Value)
	}
}

func TestDNSRecordIDNQNamePunycoded(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	w := doJSON(t, s, "POST", "/api/dns/custom", token, api.CreateDNSRecordRequest{
		QName: "bücher.example.com", RType: "A", Value: "1.2.3.4",
	})
	if w.Code != 201 {
		t.Fatalf("status = %d, body %s", w.Code, w.Body)
	}
	var rec api.DNSRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.QName != "xn--bcher-kva.example.com" {
		t.Errorf("qname = %q, want punycoded form", rec.QName)
	}

	// The Unicode spelling deletes the punycoded row.
	w = doJSON(t, s, "DELETE", "/api/dns/custom/"+url.PathEscape("bücher.example.com")+"/A", token, nil)
	if w.Code != 204 {
		t.Errorf("delete status = %d, body %s", w.Code, w.Body)
	}
}

func TestSecondaryNameservers(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	// Empty until set.
	w := doJSON(t, s, "GET", "/api/dns/secondary-nameserver", token, nil)
	var resp api.SecondaryNameservers
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Hostnames) != 0 {
		t.Errorf("initial hostnames = %v, want empty", resp.Hostnames)
	}

	// Invalid entry rejected.
	w = doJSON(t, s, "PUT", "/api/dns/secondary-nameserver", token, api.SecondaryNameservers{
		Hostnames: []string{"xfr:not-an-ip"},
	})
	if w.Code != 400 {
		t.Errorf("invalid entry status = %d, want 400", w.Code)
	}

	// Set, read back, then clear.
	want := []string{"ns2.other.net", "xfr:10.0.0.0/8"}
	w = doJSON(t, s, "PUT", "/api/dns/secondary-nameserver", token, api.SecondaryNameservers{Hostnames: want})
	if w.Code != 200 {
		t.Fatalf("set status = %d, body %s", w.Code, w.Body)
	}
	w = doJSON(t, s, "GET", "/api/dns/secondary-nameserver", token, nil)
	resp = api.SecondaryNameservers{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(resp.Hostnames) != fmt.Sprint(want) {
		t.Errorf("hostnames = %v, want %v", resp.Hostnames, want)
	}

	w = doJSON(t, s, "PUT", "/api/dns/secondary-nameserver", token, api.SecondaryNameservers{})
	if w.Code != 200 {
		t.Fatalf("clear status = %d, body %s", w.Code, w.Body)
	}
	w = doJSON(t, s, "GET", "/api/dns/secondary-nameserver", token, nil)
	resp = api.SecondaryNameservers{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Hostnames) != 0 {
		t.Errorf("after clear = %v, want empty", resp.Hostnames)
	}
}

func TestDNSMutationsFireDNSChangeHook(t *testing.T) {
	s, _ := newTestServer(t)
	fired := 0
	s.OnDNSDataChange = func() { fired++ }
	token := login(t, s).Token

	doJSON(t, s, "POST", "/api/dns/custom", token, api.CreateDNSRecordRequest{
		QName: "example.com", RType: "TXT", Value: "hello",
	})
	if fired != 1 {
		t.Errorf("after record create: fired = %d, want 1", fired)
	}

	// User mutations change domains, so they must fire it too.
	doJSON(t, s, "POST", "/api/users", token, api.CreateUserRequest{
		Email: "bob@newdomain.net", Password: testPassword,
	})
	if fired != 2 {
		t.Errorf("after user create: fired = %d, want 2", fired)
	}
}
