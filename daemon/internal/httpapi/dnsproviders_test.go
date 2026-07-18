package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"naust/daemon/internal/api"
)

func getProviders(t *testing.T, s *Server, token string) api.DNSProvidersResponse {
	t.Helper()
	w := doJSON(t, s, "GET", "/api/dns/providers", token, nil)
	if w.Code != 200 {
		t.Fatalf("GET providers = %d %s", w.Code, w.Body)
	}
	var resp api.DNSProvidersResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestDNSProviders(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token
	kicks := 0
	s.OnCertConfigChange = func() { kicks++ }

	resp := getProviders(t, s, token)
	if strings.Join(resp.Available, ",") != "cloudflare,digitalocean,hetzner" {
		t.Errorf("available = %v", resp.Available)
	}
	if len(resp.Zones) != 0 {
		t.Errorf("zones = %v", resp.Zones)
	}

	// Configure, read back (credential never echoed), upsert.
	w := doJSON(t, s, "PUT", "/api/dns/providers/example.com", token,
		api.DNSZoneProviderSetRequest{Provider: "cloudflare", Token: "secret-cf-token"})
	if w.Code != 204 {
		t.Fatalf("PUT = %d %s", w.Code, w.Body)
	}
	if kicks != 1 {
		t.Errorf("kicks = %d", kicks)
	}
	w = doJSON(t, s, "GET", "/api/dns/providers", token, nil)
	if strings.Contains(w.Body.String(), "secret-cf-token") {
		t.Error("credential echoed in list response")
	}
	resp = getProviders(t, s, token)
	if len(resp.Zones) != 1 || resp.Zones[0].Zone != "example.com" || resp.Zones[0].Provider != "cloudflare" {
		t.Errorf("zones = %v", resp.Zones)
	}
	w = doJSON(t, s, "PUT", "/api/dns/providers/example.com", token,
		api.DNSZoneProviderSetRequest{Provider: "digitalocean", Token: "do-token"})
	if w.Code != 204 {
		t.Fatalf("upsert PUT = %d %s", w.Code, w.Body)
	}
	if resp = getProviders(t, s, token); len(resp.Zones) != 1 || resp.Zones[0].Provider != "digitalocean" {
		t.Errorf("after upsert zones = %v", resp.Zones)
	}

	// Validation.
	bad := []api.DNSZoneProviderSetRequest{
		{Provider: "route53", Token: "x"},
		{Provider: "cloudflare", Token: ""},
		{Provider: "cloudflare", Token: "has space"},
	}
	for _, req := range bad {
		if w := doJSON(t, s, "PUT", "/api/dns/providers/example.com", token, req); w.Code != 400 {
			t.Errorf("bad request %+v = %d", req, w.Code)
		}
	}
	if w := doJSON(t, s, "PUT", "/api/dns/providers/not%20a%20domain", token,
		api.DNSZoneProviderSetRequest{Provider: "cloudflare", Token: "x"}); w.Code != 400 {
		t.Errorf("bad zone = %d", w.Code)
	}

	// Delete, then delete again.
	if w := doJSON(t, s, "DELETE", "/api/dns/providers/example.com", token, nil); w.Code != 204 {
		t.Errorf("DELETE = %d %s", w.Code, w.Body)
	}
	if w := doJSON(t, s, "DELETE", "/api/dns/providers/example.com", token, nil); w.Code != 404 {
		t.Errorf("second DELETE = %d", w.Code)
	}

	// Admin-only.
	if w := doJSON(t, s, "GET", "/api/dns/providers", "", nil); w.Code != 401 {
		t.Errorf("unauthenticated GET = %d", w.Code)
	}
}
