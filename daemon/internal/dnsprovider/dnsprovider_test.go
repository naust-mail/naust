package dnsprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeCloudflare is enough of the Cloudflare v4 API for the client:
// zone lookup, TXT create, filtered list, delete.
type fakeCloudflare struct {
	t  *testing.T
	mu sync.Mutex
	// records: record id -> "name\x00content"
	records map[string]string
	nextID  int
	created []string // names seen by create, in order
}

func newFakeCloudflare(t *testing.T) (*fakeCloudflare, *httptest.Server) {
	f := &fakeCloudflare{t: t, records: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeCloudflare) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer cf-token" {
		f.t.Errorf("cloudflare auth header = %q", r.Header.Get("Authorization"))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/zones":
		if r.URL.Query().Get("name") != "example.com" {
			json.NewEncoder(w).Encode(map[string]any{"result": []any{}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"result": []map[string]string{{"id": "z1"}}})
	case r.URL.Path == "/zones/z1/dns_records" && r.Method == http.MethodPost:
		var body struct {
			Type, Name, Content string
			TTL                 int
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Type != "TXT" {
			f.t.Errorf("create type = %s", body.Type)
		}
		f.nextID++
		f.records[fmt.Sprintf("r%d", f.nextID)] = body.Name + "\x00" + body.Content
		f.created = append(f.created, body.Name)
		json.NewEncoder(w).Encode(map[string]any{"result": map[string]string{}})
	case r.URL.Path == "/zones/z1/dns_records" && r.Method == http.MethodGet:
		q := r.URL.Query()
		var result []map[string]string
		for id, rec := range f.records {
			name, content, _ := strings.Cut(rec, "\x00")
			if name == q.Get("name") && content == q.Get("content") {
				result = append(result, map[string]string{"id": id})
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"result": result})
	case strings.HasPrefix(r.URL.Path, "/zones/z1/dns_records/") && r.Method == http.MethodDelete:
		delete(f.records, strings.TrimPrefix(r.URL.Path, "/zones/z1/dns_records/"))
		json.NewEncoder(w).Encode(map[string]any{"result": map[string]string{}})
	default:
		f.t.Errorf("unexpected cloudflare call %s %s", r.Method, r.URL)
		http.NotFound(w, r)
	}
}

func (f *fakeCloudflare) has(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rec := range f.records {
		if strings.HasPrefix(rec, name+"\x00") {
			return true
		}
	}
	return false
}

func (f *fakeCloudflare) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.records)
}

func TestCloudflareClient(t *testing.T) {
	f, srv := newFakeCloudflare(t)
	cf := &Cloudflare{Token: "cf-token", HTTP: srv.Client(), BaseURL: srv.URL}
	ctx := context.Background()
	if err := cf.SetTXT(ctx, "example.com", "_acme-challenge.mail.example.com", "val"); err != nil {
		t.Fatal(err)
	}
	if !f.has("_acme-challenge.mail.example.com") {
		t.Error("record not created")
	}
	if err := cf.DeleteTXT(ctx, "example.com", "_acme-challenge.mail.example.com", "val"); err != nil {
		t.Fatal(err)
	}
	if f.count() != 0 {
		t.Errorf("records remain after delete: %d", f.count())
	}
	if err := cf.SetTXT(ctx, "other.net", "_acme-challenge.other.net", "val"); err == nil {
		t.Error("unknown zone accepted")
	}
}

func TestDigitalOceanClient(t *testing.T) {
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer do-token" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/domains/example.com/records":
			var body struct {
				Type, Name, Data string
				TTL              int
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.Type != "TXT" || body.Name != "_acme-challenge.mail" || body.Data != "val" || body.TTL != 30 {
				t.Errorf("create body = %+v", body)
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{}`)
		case r.Method == http.MethodGet && r.URL.Path == "/domains/example.com/records":
			if r.URL.Query().Get("name") != "_acme-challenge.mail.example.com" {
				t.Errorf("list name = %s", r.URL.Query().Get("name"))
			}
			fmt.Fprint(w, `{"domain_records":[{"id":11,"data":"other"},{"id":22,"data":"val"}]}`)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/domains/example.com/records/"):
			deleted = append(deleted, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected call %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	do := &DigitalOcean{Token: "do-token", HTTP: srv.Client(), BaseURL: srv.URL}
	ctx := context.Background()
	if err := do.SetTXT(ctx, "example.com", "_acme-challenge.mail.example.com", "val"); err != nil {
		t.Fatal(err)
	}
	if err := do.DeleteTXT(ctx, "example.com", "_acme-challenge.mail.example.com", "val"); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0] != "/domains/example.com/records/22" {
		t.Errorf("deleted = %v", deleted)
	}
}

func TestHetznerClient(t *testing.T) {
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Auth-API-Token") != "hz-token" {
			t.Errorf("auth = %q", r.Header.Get("Auth-API-Token"))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones":
			fmt.Fprint(w, `{"zones":[{"id":"hz1"}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/records":
			var body struct {
				ZoneID string `json:"zone_id"`
				Type   string
				Name   string
				Value  string
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.ZoneID != "hz1" || body.Type != "TXT" || body.Name != "_acme-challenge.mail" || body.Value != "val" {
				t.Errorf("create body = %+v", body)
			}
			fmt.Fprint(w, `{}`)
		case r.Method == http.MethodGet && r.URL.Path == "/records":
			fmt.Fprint(w, `{"records":[
				{"id":"a","type":"TXT","name":"_acme-challenge.mail","value":"other"},
				{"id":"b","type":"TXT","name":"_acme-challenge.mail","value":"val"},
				{"id":"c","type":"A","name":"mail","value":"val"}]}`)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/records/"):
			deleted = append(deleted, r.URL.Path)
			fmt.Fprint(w, `{}`)
		default:
			t.Errorf("unexpected call %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	hz := &Hetzner{Token: "hz-token", HTTP: srv.Client(), BaseURL: srv.URL}
	ctx := context.Background()
	if err := hz.SetTXT(ctx, "example.com", "_acme-challenge.mail.example.com", "val"); err != nil {
		t.Fatal(err)
	}
	if err := hz.DeleteTXT(ctx, "example.com", "_acme-challenge.mail.example.com", "val"); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0] != "/records/b" {
		t.Errorf("deleted = %v", deleted)
	}
}

func TestRelativeName(t *testing.T) {
	cases := []struct{ fqdn, zone, want string }{
		{"_acme-challenge.mail.example.com", "example.com", "_acme-challenge.mail"},
		{"_acme-challenge.example.com", "example.com", "_acme-challenge"},
		{"example.com", "example.com", "@"},
	}
	for _, tc := range cases {
		if got := relativeName(tc.fqdn, tc.zone); got != tc.want {
			t.Errorf("relativeName(%s, %s) = %s, want %s", tc.fqdn, tc.zone, got, tc.want)
		}
	}
}

func TestProviderRegistry(t *testing.T) {
	want := []string{"cloudflare", "digitalocean", "hetzner"}
	got := Names()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Names() = %v", got)
	}
	if _, err := New("nope", "t", nil); err == nil {
		t.Error("unknown provider accepted")
	}
}
