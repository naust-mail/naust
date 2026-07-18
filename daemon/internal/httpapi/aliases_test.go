package httpapi

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"naust/daemon/internal/api"
)

func TestAliasUpsertListDelete(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	// Create.
	w := doJSON(t, s, "POST", "/api/aliases", token, api.UpsertAliasRequest{
		Source:       "sales@example.com",
		Destinations: []string{"bob@example.com", "Carol@Elsewhere.NET"},
	})
	if w.Code != 200 {
		t.Fatalf("upsert status = %d, body %s", w.Code, w.Body)
	}

	// Upsert same source replaces, does not duplicate.
	w = doJSON(t, s, "POST", "/api/aliases", token, api.UpsertAliasRequest{
		Source:           "sales@example.com",
		Destinations:     []string{"dave@example.com"},
		PermittedSenders: []string{"bob@example.com"},
	})
	if w.Code != 200 {
		t.Fatalf("re-upsert status = %d, body %s", w.Code, w.Body)
	}

	w = doJSON(t, s, "GET", "/api/aliases", token, nil)
	var list api.AliasesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Aliases) != 1 {
		t.Fatalf("aliases = %+v", list.Aliases)
	}
	a := list.Aliases[0]
	if len(a.Destinations) != 1 || a.Destinations[0] != "dave@example.com" || len(a.PermittedSenders) != 1 || a.Auto {
		t.Errorf("alias after re-upsert = %+v", a)
	}

	// Delete (source contains @ - must survive URL path encoding).
	path := "/api/aliases/" + url.PathEscape("sales@example.com")
	if w = doJSON(t, s, "DELETE", path, token, nil); w.Code != 204 {
		t.Fatalf("delete status = %d, body %s", w.Code, w.Body)
	}
	if w = doJSON(t, s, "DELETE", path, token, nil); w.Code != 404 {
		t.Errorf("re-delete status = %d, want 404", w.Code)
	}
}

func TestAliasIDNDomainPunycoded(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	w := doJSON(t, s, "POST", "/api/aliases", token, api.UpsertAliasRequest{
		Source:       "info@bücher.example",
		Destinations: []string{"bob@münchen.example"},
	})
	if w.Code != 200 {
		t.Fatalf("upsert status = %d, body %s", w.Code, w.Body)
	}
	var a api.Alias
	if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	if a.Source != "info@xn--bcher-kva.example" {
		t.Errorf("source = %q, want punycoded domain", a.Source)
	}
	if len(a.Destinations) != 1 || a.Destinations[0] != "bob@xn--mnchen-3ya.example" {
		t.Errorf("destinations = %v, want punycoded domain", a.Destinations)
	}

	// The Unicode spelling deletes the punycoded row.
	w = doJSON(t, s, "DELETE", "/api/aliases/"+url.PathEscape("info@bücher.example"), token, nil)
	if w.Code != 204 {
		t.Errorf("delete status = %d, body %s", w.Code, w.Body)
	}
}

func TestCatchAllAliasAccepted(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	w := doJSON(t, s, "POST", "/api/aliases", token, api.UpsertAliasRequest{
		Source:       "@example.com",
		Destinations: []string{"admin@example.com"},
	})
	if w.Code != 200 {
		t.Errorf("catch-all upsert status = %d, body %s", w.Code, w.Body)
	}
}

func TestAliasRejections(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	for name, req := range map[string]api.UpsertAliasRequest{
		"no destinations":   {Source: "x@example.com"},
		"bad source":        {Source: "not-an-address", Destinations: []string{"a@example.com"}},
		"bad destination":   {Source: "x@example.com", Destinations: []string{"nope"}},
		"newline injection": {Source: "x@example.com", Destinations: []string{"a@example.com\nb@evil.com"}},
		"bad sender":        {Source: "x@example.com", Destinations: []string{"a@example.com"}, PermittedSenders: []string{"bad sender"}},
	} {
		if w := doJSON(t, s, "POST", "/api/aliases", token, req); w.Code != 400 {
			t.Errorf("%s: status = %d, want 400", name, w.Code)
		}
	}
}

func TestAutoAliasProtectedFromDeleteButOverridable(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token

	s.Store.Alias.Create().
		SetSource("postmaster@example.com").
		SetDestinations([]string{"admin@example.com"}).
		SetAuto(true).
		SetTenantID(s.TenantID).
		SaveX(context.Background())

	path := "/api/aliases/" + "postmaster@example.com"
	if w := doJSON(t, s, "DELETE", path, token, nil); w.Code != 400 {
		t.Errorf("delete auto alias: status = %d, want 400", w.Code)
	}

	// Overriding converts it to a manual alias, which is then deletable.
	w := doJSON(t, s, "POST", "/api/aliases", token, api.UpsertAliasRequest{
		Source:       "postmaster@example.com",
		Destinations: []string{"other@example.com"},
	})
	if w.Code != 200 {
		t.Fatalf("override status = %d, body %s", w.Code, w.Body)
	}
	var a api.Alias
	json.Unmarshal(w.Body.Bytes(), &a)
	if a.Auto {
		t.Error("override did not clear auto flag")
	}
	if w = doJSON(t, s, "DELETE", path, token, nil); w.Code != 204 {
		t.Errorf("delete overridden alias: status = %d, want 204", w.Code)
	}
}
