package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"naust/daemon/internal/api"
	"naust/daemon/internal/checks"
)

type fakeChecks struct {
	requests []checks.RunRequest
	busy     bool
}

func (f *fakeChecks) RunNow(req checks.RunRequest) { f.requests = append(f.requests, req) }
func (f *fakeChecks) Busy() bool                   { return f.busy }

func TestChecksStatus(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token
	s.Checks = &fakeChecks{busy: true}

	ranAt := time.Date(2026, 7, 8, 11, 0, 0, 0, time.UTC)
	failedAt := ranAt.Add(-48 * time.Hour)
	steps := `[{"name":"probe","status":"error","message":"down","expected":"up","observed":"down","fix_hint":"service.restart x","elapsed_ms":12}]`
	s.Store.CheckResult.Create().
		SetCheck("service:smtp").SetCategory("services").SetStatus("error").
		SetMessage("down").SetSteps(steps).SetRanAt(ranAt).SetElapsedMs(12).
		SetFirstFailedAt(failedAt).
		SaveX(context.Background())
	s.Store.CheckResult.Create().
		SetCheck("free-memory").SetCategory("system").SetStatus("ok").
		SetSteps("[]").SetRanAt(ranAt).
		SaveX(context.Background())

	if w := doJSON(t, s, "GET", "/api/system/checks", "", nil); w.Code != 401 {
		t.Errorf("unauthenticated = %d", w.Code)
	}
	w := doJSON(t, s, "GET", "/api/system/checks", token, nil)
	if w.Code != 200 {
		t.Fatalf("GET = %d %s", w.Code, w.Body)
	}
	var resp api.ChecksStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Running || len(resp.Results) != 2 {
		t.Fatalf("running=%v results=%d", resp.Running, len(resp.Results))
	}
	smtp := resp.Results[0]
	if smtp.Check != "service:smtp" || smtp.Status != "error" ||
		smtp.FirstFailedAt == nil || !smtp.FirstFailedAt.Equal(failedAt) {
		t.Errorf("smtp = %+v", smtp)
	}
	if len(smtp.Steps) != 1 || smtp.Steps[0].FixHint != "service.restart x" || smtp.Steps[0].Observed != "down" {
		t.Errorf("steps = %+v", smtp.Steps)
	}
	if mem := resp.Results[1]; mem.FirstFailedAt != nil || len(mem.Steps) != 0 {
		t.Errorf("memory = %+v", mem)
	}
}

func TestChecksRun(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token
	fake := &fakeChecks{}
	s.Checks = fake

	if w := doJSON(t, s, "POST", "/api/system/checks/run", token, nil); w.Code != 202 {
		t.Fatalf("empty run = %d %s", w.Code, w.Body)
	}
	if len(fake.requests) != 1 || len(fake.requests[0].Checks) != 0 {
		t.Errorf("requests = %+v", fake.requests)
	}

	w := doJSON(t, s, "POST", "/api/system/checks/run", token,
		api.ChecksRunRequest{Checks: []string{"free-memory"}, Domain: "example.com"})
	if w.Code != 202 {
		t.Fatalf("scoped run = %d %s", w.Code, w.Body)
	}
	if len(fake.requests) != 2 || fake.requests[1].Checks[0] != "free-memory" || fake.requests[1].Domain != "example.com" {
		t.Errorf("requests = %+v", fake.requests)
	}

	for _, bad := range []api.ChecksRunRequest{
		{Checks: []string{"no-such-check"}},
		{Category: "no-such-category"},
	} {
		if w := doJSON(t, s, "POST", "/api/system/checks/run", token, bad); w.Code != 400 {
			t.Errorf("bad request %+v = %d", bad, w.Code)
		}
	}
	if len(fake.requests) != 2 {
		t.Errorf("rejected request still ran: %+v", fake.requests)
	}
}

func TestChecksConfig(t *testing.T) {
	s, _ := newTestServer(t)
	token := login(t, s).Token
	s.Checks = &fakeChecks{}

	w := doJSON(t, s, "GET", "/api/system/checks/config", token, nil)
	if w.Code != 200 {
		t.Fatalf("GET config = %d %s", w.Code, w.Body)
	}
	var resp api.ChecksConfigResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Available) == 0 || len(resp.Config.Checks) != 0 {
		t.Fatalf("fresh config = %+v (available %d)", resp.Config, len(resp.Available))
	}
	if !strings.Contains(w.Body.String(), `"free-memory"`) {
		t.Error("catalog missing free-memory")
	}

	off := false
	put := api.ChecksConfig{
		Checks: map[string]api.CheckOverrideConfig{
			"software-updates": {Cadence: "weekly"},
			"ufw":              {Enabled: &off},
		},
		Report: "weekly",
	}
	w = doJSON(t, s, "PUT", "/api/system/checks/config", token, put)
	if w.Code != 200 {
		t.Fatalf("PUT = %d %s", w.Code, w.Body)
	}
	resp = api.ChecksConfigResponse{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Config.Report != "weekly" || resp.Config.Checks["software-updates"].Cadence != "weekly" ||
		resp.Config.Checks["ufw"].Enabled == nil || *resp.Config.Checks["ufw"].Enabled {
		t.Errorf("round-trip = %+v", resp.Config)
	}

	// Reads back from the store.
	w = doJSON(t, s, "GET", "/api/system/checks/config", token, nil)
	if !strings.Contains(w.Body.String(), `"report":"weekly"`) {
		t.Errorf("persisted config = %s", w.Body)
	}

	// Validation.
	for _, bad := range []api.ChecksConfig{
		{Checks: map[string]api.CheckOverrideConfig{"x": {Cadence: "sometimes"}}},
		{Report: "hourly"},
	} {
		if w := doJSON(t, s, "PUT", "/api/system/checks/config", token, bad); w.Code != 400 {
			t.Errorf("bad config %+v = %d", bad, w.Code)
		}
	}
}
