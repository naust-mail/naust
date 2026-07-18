package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"naust/daemon/internal/registry"
)

// healthSpec deep-checks one registry service over HTTP, beyond the
// TCP probe: the backend answers like a healthy instance of itself.
type healthSpec struct {
	Path string
	// Validate inspects the response; nil accepts any status < 500.
	Validate func(status int, body []byte) error
}

func jsonStatus(want string) func(int, []byte) error {
	return func(status int, body []byte) error {
		var v struct {
			Status string `json:"status"`
		}
		if status != http.StatusOK {
			return fmt.Errorf("HTTP %d", status)
		}
		if err := json.Unmarshal(body, &v); err != nil || v.Status != want {
			return fmt.Errorf("unexpected health response %q", firstBytes(body, 80))
		}
		return nil
	}
}

func firstBytes(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		s = s[:n]
	}
	return s
}

// healthSpecs keys registry service names to their health endpoints.
// Services without an entry get "/" with the default validator.
var healthSpecs = map[string]healthSpec{
	"webmail-rav": {Path: "/api/health", Validate: jsonStatus("ok")},
	"filebrowser": {Path: "/files/health", Validate: jsonStatus("OK")},
}

func httpChecks() []Check {
	var checks []Check
	for _, svc := range registry.All() {
		if svc.Port == 0 || svc.Name == "admin" {
			continue
		}
		svc := svc
		checks = append(checks, Check{
			Name:        "backend:" + svc.Name,
			Title:       svc.Name + " health",
			Description: "Confirms this optional web app answers an HTTP health request like a healthy copy of itself, going beyond a simple open-port check. If it fails, that app's web interface is broken even when its port is open.",
			Category:    "services", Locus: LocusNode, Tier: TierFast,
			Enabled: func(d *Deps) bool { return svc.Enabled(d.conf) },
			Run: func(ctx context.Context, d *Deps, _ string, r *Reporter) {
				checkBackend(ctx, d, svc, r)
			},
		})
	}
	return checks
}

func checkBackend(ctx context.Context, d *Deps, svc registry.Service, r *Reporter) {
	host := "127.0.0.1"
	if svc.HostEnv != "" {
		host = d.flag(svc.HostEnv, "127.0.0.1")
	}
	spec, ok := healthSpecs[svc.Name]
	if !ok {
		spec = healthSpec{Path: "/"}
	}
	var resp *http.Response
	var body []byte
	r.Step(svc.Name+" responds to HTTP requests", func(s *StepCtx) {
		url := fmt.Sprintf("http://%s:%d%s", host, svc.Port, spec.Path)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			s.Failf("%v", err)
			return
		}
		resp, err = d.HTTP.Do(req)
		if err != nil {
			s.Failf("%s is not responding to requests: %v", svc.Name, err)
			s.Hint("service.restart " + svc.Name)
			return
		}
		defer resp.Body.Close()
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 4096))
		s.Passf("%s responded with HTTP %d.", svc.Name, resp.StatusCode)
	})
	r.Step(svc.Name+" reports itself healthy", func(s *StepCtx) {
		if resp == nil {
			s.Skipf("no HTTP response to inspect")
			return
		}
		if spec.Validate != nil {
			if err := spec.Validate(resp.StatusCode, body); err != nil {
				s.Failf("%s health check failed: %v", svc.Name, err)
				s.Hint("service.restart " + svc.Name)
				return
			}
			s.Passf("%s's health endpoint reports it healthy.", svc.Name)
			return
		}
		// No health endpoint for this app: any sensible answer proves it
		// serves HTTP. 401/403 count as healthy (an auth-gated app is
		// alive and enforcing); 404 or a server error does not.
		switch {
		case resp.StatusCode < 400,
			resp.StatusCode == http.StatusUnauthorized,
			resp.StatusCode == http.StatusForbidden:
			s.Passf("%s is responding via HTTP.", svc.Name)
		default:
			s.Failf("%s returned HTTP %d.", svc.Name, resp.StatusCode)
			s.Hint("service.restart " + svc.Name)
		}
	})
}
