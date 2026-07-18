package checks

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func runRoutingCheck(t *testing.T, files map[string]string) Result {
	t.Helper()
	d := &Deps{
		PrimaryHostname: "box.example.com",
		MapsDir:         "/maps",
		ReadFile: func(name string) ([]byte, error) {
			if content, ok := files[name]; ok {
				return []byte(content), nil
			}
			return nil, errors.New("not found")
		},
	}
	r := &Reporter{now: time.Now}
	checkSystemMailRouting(context.Background(), d, "", r)
	status, message := summarize(r.steps)
	return Result{Status: status, Message: message, Steps: r.steps}
}

func TestSystemMailRoutingCheck(t *testing.T) {
	mapPath := "/maps/virtual-alias-maps"

	// Healthy: the synthetic route is present.
	res := runRoutingCheck(t, map[string]string{
		mapPath: "postmaster@box.example.com ann@example.com\nroot@box.example.com ann@example.com\n",
	})
	if res.Status != StatusOK {
		t.Fatalf("healthy map: status = %s (%s)", res.Status, res.Message)
	}

	// Rendered but the operator route is missing: stale render.
	res = runRoutingCheck(t, map[string]string{mapPath: "someone@else.com x@y.z\n"})
	if res.Status != StatusError || !strings.Contains(res.Message, "root@box.example.com") {
		t.Fatalf("missing route: status = %s (%s)", res.Status, res.Message)
	}

	// File missing entirely: materializer never produced it.
	res = runRoutingCheck(t, map[string]string{})
	if res.Status != StatusError || !strings.Contains(res.Message, "missing") {
		t.Fatalf("missing file: status = %s (%s)", res.Status, res.Message)
	}
	// The second step must skip, not double-fail.
	if len(res.Steps) != 2 || res.Steps[1].Status != StatusSkipped {
		t.Fatalf("steps = %+v", res.Steps)
	}
}
