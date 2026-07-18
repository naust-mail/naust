package web

import (
	"context"
	"testing"

	"naust/daemon/internal/helper"
)

type okRunner struct{ calls [][]string }

func (r *okRunner) Run(_ context.Context, argv []string, _ []string) (string, error) {
	r.calls = append(r.calls, argv)
	return "", nil
}

// The renderer and the helper's web.sync_sites intent are written
// against each other but live on opposite sides of the privilege
// boundary (helperd stays stdlib-only, so it duplicates the mark
// constant instead of importing this package). This test pins the
// contract: everything Render produces must pass the intent's
// validation and land on disk unmodified.
func TestRenderOutputSyncsThroughHelper(t *testing.T) {
	if ManagedMark != helper.ManagedMark {
		t.Fatalf("managed mark drifted:\n web:    %q\n helper: %q", ManagedMark, helper.ManagedMark)
	}

	for _, hosts := range [][]Host{baseHosts(), phpHosts(), pathMountHosts()} {
		files, err := Render(testCfg, hosts)
		if err != nil {
			t.Fatal(err)
		}
		args, err := helper.EncodeSyncArgs(files)
		if err != nil {
			t.Fatal(err)
		}
		result, err := helper.Dispatch(context.Background(),
			helper.Deps{Run: &okRunner{}, Root: t.TempDir()},
			helper.Request{Intent: "web.sync_sites", Args: args})
		if err != nil {
			t.Fatalf("rendered fileset rejected by helper: %v", err)
		}
		res, err := helper.DecodeSyncResult(result)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Skipped) != 0 {
			t.Fatalf("fresh sync should skip nothing, got %v", res.Skipped)
		}
	}
}
