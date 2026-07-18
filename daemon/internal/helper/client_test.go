package helper

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The client and server each implement one side of the wire protocol;
// this exercises them against each other end to end.
func TestClientRoundTrip(t *testing.T) {
	run := &fakeRunner{}
	sock := startServer(t, run)
	c := &Client{SocketPath: sock}
	ctx := context.Background()

	// A valid intent executes and succeeds.
	if _, err := c.Call(ctx, "postfix.set", map[string]string{"key": "relayhost", "value": "[smtp.example.com]:587"}); err != nil {
		t.Fatalf("postfix.set: %v", err)
	}
	if len(run.calls) != 1 || run.calls[0][0] != "/usr/sbin/postconf" {
		t.Errorf("runner calls = %v", run.calls)
	}

	// Intent output comes back as the result.
	out, err := c.Call(ctx, "host.apt_update", nil)
	if err != nil {
		t.Fatalf("apt_update: %v", err)
	}
	if out != "fake output" {
		t.Errorf("result = %q", out)
	}

	// Server-side rejection surfaces as an error with the reason.
	_, err = c.Call(ctx, "postfix.set", map[string]string{"key": "evil", "value": "x"})
	if err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Errorf("disallowed key: err = %v", err)
	}
	_, err = c.Call(ctx, "no.such.intent", nil)
	if err == nil || !strings.Contains(err.Error(), "unknown intent") {
		t.Errorf("unknown intent: err = %v", err)
	}

	// A dead socket fails fast instead of hanging.
	dead := &Client{SocketPath: sock + ".gone"}
	ctx2, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if _, err := dead.Call(ctx2, "service.reload", map[string]string{"service": "nsd"}); err == nil {
		t.Error("dead socket: expected error")
	}
}
