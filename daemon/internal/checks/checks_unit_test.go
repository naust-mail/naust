package checks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeFS backs Deps.ReadFile with a map.
func fakeFS(files map[string]string) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		if v, ok := files[name]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("no such file")
	}
}

// runCheck executes one check function directly and returns the
// summarized result.
func runCheck(t *testing.T, d *Deps, fn func(context.Context, *Deps, string, *Reporter)) (Status, string, []Step) {
	t.Helper()
	if d.Now == nil {
		d.Now = func() time.Time { return testNow }
	}
	// Mirror fillDefaults: the queue seam falls back to Run.
	if d.PostfixQueue == nil && d.Run != nil {
		d.PostfixQueue = func(ctx context.Context) (string, error) {
			return d.Run(ctx, "/usr/sbin/postqueue", "-j")
		}
	}
	r := &Reporter{now: d.Now}
	fn(context.Background(), d, "", r)
	status, message := summarize(r.steps)
	return status, message, r.steps
}

func TestSSHDirectiveFirstMatchAndInclude(t *testing.T) {
	d := &Deps{ReadFile: fakeFS(map[string]string{
		"/etc/ssh/sshd_config": "# comment\nPasswordAuthentication no\nPasswordAuthentication yes\n",
	})}
	if v, ok := sshdDirective(d, "passwordauthentication"); !ok || v != "no" {
		t.Errorf("first-match = %q %v", v, ok)
	}

	// A Match block ends the global section.
	d = &Deps{ReadFile: fakeFS(map[string]string{
		"/etc/ssh/sshd_config": "Match User git\nPasswordAuthentication no\n",
	})}
	if _, ok := sshdDirective(d, "passwordauthentication"); ok {
		t.Error("directive inside Match block treated as global")
	}

	// Absent directive means the permissive default: the check fails.
	d = &Deps{ReadFile: fakeFS(map[string]string{"/etc/ssh/sshd_config": "Port 22\n"})}
	status, _, _ := runCheck(t, d, checkSSHPasswordAuth)
	if status != StatusError {
		t.Errorf("absent directive = %s, want error", status)
	}

	if got := sshPort(d); got != 22 {
		t.Errorf("sshPort = %d", got)
	}
	d = &Deps{ReadFile: fakeFS(map[string]string{"/etc/ssh/sshd_config": "Port 2222\n"})}
	if got := sshPort(d); got != 2222 {
		t.Errorf("sshPort = %d", got)
	}
}

func TestFreeMemoryThresholds(t *testing.T) {
	meminfo := func(availKB int) string {
		return fmt.Sprintf("MemTotal:       1000 kB\nMemFree:        1 kB\nMemAvailable:   %d kB\n", availKB)
	}
	for _, tc := range []struct {
		avail int
		want  Status
	}{{500, StatusOK}, {150, StatusWarning}, {50, StatusError}} {
		d := &Deps{ReadFile: fakeFS(map[string]string{"/proc/meminfo": meminfo(tc.avail)})}
		if status, _, _ := runCheck(t, d, checkFreeMemory); status != tc.want {
			t.Errorf("avail %d = %s, want %s", tc.avail, status, tc.want)
		}
	}

	// A kernel without MemAvailable is a parse failure, not 0% free.
	d := &Deps{ReadFile: fakeFS(map[string]string{"/proc/meminfo": "MemTotal: 1000 kB\nMemFree: 500 kB\n"})}
	if status, msg, _ := runCheck(t, d, checkFreeMemory); status != StatusError || !strings.Contains(msg, "cannot parse") {
		t.Errorf("missing MemAvailable = %s %q", status, msg)
	}
}

func TestSoftwareUpdates(t *testing.T) {
	d := &Deps{
		ReadFile: fakeFS(map[string]string{"/var/run/reboot-required": ""}),
		Run: func(ctx context.Context, argv ...string) (string, error) {
			return "Reading package lists...\nInst libssl3 [3.0.2] (3.0.5 Ubuntu:22.04)\nInst nginx-core [1.18]\nConf libssl3\n", nil
		},
	}
	status, msg, steps := runCheck(t, d, checkSoftwareUpdates)
	if status != StatusError {
		t.Fatalf("status = %s", status)
	}
	if len(steps) != 2 || steps[0].Status != StatusError || !strings.Contains(steps[1].Observed, "libssl3, nginx-core") {
		t.Errorf("steps = %+v (msg %q)", steps, msg)
	}
	if !strings.Contains(steps[1].Message, "2 software packages") || strings.Contains(steps[1].Message, "libssl3") {
		t.Errorf("step message should be a short count, not the package list: %q", steps[1].Message)
	}
	if steps[0].FixHint != "system.reboot" {
		t.Errorf("reboot hint = %q", steps[0].FixHint)
	}
}

func TestUFWUnprivilegedSkips(t *testing.T) {
	d := &Deps{RootContext: false}
	status, msg, _ := runCheck(t, d, checkUFW)
	if status != StatusSkipped || !strings.Contains(msg, "boxctl doctor") {
		t.Errorf("unprivileged ufw = %s %q", status, msg)
	}
}

func TestMailQueueThresholds(t *testing.T) {
	for _, tc := range []struct {
		count int
		want  Status
	}{{0, StatusOK}, {150, StatusWarning}, {600, StatusError}} {
		lines := strings.Repeat("{\"queue_id\":\"x\"}\n", tc.count)
		d := &Deps{Run: func(ctx context.Context, argv ...string) (string, error) { return lines, nil }}
		if status, _, _ := runCheck(t, d, checkMailQueue); status != tc.want {
			t.Errorf("queue %d = %s, want %s", tc.count, status, tc.want)
		}
	}
}

func TestRunProbePublicSemantics(t *testing.T) {
	// Reachability keyed by dialed address.
	reachable := map[string]bool{}
	d := &Deps{
		PublicIP:   "203.0.113.1",
		PublicIPv6: "2001:db8::1",
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if reachable[addr] {
				c, s := net.Pipe()
				go s.Close()
				return c, nil
			}
			return nil, errors.New("refused")
		},
	}
	p := probe{ID: "smtp", Label: "SMTP", HostVar: "MAIL_HOST", Port: 25, Public: true}
	probeStatus := func() (Status, string) {
		r := &Reporter{now: func() time.Time { return testNow }}
		runProbe(context.Background(), d, p, r)
		st, msg := summarize(r.steps)
		return st, msg
	}

	if st, msg := probeStatus(); st != StatusError || !strings.Contains(msg, "not running") {
		t.Errorf("all down = %s %q", st, msg)
	}

	reachable["127.0.0.1:25"] = true
	if st, msg := probeStatus(); st != StatusError || !strings.Contains(msg, "not publicly accessible") {
		t.Errorf("backend only = %s %q", st, msg)
	}

	reachable["203.0.113.1:25"] = true
	if st, msg := probeStatus(); st != StatusError || !strings.Contains(msg, "IPv6") {
		t.Errorf("v4 only = %s %q", st, msg)
	}

	reachable["[2001:db8::1]:25"] = true
	if st, _ := probeStatus(); st != StatusOK {
		t.Errorf("fully up = %s", st)
	}

	// Port 53 must not fall back to the backend (unbound would mask
	// a downed NSD).
	reachable = map[string]bool{"127.0.0.1:53": true}
	p = probe{ID: "nsd", Label: "Public DNS", HostVar: "DNS_HOST", Port: 53, Public: true}
	if st, msg := probeStatus(); st != StatusError || strings.Contains(msg, "not publicly accessible") {
		t.Errorf("port 53 fallback = %s %q", st, msg)
	}
}
