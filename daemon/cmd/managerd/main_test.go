package main

import (
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestManagerdShutsDownCleanlyOnSIGTERM builds and runs the real
// binary against a throwaway STORAGE_ROOT, then verifies the
// signal.NotifyContext/http.Server.Shutdown wiring in main() actually
// stops the process instead of hanging or being killed by the test
// harness's own timeout.
func TestManagerdShutsDownCleanlyOnSIGTERM(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and execs the real binary; skipped in -short")
	}

	bin := filepath.Join(t.TempDir(), "managerd")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	storageRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(storageRoot, "nsd", "zones"), 0o755); err != nil {
		t.Fatal(err)
	}

	addr := freeAddr(t)

	cmd := exec.Command(bin,
		"-listen="+addr,
		"-primary-hostname=test.example.com",
		"-public-ip=192.0.2.1",
		"-zones-dir="+filepath.Join(storageRoot, "nsd", "zones"),
		"-nsd-conf="+filepath.Join(storageRoot, "nsd", "zones.conf"),
		"-mta-sts-policy="+filepath.Join(storageRoot, "mta-sts.txt"),
		"-helper-socket="+filepath.Join(storageRoot, "helper.sock"), // no helperd listening; unused by /api/meta
		"-conf="+filepath.Join(storageRoot, "naust.conf"),           // does not exist; boxconf.Load tolerates that
	)
	cmd.Env = append(os.Environ(), "STORAGE_ROOT="+storageRoot)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start managerd: %v", err)
	}
	go io.Copy(io.Discard, stderr)

	waitForHTTP(t, "http://"+addr+"/api/meta", 10*time.Second)

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal SIGTERM: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("managerd did not exit cleanly after SIGTERM: %v", err)
		}
	case <-time.After(15 * time.Second):
		cmd.Process.Kill()
		t.Fatal("managerd did not exit within 15s of SIGTERM (shutdown hang)")
	}

	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Error("managerd still accepting connections after exit")
	}
}

// freeAddr reserves an ephemeral loopback port and immediately
// releases it for the subprocess to bind.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// waitForHTTP polls url until it responds or timeout elapses.
func waitForHTTP(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("managerd never answered %s: %v", url, lastErr)
}
