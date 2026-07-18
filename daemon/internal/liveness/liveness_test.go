package liveness

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDialReachableAndNot(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	if r := dial("api", "tcp", ln.Addr().String(), time.Second, "listening", "not listening"); !r.OK || r.Detail != "listening" {
		t.Fatalf("live endpoint = %+v, want OK/listening", r)
	}
	// Port 1 on loopback is never open in the test environment.
	if r := dial("api", "tcp", "127.0.0.1:1", 200*time.Millisecond, "listening", "not listening"); r.OK {
		t.Fatalf("closed endpoint = %+v, want not OK", r)
	}
}

func TestDialUnixSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "h.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	if r := dial("sock", "unix", sock, time.Second, "reachable", "unreachable"); !r.OK {
		t.Fatalf("live socket = %+v, want OK", r)
	}
	if r := dial("sock", "unix", filepath.Join(t.TempDir(), "nope.sock"), 200*time.Millisecond, "reachable", "unreachable"); r.OK {
		t.Fatalf("missing socket = %+v, want not OK", r)
	}
}

func TestFileReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := fileReadable("db", path); !r.OK || r.Detail != "readable" {
		t.Fatalf("present file = %+v, want readable", r)
	}
	if r := fileReadable("db", filepath.Join(t.TempDir(), "gone")); r.OK || r.Detail != "missing" {
		t.Fatalf("missing file = %+v, want missing", r)
	}
}

func TestBinaryPresent(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "managerd")
	if err := os.WriteFile(bin, []byte("#!/bin/true"), 0o755); err != nil {
		t.Fatal(err)
	}
	if ok, _ := binaryPresent(bin); !ok {
		t.Fatal("explicit existing binary should be present")
	}
	if ok, d := binaryPresent(filepath.Join(t.TempDir(), "absent")); ok || d != "missing" {
		t.Fatalf("absent binary = %v/%q, want missing", ok, d)
	}
}

func TestProbeAggregate(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	sock := filepath.Join(t.TempDir(), "h.sock")
	sockLn, _ := net.Listen("unix", sock)
	defer sockLn.Close()
	db := filepath.Join(t.TempDir(), "db")
	os.WriteFile(db, []byte("x"), 0o600)
	bin := filepath.Join(t.TempDir(), "managerd")
	os.WriteFile(bin, []byte("x"), 0o755)

	cfg := Config{
		APIAddr:         ln.Addr().String(),
		DBPath:          db,
		SocketPath:      sock,
		BinaryPath:      bin,
		SystemctlActive: func(string) bool { return true },
		Timeout:         time.Second,
	}
	results := cfg.Probe()
	if len(results) != 5 {
		t.Fatalf("got %d probes, want 5", len(results))
	}
	if !AllOK(results) {
		t.Fatalf("all-healthy config should pass every probe: %+v", results)
	}

	// A dead unit flips only its own probe and the aggregate.
	cfg.SystemctlActive = func(string) bool { return false }
	results = cfg.Probe()
	if AllOK(results) {
		t.Fatal("dead unit should fail the aggregate")
	}
	for _, r := range results {
		if r.Name == "systemd unit naust-managerd" && r.OK {
			t.Fatal("unit probe should be failing")
		}
	}
}
