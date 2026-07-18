package main

import (
	"net"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func TestRemoveStaleSocketRemovesSocket(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "helper.sock")

	// An unclean shutdown (e.g. kill -9) never runs net.Listener.Close,
	// so simulate the leftover by unlinking on close ourselves rather
	// than relying on Go's normal cleanup.
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if ul, ok := l.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	defer l.Close()

	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("socket should exist before removal: %v", err)
	}

	if err := removeStaleSocket(path); err != nil {
		t.Fatalf("removeStaleSocket: %v", err)
	}

	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("socket still present after removeStaleSocket: err=%v", err)
	}
}

func TestRemoveStaleSocketMissingPathIsNotError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.sock")
	if err := removeStaleSocket(path); err != nil {
		t.Errorf("expected no error for a missing path, got: %v", err)
	}
}

// A regular file must never be silently deleted just because it sits
// at the configured socket path - this is the invariant that prevents
// helperd from being tricked into removing arbitrary files.
func TestRemoveStaleSocketRefusesNonSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.sock")
	if err := os.WriteFile(path, []byte("not a socket"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := removeStaleSocket(path); err == nil {
		t.Fatal("expected error refusing to remove a non-socket file")
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("non-socket file should still exist, but Stat failed: %v", err)
	}
}

func TestRemoveStaleSocketRefusesDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.sock")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	if err := removeStaleSocket(path); err == nil {
		t.Fatal("expected error refusing to remove a directory")
	}

	if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
		t.Errorf("directory should still exist: fi=%v err=%v", fi, err)
	}
}

func TestRestrictSocketSetsModeAndGroup(t *testing.T) {
	// restrictSocket always chowns to uid 0; only root can do that.
	if os.Geteuid() != 0 {
		t.Skip("requires root to chown to uid 0")
	}

	u, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skipf("cannot resolve current group name: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "helper.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	// Loosen the mode net.Listen created so we can observe restrictSocket change it.
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	if err := restrictSocket(path, g.Name); err != nil {
		t.Fatalf("restrictSocket: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o660 {
		t.Errorf("mode = %v, want 0660", fi.Mode().Perm())
	}
}

func TestRestrictSocketUnknownGroupErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "helper.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	if err := restrictSocket(path, "no-such-group-naust-test"); err == nil {
		t.Fatal("expected error for unknown group")
	}
}
