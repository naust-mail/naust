// helperd is the privileged helper for the Naust management
// daemon. It listens on a local Unix socket and executes a fixed menu of
// privileged operations (service restarts, allowlisted config writes,
// apt, reboot) on behalf of the unprivileged manager process.
//
// The intent menu, wire protocol, and invariants are documented in
// .claude/memories/helper-intent-menu.md. The menu is closed: this
// program never runs caller-supplied paths or command strings.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"naust/daemon/internal/helper"
)

func main() {
	socketPath := flag.String("socket", "/run/naust/helper.sock", "unix socket path to listen on")
	socketGroup := flag.String("socket-group", "naust", "group granted connect access to the socket")
	allowUID := flag.Int("allow-uid", -1, "restrict callers to this peer uid (-1 allows any; socket permissions remain the primary gate)")
	flag.Parse()

	logger := log.New(os.Stderr, "", log.LstdFlags)

	if err := os.MkdirAll(filepath.Dir(*socketPath), 0o750); err != nil {
		logger.Fatalf("create socket directory: %v", err)
	}
	// Remove a stale socket from an unclean shutdown; refuse to remove
	// anything that is not a socket.
	if err := removeStaleSocket(*socketPath); err != nil {
		logger.Fatalf("%v", err)
	}

	l, err := net.Listen("unix", *socketPath)
	if err != nil {
		logger.Fatalf("listen: %v", err)
	}

	if err := restrictSocket(*socketPath, *socketGroup); err != nil {
		l.Close()
		logger.Fatalf("socket permissions: %v", err)
	}

	srv := &helper.Server{
		Deps:     helper.Deps{Run: helper.ExecRunner{}},
		AllowUID: *allowUID,
		Log:      logger,
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		l.Close()
	}()

	logger.Printf("helperd listening on %s (group %s, allow-uid %d)", *socketPath, *socketGroup, *allowUID)
	if err := srv.Serve(l); err != nil {
		logger.Fatalf("serve: %v", err)
	}
}

// removeStaleSocket removes a leftover socket file from an unclean
// shutdown so a fresh net.Listen can bind the path. It refuses to
// remove anything that is not actually a socket, and it is not an
// error for the path to not exist yet.
func removeStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket; refusing to remove", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	return nil
}

// restrictSocket sets the socket to 0660 root:<group> so only the
// manager's group may connect.
func restrictSocket(path, group string) error {
	g, err := user.LookupGroup(group)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return err
	}
	if err := os.Chown(path, 0, gid); err != nil {
		return err
	}
	return os.Chmod(path, 0o660)
}
