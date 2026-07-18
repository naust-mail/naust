// Package liveness implements the small "is the daemon even up?" probe set that
// boxctl runs ITSELF, distinct from the health roster managerd owns. It answers a
// different question - "can I trust the stored check results at all" - so it is
// rendered as its own strip above the roster (see boxctl doctor). When every probe
// passes it collapses to one line; when any fails it becomes the headline and the
// roster is shown stale.
//
// It is stdlib-only and depends on nothing else in the daemon: boxctl must be able
// to report on a box where managerd will not start.
package liveness

import (
	"net"
	"os"
	"os/exec"
	"time"
)

// Result is one probe outcome. Detail is the observed short phrase ("active",
// "not listening", "readable", "unreachable"); Expected is what a healthy probe
// would show, so a viewer can render a failed probe in the same
// expected/observed form as a failed check.
type Result struct {
	Name     string
	OK       bool
	Detail   string
	Expected string
}

// Config names what to probe. Zero-value fields fall back to the standard box
// locations. SystemctlActive and Timeout are injectable for testing.
type Config struct {
	Unit       string // systemd unit, default "naust-managerd"
	APIAddr    string // manager API, default "127.0.0.1:10223"
	DBPath     string // control DB file, default STORAGE_ROOT/control/manager.sqlite; boxctl passes the resolved path
	SocketPath string // helper socket, default "/run/naust/helper.sock"
	BinaryPath string // managerd binary; empty = look it up on PATH

	// SystemctlActive reports whether unit is active; nil = real systemctl.
	SystemctlActive func(unit string) bool
	// Timeout bounds each network probe; zero = 1s.
	Timeout time.Duration
}

func (c Config) withDefaults() Config {
	if c.Unit == "" {
		c.Unit = "naust-managerd"
	}
	if c.APIAddr == "" {
		c.APIAddr = "127.0.0.1:10223"
	}
	if c.DBPath == "" {
		c.DBPath = "/home/user-data/control/manager.sqlite"
	}
	if c.SocketPath == "" {
		c.SocketPath = "/run/naust/helper.sock"
	}
	if c.SystemctlActive == nil {
		c.SystemctlActive = systemctlActive
	}
	if c.Timeout == 0 {
		c.Timeout = time.Second
	}
	return c
}

// Probe runs every probe in a fixed order and returns their results.
func (c Config) Probe() []Result {
	c = c.withDefaults()

	binOK, binDetail := binaryPresent(c.BinaryPath)
	unitOK := c.SystemctlActive(c.Unit)
	unitDetail := "active"
	if !unitOK {
		unitDetail = "not active"
	}

	return []Result{
		{Name: "managerd binary", OK: binOK, Detail: binDetail, Expected: "present"},
		{Name: "systemd unit " + c.Unit, OK: unitOK, Detail: unitDetail, Expected: "active"},
		dial("API "+c.APIAddr, "tcp", c.APIAddr, c.Timeout, "listening", "not listening"),
		fileReadable("control DB "+c.DBPath, c.DBPath),
		dial("helper socket "+c.SocketPath, "unix", c.SocketPath, c.Timeout, "reachable", "unreachable"),
	}
}

// AllOK reports whether every probe passed.
func AllOK(results []Result) bool {
	for _, r := range results {
		if !r.OK {
			return false
		}
	}
	return true
}

// dial reports whether a tcp/unix endpoint accepts a connection.
func dial(name, network, addr string, timeout time.Duration, okDetail, failDetail string) Result {
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return Result{Name: name, OK: false, Detail: failDetail, Expected: okDetail}
	}
	conn.Close()
	return Result{Name: name, OK: true, Detail: okDetail, Expected: okDetail}
}

// fileReadable reports whether path exists and can be opened for reading.
func fileReadable(name, path string) Result {
	f, err := os.Open(path)
	if err != nil {
		detail := "unreadable"
		if os.IsNotExist(err) {
			detail = "missing"
		}
		return Result{Name: name, OK: false, Detail: detail, Expected: "readable"}
	}
	f.Close()
	return Result{Name: name, OK: true, Detail: "readable", Expected: "readable"}
}

// binaryPresent reports whether the managerd binary exists. An explicit path is
// stat'd; an empty path is looked up on PATH.
func binaryPresent(path string) (bool, string) {
	if path != "" {
		if _, err := os.Stat(path); err != nil {
			return false, "missing"
		}
		return true, "present"
	}
	if _, err := exec.LookPath("managerd"); err != nil {
		return false, "not found"
	}
	return true, "present"
}

// systemctlActive shells to systemctl for the real unit-active check.
func systemctlActive(unit string) bool {
	return exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil
}
