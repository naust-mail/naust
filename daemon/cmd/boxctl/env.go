package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"naust/daemon/internal/boxconf"
	"naust/daemon/internal/liveness"
	"naust/daemon/internal/materialize"
	"naust/daemon/internal/store"
	"naust/daemon/internal/store/ent"
)

// confPath is the box configuration setup writes; boxctl reads STORAGE_ROOT and
// PRIMARY_HOSTNAME from it, the same file managerd loads.
const confPath = "/etc/naust.conf"

// ensureNaust re-executes boxctl as the naust user for any command that opens the
// control store, so the SQLite DB and its WAL/SHM sidecars stay naust-owned (root
// would create root-owned files managerd then cannot write). No-op when already
// running as naust; re-execs via runuser when root; errors otherwise.
func ensureNaust() error {
	u, err := user.Lookup("naust")
	if err != nil {
		return fmt.Errorf("naust user not found (is the box set up?): %w", err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("parse naust uid: %w", err)
	}
	if os.Geteuid() == uid {
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (via sudo) or the naust user")
	}
	runuser, err := exec.LookPath("runuser")
	if err != nil {
		return fmt.Errorf("runuser not found: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	// syscall.Exec replaces this process; on success it does not return.
	argv := append([]string{"runuser", "-u", "naust", "--", self}, os.Args[1:]...)
	return syscall.Exec(runuser, argv, os.Environ())
}

// boxStore bundles the control store client with the box facts commands need.
type boxStore struct {
	client      *ent.Client
	storageRoot string
	hostname    string
	publicIP    string
}

// openStore loads the box config and opens the control store. Callers must Close.
func openStore() (*boxStore, error) {
	conf, err := boxconf.Load(confPath)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", confPath, err)
	}
	storageRoot := conf.Get("STORAGE_ROOT")
	if storageRoot == "" {
		storageRoot = "/home/user-data"
	}
	dsn := filepath.Join(storageRoot, "control", "manager.sqlite")
	client, err := store.Open(store.EngineSQLite, dsn)
	if err != nil {
		return nil, fmt.Errorf("open control store: %w", err)
	}
	return &boxStore{
		client:      client,
		storageRoot: storageRoot,
		hostname:    conf.Get("PRIMARY_HOSTNAME"),
		publicIP:    conf.Get("PUBLIC_IP"),
	}, nil
}

// dbPath is where the control store lives, for the liveness probe.
func (b *boxStore) dbPath() string {
	return filepath.Join(b.storageRoot, "control", "manager.sqlite")
}

// livenessConfig builds the daemon-liveness probe config. In Docker, managerd
// runs unpackaged (no systemd unit, no $PATH entry): the binary is installed
// at a fixed path and "is it running" is answered by looking for the process
// directly, matching how supervisord actually started it, rather than a
// systemd unit that does not exist in that runtime.
func (b *boxStore) livenessConfig() liveness.Config {
	cfg := liveness.Config{DBPath: b.dbPath()}
	if os.Getenv("RUNTIME") == "docker" {
		cfg.BinaryPath = "/usr/local/lib/naust/managerd"
		cfg.SystemctlActive = func(string) bool {
			return exec.Command("pgrep", "-x", "managerd").Run() == nil
		}
	}
	return cfg
}

// materializer builds a one-shot materializer so a store write (e.g. a password
// reset) reaches Dovecot immediately rather than on managerd's next hourly tick.
func (b *boxStore) materializer() *materialize.Materializer {
	return &materialize.Materializer{
		Store:       b.client,
		Dir:         filepath.Join(b.storageRoot, "mail", "materialized"),
		StorageRoot: b.storageRoot,
		Hostname:    b.hostname,
		Run:         materialize.ExecRunner{},
		Log:         log.New(os.Stderr, "", 0),
	}
}
