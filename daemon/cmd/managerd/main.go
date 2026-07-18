// managerd is the Naust management daemon (Go rewrite of the
// Python management/ daemon, in progress). It runs as an unprivileged
// user and holds no state outside the database: sessions, credentials,
// desired configuration, rate-limit windows, and counters all live in
// the store, so the process is disposable and any number of replicas
// against one store can serve requests. Background singletons (backup
// runs, scheduled check batches and their digest, ACME renewal
// sweeps) coordinate through store leases so exactly one replica runs
// each; the config appliers instead run on every process, because
// they converge host-local files and re-tick periodically to pick up
// mutations another replica handled. The one designed exception to
// store-only state is the bootstrap token: a root-minted file on this
// host, because first-admin trust anchors to the operator's shell,
// not to database contents. Privileged operations are delegated to
// helperd over its intent socket.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"naust/daemon/internal/acmeprov"
	"naust/daemon/internal/backup"
	"naust/daemon/internal/boxconf"
	"naust/daemon/internal/checks"
	"naust/daemon/internal/dnsapply"
	"naust/daemon/internal/helper"
	"naust/daemon/internal/httpapi"
	"naust/daemon/internal/materialize"
	"naust/daemon/internal/store"
	"naust/daemon/internal/webapply"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:10223", "address to serve the management API on (behind nginx)")
	debugAddr := flag.String("debug-listen", "127.0.0.1:6060", "loopback-only address serving net/http/pprof profiles for `go tool pprof`; empty disables it")
	dbEngine := flag.String("db-engine", "sqlite", "database engine: sqlite or postgres")
	dbDSN := flag.String("db-dsn", "", "database DSN; for sqlite a file path (default STORAGE_ROOT/control/manager.sqlite)")
	mapsDir := flag.String("maps-dir", "", "directory for materialized mail maps (default STORAGE_ROOT/mail/materialized)")
	primaryHostname := flag.String("primary-hostname", os.Getenv("PRIMARY_HOSTNAME"), "the box's own FQDN (default $PRIMARY_HOSTNAME)")
	publicIP := flag.String("public-ip", os.Getenv("PUBLIC_IP"), "the box's public IPv4 address (default $PUBLIC_IP)")
	publicIPv6 := flag.String("public-ipv6", os.Getenv("PUBLIC_IPV6"), "the box's public IPv6 address, empty for none (default $PUBLIC_IPV6)")
	zonesDir := flag.String("zones-dir", "/etc/nsd/zones", "directory for generated zone files")
	nsdConf := flag.String("nsd-conf", "/etc/nsd/nsd.conf.d/zones.conf", "path of the generated nsd zone list")
	mtaSTSPolicy := flag.String("mta-sts-policy", "/var/lib/naust/mta-sts.txt", "MTA-STS policy file nginx serves at /.well-known/mta-sts.txt; must match the nginx alias")
	helperSocket := flag.String("helper-socket", "/run/naust/helper.sock", "unix socket of the privileged helper daemon")
	submitAddr := flag.String("submit-addr", "localhost:25", "SMTP address for submitting test mail (the mail container in Docker)")
	confPath := flag.String("conf", "/etc/naust.conf", "box configuration written by setup; real environment variables take precedence (Docker)")
	acmeDirectory := flag.String("acme-directory", "", "ACME directory URL for certificate provisioning (default Let's Encrypt production)")
	mailcryptKey := flag.String("mailcrypt-key", "/var/lib/naust/mailcrypt-unwrap.key", "shared-secret file gating the internal mail-key unwrap endpoint (Dovecot's Lua passdb holds the same file)")
	bootstrapToken := flag.String("bootstrap-token", "", "setup-code file written by boxctl bootstrap, gating first-admin creation (default STORAGE_ROOT/control/bootstrap.token)")
	flag.Parse()

	logger := log.New(os.Stderr, "", log.LstdFlags)
	conf, err := boxconf.Load(*confPath)
	if err != nil {
		logger.Fatalf("load %s: %v", *confPath, err)
	}
	// Flag defaults come from real environment variables (the Docker
	// model); on bare metal the same values live in the conf file setup
	// wrote. Environment still wins - the file only fills what is empty.
	if *publicIP == "" {
		*publicIP = conf.Get("PUBLIC_IP")
	}
	if *publicIPv6 == "" {
		*publicIPv6 = conf.Get("PUBLIC_IPV6")
	}
	if *primaryHostname == "" {
		*primaryHostname = conf.Get("PRIMARY_HOSTNAME")
	}
	if *publicIP == "" {
		logger.Fatalf("PUBLIC_IP is not set (in %s, -public-ip, or $PUBLIC_IP); required so DNS zones and cert issuance don't silently point at nothing", *confPath)
	}
	storageRoot := conf.Get("STORAGE_ROOT")
	if storageRoot == "" {
		storageRoot = "/home/user-data"
	}
	if *bootstrapToken == "" {
		*bootstrapToken = filepath.Join(storageRoot, "control", "bootstrap.token")
	}

	dsn := *dbDSN
	if dsn == "" && store.Engine(*dbEngine) == store.EngineSQLite {
		dsn = filepath.Join(storageRoot, "control", "manager.sqlite")
		if err := os.MkdirAll(filepath.Dir(dsn), 0o750); err != nil {
			logger.Fatalf("create database directory: %v", err)
		}
	}

	client, err := store.Open(store.Engine(*dbEngine), dsn)
	if err != nil {
		logger.Fatalf("open store: %v", err)
	}
	defer client.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := client.Schema.Create(ctx); err != nil {
		logger.Fatalf("migrate schema: %v", err)
	}
	tenant, err := store.EnsureDefaultTenant(ctx, client)
	if err != nil {
		logger.Fatalf("ensure default tenant: %v", err)
	}

	if *mapsDir == "" {
		*mapsDir = filepath.Join(storageRoot, "mail", "materialized")
	}
	mat := &materialize.Materializer{
		Store:       client,
		Dir:         *mapsDir,
		StorageRoot: storageRoot,
		Hostname:    *primaryHostname,
		Run:         materialize.ExecRunner{},
		Log:         logger,
	}
	mat.Start(ctx)
	// Converge on startup: the files must reflect the store even if the
	// last change happened while this process was down.
	mat.Kick()

	helperClient := &helper.Client{SocketPath: *helperSocket}

	applier := &dnsapply.Applier{
		Store:            client,
		ZonesDir:         *zonesDir,
		NSDConfPath:      *nsdConf,
		DNSSECDir:        filepath.Join(storageRoot, "dns", "dnssec"),
		DKIMTxtPath:      filepath.Join(storageRoot, "mail", "dkim", "mail.txt"),
		SSLRoot:          filepath.Join(storageRoot, "ssl"),
		MTASTSPolicyPath: *mtaSTSPolicy,
		PrimaryHostname:  *primaryHostname,
		PublicIP:         *publicIP,
		PublicIPv6:       *publicIPv6,
		Run:              dnsapply.ExecRunner{},
		Reload: func(ctx context.Context, service string) error {
			_, err := helperClient.Call(ctx, "service.reload", map[string]string{"service": service})
			return err
		},
		Log: logger,
	}
	applier.Start(ctx)
	applier.Kick()

	webApplier := &webapply.Applier{
		Store:           client,
		Conf:            conf.Get,
		PrimaryHostname: *primaryHostname,
		PublicIP:        *publicIP,
		PublicIPv6:      *publicIPv6,
		StorageRoot:     storageRoot,
		Helper:          helperClient,
		Log:             logger,
	}
	webApplier.Start(ctx)
	webApplier.Kick()

	certProvisioner := &acmeprov.Provisioner{
		Store:           client,
		PrimaryHostname: *primaryHostname,
		PublicIP:        *publicIP,
		PublicIPv6:      *publicIPv6,
		StorageRoot:     storageRoot,
		DirectoryURL:    *acmeDirectory,
		Selector: &acmeprov.StandardSelector{
			Webroot: &acmeprov.Webroot{
				Dir:        filepath.Join(storageRoot, "ssl", "lets_encrypt", "webroot"),
				PublicIP:   *publicIP,
				PublicIPv6: *publicIPv6,
			},
			Store: client,
		},
		Helper:  helperClient,
		KickWeb: webApplier.Kick,
		KickDNS: applier.Kick,
		Log:     logger,
	}
	certProvisioner.Start(ctx)

	checkEngine := &checks.Engine{
		Deps: checks.Deps{
			Store:           client,
			Conf:            conf.Get,
			PrimaryHostname: *primaryHostname,
			PublicIP:        *publicIP,
			PublicIPv6:      *publicIPv6,
			StorageRoot:     storageRoot,
			MapsDir:         *mapsDir,
			InDocker:        os.Getenv("RUNTIME") == "docker",
			Zones:           applier.DesiredZones,
			SMTPAddr:        *submitAddr,
			Log:             logger,
			AuthFailures: func(ctx context.Context) (int64, error) {
				return store.CounterValue(ctx, client, store.CounterAuthFailures)
			},
			PostfixQueue: func(ctx context.Context) (string, error) {
				return helperClient.Call(ctx, "postfix.queue", nil)
			},
		},
		Checks: checks.All(),
	}
	checkEngine.Start(ctx)

	apiServer := &httpapi.Server{
		Store:              client,
		Log:                logger,
		TenantID:           tenant.ID,
		PrimaryHostname:    *primaryHostname,
		PublicIP:           *publicIP,
		PublicIPv6:         *publicIPv6,
		StorageRoot:        storageRoot,
		Conf:               conf.Get,
		OnMailDataChange:   mat.Kick,
		OnDNSDataChange:    applier.Kick,
		OnWebDataChange:    webApplier.Kick,
		OnCertConfigChange: certProvisioner.Kick,
		Certs:              certProvisioner,
		Checks:             checkEngine,
		Zones:              applier.DesiredZones,
		Helper:             helperClient,
		RelayDir:           filepath.Join(storageRoot, "mail", "relay"),
		RunPostmap: func(ctx context.Context, path string) error {
			out, err := exec.CommandContext(ctx, "/usr/sbin/postmap", path).CombinedOutput()
			if err != nil {
				return fmt.Errorf("postmap: %v: %s", err, out)
			}
			return nil
		},
		SubmitAddr:         *submitAddr,
		MailcryptKeyPath:   *mailcryptKey,
		BootstrapTokenPath: *bootstrapToken,
		AutodiscoverPath:   "/var/lib/naust/autodiscover.xml",
	}

	backupEngine := &backup.Engine{
		Store:       client,
		StorageRoot: storageRoot,
		Conf:        conf.Get,
		Hostname:    *primaryHostname,
		Log:         logger,
	}
	backupEngine.Start(ctx)
	apiServer.Backup = backupEngine

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	// Separate listener, never proxied by nginx, so /debug/pprof/* is
	// reachable only via docker exec or an SSH tunnel - same loopback-only
	// posture as LMTP. http.DefaultServeMux is what net/http/pprof's blank
	// import registers onto; the main API server above uses its own
	// handler and never sees these routes.
	if *debugAddr != "" {
		debugSrv := &http.Server{Addr: *debugAddr, Handler: http.DefaultServeMux}
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			debugSrv.Shutdown(shutdownCtx)
		}()
		go func() {
			logger.Printf("pprof debug endpoint listening on %s", *debugAddr)
			if err := debugSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Printf("pprof debug server: %v", err)
			}
		}()
	}

	logger.Printf("managerd listening on %s (engine %s)", *listenAddr, *dbEngine)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("serve: %v", err)
	}
}
