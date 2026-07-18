// Package acmeprov provisions TLS certificates from an ACME CA
// (Let's Encrypt by default) for the web hostnames the box serves.
// One certificate per hostname: at our scale (a handful of domains)
// CA rate limits are irrelevant, and per-hostname orders give perfect
// failure isolation with no partial-bundle repair logic.
//
// Certificates are requested over the system private key
// (ssl/ssl_private_key.pem), never a fresh one: the DANE TLSA record
// pins that key's SPKI, so renewals must not rotate it. Key rotation
// is a separate deliberate operation paired with a TLSA rollover.
//
// Challenge fulfillment is pluggable (Solver): the webroot HTTP-01
// solver ships today, and DNS-01 solvers driven by provider APIs
// slot in for externally hosted DNS, proxied domains, and wildcards.
package acmeprov

import (
	"context"
	"crypto"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"naust/daemon/internal/sslcert"
	"naust/daemon/internal/store"
	"naust/daemon/internal/store/ent"
	"naust/daemon/internal/webapply"

	"golang.org/x/crypto/acme"
)

// LetsEncryptDirectory is the production ACME directory used when
// Provisioner.DirectoryURL is empty.
const LetsEncryptDirectory = "https://acme-v02.api.letsencrypt.org/directory"

const (
	// renewBefore renews certificates with less than this much
	// validity left: certbot's default, since x/crypto/acme has no
	// ARI support to ask the CA for a renewal window.
	renewBefore = 30 * 24 * time.Hour
	// checkEvery is the renewal loop cadence.
	checkEvery = 24 * time.Hour
	// startupDelay lets webapply finish its first sync so nginx
	// serves the ACME webroot before the first provisioning pass.
	startupDelay = time.Minute
	// leaseName/leaseTTL: scheduled renewal sweeps run on one replica
	// per store; DNS-01 propagation waits make a full sweep slow.
	leaseName = "acme"
	leaseTTL  = time.Hour
	// perDomainTimeout bounds one order end to end; CA polling
	// inside the acme client honors Retry-After within it.
	perDomainTimeout = 4 * time.Minute
)

// Status classifies the outcome for one domain in a provisioning run.
type Status string

const (
	StatusInstalled Status = "installed"
	StatusSkipped   Status = "skipped"
	StatusError     Status = "error"
)

// Result is the outcome for one domain. A Result with an empty Domain
// reports a run-level failure (store unreadable, account unusable).
type Result struct {
	Domain string
	Status Status
	Detail string
}

// HelperClient is the slice of the helperd client used to restart
// mail services after the primary certificate changes.
type HelperClient interface {
	Call(ctx context.Context, intent string, args map[string]string) (string, error)
}

type Provisioner struct {
	Store           *ent.Client
	PrimaryHostname string
	PublicIP        string
	PublicIPv6      string
	// StorageRoot anchors ssl/ (certificates, system key, ACME
	// account key).
	StorageRoot string
	// DirectoryURL of the ACME CA; empty means Let's Encrypt
	// production.
	DirectoryURL string
	// Selector picks the challenge solver per domain; required.
	// Normally a StandardSelector (webroot first, provider DNS-01
	// fallback).
	Selector Selector

	Helper HelperClient
	// KickWeb pokes the web applier after installs so nginx picks up
	// the new certificate files (the rendered cert hash changes).
	KickWeb func()
	// KickDNS pokes the DNS applier after installs: the MTA-STS
	// records are gated on certificate validity, so a first real
	// certificate changes zone content.
	KickDNS func()
	Log     *log.Logger

	// HTTPClient overrides the ACME client's transport (tests).
	HTTPClient *http.Client

	runMu sync.Mutex   // one provisioning pass at a time
	busy  atomic.Int32 // runs in flight or queued, for Busy
	mu    sync.Mutex   // guards the fields below
	last  []Result
	ranAt time.Time
	kick  chan struct{}
}

// Kick requests a prompt provisioning pass from the renewal loop
// (e.g. after a DNS provider is configured). Never blocks; kicks
// collapse. A no-op before Start.
func (p *Provisioner) Kick() {
	if p.kick == nil {
		return
	}
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// Start runs the daily renewal loop until ctx is cancelled. Call once.
func (p *Provisioner) Start(ctx context.Context) {
	p.kick = make(chan struct{}, 1)
	go func() {
		t := time.NewTimer(startupDelay)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			case <-p.kick:
				if !t.Stop() {
					select {
					case <-t.C:
					default:
					}
				}
			}
			p.renewalPass(ctx)
			t.Reset(checkEvery)
		}
	}()
}

// renewalPass runs one scheduled provisioning sweep under the store
// lease: replicas must not order certificates for the same hostnames
// concurrently (duplicate orders, CA rate limits). Manual provisioning
// (StartRun) stays ungated - one panel request reaches one replica.
func (p *Provisioner) renewalPass(ctx context.Context) {
	got, err := store.AcquireLease(ctx, p.Store, leaseName, leaseTTL)
	if err != nil {
		p.Log.Printf("acmeprov: lease: %v", err)
		return
	}
	if !got {
		return
	}
	defer func() {
		if err := store.ReleaseLease(ctx, p.Store, leaseName); err != nil {
			p.Log.Printf("acmeprov: release lease: %v", err)
		}
	}()
	for _, r := range p.Run(ctx, nil) {
		if r.Status != StatusSkipped {
			p.Log.Printf("acmeprov: %s: %s %s", r.Domain, r.Status, r.Detail)
		}
	}
}

// Status returns the results of the most recent run and when it ran.
func (p *Provisioner) Status() ([]Result, time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Result(nil), p.last...), p.ranAt
}

// Run executes one provisioning pass. With a non-empty limit only
// those domains are considered (the manual-provision path). Runs are
// serialized; results are also retained for Status.
func (p *Provisioner) Run(ctx context.Context, limit []string) []Result {
	p.busy.Add(1)
	defer p.busy.Add(-1)
	p.runMu.Lock()
	defer p.runMu.Unlock()
	results := p.provisionAll(ctx, limit)
	p.mu.Lock()
	p.last = results
	p.ranAt = time.Now()
	p.mu.Unlock()
	return results
}

func (p *Provisioner) provisionAll(ctx context.Context, limit []string) []Result {
	in, err := webapply.LoadInput(ctx, p.Store, p.PrimaryHostname, p.PublicIP, p.PublicIPv6)
	if err != nil {
		return []Result{{Status: StatusError, Detail: fmt.Sprintf("load domains: %v", err)}}
	}
	sslRoot := filepath.Join(p.StorageRoot, "ssl")
	now := time.Now()
	certs, err := sslcert.Scan(sslRoot, p.PrimaryHostname, now)
	if err != nil {
		return []Result{{Status: StatusError, Detail: fmt.Sprintf("scan certificates: %v", err)}}
	}

	var limitSet map[string]bool
	if len(limit) > 0 {
		limitSet = map[string]bool{}
		for _, d := range limit {
			limitSet[d] = true
		}
	}

	// The ACME account and system key are only touched once a domain
	// actually needs a certificate: the steady state (everything
	// valid) contacts nothing.
	var cl *acme.Client
	var sysKey crypto.Signer
	var clientErr error
	installed := 0

	var results []Result
	for _, site := range webapply.Derive(in) {
		domain := site.Domain
		if limitSet != nil && !limitSet[domain] {
			continue
		}
		if pair, ok := certs[domain]; ok && !pair.SelfSigned && pair.Valid(now) && now.Add(renewBefore).Before(pair.NotAfter) {
			results = append(results, Result{domain, StatusSkipped,
				"certificate valid until " + pair.NotAfter.Format("2006-01-02")})
			continue
		}
		solver, why := p.Selector.Pick(ctx, domain)
		if solver == nil {
			results = append(results, Result{domain, StatusSkipped, why})
			continue
		}

		if cl == nil && clientErr == nil {
			sysKey, clientErr = loadSigner(filepath.Join(sslRoot, "ssl_private_key.pem"))
			if clientErr == nil {
				cl, clientErr = p.newClient(ctx)
			}
		}
		if clientErr != nil {
			results = append(results, Result{domain, StatusError, clientErr.Error()})
			continue
		}
		if err := p.provisionOne(ctx, cl, sysKey, solver, domain, sslRoot); err != nil {
			results = append(results, Result{domain, StatusError, err.Error()})
			continue
		}
		installed++
		results = append(results, Result{domain, StatusInstalled, ""})
	}

	if installed > 0 {
		p.postInstall(ctx, sslRoot)
	}
	return results
}
