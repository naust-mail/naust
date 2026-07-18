package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"naust/daemon/internal/store"
	"naust/daemon/internal/store/ent"
	entcheckresult "naust/daemon/internal/store/ent/checkresult"
)

const (
	defaultTimeout  = 30 * time.Second
	defaultParallel = 8
	tickEvery       = time.Minute
	startupDelay    = 90 * time.Second // let appliers converge first
	// leaseName/leaseTTL: scheduled passes (and the digest they end
	// with) run on one replica per store; the TTL covers a slow
	// full batch with room to spare.
	leaseName = "checks"
	leaseTTL  = 30 * time.Minute
)

// RunRequest selects checks for a manual run. Zero value = everything.
// A manual run ignores cadence and the admin's disabled flag (an
// explicit request wins over a schedule preference).
type RunRequest struct {
	Checks   []string // exact names; empty = no name filter
	Category string   // e.g. "system"; empty = no category filter
	Domain   string   // limit per-domain checks to one domain
}

// Engine schedules and runs the registered checks, persisting results
// to the store.
type Engine struct {
	Deps   Deps
	Checks []Check

	// MaxParallel bounds concurrent check runs (default 8);
	// CheckTimeout bounds one run (default 30s, per-check override
	// via Check.Timeout).
	MaxParallel  int
	CheckTimeout time.Duration

	mu      sync.Mutex
	pending []RunRequest
	kick    chan struct{}
	busy    atomic.Int32
	runMu   sync.Mutex // one batch at a time
}

// fillDefaults completes nil Deps seams with real implementations.
func (e *Engine) fillDefaults() {
	d := &e.Deps
	if d.Dial == nil {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		d.Dial = dialer.DialContext
	}
	if d.HTTP == nil {
		d.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	if d.Run == nil {
		d.Run = func(ctx context.Context, argv ...string) (string, error) {
			out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
			if err != nil {
				return string(out), fmt.Errorf("%s: %w: %s", argv[0], err, out)
			}
			return string(out), nil
		}
	}
	if d.ReadFile == nil {
		d.ReadFile = os.ReadFile
	}
	if d.PostfixQueue == nil {
		d.PostfixQueue = func(ctx context.Context) (string, error) {
			return d.Run(ctx, "/usr/sbin/postqueue", "-j")
		}
	}
	if d.Query == nil {
		d.Query = defaultDNSQuery
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = log.New(os.Stderr, "", log.LstdFlags)
	}
	if e.MaxParallel <= 0 {
		e.MaxParallel = defaultParallel
	}
	if e.CheckTimeout <= 0 {
		e.CheckTimeout = defaultTimeout
	}
}

// Kick wakes the scheduler early (manual runs use RunNow instead).
func (e *Engine) Kick() {
	if e.kick == nil {
		return
	}
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

// RunNow queues a manual run and wakes the scheduler. Never blocks.
func (e *Engine) RunNow(req RunRequest) {
	e.mu.Lock()
	e.pending = append(e.pending, req)
	e.mu.Unlock()
	e.busy.Add(1) // counted until the request is executed
	e.Kick()
}

// Busy reports whether a run is executing or queued.
func (e *Engine) Busy() bool {
	return e.busy.Load() > 0
}

// Start runs the scheduler until ctx is cancelled. Call once. The
// first pass runs every applicable check (after a startup delay so
// the appliers converge first); afterwards cadences and manual
// requests drive the work.
func (e *Engine) Start(ctx context.Context) {
	e.fillDefaults()
	e.kick = make(chan struct{}, 1)
	go func() {
		e.pruneStale(ctx)
		t := time.NewTimer(startupDelay)
		defer t.Stop()
		first := true
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			case <-e.kick:
			}
			for _, req := range e.drain() {
				e.runManual(ctx, req)
				e.busy.Add(-1)
			}
			if err := e.runDue(ctx, first); err != nil {
				e.Deps.Log.Printf("checks: %v", err)
			}
			first = false
			t.Reset(tickEvery)
		}
	}()
}

func (e *Engine) drain() []RunRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	reqs := e.pending
	e.pending = nil
	return reqs
}

// runDue executes every check whose latest result is older than its
// effective cadence. Admin-disabled checks get their stored result
// replaced by a "disabled" skip so the panel reflects the config.
func (e *Engine) runDue(ctx context.Context, all bool) error {
	// Manual panel runs stay ungated (one request reaches one
	// replica); the skip is silent because the lease holder is doing
	// this same work on the same store.
	got, err := store.AcquireLease(ctx, e.Deps.Store, leaseName, leaseTTL)
	if err != nil || !got {
		return err
	}
	defer func() {
		if err := store.ReleaseLease(ctx, e.Deps.Store, leaseName); err != nil {
			e.Deps.Log.Printf("checks: release lease: %v", err)
		}
	}()

	cfg, err := LoadConfig(ctx, e.Deps.Store)
	if err != nil {
		return err
	}
	newest, err := e.newestRuns(ctx)
	if err != nil {
		return err
	}
	now := e.Deps.Now()
	var due []Check
	for _, chk := range e.Checks {
		interval, enabled := cfg.effective(chk)
		if !enabled {
			e.saveDisabled(ctx, chk)
			continue
		}
		last, ran := newest[chk.Name]
		if all || !ran || now.Sub(last) >= interval {
			due = append(due, chk)
		}
	}
	if len(due) > 0 {
		e.busy.Add(1)
		e.runBatch(ctx, due, "", true)
		e.busy.Add(-1)
	}
	return e.maybeReport(ctx, cfg)
}

func (e *Engine) runManual(ctx context.Context, req RunRequest) {
	var selected []Check
	for _, chk := range e.Checks {
		if len(req.Checks) > 0 && !contains(req.Checks, chk.Name) {
			continue
		}
		if req.Category != "" && chk.Category != req.Category {
			continue
		}
		selected = append(selected, chk)
	}
	// prune=false: a filtered manual run must not delete rows for
	// domains it did not visit.
	e.runBatch(ctx, selected, req.Domain, req.Domain == "" && len(req.Checks) == 0 && req.Category == "")
}

// runBatch runs the given checks, dependencies within the batch
// first. Dependency gating uses just-run results when the dependency
// is in the batch, else the stored latest.
func (e *Engine) runBatch(ctx context.Context, batch []Check, domainFilter string, prune bool) {
	e.runMu.Lock()
	defer e.runMu.Unlock()

	inBatch := map[string]bool{}
	for _, chk := range batch {
		inBatch[chk.Name] = true
	}
	statuses := map[string]Status{} // check name -> just-run status
	var mu sync.Mutex

	// Waves: run everything whose in-batch dependencies are done.
	remaining := batch
	for len(remaining) > 0 {
		var wave, next []Check
		for _, chk := range remaining {
			ready := true
			for _, dep := range chk.DependsOn {
				mu.Lock()
				_, done := statuses[dep]
				mu.Unlock()
				if inBatch[dep] && !done {
					ready = false
					break
				}
			}
			if ready {
				wave = append(wave, chk)
			} else {
				next = append(next, chk)
			}
		}
		if len(wave) == 0 {
			// Dependency cycle or typo: record the rest as skipped.
			for _, chk := range remaining {
				e.saveResult(ctx, Result{Check: chk.Name, Category: chk.Category,
					Status: StatusSkipped, Message: "dependency could not be resolved", RanAt: e.Deps.Now()})
			}
			return
		}

		sem := make(chan struct{}, e.MaxParallel)
		var wg sync.WaitGroup
		for _, chk := range wave {
			if chk.Enabled != nil && !chk.Enabled(&e.Deps) {
				e.saveResult(ctx, Result{Check: chk.Name, Category: chk.Category,
					Status: StatusSkipped, Message: "not applicable", RanAt: e.Deps.Now()})
				mu.Lock()
				statuses[chk.Name] = StatusSkipped
				mu.Unlock()
				continue
			}
			if dep, bad := e.failedDependency(ctx, chk, statuses, &mu); bad {
				e.skipForDependency(ctx, chk, dep, domainFilter)
				mu.Lock()
				statuses[chk.Name] = StatusSkipped
				mu.Unlock()
				continue
			}
			wg.Add(1)
			go func(chk Check) {
				defer wg.Done()
				worst := e.runOne(ctx, chk, domainFilter, prune, sem)
				mu.Lock()
				statuses[chk.Name] = worst
				mu.Unlock()
			}(chk)
		}
		wg.Wait()
		remaining = next
	}
}

// failedDependency reports whether any dependency's status (just-run
// or stored) is error.
func (e *Engine) failedDependency(ctx context.Context, chk Check, statuses map[string]Status, mu *sync.Mutex) (string, bool) {
	for _, dep := range chk.DependsOn {
		mu.Lock()
		st, ok := statuses[dep]
		mu.Unlock()
		if !ok {
			row, err := e.Deps.Store.CheckResult.Query().
				Where(entcheckresult.CheckEQ(dep), entcheckresult.DomainEQ("")).
				Only(ctx)
			if err != nil {
				continue // no verdict on the dependency: run anyway
			}
			st = Status(row.Status)
		}
		if st == StatusError {
			return dep, true
		}
	}
	return "", false
}

func (e *Engine) skipForDependency(ctx context.Context, chk Check, dep, domainFilter string) {
	msg := fmt.Sprintf("skipped: %q failed", dep)
	domains := []string{""}
	if chk.Domains != nil {
		list, err := chk.Domains(ctx, &e.Deps)
		if err == nil {
			domains = filterDomains(list, domainFilter)
		}
	}
	for _, dom := range domains {
		e.saveResult(ctx, Result{Check: chk.Name, Category: chk.Category, Domain: dom,
			Status: StatusSkipped, Message: msg, RanAt: e.Deps.Now()})
	}
}

// runOne executes one check (fanning out per domain) and returns the
// worst status across its instances.
func (e *Engine) runOne(ctx context.Context, chk Check, domainFilter string, prune bool, sem chan struct{}) Status {
	domains := []string{""}
	if chk.Domains != nil {
		list, err := chk.Domains(ctx, &e.Deps)
		if err != nil {
			e.saveResult(ctx, Result{Check: chk.Name, Category: chk.Category,
				Status: StatusError, Message: fmt.Sprintf("list domains: %v", err), RanAt: e.Deps.Now()})
			return StatusError
		}
		domains = filterDomains(list, domainFilter)
	}

	worst := StatusOK
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, dom := range domains {
		sem <- struct{}{}
		wg.Add(1)
		go func(dom string) {
			defer wg.Done()
			defer func() { <-sem }()
			res := e.execute(ctx, chk, dom)
			e.saveResult(ctx, res)
			mu.Lock()
			if severity(res.Status) > severity(worst) {
				worst = res.Status
			}
			mu.Unlock()
		}(dom)
	}
	wg.Wait()

	// After a complete, unfiltered fan-out, rows for domains that no
	// longer exist are stale: remove them.
	if prune && chk.Domains != nil && domainFilter == "" {
		_, err := e.Deps.Store.CheckResult.Delete().
			Where(entcheckresult.CheckEQ(chk.Name), entcheckresult.DomainNotIn(domains...)).
			Exec(ctx)
		if err != nil {
			e.Deps.Log.Printf("checks: prune %s: %v", chk.Name, err)
		}
	}
	return worst
}

func (e *Engine) execute(ctx context.Context, chk Check, domain string) Result {
	timeout := e.CheckTimeout
	if chk.Timeout > 0 {
		timeout = chk.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	r := &Reporter{now: e.Deps.Now}
	start := e.Deps.Now()
	chk.Run(ctx, &e.Deps, domain, r)
	status, message := summarize(r.steps)
	if len(r.steps) == 0 {
		status, message = StatusOK, ""
	}
	return Result{
		Check: chk.Name, Category: chk.Category, Domain: domain,
		Status: status, Message: message, Steps: r.steps,
		RanAt: start, Elapsed: e.Deps.Now().Sub(start),
	}
}

// pruneStale deletes stored results whose check no longer exists in
// the registered set. Without this, a removed or renamed check's last
// result sits on the status page forever with nothing to update it.
func (e *Engine) pruneStale(ctx context.Context) {
	known := make([]string, 0, len(e.Checks))
	for _, chk := range e.Checks {
		known = append(known, chk.Name)
	}
	n, err := e.Deps.Store.CheckResult.Delete().
		Where(entcheckresult.CheckNotIn(known...)).
		Exec(ctx)
	if err != nil {
		e.Deps.Log.Printf("checks: prune stale results: %v", err)
	} else if n > 0 {
		e.Deps.Log.Printf("checks: pruned %d results from removed checks", n)
	}
}

// saveResult upserts the (check, domain) row, maintaining
// first_failed_at: set on entering warning/error, preserved while
// failing, cleared on recovery.
func (e *Engine) saveResult(ctx context.Context, res Result) {
	stepsJSON, err := json.Marshal(res.Steps)
	if err != nil || res.Steps == nil {
		stepsJSON = []byte("[]")
	}

	failing := res.Status == StatusWarning || res.Status == StatusError
	prev, err := e.Deps.Store.CheckResult.Query().
		Where(entcheckresult.CheckEQ(res.Check), entcheckresult.DomainEQ(res.Domain)).
		Only(ctx)
	switch {
	case err == nil:
		upd := prev.Update().
			SetCategory(res.Category).
			SetStatus(string(res.Status)).
			SetMessage(res.Message).
			SetSteps(string(stepsJSON)).
			SetRanAt(res.RanAt).
			SetElapsedMs(res.Elapsed.Milliseconds())
		switch {
		case !failing:
			upd = upd.ClearFirstFailedAt()
		case prev.FirstFailedAt != nil &&
			(Status(prev.Status) == StatusWarning || Status(prev.Status) == StatusError):
			// Still failing: keep the original onset time.
		default:
			upd = upd.SetFirstFailedAt(res.RanAt)
		}
		err = upd.Exec(ctx)
	case ent.IsNotFound(err):
		create := e.Deps.Store.CheckResult.Create().
			SetCheck(res.Check).
			SetDomain(res.Domain).
			SetCategory(res.Category).
			SetStatus(string(res.Status)).
			SetMessage(res.Message).
			SetSteps(string(stepsJSON)).
			SetRanAt(res.RanAt).
			SetElapsedMs(res.Elapsed.Milliseconds())
		if failing {
			create = create.SetFirstFailedAt(res.RanAt)
		}
		err = create.Exec(ctx)
	}
	if err != nil {
		e.Deps.Log.Printf("checks: save %s/%s: %v", res.Check, res.Domain, err)
	}
}

// saveDisabled records the admin's off switch unless already recorded.
func (e *Engine) saveDisabled(ctx context.Context, chk Check) {
	row, err := e.Deps.Store.CheckResult.Query().
		Where(entcheckresult.CheckEQ(chk.Name), entcheckresult.DomainEQ("")).
		Only(ctx)
	if err == nil && Status(row.Status) == StatusSkipped && row.Message == "disabled by configuration" {
		return
	}
	// Per-domain rows of a disabled check are stale; a single
	// domainless row represents it.
	_, _ = e.Deps.Store.CheckResult.Delete().
		Where(entcheckresult.CheckEQ(chk.Name), entcheckresult.DomainNEQ("")).
		Exec(ctx)
	e.saveResult(ctx, Result{Check: chk.Name, Category: chk.Category,
		Status: StatusSkipped, Message: "disabled by configuration", RanAt: e.Deps.Now()})
}

// newestRuns maps each check name to its most recent ran_at.
func (e *Engine) newestRuns(ctx context.Context) (map[string]time.Time, error) {
	rows, err := e.Deps.Store.CheckResult.Query().All(ctx)
	if err != nil {
		return nil, err
	}
	newest := map[string]time.Time{}
	for _, row := range rows {
		if t, ok := newest[row.Check]; !ok || row.RanAt.After(t) {
			newest[row.Check] = row.RanAt
		}
	}
	return newest, nil
}

func filterDomains(domains []string, filter string) []string {
	if filter == "" {
		return domains
	}
	for _, d := range domains {
		if d == filter {
			return []string{d}
		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
