// Package kickloop runs a rebuild function on demand with coalescing:
// any number of Kicks while a run is in flight collapse into exactly
// one follow-up run. Failures self-retry, so a transient error heals
// without waiting for the next mutation.
package kickloop

import (
	"context"
	"log"
	"time"
)

type Loop struct {
	// Name prefixes log lines ("materialize", "dnsapply").
	Name string
	// Do performs one rebuild.
	Do  func(ctx context.Context) error
	Log *log.Logger
	// RetryAfter delays the automatic retry after a failed run. Zero
	// means 30 seconds.
	RetryAfter time.Duration
	// Tick re-runs periodically even without a kick, so a replica
	// that missed a mutation (another process handled the request)
	// still converges, and time-based work inside Do (RRSIG renewal)
	// gets evaluated. Zero disables the tick. Idle runs are cheap:
	// Do implementations hash-compare before writing.
	Tick time.Duration

	kick chan struct{}
}

// Kick requests a run. Never blocks; multiple kicks collapse.
func (l *Loop) Kick() {
	select {
	case l.kick <- struct{}{}:
	default:
	}
}

// Start runs the loop until ctx is cancelled. Call exactly once,
// before any Kick.
func (l *Loop) Start(ctx context.Context) {
	retry := l.RetryAfter
	if retry == 0 {
		retry = 30 * time.Second
	}
	l.kick = make(chan struct{}, 1)
	if l.Tick > 0 {
		go func() {
			t := time.NewTicker(l.Tick)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					l.Kick()
				}
			}
		}()
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-l.kick:
				if err := l.Do(ctx); err != nil && ctx.Err() == nil {
					l.Log.Printf("%s: rebuild failed (retrying in %s): %v", l.Name, retry, err)
					time.AfterFunc(retry, l.Kick)
				}
			}
		}
	}()
}
