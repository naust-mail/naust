package kickloop

import (
	"context"
	"errors"
	"io"
	"log"
	"sync/atomic"
	"testing"
	"time"
)

func discardLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

func waitForCount(t *testing.T, got *int32, want int32, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(got) >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("count = %d, want >= %d within %s", atomic.LoadInt32(got), want, timeout)
}

func TestLoopRunsOnKick(t *testing.T) {
	var calls int32
	l := &Loop{
		Name: "test",
		Do:   func(ctx context.Context) error { atomic.AddInt32(&calls, 1); return nil },
		Log:  discardLogger(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.Start(ctx)

	l.Kick()
	waitForCount(t, &calls, 1, time.Second)
}

func TestLoopKickBeforeStartIsNotLost(t *testing.T) {
	// Kick is documented as callable only after Start, but a kick that
	// arrives the instant Start wires the channel must still register
	// rather than panic or silently vanish.
	var calls int32
	l := &Loop{
		Name: "test",
		Do:   func(ctx context.Context) error { atomic.AddInt32(&calls, 1); return nil },
		Log:  discardLogger(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.Start(ctx)
	l.Kick()
	waitForCount(t, &calls, 1, time.Second)
}

// TestLoopCoalescesConcurrentKicks proves the central promise of the
// package: any number of kicks that land while a run is already in
// flight collapse into exactly one follow-up run, not one per kick.
func TestLoopCoalescesConcurrentKicks(t *testing.T) {
	var calls int32
	release := make(chan struct{})
	inFirstRun := make(chan struct{})
	l := &Loop{
		Name: "test",
		Do: func(ctx context.Context) error {
			n := atomic.AddInt32(&calls, 1)
			if n == 1 {
				close(inFirstRun)
				<-release
			}
			return nil
		},
		Log: discardLogger(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.Start(ctx)

	l.Kick()
	<-inFirstRun // first run is now blocked inside Do

	// Ten kicks while the first run is in flight must collapse to one
	// follow-up run, not ten.
	for i := 0; i < 10; i++ {
		l.Kick()
	}
	close(release)

	waitForCount(t, &calls, 2, time.Second)
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("calls = %d, want exactly 2 (coalesced run), extra kicks were not collapsed", got)
	}
}

// TestLoopRetriesOnFailure proves a failed run self-heals: it retries
// after RetryAfter without needing an external Kick.
func TestLoopRetriesOnFailure(t *testing.T) {
	var calls int32
	l := &Loop{
		Name: "test",
		Do: func(ctx context.Context) error {
			if atomic.AddInt32(&calls, 1) == 1 {
				return errors.New("transient failure")
			}
			return nil
		},
		Log:        discardLogger(),
		RetryAfter: 20 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.Start(ctx)

	l.Kick()
	waitForCount(t, &calls, 2, time.Second)
}

// TestLoopTicksWithoutExplicitKick proves Tick drives runs on its own,
// which is what lets a replica that missed another process's kick
// still converge.
func TestLoopTicksWithoutExplicitKick(t *testing.T) {
	var calls int32
	l := &Loop{
		Name: "test",
		Do:   func(ctx context.Context) error { atomic.AddInt32(&calls, 1); return nil },
		Log:  discardLogger(),
		Tick: 10 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.Start(ctx)

	waitForCount(t, &calls, 3, time.Second)
}

// TestLoopStopsRetryingAfterContextCancel proves a run failing right
// as the loop is cancelled does not keep the retry timer alive
// producing runs after Start's goroutine has already exited.
func TestLoopStopsRetryingAfterContextCancel(t *testing.T) {
	var calls int32
	l := &Loop{
		Name:       "test",
		Do:         func(ctx context.Context) error { atomic.AddInt32(&calls, 1); return errors.New("always fails") },
		Log:        discardLogger(),
		RetryAfter: 10 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	l.Start(ctx)

	l.Kick()
	waitForCount(t, &calls, 1, time.Second)
	cancel()

	seenAtCancel := atomic.LoadInt32(&calls)
	time.Sleep(100 * time.Millisecond) // well past RetryAfter
	if got := atomic.LoadInt32(&calls); got != seenAtCancel {
		t.Errorf("calls grew from %d to %d after context cancellation; retry kept firing post-shutdown", seenAtCancel, got)
	}
}
