package checks

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	entmetricsample "naust/daemon/internal/store/ent/metricsample"
)

func TestMedian(t *testing.T) {
	for _, c := range []struct {
		in   []float64
		want float64
	}{
		{nil, 0},
		{[]float64{3}, 3},
		{[]float64{1, 9}, 5},
		{[]float64{9, 1, 5}, 5},
		{[]float64{0, 0, 0, 100}, 0},
	} {
		if got := median(c.in); got != c.want {
			t.Errorf("median(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestZeroCrossing(t *testing.T) {
	day := 24 * time.Hour
	series := func(days int, f func(i int) float64) []sample {
		var out []sample
		for i := 0; i < days; i++ {
			out = append(out, sample{at: testNow.Add(time.Duration(i) * day), value: f(i)})
		}
		return out
	}

	// 100 GB shrinking 10/day: crosses zero at day 10.
	if at, ok := zeroCrossing(series(8, func(i int) float64 { return 100 - 10*float64(i) })); !ok {
		t.Error("shrinking series must cross")
	} else if want := testNow.Add(10 * day); at.Sub(want) > time.Hour || want.Sub(at) > time.Hour {
		t.Errorf("crossing = %v, want ~%v", at, want)
	}
	if _, ok := zeroCrossing(series(8, func(i int) float64 { return 100 })); ok {
		t.Error("flat series must not cross")
	}
	if _, ok := zeroCrossing(series(8, func(i int) float64 { return 100 + float64(i) })); ok {
		t.Error("rising series must not cross")
	}
	if _, ok := zeroCrossing(series(4, func(i int) float64 { return 100 - 30*float64(i) })); ok {
		t.Error("4 samples are too few")
	}
	short := []sample{
		{at: testNow, value: 100}, {at: testNow.Add(time.Hour), value: 90},
		{at: testNow.Add(2 * time.Hour), value: 80}, {at: testNow.Add(3 * time.Hour), value: 70},
		{at: testNow.Add(4 * time.Hour), value: 60},
	}
	if _, ok := zeroCrossing(short); ok {
		t.Error("a few hours of span must not project")
	}
}

func metricDeps(t *testing.T) *Deps {
	t.Helper()
	return &Deps{
		Store: testStore(t),
		Now:   func() time.Time { return testNow },
		Log:   log.New(os.Stderr, "", 0),
	}
}

func seedSamples(t *testing.T, d *Deps, metric string, samples []sample) {
	t.Helper()
	for _, smp := range samples {
		if err := d.Store.MetricSample.Create().
			SetMetric(metric).SetSampledAt(smp.at).SetValue(smp.value).
			Exec(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRecordSamplePrunesAndDailyDedupes(t *testing.T) {
	d := metricDeps(t)
	ctx := context.Background()
	seedSamples(t, d, "m", []sample{
		{at: testNow.Add(-8 * 24 * time.Hour), value: 1}, // beyond the 7d window
		{at: testNow.Add(-time.Hour), value: 2},
	})
	recordSample(ctx, d, "m", 3, 7*24*time.Hour)
	rows, err := d.Store.MetricSample.Query().Where(entmetricsample.Metric("m")).All(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows = %d (%v)", len(rows), err)
	}

	// A daily sample an hour after the last one is dropped...
	recordDailySample(ctx, d, "m", 4, 7*24*time.Hour)
	if n, _ := d.Store.MetricSample.Query().Where(entmetricsample.Metric("m")).Count(ctx); n != 2 {
		t.Errorf("daily dedupe failed: %d rows", n)
	}
	// ...but lands once the newest is a day old.
	d.Now = func() time.Time { return testNow.Add(25 * time.Hour) }
	recordDailySample(ctx, d, "m", 4, 7*24*time.Hour)
	if n, _ := d.Store.MetricSample.Query().Where(entmetricsample.Metric("m")).Count(ctx); n != 3 {
		t.Errorf("daily record failed: %d rows", n)
	}
}

// queueOutput fakes postqueue -j output with n queued messages.
func queueOutput(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "{\"queue_id\": \"%d\"}\n", i)
	}
	return b.String()
}

func TestQueueSpikeHeuristic(t *testing.T) {
	d := metricDeps(t)
	d.Run = func(ctx context.Context, argv ...string) (string, error) {
		return queueOutput(40), nil
	}
	// A day of near-empty queue samples every 5 minutes.
	var history []sample
	for at := testNow.Add(-24 * time.Hour); at.Before(testNow); at = at.Add(5 * time.Minute) {
		history = append(history, sample{at: at, value: 1})
	}
	seedSamples(t, d, "mail-queue-depth", history)

	_, _, steps := runCheck(t, d, checkMailQueue)
	spike := stepByName(t, steps, "Mail queue is near its usual size")
	if spike.Status != StatusWarning || !strings.Contains(spike.Message, "jumped to 40") {
		t.Errorf("spike = %+v", spike)
	}
	// The absolute threshold step stays ok: 40 < 100.
	if abs := stepByName(t, steps, "Mail queue is not backing up"); abs.Status != StatusOK {
		t.Errorf("absolute = %+v", abs)
	}

	// 40 queued with a usual depth of 10 is not a spike.
	d2 := metricDeps(t)
	d2.Run = d.Run
	history = history[:0]
	for at := testNow.Add(-24 * time.Hour); at.Before(testNow); at = at.Add(5 * time.Minute) {
		history = append(history, sample{at: at, value: 10})
	}
	seedSamples(t, d2, "mail-queue-depth", history)
	_, _, steps = runCheck(t, d2, checkMailQueue)
	if spike := stepByName(t, steps, "Mail queue is near its usual size"); spike.Status != StatusOK {
		t.Errorf("normal = %+v", spike)
	}

	// No history: records the first sample, judges nothing.
	d3 := metricDeps(t)
	d3.Run = d.Run
	_, _, steps = runCheck(t, d3, checkMailQueue)
	if spike := stepByName(t, steps, "Mail queue is near its usual size"); spike.Status != StatusOK {
		t.Errorf("cold start = %+v", spike)
	}
	if n, _ := d3.Store.MetricSample.Query().Count(context.Background()); n != 1 {
		t.Errorf("cold start rows = %d", n)
	}
}

func TestLoginFailureHeuristic(t *testing.T) {
	// Two weeks of hourly cumulative samples rising 2/hour, then 80
	// failures in the last hour.
	var history []sample
	total := 0.0
	for at := testNow.Add(-14 * 24 * time.Hour); at.Before(testNow); at = at.Add(time.Hour) {
		history = append(history, sample{at: at, value: total})
		total += 2
	}
	d := metricDeps(t)
	d.AuthFailures = func(context.Context) (int64, error) { return int64(total) + 80, nil }
	seedSamples(t, d, "auth-failures-total", history)

	status, msg, _ := runCheck(t, d, checkLoginFailures)
	if status != StatusWarning || !strings.Contains(msg, "failed admin login") {
		t.Errorf("spike = %s %q", status, msg)
	}

	// The usual rate stays quiet.
	d2 := metricDeps(t)
	d2.AuthFailures = func(context.Context) (int64, error) { return int64(total) + 2, nil }
	seedSamples(t, d2, "auth-failures-total", history)
	if status, msg, _ := runCheck(t, d2, checkLoginFailures); status != StatusOK {
		t.Errorf("normal = %s %q", status, msg)
	}

	// A counter reset (daemon restart) is not a spike.
	d3 := metricDeps(t)
	d3.AuthFailures = func(context.Context) (int64, error) { return 0, nil }
	seedSamples(t, d3, "auth-failures-total", history)
	if status, msg, _ := runCheck(t, d3, checkLoginFailures); status != StatusOK {
		t.Errorf("restart = %s %q", status, msg)
	}
}
