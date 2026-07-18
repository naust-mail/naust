package checks

import (
	"context"
	"sort"
	"time"

	"entgo.io/ent/dialect/sql"

	entmetricsample "naust/daemon/internal/store/ent/metricsample"
)

// Metric samples back the three deviation heuristics. Checks write
// them at their own cadence and prune per metric, so the store never
// grows beyond a bounded window. The rule for heuristics themselves:
// exactly the three below, no sensitivity knobs, and one that cries
// wolf gets deleted, not tuned.

type sample struct {
	at    time.Time
	value float64
}

// recordSample appends one observation and prunes the metric's window.
func recordSample(ctx context.Context, d *Deps, metric string, value float64, keep time.Duration) {
	err := d.Store.MetricSample.Create().
		SetMetric(metric).
		SetSampledAt(d.Now()).
		SetValue(value).
		Exec(ctx)
	if err != nil {
		d.Log.Printf("checks: sample %s: %v", metric, err)
		return
	}
	_, err = d.Store.MetricSample.Delete().
		Where(entmetricsample.Metric(metric), entmetricsample.SampledAtLT(d.Now().Add(-keep))).
		Exec(ctx)
	if err != nil {
		d.Log.Printf("checks: prune %s: %v", metric, err)
	}
}

// recordDailySample records only when the newest sample is at least
// ~a day old, so fast-cadence checks can carry slow-moving metrics.
func recordDailySample(ctx context.Context, d *Deps, metric string, value float64, keep time.Duration) {
	last, err := d.Store.MetricSample.Query().
		Where(entmetricsample.Metric(metric)).
		Order(entmetricsample.BySampledAt(sql.OrderDesc())).
		First(ctx)
	if err == nil && d.Now().Sub(last.SampledAt) < 23*time.Hour {
		return
	}
	recordSample(ctx, d, metric, value, keep)
}

// samplesSince returns the metric's samples newer than since, oldest
// first. Heuristics read their baseline BEFORE recording the current
// observation so a spike cannot feed its own median.
func samplesSince(ctx context.Context, d *Deps, metric string, since time.Time) ([]sample, error) {
	rows, err := d.Store.MetricSample.Query().
		Where(entmetricsample.Metric(metric), entmetricsample.SampledAtGT(since)).
		Order(entmetricsample.BySampledAt()).
		All(ctx)
	if err != nil {
		return nil, err
	}
	var out []sample
	for _, row := range rows {
		out = append(out, sample{at: row.SampledAt, value: row.Value})
	}
	return out, nil
}

func median(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}

// zeroCrossing fits a least-squares line through the samples and
// returns when it reaches zero. ok is false when the trend is flat,
// rising, or there are too few points spread over too little time to
// mean anything (under 5 samples or 3 days).
func zeroCrossing(samples []sample) (time.Time, bool) {
	if len(samples) < 5 {
		return time.Time{}, false
	}
	t0 := samples[0].at
	span := samples[len(samples)-1].at.Sub(t0)
	if span < 3*24*time.Hour {
		return time.Time{}, false
	}
	var n, sumX, sumY, sumXX, sumXY float64
	for _, s := range samples {
		x := s.at.Sub(t0).Hours()
		n++
		sumX += x
		sumY += s.value
		sumXX += x * x
		sumXY += x * s.value
	}
	denom := n*sumXX - sumX*sumX
	if denom == 0 {
		return time.Time{}, false
	}
	slope := (n*sumXY - sumX*sumY) / denom
	intercept := (sumY - slope*sumX) / n
	if slope >= 0 || intercept <= 0 {
		return time.Time{}, false
	}
	hours := -intercept / slope
	return t0.Add(time.Duration(hours * float64(time.Hour))), true
}
