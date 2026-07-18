// Package checkview turns the daemon's stored health-check results into a
// render-ready snapshot for `boxctl doctor` and `boxctl status`. Per the Model-B
// design, managerd is the ONLY thing that runs checks; boxctl reads the stored
// CheckResult rows directly (so it works even when the daemon is down, showing
// them stale) and joins them with the check catalog (checks.All()) for each
// check's Title and Class. It does NOT re-run or re-implement any check.
//
// The snapshot is grouped by category and carries each check's Class so the
// renderers can apply the collapse rule (quiet folds when all-ok, metric never
// folds); the collapse itself is a rendering concern and lives in the renderers.
package checkview

import (
	"context"
	"encoding/json"
	"time"

	"naust/daemon/internal/api"
	"naust/daemon/internal/checks"
	"naust/daemon/internal/store/ent"
	entcheckresult "naust/daemon/internal/store/ent/checkresult"
)

// Status values as stored by the check engine.
const (
	StatusOK      = "ok"
	StatusWarning = "warning"
	StatusError   = "error"
	StatusSkipped = "skipped"
)

// Meta is the catalog metadata for one check, joined onto its result.
type Meta struct {
	Title      string
	ShortLabel string
	Class      string
}

// Row is one stored result joined with its catalog metadata.
type Row struct {
	Name       string // check key (CheckResult.Check / catalog Name)
	Title      string
	ShortLabel string // one-word metric badge tag; empty for non-metric checks
	Category   string
	Class      string // standard / quiet / metric
	Domain     string // empty for box-global checks
	Status     string
	Message    string
	Steps      []api.CheckStep
	RanAt      time.Time
}

// Group is the checks of one category, in the engine's stable order.
type Group struct {
	Category string
	Rows     []Row
}

// Snapshot is the whole render-ready view of the last stored results.
type Snapshot struct {
	Groups  []Group
	LastRun time.Time // most recent RanAt across all rows; zero if none
	OK      int
	Warning int
	Error   int
	Skipped int
}

// ExitCode is the 3-valued convention for `boxctl status`: 2 if anything is in
// error, 1 if there are warnings but no errors, 0 if all clear.
func (s Snapshot) ExitCode() int {
	switch {
	case s.Error > 0:
		return 2
	case s.Warning > 0:
		return 1
	default:
		return 0
	}
}

// Load reads the stored results and joins them with the live check catalog.
func Load(ctx context.Context, client *ent.Client) (Snapshot, error) {
	rows, err := client.CheckResult.Query().
		Order(entcheckresult.ByCategory(), entcheckresult.ByCheck(), entcheckresult.ByDomain()).
		All(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	return build(rows, catalog()), nil
}

// catalog maps check name -> metadata from the live check definitions.
func catalog() map[string]Meta {
	out := make(map[string]Meta)
	for _, c := range checks.All() {
		title := c.Title
		if title == "" {
			title = c.Name
		}
		class := string(c.Class)
		if class == "" {
			class = string(checks.ClassStandard)
		}
		out[c.Name] = Meta{Title: title, ShortLabel: c.ShortLabel, Class: class}
	}
	return out
}

// build joins result rows with catalog metadata and groups them by category.
// Pure so it is testable without a store or the real catalog. Rows must already
// be ordered by (category, check, domain), as the store query returns them.
func build(rows []*ent.CheckResult, cat map[string]Meta) Snapshot {
	var snap Snapshot
	var cur *Group
	for _, r := range rows {
		meta, ok := cat[r.Check]
		if !ok {
			// A retired check with a lingering row: show it honestly rather
			// than dropping it, titled by its key, treated as standard.
			meta = Meta{Title: r.Check, Class: string(checks.ClassStandard)}
		}
		if cur == nil || cur.Category != r.Category {
			snap.Groups = append(snap.Groups, Group{Category: r.Category})
			cur = &snap.Groups[len(snap.Groups)-1]
		}
		cur.Rows = append(cur.Rows, Row{
			Name:       r.Check,
			Title:      meta.Title,
			ShortLabel: meta.ShortLabel,
			Category:   r.Category,
			Class:      meta.Class,
			Domain:     r.Domain,
			Status:     r.Status,
			Message:    r.Message,
			Steps:      decodeSteps(r.Steps),
			RanAt:      r.RanAt,
		})
		if r.RanAt.After(snap.LastRun) {
			snap.LastRun = r.RanAt
		}
		switch r.Status {
		case StatusOK:
			snap.OK++
		case StatusWarning:
			snap.Warning++
		case StatusError:
			snap.Error++
		case StatusSkipped:
			snap.Skipped++
		}
	}
	return snap
}

// decodeSteps parses the engine's JSON step blob; a bad/empty blob yields none.
func decodeSteps(blob string) []api.CheckStep {
	if blob == "" {
		return nil
	}
	var steps []api.CheckStep
	if err := json.Unmarshal([]byte(blob), &steps); err != nil {
		return nil
	}
	return steps
}
