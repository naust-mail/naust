package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"naust/daemon/internal/api"
	"naust/daemon/internal/checkview"
	"naust/daemon/internal/liveness"
)

// ── palette ──────────────────────────────────────────────────────────────────
// Ported from the original boxctl (setup/boxctl/ui.py + doctor.py) so this screen
// is the same product, not a new theme: lavender accent with exactly one job
// (selection), a white/gray neutral ramp, and vivid status colors - green ok,
// gold warning, red error - so a healthy box reads calm and problems pop.
const (
	contentWidth = 74
	detailIndent = "     " // 5 spaces: aligns the tree under the category name
	detailFillW  = contentWidth - 5
	rowW         = detailFillW - 3 // leaves room for the "├─ " connector so values align
)

var (
	accent    = lipgloss.NewStyle().Foreground(lipgloss.Color("#A6AFF3")).Bold(true) // cursor + selected label
	primary   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))            // labels
	secondary = lipgloss.NewStyle().Foreground(lipgloss.Color("#989BA1"))            // messages, values
	chrome    = lipgloss.NewStyle().Foreground(lipgloss.Color("#676972"))            // dividers, chevrons, footer
	okStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#3FB950"))            // green ok
	warnStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))                // gold (downsample-safe)
	errStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555"))            // red
)

// glyph returns the status marker: green tick for ok, gold ! for warning, red ✗
// for error, dim - for skipped/unknown.
func glyph(status string) string {
	switch status {
	case checkview.StatusOK:
		return okStyle.Render("✓")
	case checkview.StatusWarning:
		return warnStyle.Render("!")
	case checkview.StatusError:
		return errStyle.Render("✗")
	default: // skipped / unknown
		return chrome.Render("-")
	}
}

type doctorModel struct {
	hostname string
	probes   []liveness.Result
	snap     checkview.Snapshot
	cats     []checkview.Group // fixed order: daemon first, then the roster
	expanded map[string]bool
	cursor   int
	quitting bool
}

func newDoctorModel(hostname string, probes []liveness.Result, snap checkview.Snapshot) doctorModel {
	cats := append([]checkview.Group{daemonGroup(probes)}, snap.Groups...)
	return doctorModel{hostname: hostname, probes: probes, snap: snap, cats: cats, expanded: map[string]bool{}}
}

func (m doctorModel) Init() tea.Cmd { return nil }

func (m doctorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "q", "esc", "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.cats)-1 {
			m.cursor++
		}
	case "enter", " ":
		k := "cat:" + m.cats[m.cursor].Category
		m.expanded[k] = !m.expanded[k]
	}
	return m, nil
}

func (m doctorModel) View() string {
	if m.quitting {
		return ""
	}
	var b strings.Builder

	// Header: a line of breathing room, title + host, then a rule.
	title := primary.Bold(true).Render("boxctl doctor")
	host := secondary.Render(m.hostname)
	pad := max(1, contentWidth-lipgloss.Width(title)-lipgloss.Width(host))
	b.WriteString("\n  " + title + strings.Repeat(" ", pad) + host + "\n")
	b.WriteString("  " + chrome.Render(strings.Repeat("─", contentWidth)) + "\n\n")

	if !liveness.AllOK(m.probes) {
		b.WriteString("  " + chrome.Render("results below reflect the last successful run, not re-verified") + "\n\n")
	}

	for i, g := range m.cats {
		b.WriteString(m.renderCategory(g, i == m.cursor))
	}

	b.WriteString("\n  " + secondary.Render(m.summaryLine()) + "\n")
	b.WriteString("\n" + chrome.Render("  ↑↓ navigate · enter expand · q quit") + "\n")
	return b.String()
}

// renderCategory renders one category as a collapsible one-liner: chevron, status
// glyph, name, and a count + inline metric badges. When expanded it lists its
// checks underneath. The selected row gets the accent cursor and a tinted name.
func (m doctorModel) renderCategory(g checkview.Group, selected bool) string {
	key := "cat:" + g.Category
	expanded := m.expanded[key]
	worst := worstStatus(g.Rows)

	gutter := "   "
	chev := chrome.Render("▸")
	if expanded {
		chev = chrome.Render("▾")
	}
	name := fmt.Sprintf("%-9s", strings.ToUpper(g.Category))
	nameStyled := primary.Bold(true).Render(name) // the category is the anchor: bold
	if selected {
		gutter = " " + accent.Render("❯") + " "
		nameStyled = accent.Render(name)
	}

	// Count sits in a fixed column right after the name so the eye can scan it.
	// Metric badges give a peek while collapsed, but drop once expanded - the
	// check rows show those same numbers.
	label := m.countLabel(g, worst)
	if !expanded {
		label += metricBadges(g.Rows)
	}
	out := gutter + chev + " " + glyph(worst) + "  " + nameStyled + "  " + secondary.Render(label) + "\n"

	if !expanded {
		return out
	}
	var b strings.Builder
	b.WriteString(out)
	var lines []string
	renderTree(m.categoryTree(g), detailIndent, &lines)
	for _, ln := range lines {
		b.WriteString(ln + "\n")
	}
	return b.String()
}

// node is one item in the expanded category tree. text is already styled; the
// connector prefix is added at render time.
type node struct {
	text     string
	children []node
}

// renderTree draws nodes with box-drawing connectors, recursing into children
// with a continuation prefix (│ under a sibling that follows, blank under the
// last one).
func renderTree(nodes []node, prefix string, out *[]string) {
	for i, n := range nodes {
		last := i == len(nodes)-1
		branch, cont := "├─ ", "│  "
		if last {
			branch, cont = "└─ ", "   "
		}
		*out = append(*out, prefix+chrome.Render(branch)+n.text)
		renderTree(n.children, prefix+chrome.Render(cont), out)
		// After a node that opened a sub-tree, carry the │ through one blank line
		// so the multi-line block is set off from the next sibling.
		if len(n.children) > 0 && !last {
			*out = append(*out, prefix+chrome.Render("│"))
		}
	}
}

// countLabel is the right-hand summary for a collapsed category: "N checks ok"
// when clean, or the failing/warning tally when not.
func (m doctorModel) countLabel(g checkview.Group, worst string) string {
	if worst == checkview.StatusError || worst == checkview.StatusWarning {
		errs, warns := countStatuses(g.Rows)
		var parts []string
		if errs > 0 {
			parts = append(parts, fmt.Sprintf("%d failing", errs))
		}
		if warns > 0 {
			parts = append(parts, fmt.Sprintf("%d warning", warns))
		}
		return strings.Join(parts, ", ")
	}
	return fmt.Sprintf("%d checks ok", distinctChecks(g.Rows))
}

// categoryTree builds the child nodes of an expanded category, ordered errors
// first, then warnings, then ok, alphabetical within each tier. A failing check
// carries its expected/observed steps as children (and each step its fix hint);
// passing "quiet" checks collapse to a single trailing count.
func (m doctorModel) categoryTree(g checkview.Group) []node {
	var nodes []node
	quietOK := 0
	for _, grp := range sortedCheckGroups(g.Rows) {
		if len(grp) > 1 {
			nodes = append(nodes, perDomainNode(grp))
			continue
		}
		r := grp[0]
		if r.Class == "quiet" && r.Status == checkview.StatusOK {
			quietOK++
			continue
		}
		nodes = append(nodes, checkNode(r))
	}
	if quietOK > 0 {
		nodes = append(nodes, node{text: secondary.Render(fmt.Sprintf("%d background checks passing", quietOK))})
	}
	return nodes
}

func checkNode(r checkview.Row) node {
	n := node{text: rowText(r.Status, r.Title, rowMessage(r))}
	if r.Status != checkview.StatusError && r.Status != checkview.StatusWarning {
		return n
	}
	// A step earns a child line only when it says something the row does not (a
	// distinct sub-check with its own expected/observed). A fix hint hangs off
	// the check itself, not the step - it fixes the whole check.
	for _, s := range r.Steps {
		if txt := stepText(s); txt != "" {
			n.children = append(n.children, node{text: secondary.Render(txt)})
		}
		if s.FixHint != "" {
			n.children = append(n.children, node{text: secondary.Render("fix: " + s.FixHint)})
		}
	}
	return n
}

// perDomainNode renders a check that fanned out across domains: one summary line
// with each failing domain as a child.
func perDomainNode(rows []checkview.Row) node {
	var bad []checkview.Row
	for _, r := range rows {
		if r.Status != checkview.StatusOK {
			bad = append(bad, r)
		}
	}
	msg := fmt.Sprintf("%d/%d domains ok", len(rows), len(rows))
	if len(bad) > 0 {
		msg = fmt.Sprintf("%d of %d domains", len(bad), len(rows))
	}
	n := node{text: rowText(worstStatus(rows), rows[0].Title, msg)}
	for _, r := range bad {
		n.children = append(n.children, node{text: secondary.Render(r.Domain + "  " + r.Message)})
	}
	return n
}

func rowMessage(r checkview.Row) string {
	if r.Message != "" {
		return r.Message
	}
	return r.Status
}

// rowText lays a check on the left and its value on the right, filled to rowW so
// values line up under a category. Hierarchy lives here: an ok check is a dim,
// glyph-less label so a healthy category reads as a calm list; only a warning or
// error gets a colored mark and a brightened title, so problems are the only
// thing that pops.
func rowText(status, title, right string) string {
	mark := chrome.Render("✓") // dim tick: quiet confirmation, not a wall of green
	titleStyle := secondary
	switch status {
	case checkview.StatusError:
		mark = errStyle.Render("✗")
		titleStyle = primary
	case checkview.StatusWarning:
		mark = warnStyle.Render("!")
		titleStyle = primary
	case checkview.StatusSkipped:
		mark = chrome.Render("-")
	}
	return fill(mark+"  "+titleStyle.Render(title), secondary.Render(right), rowW)
}

func (m doctorModel) summaryLine() string {
	errs, warns := m.snap.Error, m.snap.Warning
	if !liveness.AllOK(m.probes) {
		de, dw := countStatuses(daemonGroup(m.probes).Rows)
		errs += de
		warns += dw
	}
	base := "All checks passing."
	if errs > 0 || warns > 0 {
		base = fmt.Sprintf("%d error, %d warning.", errs, warns)
	}
	if !m.snap.LastRun.IsZero() {
		if time.Since(m.snap.LastRun) < time.Minute {
			base += "  Last run just now."
		} else {
			base += "  Last run " + ago(m.snap.LastRun) + " ago."
		}
	}
	return base
}

// ── categories & ordering ────────────────────────────────────────────────────

// daemonGroup turns the liveness probes into a first-class category so the daemon
// renders exactly like any other: a collapsed one-liner that expands to its
// probes, red when down. The first failing probe carries the restart fix hint.
func daemonGroup(probes []liveness.Result) checkview.Group {
	var rows []checkview.Row
	fixShown := false
	for _, p := range probes {
		st := checkview.StatusOK
		var steps []api.CheckStep
		if !p.OK {
			st = checkview.StatusError
			// A probe is atomic: its row (title + observed detail) says it all, so
			// no expected/observed child. Only the first failure carries the fix.
			if !fixShown {
				steps = []api.CheckStep{{FixHint: "sudo systemctl restart naust-managerd"}}
				fixShown = true
			}
		}
		rows = append(rows, checkview.Row{
			Name: "daemon:" + p.Name, Title: p.Name, Category: "daemon",
			Class: "standard", Status: st, Message: p.Detail, Steps: steps, RanAt: time.Now(),
		})
	}
	return checkview.Group{Category: "daemon", Rows: rows}
}

// sortedCheckGroups groups a category's rows by check (keeping per-domain fan-outs
// together) then orders those groups errors first, warnings next, ok last, and
// alphabetically by title within each tier.
func sortedCheckGroups(rows []checkview.Row) [][]checkview.Row {
	groups := groupByCheck(rows)
	sort.SliceStable(groups, func(i, j int) bool {
		ti, tj := statusTier(worstStatus(groups[i])), statusTier(worstStatus(groups[j]))
		if ti != tj {
			return ti < tj
		}
		return groups[i][0].Title < groups[j][0].Title
	})
	return groups
}

func statusTier(status string) int {
	switch status {
	case checkview.StatusError:
		return 0
	case checkview.StatusWarning:
		return 1
	default:
		return 2
	}
}

func worstStatus(rows []checkview.Row) string {
	worst := checkview.StatusOK
	for _, r := range rows {
		if statusTier(r.Status) < statusTier(worst) {
			worst = r.Status
		}
	}
	return worst
}

func countStatuses(rows []checkview.Row) (errs, warns int) {
	for _, r := range rows {
		switch r.Status {
		case checkview.StatusError:
			errs++
		case checkview.StatusWarning:
			warns++
		}
	}
	return
}

// ── helpers ──────────────────────────────────────────────────────────────────

func distinctChecks(rows []checkview.Row) int {
	seen := map[string]bool{}
	for _, r := range rows {
		seen[r.Name] = true
	}
	return len(seen)
}

// metricBadges appends each metric-class check's value inline, so the collapsed
// category line still shows the numbers worth glancing at.
func metricBadges(rows []checkview.Row) string {
	var out string
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Class != "metric" || seen[r.Name] {
			continue
		}
		seen[r.Name] = true
		if r.Message == "" {
			continue
		}
		out += "  ·  " + metricLabel(r) + " " + r.Message
	}
	return out
}

// metricLabel is the badge tag for a metric row: the check definition's
// ShortLabel when set, otherwise a dumb shortening of the Title as a fallback
// for rows with no catalog entry.
func metricLabel(r checkview.Row) string {
	if r.ShortLabel != "" {
		return r.ShortLabel
	}
	return strings.TrimPrefix(strings.ToLower(r.Title), "free ")
}

func groupByCheck(rows []checkview.Row) [][]checkview.Row {
	var out [][]checkview.Row
	for _, r := range rows {
		if n := len(out); n > 0 && out[n-1][0].Name == r.Name {
			out[n-1] = append(out[n-1], r)
			continue
		}
		out = append(out, []checkview.Row{r})
	}
	return out
}

// fill lays a pre-styled left label and right value across width, measuring
// ANSI-stripped so colored glyphs never break alignment.
func fill(left, right string, width int) string {
	gap := width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
}

func stepText(s api.CheckStep) string {
	switch {
	case s.Expected != "" || s.Observed != "":
		return fmt.Sprintf("%s  expected: %s  observed: %s", s.Name, s.Expected, s.Observed)
	case s.Message != "":
		return s.Name + "  " + s.Message
	default:
		return s.Name
	}
}

// ago renders how long since t in a compact form ("3m", "4h", "2d").
func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ── command ──────────────────────────────────────────────────────────────────

func runDoctor(demo string, printOnce bool) error {
	hostname, probes, snap := demoData(demo)
	if demo == "" {
		if err := ensureNaust(); err != nil {
			return err
		}
		b, err := openStore()
		if err != nil {
			return err
		}
		defer b.client.Close()
		s, err := checkview.Load(context.Background(), b.client)
		if err != nil {
			return err
		}
		hostname, probes, snap = b.hostname, b.livenessConfig().Probe(), s
	}
	model := newDoctorModel(hostname, probes, snap)
	if printOnce {
		fmt.Print(model.View())
		return nil
	}
	_, err := tea.NewProgram(model, tea.WithAltScreen()).Run()
	return err
}

func doctorCommand() *cobra.Command {
	var demo string
	var printOnce bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Interactive health dashboard",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return runDoctor(demo, printOnce)
		},
	}
	cmd.Flags().StringVar(&demo, "demo", "", "render fake data for testing: healthy | failures | down")
	cmd.Flags().BoolVar(&printOnce, "print", false, "render once to stdout instead of the interactive TUI")
	return cmd
}
