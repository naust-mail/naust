package checks

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"naust/daemon/internal/store/ent"
	entcheckresult "naust/daemon/internal/store/ent/checkresult"
	entsetting "naust/daemon/internal/store/ent/setting"
)

// settingReportSent records when the last digest went out, so the
// schedule survives restarts and replicas do not double-send.
const settingReportSent = "status_checks_report_sent"

// maybeReport sends the status digest when one is due. Digests only
// go out when something is warning or failing: a healthy box is
// silent. The first due time is measured from when reporting was
// (re)enabled, not from the beginning of time.
func (e *Engine) maybeReport(ctx context.Context, cfg Config) error {
	var interval time.Duration
	switch cfg.Report {
	case "daily":
		interval = 24 * time.Hour
	case "weekly":
		interval = 7 * 24 * time.Hour
	default:
		return nil
	}

	row, err := e.Deps.Store.Setting.Query().
		Where(entsetting.Key(settingReportSent)).
		Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return err
	}
	now := e.Deps.Now()
	if row == nil {
		return e.markReported(ctx, now)
	}
	last, err := time.Parse(time.RFC3339, row.Value)
	if err != nil || now.Sub(last) < interval {
		return nil
	}

	rows, err := e.Deps.Store.CheckResult.Query().
		Where(entcheckresult.StatusIn(string(StatusWarning), string(StatusError))).
		Order(entcheckresult.ByCategory(), entcheckresult.ByCheck(), entcheckresult.ByDomain()).
		All(ctx)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return e.markReported(ctx, now)
	}

	subject, body := composeReport(e.Deps.PrimaryHostname, rows, now)
	// root@hostname is system mail routing's address for the operator:
	// the materializer aliases it to the first admin's real mailbox.
	to := "root@" + e.Deps.PrimaryHostname
	if err := e.sendMail(ctx, to, subject, body); err != nil {
		return fmt.Errorf("status report: %w", err)
	}
	e.Deps.Log.Printf("checks: sent status report to %s (%d problems)", to, len(rows))
	return e.markReported(ctx, now)
}

func (e *Engine) markReported(ctx context.Context, now time.Time) error {
	return e.Deps.Store.Setting.Create().
		SetKey(settingReportSent).
		SetValue(now.Format(time.RFC3339)).
		OnConflictColumns(entsetting.FieldKey).
		UpdateNewValues().
		Exec(ctx)
}

func composeReport(hostname string, rows []*ent.CheckResult, now time.Time) (subject, body string) {
	errors, warnings := 0, 0
	for _, row := range rows {
		if row.Status == string(StatusError) {
			errors++
		} else {
			warnings++
		}
	}
	subject = fmt.Sprintf("[%s] Status checks: %s", hostname, countPhrase(errors, warnings))

	var b strings.Builder
	fmt.Fprintf(&b, "Status check digest for %s, %s.\n\n", hostname, now.UTC().Format("2006-01-02 15:04 UTC"))
	category := ""
	for _, row := range rows {
		if row.Category != category {
			category = row.Category
			fmt.Fprintf(&b, "%s\n%s\n", strings.ToUpper(category), strings.Repeat("=", len(category)))
		}
		name := row.Check
		if row.Domain != "" {
			name += " (" + row.Domain + ")"
		}
		fmt.Fprintf(&b, "[%s] %s: %s", row.Status, name, row.Message)
		if row.FirstFailedAt != nil {
			fmt.Fprintf(&b, " (since %s)", row.FirstFailedAt.UTC().Format("2006-01-02"))
		}
		b.WriteString("\n\n")
	}
	b.WriteString("Details and manual re-runs: the System Checks page of the admin panel.\n")
	return subject, b.String()
}

func countPhrase(errors, warnings int) string {
	var parts []string
	if errors > 0 {
		parts = append(parts, fmt.Sprintf("%d problem(s)", errors))
	}
	if warnings > 0 {
		parts = append(parts, fmt.Sprintf("%d warning(s)", warnings))
	}
	return strings.Join(parts, ", ")
}

// sendMail submits the digest through the local MTA, or the SendMail
// seam in tests.
func (e *Engine) sendMail(ctx context.Context, to, subject, body string) error {
	if e.Deps.SendMail != nil {
		return e.Deps.SendMail(ctx, to, subject, body)
	}
	addr := e.Deps.SMTPAddr
	if addr == "" {
		addr = "localhost:25"
	}
	from := "root@" + e.Deps.PrimaryHostname
	msg := fmt.Sprintf("From: Status Checks <%s>\r\nTo: <%s>\r\nSubject: %s\r\nDate: %s\r\nAuto-Submitted: auto-generated\r\n\r\n%s",
		from, to, subject, e.Deps.Now().Format(time.RFC1123Z),
		strings.ReplaceAll(body, "\n", "\r\n"))
	return smtp.SendMail(addr, nil, from, []string{to}, []byte(msg))
}
