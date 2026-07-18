package checks

import (
	"context"
	"strings"
	"testing"
	"time"

	entsetting "naust/daemon/internal/store/ent/setting"
)

type sentMail struct {
	to, subject, body string
}

func reportEngine(t *testing.T, report string, sent *[]sentMail) *Engine {
	t.Helper()
	e := testEngine(t, nil)
	e.Deps.PrimaryHostname = "box.example.com"
	e.Deps.SendMail = func(_ context.Context, to, subject, body string) error {
		*sent = append(*sent, sentMail{to, subject, body})
		return nil
	}
	cfgJSON := `{"report":"` + report + `"}`
	if err := e.Deps.Store.Setting.Create().
		SetKey(SettingKey).SetValue(cfgJSON).Exec(context.Background()); err != nil {
		t.Fatal(err)
	}
	return e
}

func seedFailure(t *testing.T, e *Engine) {
	t.Helper()
	failedAt := testNow.Add(-48 * time.Hour)
	e.Deps.Store.CheckResult.Create().
		SetCheck("service:smtp").SetCategory("services").SetStatus("error").
		SetMessage("SMTP is not running.").SetSteps("[]").
		SetRanAt(testNow).SetFirstFailedAt(failedAt).
		SaveX(context.Background())
	e.Deps.Store.CheckResult.Create().
		SetCheck("reverse-dns").SetCategory("dns").SetStatus("warning").
		SetMessage("PTR mismatch.").SetSteps("[]").SetRanAt(testNow).
		SaveX(context.Background())
	e.Deps.Store.CheckResult.Create().
		SetCheck("free-memory").SetCategory("system").SetStatus("ok").
		SetSteps("[]").SetRanAt(testNow).
		SaveX(context.Background())
}

func lastSent(t *testing.T, e *Engine) string {
	t.Helper()
	row, err := e.Deps.Store.Setting.Query().
		Where(entsetting.Key(settingReportSent)).Only(context.Background())
	if err != nil {
		return ""
	}
	return row.Value
}

func report(t *testing.T, e *Engine) {
	t.Helper()
	cfg, err := LoadConfig(context.Background(), e.Deps.Store)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.maybeReport(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}

func TestReportDigest(t *testing.T) {
	var sent []sentMail
	e := reportEngine(t, "daily", &sent)
	seedFailure(t, e)

	// First pass only anchors the schedule.
	report(t, e)
	if len(sent) != 0 || lastSent(t, e) == "" {
		t.Fatalf("first pass sent %d, anchor %q", len(sent), lastSent(t, e))
	}
	// Not due yet.
	e.Deps.Now = func() time.Time { return testNow.Add(12 * time.Hour) }
	report(t, e)
	if len(sent) != 0 {
		t.Fatalf("sent before due: %+v", sent)
	}
	// Due: digest goes to the system-routed operator address.
	e.Deps.Now = func() time.Time { return testNow.Add(25 * time.Hour) }
	report(t, e)
	if len(sent) != 1 {
		t.Fatalf("sent = %+v", sent)
	}
	m := sent[0]
	if m.to != "root@box.example.com" ||
		!strings.Contains(m.subject, "1 problem(s), 1 warning(s)") {
		t.Errorf("mail = %s %q", m.to, m.subject)
	}
	for _, want := range []string{"SERVICES", "service:smtp", "since 2026-07-06", "DNS", "PTR mismatch."} {
		if !strings.Contains(m.body, want) {
			t.Errorf("body missing %q:\n%s", want, m.body)
		}
	}
	if strings.Contains(m.body, "free-memory") {
		t.Error("ok results must not appear in the digest")
	}
	// Sending advanced the anchor: not due again immediately.
	report(t, e)
	if len(sent) != 1 {
		t.Errorf("double-sent: %+v", sent)
	}
}

func TestReportHealthyAndOff(t *testing.T) {
	var sent []sentMail
	e := reportEngine(t, "weekly", &sent)
	report(t, e) // anchor
	e.Deps.Now = func() time.Time { return testNow.Add(8 * 24 * time.Hour) }
	report(t, e)
	if len(sent) != 0 {
		t.Errorf("healthy box sent a digest: %+v", sent)
	}
	// A healthy due pass still advances the anchor.
	if got := lastSent(t, e); !strings.HasPrefix(got, "2026-07-16") {
		t.Errorf("anchor = %q", got)
	}

	off := reportEngine(t, "off", &sent)
	seedFailure(t, off)
	report(t, off)
	if len(sent) != 0 || lastSent(t, off) != "" {
		t.Errorf("off still reported: %d, %q", len(sent), lastSent(t, off))
	}
}
