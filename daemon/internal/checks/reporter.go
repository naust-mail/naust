package checks

import (
	"fmt"
	"time"
)

// Reporter collects a check's steps. Checks call Step for each phase;
// a failing step is recorded and execution continues with the next
// step, so one run shows every phase like a CI job rather than
// stopping at the first problem.
type Reporter struct {
	now   func() time.Time
	steps []Step
}

// StepCtx is the recording surface inside one step.
type StepCtx struct {
	step Step
}

// Failf marks the step as an error.
func (s *StepCtx) Failf(format string, args ...any) {
	s.step.Status = StatusError
	s.step.Message = fmt.Sprintf(format, args...)
}

// Warnf marks the step as a warning unless it already failed.
func (s *StepCtx) Warnf(format string, args ...any) {
	if s.step.Status == StatusError {
		return
	}
	s.step.Status = StatusWarning
	s.step.Message = fmt.Sprintf(format, args...)
}

// Skipf marks the step as skipped with a reason - the honest verdict
// when this execution context cannot observe the fact (root-only
// reads in the unprivileged daemon).
func (s *StepCtx) Skipf(format string, args ...any) {
	s.step.Status = StatusSkipped
	s.step.Message = fmt.Sprintf(format, args...)
}

// Passf records why a step passed. Failf/Warnf/Skipf already explain
// a bad outcome; without this a green step carries no text at all,
// leaving the panel showing a bare title next to the checkmark.
func (s *StepCtx) Passf(format string, args ...any) {
	if s.step.Status != StatusOK {
		return
	}
	s.step.Message = fmt.Sprintf(format, args...)
}

// Expect records the structured diff the step evaluated, regardless
// of outcome, so the panel can render expected vs observed.
func (s *StepCtx) Expect(expected, observed string) {
	s.step.Expected = expected
	s.step.Observed = observed
}

// Hint records what would fix a failure; it may name a helper intent
// ("service.restart dovecot") so a panel fix button is wiring, not
// new machinery.
func (s *StepCtx) Hint(hint string) {
	s.step.FixHint = hint
}

// Step runs one named phase. A panic inside fn is recorded as an
// error step instead of taking down the engine.
func (r *Reporter) Step(name string, fn func(s *StepCtx)) {
	s := &StepCtx{step: Step{Name: name, Status: StatusOK}}
	start := r.now()
	func() {
		defer func() {
			if p := recover(); p != nil {
				s.step.Status = StatusError
				s.step.Message = fmt.Sprintf("check bug: %v", p)
			}
		}()
		fn(s)
	}()
	s.step.ElapsedMs = r.now().Sub(start).Milliseconds()
	r.steps = append(r.steps, s.step)
}

// summarize folds steps into the check-level status and message: the
// worst step wins, and the message comes from the first step at that
// severity. A check whose every step was skipped is itself skipped.
func summarize(steps []Step) (Status, string) {
	status, message := StatusSkipped, ""
	for _, s := range steps {
		if severity(s.Status) > severity(status) || message == "" && s.Message != "" && s.Status == status {
			status, message = s.Status, s.Message
		}
	}
	if len(steps) == 0 {
		return StatusOK, ""
	}
	return status, message
}
