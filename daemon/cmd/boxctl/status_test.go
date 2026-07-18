package main

import (
	"testing"

	"naust/daemon/internal/checkview"
)

// statusWord maps the known statuses to fixed-width labels and, for anything
// unrecognized, uppercases it rather than emitting a blank column - the plain
// status output is grepped, so a row must always carry a status token.
func TestStatusWord(t *testing.T) {
	cases := map[string]string{
		checkview.StatusOK:      "OK",
		checkview.StatusWarning: "WARN",
		checkview.StatusError:   "ERR",
		checkview.StatusSkipped: "SKIP",
		"mystery":               "MYSTERY", // unknown -> uppercased, never blank
	}
	for in, want := range cases {
		if got := statusWord(in); got != want {
			t.Errorf("statusWord(%q) = %q, want %q", in, got, want)
		}
	}
	if got := statusWord(""); got != "" {
		t.Errorf("statusWord(\"\") = %q, want empty", got)
	}
}
