package main

import (
	"strings"
	"testing"
)

// TestConfirmEmailFrom exercises the wrong-account gate that stands in front of
// every destructive recover action. The happy path (an exact match) is the least
// interesting case; the point of the gate is that everything else is rejected.
func TestConfirmEmailFrom(t *testing.T) {
	const target = "admin@box.example.com"

	cases := []struct {
		name  string
		input string
		ok    bool
	}{
		{"exact match", "admin@box.example.com\n", true},
		{"surrounding whitespace trimmed", "   admin@box.example.com  \n", true},
		{"no trailing newline (EOF)", "admin@box.example.com", true},
		{"different account", "other@box.example.com\n", false},
		{"wrong case is not a match", "Admin@Box.Example.com\n", false},
		{"substring is not a match", "admin@box.example\n", false},
		{"trailing character", "admin@box.example.comX\n", false},
		{"empty line", "\n", false},
		{"whitespace only", "   \n", false},
		{"empty input (EOF, no line)", "", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := confirmEmailFrom(strings.NewReader(c.input), target)
			if c.ok && err != nil {
				t.Fatalf("input %q: want match, got error %v", c.input, err)
			}
			if !c.ok && err == nil {
				t.Fatalf("input %q: want rejection, got nil (would proceed on the WRONG account)", c.input)
			}
		})
	}
}
