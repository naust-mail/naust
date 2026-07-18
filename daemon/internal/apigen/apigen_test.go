package apigen

import (
	"os"
	"strings"
	"testing"
)

const generatedPath = "../../../frontend/src/api/types.gen.ts"

// TestGeneratedFileIsCurrent regenerates the TypeScript contract from
// internal/api and compares it to the checked-in file, so any change to
// the Go structs without a regeneration fails the suite.
func TestGeneratedFileIsCurrent(t *testing.T) {
	want, err := Generate("../api")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	got, err := os.ReadFile(generatedPath)
	if err != nil {
		t.Fatalf("read %s: %v (run: go generate ./internal/api)", generatedPath, err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s is stale; run: go generate ./internal/api", generatedPath)
	}
}

func TestMappingRules(t *testing.T) {
	src, err := Generate("../api")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	out := string(src)
	for _, want := range []string{
		// Plain struct with comment carried over.
		"export type User = {",
		"  email: string\n",
		// int64 -> number.
		"  quota_bytes: number\n",
		// time.Time -> string.
		"  expires_at: string\n",
		// omitempty scalar -> optional.
		"  totp_code?: string\n",
		// *time.Time with omitempty -> optional string.
		"  last_used?: string\n",
		// *string WITHOUT omitempty -> null union (MailcryptUnwrapResponse).
		"  mail_key: string | null\n",
		// slice without omitempty -> null union (nil marshals to null).
		"  users: User[] | null\n",
		// slice with omitempty -> optional.
		"  permitted_senders?: string[]\n",
		// json.RawMessage -> unknown.
		"  options: unknown\n",
		// map -> Record, no omitempty -> null union.
		"  mounts: Record<string, string> | null\n",
		// map with omitempty -> optional.
		"  checks?: Record<string, CheckOverrideConfig>\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("generated output missing %q", want)
		}
	}
	if strings.Contains(out, "interface ") {
		t.Error("generated output must use type aliases, not interfaces")
	}
	for i, c := range out {
		if c > 127 {
			t.Fatalf("non-ASCII character at byte %d", i)
		}
	}
}
