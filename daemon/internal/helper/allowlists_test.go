package helper

import "testing"

// The service vocabulary is a contract with managerd's hardcoded
// callers: acmeprov restarts cert holders (pinned in its own drift
// test), and dnsapply reloads the names below after zone writes.
// Removing or renaming an entry here breaks those callers at runtime
// on a box, so the removal must be deliberate enough to update this
// test too.
func TestServiceVocabularyCoversDNSApplyReloads(t *testing.T) {
	// Kept in sync with the reload calls in dnsapply/apply.go.
	for _, svc := range []string{"nsd", "unbound", "opendkim"} {
		if !KnownService(svc) {
			t.Errorf("dnsapply reloads %q after zone writes, but the service vocabulary does not know it", svc)
		}
	}
}
