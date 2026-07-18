package acmeprov

import (
	"testing"

	"naust/daemon/internal/helper"
)

// The registry doc promises one-way consistency tests between managerd
// callers and helperd's closed vocabulary; this is the acmeprov half.
// A rename on either side (the rav rename changed this map once
// already) must fail here, not on a box after a cert renewal.
func TestCertRestartServicesKnownToHelper(t *testing.T) {
	for _, svc := range certRestartServices {
		if !helper.KnownService(svc) {
			t.Errorf("certRestartServices includes %q, which the helper's service vocabulary does not know - the post-renewal restart would fail on the box", svc)
		}
	}
}
