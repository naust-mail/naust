package auth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// rfcSecret is the RFC 6238 Appendix B test secret ("12345678901234567890").
var rfcSecret = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

func TestVerifyTOTPAgainstRFCVectors(t *testing.T) {
	// RFC 6238 Appendix B, truncated to 6 digits (value mod 10^6).
	vectors := []struct {
		unix int64
		code string
	}{
		{59, "287082"},         // 94287082
		{1111111109, "081804"}, // 07081804
		{1111111111, "050471"}, // 14050471
		{1234567890, "005924"}, // 89005924
		{2000000000, "279037"}, // 69279037
	}
	for _, v := range vectors {
		if _, ok := VerifyTOTP(rfcSecret, v.code, time.Unix(v.unix, 0)); !ok {
			t.Errorf("t=%d code %s must verify", v.unix, v.code)
		}
		if _, ok := VerifyTOTP(rfcSecret, "000000", time.Unix(v.unix, 0)); ok {
			t.Errorf("t=%d wrong code must not verify", v.unix)
		}
	}
}

func TestVerifyTOTPWindow(t *testing.T) {
	now := time.Unix(1111111109, 0)
	prev := time.Unix(1111111109-30, 0)
	next := time.Unix(1111111109+30, 0)
	code := "081804" // valid at now

	for _, at := range []time.Time{prev, now, next} {
		if _, ok := VerifyTOTP(rfcSecret, code, at); !ok {
			t.Errorf("code must verify within one step of skew (at %d)", at.Unix())
		}
	}
	// Two steps away is out of window.
	if _, ok := VerifyTOTP(rfcSecret, code, time.Unix(1111111109+61, 0)); ok {
		t.Error("code must not verify two steps late")
	}

	// The matched step reflects where the code landed, so consuming it
	// prevents replay even across the skew window.
	stepAtNow, _ := VerifyTOTP(rfcSecret, code, now)
	stepAtNext, _ := VerifyTOTP(rfcSecret, code, next)
	if stepAtNow != stepAtNext {
		t.Errorf("matched step must be the code's own step: %d vs %d", stepAtNow, stepAtNext)
	}
}

func TestNewTOTPSecretShape(t *testing.T) {
	s, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTOTPSecret(s); err != nil {
		t.Errorf("generated secret invalid: %v", err)
	}
	if s2, _ := NewTOTPSecret(); s2 == s {
		t.Error("secrets must be random")
	}
}

func TestValidateTOTPSecretRejections(t *testing.T) {
	for _, bad := range []string{"", "short", strings.Repeat("A", 31), strings.Repeat("1", 32), strings.Repeat("A", 33)} {
		if err := ValidateTOTPSecret(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestTOTPURI(t *testing.T) {
	uri := TOTPURI("SECRETBASE32", "bob@example.com", "box.example.com Control Panel")
	for _, want := range []string{
		"otpauth://totp/",
		"secret=SECRETBASE32",
		"issuer=box.example.com+Control+Panel",
		"bob@example.com",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("URI missing %q: %s", want, uri)
		}
	}
}

func TestFormatTOTPStepOrders(t *testing.T) {
	// String comparison must order steps correctly across digit-count
	// boundaries (the reason for zero padding).
	if !(FormatTOTPStep(99999999) < FormatTOTPStep(100000000)) {
		t.Error("padded steps must compare in numeric order")
	}
}
