package mailaddr

import "testing"

func TestUserEmail(t *testing.T) {
	valid := []string{"alice@example.com", "a.b_c-d@sub.example.com"}
	invalid := []string{"", "no-at-sign", "Upper@example.com", "a@@b.com", "a@example", "a@1.2"}
	for _, e := range valid {
		if err := UserEmail(e); err != nil {
			t.Errorf("UserEmail(%q) = %v, want nil", e, err)
		}
	}
	for _, e := range invalid {
		if err := UserEmail(e); err == nil {
			t.Errorf("UserEmail(%q) = nil, want error", e)
		}
	}
}

func TestAliasSourceAllowsCatchAll(t *testing.T) {
	if err := AliasSource("@example.com"); err != nil {
		t.Errorf("catch-all should be valid: %v", err)
	}
	if err := AliasSource("info@example.com"); err != nil {
		t.Errorf("plain alias should be valid: %v", err)
	}
	if err := AliasSource("@notadomain"); err == nil {
		t.Errorf("bad catch-all domain should be rejected")
	}
}

func TestIsDCV(t *testing.T) {
	for _, e := range []string{"admin@example.com", "postmaster@example.com", "abuse+x@example.com"} {
		if !IsDCV(e) {
			t.Errorf("IsDCV(%q) = false, want true", e)
		}
	}
	if IsDCV("alice@example.com") {
		t.Errorf("IsDCV(alice) = true, want false")
	}
}

func TestPassword(t *testing.T) {
	if err := Password("longenough"); err != nil {
		t.Errorf("valid password rejected: %v", err)
	}
	for _, p := range []string{"", "short"} {
		if err := Password(p); err == nil {
			t.Errorf("Password(%q) = nil, want error", p)
		}
	}
}
