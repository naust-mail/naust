package dns

import (
	"reflect"
	"testing"
)

func TestZonesCollapsesSubdomains(t *testing.T) {
	got := Zones([]string{
		"mail.example.com", // subdomain of a hosted zone: folds in
		"example.com",
		"other.net",
		"deep.sub.other.net",
		"example.org",
	})
	want := []string{"example.com", "example.org", "other.net"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Zones = %v, want %v", got, want)
	}
}

func TestZonesDropsExactDuplicates(t *testing.T) {
	// The common case that trips this: the primary hostname is also used
	// as a mail domain, so it appears twice in the input (once from each
	// source) before Zones sees it.
	got := Zones([]string{"box.example.com", "box.example.com"})
	want := []string{"box.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Zones = %v, want %v", got, want)
	}
}

func TestZoneFor(t *testing.T) {
	zones := []string{"example.com", "other.net"}
	if z, ok := ZoneFor("sub.example.com", zones); !ok || z != "example.com" {
		t.Errorf("sub.example.com -> %q, %v", z, ok)
	}
	if z, ok := ZoneFor("example.com", zones); !ok || z != "example.com" {
		t.Errorf("apex -> %q, %v", z, ok)
	}
	// Suffix match must respect label boundaries.
	if _, ok := ZoneFor("notexample.com", zones); ok {
		t.Error("notexample.com must not match example.com")
	}
	if _, ok := ZoneFor("elsewhere.io", zones); ok {
		t.Error("unrelated domain matched")
	}
}

func TestValidRecordName(t *testing.T) {
	valid := []string{
		"example.com",
		"sub.example.com",
		"*.example.com",
		"_dmarc.example.com",
		"_25._tcp.example.com",
		"xn--bcher-kva.example.com",
		"example.com.",
	}
	for _, name := range valid {
		if !ValidRecordName(name) {
			t.Errorf("%q should be valid", name)
		}
	}
	invalid := []string{
		"",
		"example",          // single label
		"-bad.example.com", // leading hyphen
		"bad-.example.com", // trailing hyphen
		"foo.example.123",  // numeric TLD
		"foo..example.com", // empty label
		"foo bar.example.com",
		"*.*.example.com", // wildcard only allowed as first label once
	}
	for _, name := range invalid {
		if ValidRecordName(name) {
			t.Errorf("%q should be invalid", name)
		}
	}
}

func TestValidateValue(t *testing.T) {
	cases := []struct {
		qname, rtype, value string
		want                string
		wantErr             bool
	}{
		{"example.com", "A", "1.2.3.4", "1.2.3.4", false},
		{"example.com", "A", "local", "local", false},
		{"example.com", "A", "::1", "", true},
		{"example.com", "AAAA", "2001:db8::1", "2001:db8::1", false},
		{"example.com", "AAAA", "1.2.3.4", "", true},
		{"example.com", "A", "not-an-ip", "", true},
		// CNAME target gains a trailing dot.
		{"www.example.com", "CNAME", "target.other.net", "target.other.net.", false},
		{"www.example.com", "CNAME", "target.other.net.", "target.other.net.", false},
		{"www.example.com", "CNAME", "not valid", "", true},
		// Internationalized targets are punycoded.
		{"www.example.com", "CNAME", "bücher.other.net", "xn--bcher-kva.other.net.", false},
		// NS only below the apex.
		{"sub.example.com", "NS", "ns.other.net", "ns.other.net.", false},
		{"example.com", "NS", "ns.other.net", "", true},
		{"example.com", "TXT", "v=spf1 -all", "v=spf1 -all", false},
		{"example.com", "TXT", "bad\nvalue", "", true},
		{"example.com", "TXT", "", "", true},
		{"example.com", "MX", "10 mail.other.net.", "10 mail.other.net.", false},
		{"example.com", "PTR", "whatever", "", true},
	}
	for _, c := range cases {
		got, err := ValidateValue(c.qname, "example.com", c.rtype, c.value)
		if (err != nil) != c.wantErr {
			t.Errorf("ValidateValue(%q,%q,%q) err = %v, wantErr %v", c.qname, c.rtype, c.value, err, c.wantErr)
			continue
		}
		if err == nil && got != c.want {
			t.Errorf("ValidateValue(%q,%q,%q) = %q, want %q", c.qname, c.rtype, c.value, got, c.want)
		}
	}
}

func TestValidateSecondaryNameserver(t *testing.T) {
	for _, ok := range []string{"ns2.example.com", "xfr:1.2.3.4", "xfr:10.0.0.0/8", "xfr:2001:db8::1"} {
		if _, err := ValidateSecondaryNameserver(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "xfr:not-an-ip", "*.example.com", "just_one_label", "bad host.example.com", "_dmarc.example.com"} {
		if _, err := ValidateSecondaryNameserver(bad); err == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
	// Internationalized hostnames come back punycoded.
	got, err := ValidateSecondaryNameserver("ns2.bücher.example")
	if err != nil || got != "ns2.xn--bcher-kva.example" {
		t.Errorf("IDN nameserver = %q, %v", got, err)
	}
}

func TestNormalizeName(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"Example.COM", "example.com", false},
		{"example.com.", "example.com", false},
		{" example.com ", "example.com", false},
		{"bücher.example.com", "xn--bcher-kva.example.com", false},
		{"МОСКВА.example", "xn--80adxhks.example", false},
		// Already-punycoded names pass through unchanged.
		{"xn--bcher-kva.example.com", "xn--bcher-kva.example.com", false},
		// Service labels and wildcards survive normalization.
		{"_dmarc.example.com", "_dmarc.example.com", false},
		{"*.example.com", "*.example.com", false},
		{"", "", true},
		{".", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeName(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("NormalizeName(%q) err = %v, wantErr %v", c.in, err, c.wantErr)
			continue
		}
		if err == nil && got != c.want {
			t.Errorf("NormalizeName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
