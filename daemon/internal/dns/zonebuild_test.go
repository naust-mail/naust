package dns

import (
	"strings"
	"testing"
)

func baseInput() ZoneInput {
	return ZoneInput{
		PrimaryHostname: "box.example.com",
		PublicIP:        "203.0.113.1",
		PublicIPv6:      "2001:db8::1",
		MailDomains:     []string{"example.com"},
		UserDomains:     []string{"example.com"},
		DKIMSelector:    "mail._domainkey",
		DKIMRecord:      "v=DKIM1; k=rsa; p=KEY",
	}
}

func findZone(t *testing.T, zones []Zone, apex string) Zone {
	t.Helper()
	for _, z := range zones {
		if z.Apex == apex {
			return z
		}
	}
	t.Fatalf("zone %s not generated; got %+v", apex, zones)
	return Zone{}
}

func has(z Zone, name, rtype, valuePrefix string) bool {
	for _, r := range z.Records {
		if r.Name == name && r.Type == rtype && strings.HasPrefix(r.Value, valuePrefix) {
			return true
		}
	}
	return false
}

func TestBuildZonesBasic(t *testing.T) {
	zones := BuildZones(baseInput())
	if len(zones) != 1 {
		t.Fatalf("zones = %+v, want just example.com", zones)
	}
	z := findZone(t, zones, "example.com")

	for _, want := range []struct{ name, rtype, prefix string }{
		{"", "NS", "ns1.box.example.com."},
		{"", "NS", "ns2.box.example.com."}, // default secondary
		{"", "A", "203.0.113.1"},
		{"", "AAAA", "2001:db8::1"},
		{"", "MX", "10 box.example.com."},
		{"", "TXT", "v=spf1 mx -all"},
		{"mail._domainkey", "TXT", "v=DKIM1; "},
		{"_dmarc", "TXT", "v=DMARC1; p=quarantine;"},
		// The box itself, folded in as a subdomain.
		{"box", "A", "203.0.113.1"},
		{"box", "AAAA", "2001:db8::1"},
		// Service names.
		{"www", "A", "203.0.113.1"},
		{"autoconfig", "A", "203.0.113.1"},
		{"autodiscover", "A", "203.0.113.1"},
		{"mta-sts", "A", "203.0.113.1"},
		{"ns1.box", "A", "203.0.113.1"},
		{"ns2.box", "A", "203.0.113.1"},
		// Hardening on a resolving non-mail name.
		{"www", "TXT", "v=spf1 -all"},
		{"_dmarc.www", "TXT", "v=DMARC1; p=reject;"},
		{"www", "MX", "0 ."},
	} {
		if !has(z, want.name, want.rtype, want.prefix) {
			t.Errorf("missing %q %s %q", want.name, want.rtype, want.prefix)
		}
	}
	// The apex takes mail, so no hardening there.
	if has(z, "", "MX", "0 .") || has(z, "", "TXT", "v=spf1 -all") {
		t.Error("apex must not carry no-mail hardening")
	}
	// Records must start at the apex.
	if z.Records[0].Name != "" {
		t.Errorf("first record is %+v, want an apex record", z.Records[0])
	}
}

func TestBuildZonesCustomRecordPrecedence(t *testing.T) {
	in := baseInput()
	in.Custom = []Record{
		{"example.com", "A", "5.5.5.5"},               // replaces default A and suppresses AAAA
		{"example.com", "TXT", "v=spf1 a -all"},       // replaces default SPF
		{"example.com", "MX", "20 backup.other.net."}, // backup MX: default 10 stays
		{"home.example.com", "A", "local"},            // sentinel resolves
	}
	z := findZone(t, BuildZones(in), "example.com")

	if !has(z, "", "A", "5.5.5.5") || has(z, "", "A", "203.0.113.1") {
		t.Error("custom apex A must replace the default")
	}
	if has(z, "", "AAAA", "") {
		t.Error("custom A must suppress the default AAAA")
	}
	if !has(z, "", "TXT", "v=spf1 a -all") || has(z, "", "TXT", "v=spf1 mx -all") {
		t.Error("custom SPF must replace the default")
	}
	if !has(z, "", "MX", "20 backup.other.net.") || !has(z, "", "MX", "10 box.example.com.") {
		t.Error("a backup MX must coexist with the default MX 10")
	}
	if !has(z, "home", "A", "203.0.113.1") {
		t.Error("the local sentinel must resolve to the public IP")
	}
}

func TestBuildZonesPointedElsewhereSuppressesAutoName(t *testing.T) {
	in := baseInput()
	in.Custom = []Record{{"www.example.com", "A", "9.9.9.9"}}
	z := findZone(t, BuildZones(in), "example.com")

	if !has(z, "www", "A", "9.9.9.9") || has(z, "www", "A", "203.0.113.1") {
		t.Error("www must carry only the custom address")
	}
	// It still resolves and takes no mail, so hardening applies.
	if !has(z, "www", "MX", "0 .") {
		t.Error("www must keep the null-MX hardening")
	}
	// ns1/ns2 names always exist (glue must resolve), though a custom
	// record may supply their value, as in legacy.
	in.Custom = []Record{{"ns1.box.example.com", "A", "9.9.9.9"}}
	z = findZone(t, BuildZones(in), "example.com")
	if !has(z, "ns1.box", "A", "9.9.9.9") {
		t.Error("custom ns1 address must apply")
	}
	if !has(z, "ns2.box", "A", "203.0.113.1") {
		t.Error("ns2 must keep the box's address")
	}
}

func TestBuildZonesSecondaryNS(t *testing.T) {
	in := baseInput()
	in.SecondaryNS = []string{"ns2.other.net", "xfr:10.0.0.0/8"}
	z := findZone(t, BuildZones(in), "example.com")

	if !has(z, "", "NS", "ns2.other.net.") {
		t.Error("configured secondary NS missing")
	}
	if has(z, "", "NS", "ns2.box.example.com.") {
		t.Error("default ns2 must yield to the configured secondary")
	}
	if has(z, "", "NS", "xfr:") {
		t.Error("xfr entries must not become NS records")
	}
}

func TestBuildZonesMailSubdomainFoldsIn(t *testing.T) {
	in := baseInput()
	in.MailDomains = []string{"other.net", "corp.other.net"}
	in.UserDomains = []string{"corp.other.net"}
	zones := BuildZones(in)
	// other.net and the box's own example.com.
	if len(zones) != 2 {
		t.Fatalf("zones = %+v, want other.net and example.com", zones)
	}
	z := findZone(t, zones, "other.net")

	for _, want := range []struct{ name, rtype, prefix string }{
		{"corp", "MX", "10 box.example.com."},
		{"corp", "TXT", "v=spf1 mx -all"},
		{"_dmarc.corp", "TXT", "v=DMARC1; p=quarantine;"},
		{"mail._domainkey.corp", "TXT", "v=DKIM1; "},
		{"autoconfig.corp", "A", "203.0.113.1"},
		{"mta-sts.corp", "A", "203.0.113.1"},
	} {
		if !has(z, want.name, want.rtype, want.prefix) {
			t.Errorf("missing %q %s %q", want.name, want.rtype, want.prefix)
		}
	}
	// No autoconfig at the alias-only apex (no login users there).
	if has(z, "autoconfig", "A", "") {
		t.Error("autoconfig must only exist for domains with users")
	}
}

func TestBuildZonesNoIPv6(t *testing.T) {
	in := baseInput()
	in.PublicIPv6 = ""
	in.Custom = []Record{{"home.example.com", "AAAA", "local"}}
	z := findZone(t, BuildZones(in), "example.com")

	if has(z, "", "AAAA", "") || has(z, "box", "AAAA", "") {
		t.Error("no AAAA records without a public IPv6")
	}
	// A local AAAA sentinel without IPv6 silently drops.
	if has(z, "home", "AAAA", "") {
		t.Error("local AAAA sentinel must drop without IPv6")
	}
	// But the name gets its default A anyway? No: home is not a hosted
	// service name, and its only custom record dropped, so it must not
	// resolve at all.
	if has(z, "home", "A", "") {
		t.Error("home must not resolve")
	}
}

func TestBuildZonesSPFInclude(t *testing.T) {
	in := baseInput()
	in.SPFInclude = "spf.relay.example"
	z := findZone(t, BuildZones(in), "example.com")
	if !has(z, "", "TXT", "v=spf1 mx include:spf.relay.example -all") {
		t.Error("SPF include missing")
	}
}

func TestBuildZonesTLSA(t *testing.T) {
	in := baseInput()
	in.TLSARecord = "3 1 1 abc123"
	z := findZone(t, BuildZones(in), "example.com")

	// The primary hostname folds into the zone, so the TLSA names are
	// relative to box.
	if !has(z, "_25._tcp.box", "TLSA", "3 1 1 abc123") {
		t.Error("SMTP TLSA record missing")
	}
	if !has(z, "_443._tcp.box", "TLSA", "3 1 1 abc123") {
		t.Error("HTTPS TLSA record missing")
	}

	// Without the input, no TLSA at all.
	z = findZone(t, BuildZones(baseInput()), "example.com")
	for _, r := range z.Records {
		if r.Type == "TLSA" {
			t.Fatalf("unexpected TLSA record %+v", r)
		}
	}
}

func TestBuildZonesMTASTS(t *testing.T) {
	in := baseInput()
	in.MailDomains = []string{"example.com", "other.example.com"}
	in.MTASTSPolicyID = "abcdefghij0123456789"
	in.MTASTSDomains = map[string]bool{"example.com": true}
	z := findZone(t, BuildZones(in), "example.com")

	if !has(z, "_mta-sts", "TXT", "v=STSv1; id=abcdefghij0123456789") {
		t.Error("_mta-sts TXT missing for the eligible domain")
	}
	// other.example.com's certificate was not vouched for: no policy.
	if has(z, "_mta-sts.other", "TXT", "") {
		t.Error("_mta-sts TXT emitted for a domain without a valid certificate")
	}
	// The policy host's A record is unconditional so its certificate
	// can be provisioned before the TXT appears.
	if !has(z, "mta-sts.other", "A", "203.0.113.1") {
		t.Error("mta-sts A record must not depend on certificate validity")
	}

	// A custom _mta-sts TXT wins over the generated one.
	in.Custom = []Record{{"_mta-sts.example.com", "TXT", "v=STSv1; id=custom"}}
	z = findZone(t, BuildZones(in), "example.com")
	if !has(z, "_mta-sts", "TXT", "v=STSv1; id=custom") || has(z, "_mta-sts", "TXT", "v=STSv1; id=abcdefghij0123456789") {
		t.Error("custom _mta-sts TXT must replace the generated one")
	}

	// No policy id (no policy file served): nothing, even when vouched.
	in.Custom = nil
	in.MTASTSPolicyID = ""
	z = findZone(t, BuildZones(in), "example.com")
	if has(z, "_mta-sts", "TXT", "") {
		t.Error("_mta-sts TXT must require a policy id")
	}
}
