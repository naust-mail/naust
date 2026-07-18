package dns

import (
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)

func testZone(spf string) Zone {
	return Zone{
		Apex: "example.com",
		Records: []ZoneRecord{
			{"", "NS", "ns1.box.example.com.", CatInternal},
			{"", "A", "203.0.113.1", CatRequired},
			{"", "TXT", spf, CatRecommended},
			{"www", "A", "203.0.113.1", CatOptional},
		},
	}
}

func TestRenderZoneShape(t *testing.T) {
	text := RenderZone(testZone("v=spf1 mx -all"), "box.example.com", "abc123", 2026071000)
	for _, want := range []string{
		"$ORIGIN example.com.\n",
		"@ IN SOA ns1.box.example.com. hostmaster.box.example.com. (",
		"2026071000       ; serial number",
		"\tIN\tA\t203.0.113.1\n",
		"\tIN\tTXT\t\"v=spf1 mx -all\"\n",
		"www\tIN\tA\t203.0.113.1\n",
		"; DNSSEC signing keys hash: abc123\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("zone missing %q; got:\n%s", want, text)
		}
	}
	// Nothing may follow the domain on the $ORIGIN line (ldns-signzone).
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "$ORIGIN") && line != "$ORIGIN example.com." {
			t.Errorf("$ORIGIN line = %q", line)
		}
	}
}

func TestZoneHashIgnoresSerialOnly(t *testing.T) {
	z := testZone("v=spf1 mx -all")
	h1 := ZoneHash(z, "box.example.com", "keys1")
	if h1 != ZoneHash(z, "box.example.com", "keys1") {
		t.Error("hash must be deterministic")
	}
	if h1 == ZoneHash(testZone("v=spf1 a -all"), "box.example.com", "keys1") {
		t.Error("record change must change the hash")
	}
	// A key rotation must change the hash (forces re-sign).
	if h1 == ZoneHash(z, "box.example.com", "keys2") {
		t.Error("keys-hash change must change the hash")
	}
}

func TestNextSerial(t *testing.T) {
	cases := []struct {
		current int64
		want    int64
	}{
		{0, 2026071000},          // first publication
		{2026070999, 2026071000}, // yesterday's: date wins
		{2026071000, 2026071001}, // second change today
		{2026071005, 2026071006}, // several changes today
		{2026071100, 2026071101}, // clock went backward: keep counting
	}
	for _, c := range cases {
		if got := NextSerial(c.current, testNow); got != c.want {
			t.Errorf("NextSerial(%d) = %d, want %d", c.current, got, c.want)
		}
	}
}

func TestEncodeTXTChunksAndEscapes(t *testing.T) {
	long := strings.Repeat("a", 300)
	got := encodeTXT(long)
	if !strings.Contains(got, `" "`) {
		t.Error("300-byte TXT must split into two quoted strings")
	}
	if strings.HasSuffix(got, " ") {
		t.Error("no trailing space")
	}
	if got := encodeTXT(`say "hi" \now`); !strings.Contains(got, `\"hi\"`) || !strings.Contains(got, `\\now`) {
		t.Errorf("escaping wrong: %q", got)
	}
}

func TestSignatureNeedsRenewal(t *testing.T) {
	fresh := "example.com.\t86400\tIN\tRRSIG\tSOA 8 2 86400 20260801120000 20260701120000 12345 example.com. sig=="
	if SignatureNeedsRenewal(fresh, testNow) {
		t.Error("3 weeks out must not renew")
	}
	soon := "example.com.\t86400\tIN\tRRSIG\tSOA 8 2 86400 20260712000000 20260601120000 12345 example.com. sig=="
	if !SignatureNeedsRenewal(soon, testNow) {
		t.Error("under 2 days must renew")
	}
	margin := "example.com.\t86400\tIN\tRRSIG\tSOA 8 2 86400 20260717000000 20260601120000 12345 example.com. sig=="
	if !SignatureNeedsRenewal(margin, testNow) {
		t.Error("under 10 days must renew")
	}
	if !SignatureNeedsRenewal("no rrsig here", testNow) {
		t.Error("missing RRSIG must renew")
	}
}

func TestRenderNSDConf(t *testing.T) {
	zones := []Zone{{Apex: "example.com"}, {Apex: "other.net"}}
	name := func(apex string) string { return apex + ".txt.signed" }
	got := RenderNSDConf(zones, name, []string{"198.51.100.7", "10.0.0.0/8"})
	for _, want := range []string{
		"zone:\n\tname: example.com\n\tzonefile: example.com.txt.signed\n",
		"zone:\n\tname: other.net\n",
		"\tnotify: 198.51.100.7 NOKEY",
		"\tprovide-xfr: 198.51.100.7 NOKEY",
		"\tprovide-xfr: 10.0.0.0/8 NOKEY",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("nsd.conf missing %q; got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "notify: 10.0.0.0/8") {
		t.Error("subnets must not get notify lines")
	}
}
