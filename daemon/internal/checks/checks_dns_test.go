package checks

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	dnszone "naust/daemon/internal/dns"
	"naust/daemon/internal/dnsapply"
)

const (
	testAuth     = "203.0.113.5:53" // authAddr for PublicIP 203.0.113.5
	testResolver = "127.0.0.1:53"   // resolverAddr default
)

// fakeDNS answers Deps.Query from a map of zone-file RR lines keyed by
// (server, name, type, recursion).
type fakeDNS struct {
	answers map[string][]string
	errs    map[string]error
}

func newFakeDNS() *fakeDNS {
	return &fakeDNS{answers: map[string][]string{}, errs: map[string]error{}}
}

func dnsTestKey(server, name, rtype string, recurse bool) string {
	return fmt.Sprintf("%s %s %s %v", server, strings.ToLower(mdns.Fqdn(name)), rtype, recurse)
}

func (f *fakeDNS) query(_ context.Context, q DNSQuery) (*DNSReply, error) {
	k := dnsTestKey(q.Server, q.Name, mdns.TypeToString[q.Type], q.Recurse)
	if err := f.errs[k]; err != nil {
		return nil, err
	}
	lines, ok := f.answers[k]
	if !ok {
		return &DNSReply{Rcode: mdns.RcodeNameError}, nil
	}
	var rrs []mdns.RR
	for _, l := range lines {
		rr, err := mdns.NewRR(l)
		if err != nil {
			panic(fmt.Sprintf("bad fake RR %q: %v", l, err))
		}
		rrs = append(rrs, rr)
	}
	return &DNSReply{Rcode: mdns.RcodeSuccess, Answer: rrs}, nil
}

// load registers every record of the zones as served by one viewpoint.
func (f *fakeDNS) load(server string, recurse bool, zones []dnszone.Zone) {
	for _, z := range zones {
		for _, rec := range z.Records {
			value := rec.Value
			if rec.Type == "TXT" {
				value = fmt.Sprintf("%q", rec.Value)
			}
			k := dnsTestKey(server, fqdnOf(rec.Name, z.Apex), rec.Type, recurse)
			f.answers[k] = append(f.answers[k],
				fmt.Sprintf("%s 300 IN %s %s", fqdnOf(rec.Name, z.Apex), rec.Type, value))
		}
	}
}

func (f *fakeDNS) remove(server, name, rtype string, recurse bool) {
	delete(f.answers, dnsTestKey(server, name, rtype, recurse))
}

func differInput() dnszone.ZoneInput {
	return dnszone.ZoneInput{
		PrimaryHostname: "box.example.com",
		PublicIP:        "203.0.113.5",
		MailDomains:     []string{"example.com"},
		UserDomains:     []string{"example.com"},
		DKIMSelector:    "mail",
		DKIMRecord:      "v=DKIM1; k=rsa; p=TESTKEY",
		TLSARecord:      "3 1 1 aabbccdd",
		MTASTSPolicyID:  "TESTPOLICYID12345678",
		MTASTSDomains:   map[string]bool{"example.com": true},
	}
}

func dnsTestDeps(f *fakeDNS, zones []dnszone.Zone) *Deps {
	return &Deps{
		PrimaryHostname: "box.example.com",
		PublicIP:        "203.0.113.5",
		Zones: func(ctx context.Context) ([]dnszone.Zone, error) {
			return zones, nil
		},
		Query: f.query,
		Now:   func() time.Time { return testNow },
	}
}

// runDomainCheck executes one per-domain check function directly.
func runDomainCheck(d *Deps, fn func(context.Context, *Deps, string, *Reporter), domain string) []Step {
	r := &Reporter{now: d.Now}
	fn(context.Background(), d, domain, r)
	return r.steps
}

func stepByName(t *testing.T, steps []Step, prefix string) Step {
	t.Helper()
	for _, s := range steps {
		if strings.HasPrefix(s.Name, prefix) {
			return s
		}
	}
	t.Fatalf("no step %q in %+v", prefix, steps)
	return Step{}
}

func TestZoneDifferAllMatch(t *testing.T) {
	zones := dnszone.BuildZones(differInput())
	f := newFakeDNS()
	f.load(testAuth, false, zones)
	f.load(testResolver, true, zones)
	// The apex NS set is the registrar's business (dns-delegation),
	// never the differ's: removing it publicly must not fail the check.
	f.remove(testResolver, "example.com.", "NS", true)

	steps := runDomainCheck(dnsTestDeps(f, zones), checkZoneRecords, "example.com")
	if len(steps) != 3 {
		t.Fatalf("steps = %+v", steps)
	}
	for _, s := range steps {
		if s.Status != StatusOK {
			t.Errorf("step %q = %s: %s\nexpected: %s\nobserved: %s", s.Name, s.Status, s.Message, s.Expected, s.Observed)
		}
	}
}

func TestZoneDifferAuthStale(t *testing.T) {
	zones := dnszone.BuildZones(differInput())
	f := newFakeDNS()
	f.load(testAuth, false, zones)
	f.load(testResolver, true, zones)
	f.remove(testAuth, "example.com.", "MX", false)

	steps := runDomainCheck(dnsTestDeps(f, zones), checkZoneRecords, "example.com")
	auth := stepByName(t, steps, "This box's nameserver")
	if auth.Status != StatusError || auth.FixHint != "service.restart nsd" {
		t.Errorf("auth step = %+v", auth)
	}
	if world := stepByName(t, steps, "Required DNS records"); world.Status != StatusOK {
		t.Errorf("world step = %+v", world)
	}
}

func TestZoneDifferPublicSeverity(t *testing.T) {
	zones := dnszone.BuildZones(differInput())

	// A required record (the MX) missing publicly is an error, and the
	// message carries the per-type consequence plus the external-DNS
	// wording since our own nsd serves the zone correctly.
	f := newFakeDNS()
	f.load(testAuth, false, zones)
	f.load(testResolver, true, zones)
	f.remove(testResolver, "example.com.", "MX", true)
	steps := runDomainCheck(dnsTestDeps(f, zones), checkZoneRecords, "example.com")
	world := stepByName(t, steps, "Required DNS records")
	if world.Status != StatusError {
		t.Fatalf("world step = %+v", world)
	}
	for _, want := range []string{"MX", "will not reach this box", "hosted elsewhere"} {
		if !strings.Contains(world.Message, want) {
			t.Errorf("message %q missing %q", world.Message, want)
		}
	}
	if lesser := stepByName(t, steps, "Recommended and optional"); lesser.Status != StatusOK {
		t.Errorf("lesser step = %+v", lesser)
	}

	// Only a hardening record missing publicly is a warning, and it
	// lands in the lesser step - the required step stays green.
	f = newFakeDNS()
	f.load(testAuth, false, zones)
	f.load(testResolver, true, zones)
	f.remove(testResolver, "www.example.com.", "TXT", true)
	steps = runDomainCheck(dnsTestDeps(f, zones), checkZoneRecords, "example.com")
	if world := stepByName(t, steps, "Required DNS records"); world.Status != StatusOK {
		t.Errorf("world step = %+v", world)
	}
	if lesser := stepByName(t, steps, "Recommended and optional"); lesser.Status != StatusWarning {
		t.Errorf("lesser step = %+v", lesser)
	}
}

func TestZoneDifferCloudflareProxyHint(t *testing.T) {
	zones := dnszone.BuildZones(differInput())

	// The public resolver sees a Cloudflare proxy IP instead of this
	// box's real address for its own hostname - the shape of "DNS
	// points at Cloudflare, not here" that breaks certificate issuance
	// and mail delivery in practice. box.example.com is a relative
	// record inside the example.com zone, not a separate zone.
	f := newFakeDNS()
	f.load(testAuth, false, zones)
	f.load(testResolver, true, zones)
	f.answers[dnsTestKey(testResolver, "box.example.com.", "A", true)] =
		[]string{"box.example.com. 300 IN A 104.21.30.36"}

	steps := runDomainCheck(dnsTestDeps(f, zones), checkZoneRecords, "example.com")
	world := stepByName(t, steps, "Required DNS records")
	if world.Status != StatusError {
		t.Fatalf("world step = %+v", world)
	}
	if !strings.Contains(world.Message, "Cloudflare") {
		t.Errorf("message missing %q:\n%s", "Cloudflare", world.Message)
	}
	if world.FixHint != "Turn off Cloudflare's proxy (orange cloud)" {
		t.Errorf("fix hint = %q", world.FixHint)
	}

	// A non-Cloudflare mismatch must not get the Cloudflare-specific
	// wording - it would be a wrong, actively misleading hint.
	f2 := newFakeDNS()
	f2.load(testAuth, false, zones)
	f2.load(testResolver, true, zones)
	f2.answers[dnsTestKey(testResolver, "box.example.com.", "A", true)] =
		[]string{"box.example.com. 300 IN A 198.51.100.9"}
	steps = runDomainCheck(dnsTestDeps(f2, zones), checkZoneRecords, "example.com")
	world = stepByName(t, steps, "Required DNS records")
	if strings.Contains(world.Message, "Cloudflare") || strings.Contains(world.FixHint, "Cloudflare") {
		t.Errorf("unrelated mismatch got the Cloudflare hint: %s / %s", world.Message, world.FixHint)
	}
}

func TestValuesEqual(t *testing.T) {
	cases := []struct {
		rtype, generated, observed string
		want                       bool
	}{
		{"A", "1.2.3.4", "1.2.3.4", true},
		{"A", "1.2.3.4", "1.2.3.5", false},
		{"MX", "10 Box.Example.COM.", "10 box.example.com.", true},
		{"MX", "0 .", "0 .", true},
		{"TLSA", "3 1 1 aabbcc", "3 1 1 AABBCC", true},
		{"AAAA", "2001:db8:0:0::1", "2001:db8::1", true},
		{"TXT", "v=spf1 mx -all", "v=spf1 mx -all", true},
		{"TXT", "v=spf1 MX -all", "v=spf1 mx -all", false}, // TXT is case-sensitive
	}
	for _, c := range cases {
		if got := valuesEqual(c.rtype, c.generated, c.observed); got != c.want {
			t.Errorf("valuesEqual(%s, %q, %q) = %v", c.rtype, c.generated, c.observed, got)
		}
	}
}

// delegationFixture returns zones with an external secondary NS and a
// fake preloaded with a fully healthy world: delegation, glue, no
// DNSSEC, secondary in sync.
func delegationFixture() ([]dnszone.Zone, *fakeDNS) {
	in := differInput()
	in.SecondaryNS = []string{"ns.backup.net"}
	zones := dnszone.BuildZones(in)

	f := newFakeDNS()
	f.load(testAuth, false, zones)
	f.load(testResolver, true, zones)
	f.answers[dnsTestKey(testAuth, "example.com.", "SOA", false)] = []string{
		"example.com. 300 IN SOA ns1.box.example.com. hostmaster.example.com. 100 7200 3600 1209600 86400"}
	f.answers[dnsTestKey("ns.backup.net:53", "example.com.", "SOA", false)] = []string{
		"example.com. 300 IN SOA ns1.box.example.com. hostmaster.example.com. 100 7200 3600 1209600 86400"}
	return zones, f
}

func TestDelegationHealthy(t *testing.T) {
	zones, f := delegationFixture()
	steps := runDomainCheck(dnsTestDeps(f, zones), checkDelegation, "example.com")
	if s := stepByName(t, steps, "Nameserver delegation"); s.Status != StatusOK {
		t.Errorf("delegation = %+v", s)
	}
	if s := stepByName(t, steps, "Nameserver glue"); s.Status != StatusOK {
		t.Errorf("glue = %+v", s)
	}
	if s := stepByName(t, steps, "Zone signing state"); s.Status != StatusSkipped {
		t.Errorf("signing state = %+v", s)
	}
	if s := stepByName(t, steps, "Registrar DS record"); s.Status != StatusSkipped {
		t.Errorf("ds match = %+v", s)
	}
	if s := stepByName(t, steps, "Secondary nameservers"); s.Status != StatusOK {
		t.Errorf("secondary = %+v", s)
	}
}

func TestDelegationProblems(t *testing.T) {
	zones, f := delegationFixture()
	f.answers[dnsTestKey(testResolver, "example.com.", "NS", true)] = []string{
		"example.com. 300 IN NS ns1.other-host.net."}
	f.answers[dnsTestKey(testResolver, "ns1.box.example.com.", "A", true)] = []string{
		"ns1.box.example.com. 300 IN A 198.51.100.9"}
	f.answers[dnsTestKey("ns.backup.net:53", "example.com.", "SOA", false)] = []string{
		"example.com. 300 IN SOA ns1.box.example.com. hostmaster.example.com. 99 7200 3600 1209600 86400"}

	steps := runDomainCheck(dnsTestDeps(f, zones), checkDelegation, "example.com")
	if s := stepByName(t, steps, "Nameserver delegation"); s.Status != StatusError ||
		!strings.Contains(s.FixHint, "registrar") {
		t.Errorf("delegation = %+v", s)
	}
	if s := stepByName(t, steps, "Nameserver glue"); s.Status != StatusWarning ||
		!strings.Contains(s.Message, "ns1.box.example.com") {
		t.Errorf("glue = %+v", s)
	}
	if s := stepByName(t, steps, "Secondary nameservers"); s.Status != StatusWarning ||
		!strings.Contains(s.Message, "serial 99") {
		t.Errorf("secondary = %+v", s)
	}
}

const testDNSKEY = "example.com. 3600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="

func TestDelegationDNSSEC(t *testing.T) {
	rr, err := mdns.NewRR(testDNSKEY)
	if err != nil {
		t.Fatal(err)
	}
	ds := rr.(*mdns.DNSKEY).ToDS(mdns.SHA256)

	run := func(dsAnswer []string, signed bool) (state, match Step) {
		zones, f := delegationFixture()
		if signed {
			f.answers[dnsTestKey(testAuth, "example.com.", "DNSKEY", false)] = []string{testDNSKEY}
		}
		if dsAnswer != nil {
			f.answers[dnsTestKey(testResolver, "example.com.", "DS", true)] = dsAnswer
		}
		steps := runDomainCheck(dnsTestDeps(f, zones), checkDelegation, "example.com")
		return stepByName(t, steps, "Zone signing state"), stepByName(t, steps, "Registrar DS record")
	}

	if state, match := run([]string{ds.String()}, true); state.Status != StatusOK || match.Status != StatusOK {
		t.Errorf("matching DS = %+v / %+v", state, match)
	}
	if state, match := run(nil, true); state.Status != StatusWarning || !strings.Contains(state.Message, "not active") ||
		match.Status != StatusSkipped {
		t.Errorf("missing DS = %+v / %+v", state, match)
	}
	wrong := fmt.Sprintf("example.com. 3600 IN DS %d 13 2 %s", ds.KeyTag+1, ds.Digest)
	if state, match := run([]string{wrong}, true); state.Status != StatusOK ||
		match.Status != StatusError || !strings.Contains(match.Message, "does not match") {
		t.Errorf("wrong DS = %+v / %+v", state, match)
	}
	if state, match := run([]string{ds.String()}, false); state.Status != StatusError ||
		!strings.Contains(state.FixHint, "Remove DS record") || match.Status != StatusSkipped {
		t.Errorf("orphan DS = %+v / %+v", state, match)
	}
}

func TestReverseDNS(t *testing.T) {
	f := newFakeDNS()
	d := dnsTestDeps(f, nil)
	d.PublicIPv6 = "2001:db8::1"
	rev4, _ := mdns.ReverseAddr("203.0.113.5")
	rev6, _ := mdns.ReverseAddr("2001:db8::1")
	f.answers[dnsTestKey(testResolver, rev4, "PTR", true)] = []string{rev4 + " 300 IN PTR box.example.com."}
	f.answers[dnsTestKey(testResolver, rev6, "PTR", true)] = []string{rev6 + " 300 IN PTR other-host.net."}

	steps := runDomainCheck(d, checkReverseDNS, "")
	if len(steps) != 2 {
		t.Fatalf("steps = %+v", steps)
	}
	if steps[0].Status != StatusOK {
		t.Errorf("v4 = %+v", steps[0])
	}
	if steps[1].Status != StatusWarning || !strings.Contains(steps[1].Message, "other-host.net") {
		t.Errorf("v6 = %+v", steps[1])
	}
}

func TestRRSIGExpiry(t *testing.T) {
	soa := "example.com. 300 IN SOA ns1.box.example.com. hostmaster.example.com. 100 7200 3600 1209600 86400"
	run := func(lines ...string) Step {
		f := newFakeDNS()
		f.answers[dnsTestKey(testAuth, "example.com.", "SOA", false)] = lines
		steps := runDomainCheck(dnsTestDeps(f, nil), checkRRSIGExpiry, "example.com")
		return steps[0]
	}
	sig := func(expiry string) string {
		return "example.com. 300 IN RRSIG SOA 13 2 300 " + expiry + " 20260601000000 12345 example.com. dGVzdHNpZ25hdHVyZQ=="
	}

	// testNow is 2026-07-08.
	if s := run(soa, sig("20260801000000")); s.Status != StatusOK {
		t.Errorf("fresh = %+v", s)
	}
	if s := run(soa, sig("20260712000000")); s.Status != StatusWarning {
		t.Errorf("expiring = %+v", s)
	}
	if s := run(soa, sig("20260709000000")); s.Status != StatusError {
		t.Errorf("imminent = %+v", s)
	}
	if s := run(soa, sig("20260707000000")); s.Status != StatusError || !strings.Contains(s.Message, "expired") {
		t.Errorf("expired = %+v", s)
	}
	if s := run(soa); s.Status != StatusSkipped {
		t.Errorf("unsigned = %+v", s)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMTASTSPolicy(t *testing.T) {
	policy := []byte("version: STSv1\nmode: enforce\nmx: box.example.com\nmax_age: 604800\n")
	in := differInput()
	in.MTASTSPolicyID = dnsapply.PolicyID(policy)
	zones := dnszone.BuildZones(in)

	d := dnsTestDeps(newFakeDNS(), zones)
	if domains, err := mtaSTSDomains(context.Background(), d); err != nil ||
		len(domains) != 1 || domains[0] != "example.com" {
		t.Fatalf("mtaSTSDomains = %v, %v", domains, err)
	}

	run := func(status int, body []byte) (fetch, match Step) {
		d.HTTP = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != "https://mta-sts.example.com/.well-known/mta-sts.txt" {
				t.Errorf("URL = %s", req.URL)
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body))}, nil
		})}
		steps := runDomainCheck(d, checkMTASTSPolicy, "example.com")
		return stepByName(t, steps, "MTA-STS policy is reachable"), stepByName(t, steps, "MTA-STS policy id")
	}

	if fetch, match := run(200, policy); fetch.Status != StatusOK || match.Status != StatusOK {
		t.Errorf("matching = %+v / %+v", fetch, match)
	}
	if fetch, match := run(200, []byte("version: STSv1\nmode: testing\n")); fetch.Status != StatusOK ||
		match.Status != StatusWarning || !strings.Contains(match.Message, "does not match the id") {
		t.Errorf("stale = %+v / %+v", fetch, match)
	}
	if fetch, match := run(500, nil); fetch.Status != StatusError || match.Status != StatusSkipped {
		t.Errorf("http 500 = %+v / %+v", fetch, match)
	}
}

func TestBlocklists(t *testing.T) {
	f := newFakeDNS()
	d := dnsTestDeps(f, nil)

	// Clean: NXDOMAIN on the DNSBL name.
	if s := runDomainCheck(d, checkIPBlocklist, "")[0]; s.Status != StatusOK {
		t.Errorf("clean ip = %+v", s)
	}
	// Listed: 203.0.113.5 reversed under zen.spamhaus.org.
	f.answers[dnsTestKey(testResolver, "5.113.0.203.zen.spamhaus.org.", "A", true)] = []string{
		"5.113.0.203.zen.spamhaus.org. 300 IN A 127.0.0.2"}
	if s := runDomainCheck(d, checkIPBlocklist, "")[0]; s.Status != StatusError ||
		!strings.Contains(s.Message, "Spamhaus Block List") {
		t.Errorf("listed ip = %+v", s)
	}
	// Refused (open resolver / rate limit code): honest skip, not ok.
	f.answers[dnsTestKey(testResolver, "5.113.0.203.zen.spamhaus.org.", "A", true)] = []string{
		"5.113.0.203.zen.spamhaus.org. 300 IN A 127.255.255.254"}
	if s := runDomainCheck(d, checkIPBlocklist, "")[0]; s.Status != StatusSkipped {
		t.Errorf("refused ip = %+v", s)
	}
	delete(f.answers, dnsTestKey(testResolver, "5.113.0.203.zen.spamhaus.org.", "A", true))

	// With an IPv6 address configured, the nibble name is checked too.
	if steps := runDomainCheck(d, checkIPBlocklist, ""); len(steps) != 1 {
		t.Errorf("no-IPv6 steps = %+v", steps)
	}
	d.PublicIPv6 = "2001:db8::1"
	rev6, _ := mdns.ReverseAddr("2001:db8::1")
	qname6 := strings.TrimSuffix(rev6, "ip6.arpa.") + "zen.spamhaus.org."
	f.answers[dnsTestKey(testResolver, qname6, "A", true)] = []string{qname6 + " 300 IN A 127.0.0.2"}
	steps := runDomainCheck(d, checkIPBlocklist, "")
	if len(steps) != 2 || steps[0].Status != StatusOK {
		t.Fatalf("v6 steps = %+v", steps)
	}
	if steps[1].Status != StatusError || !strings.Contains(steps[1].Message, "2001:db8::1") {
		t.Errorf("listed v6 = %+v", steps[1])
	}
	d.PublicIPv6 = ""

	if s := runDomainCheck(d, checkDomainBlocklist, "example.com")[0]; s.Status != StatusOK {
		t.Errorf("clean domain = %+v", s)
	}
	f.answers[dnsTestKey(testResolver, "example.com.dbl.spamhaus.org.", "A", true)] = []string{
		"example.com.dbl.spamhaus.org. 300 IN A 127.0.1.2"}
	if s := runDomainCheck(d, checkDomainBlocklist, "example.com")[0]; s.Status != StatusError ||
		!strings.Contains(s.Message, "Domain Block List") {
		t.Errorf("listed domain = %+v", s)
	}
}
