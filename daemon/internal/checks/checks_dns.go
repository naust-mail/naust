package checks

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	mdns "github.com/miekg/dns"

	dnszone "naust/daemon/internal/dns"
	"naust/daemon/internal/dnsapply"
	entalias "naust/daemon/internal/store/ent/alias"
	entuser "naust/daemon/internal/store/ent/user"
)

// DNSQuery is one question to one server. The two viewpoints the DNS
// checks use: this box's authoritative nsd (Recurse false, asked at
// the public IP) and the local recursive resolver (Recurse true),
// which sees what the rest of the world sees.
type DNSQuery struct {
	Server  string // "host:port" to ask
	Name    string // query name; a missing trailing dot is added
	Type    uint16 // record type (mdns.TypeA, ...)
	Recurse bool   // RD bit: true through resolvers, false at authoritatives
	DNSSEC  bool   // DO bit: include RRSIG records in the answer
}

// DNSReply is the answer section plus the response code.
type DNSReply struct {
	Rcode  int
	Answer []mdns.RR
}

func defaultDNSQuery(ctx context.Context, q DNSQuery) (*DNSReply, error) {
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(q.Name), q.Type)
	m.RecursionDesired = q.Recurse
	m.SetEdns0(1232, q.DNSSEC)
	for _, network := range []string{"udp", "tcp"} {
		c := &mdns.Client{Net: network, Timeout: 5 * time.Second}
		r, _, err := c.ExchangeContext(ctx, m, q.Server)
		if err != nil {
			return nil, err
		}
		if !r.Truncated || network == "tcp" {
			return &DNSReply{Rcode: r.Rcode, Answer: r.Answer}, nil
		}
	}
	return nil, fmt.Errorf("%s: unreachable", q.Name)
}

// resolverAddr is the local recursive resolver (unbound): the
// world's viewpoint. authAddr is this box's authoritative nsd.
func resolverAddr(d *Deps) string {
	return net.JoinHostPort(d.flag("DNS_HOST", "127.0.0.1"), "53")
}

// authAddr is dialed to query the authoritative nsd directly, bypassing
// the recursive resolver - on bare metal that means the box's own public
// address, proving nsd actually answers on the interface the internet
// sees. In Docker, PublicIP is not bound to any interface inside the
// sibling "dns" container, so it can never be reached that way; DNS_HOST
// (the container name) on nsd's real port (see nsdPort in
// checks_services.go) is the only address that means anything there.
func authAddr(d *Deps) string {
	if d.InDocker {
		return net.JoinHostPort(d.flag("DNS_HOST", "127.0.0.1"), fmt.Sprint(nsdPort(d)))
	}
	return net.JoinHostPort(d.PublicIP, "53")
}

func dnsChecks() []Check {
	zonesEnabled := func(d *Deps) bool { return d.Zones != nil }
	return []Check{
		{
			// The two-viewpoint zone differ: every generated record is
			// checked against what nsd serves and what the world
			// resolves, replacing the legacy per-record-type checks and
			// covering SRV/CAA/custom/TLSA records those never did.
			Name:        "dns-zone",
			Title:       "DNS records published",
			Description: "Confirms that every DNS record this box generates for a domain (mail routing, sender authentication, and the rest) is actually being served by this box's nameserver and can be looked up out on the internet. If they do not resolve, other mail servers cannot find yours and mail may be rejected.",
			Category:    "dns", Locus: LocusWorld, Tier: TierHourly,
			Timeout: 2 * time.Minute, DependsOn: []string{"unbound"},
			Enabled: zonesEnabled, Domains: zoneApexes,
			Run: checkZoneRecords,
		},
		{
			Name:        "dns-delegation",
			Title:       "Nameserver delegation",
			Description: "Confirms that your domain registrar points the world at this box's nameservers and that the DNSSEC security link recorded at the registrar matches this box's signing keys. If the delegation or that link is wrong, the world may be unable to look up your domain at all.",
			Category:    "dns", Locus: LocusWorld, Tier: TierDaily,
			Timeout: time.Minute, DependsOn: []string{"unbound"},
			Enabled: zonesEnabled, Domains: zoneApexes,
			Run: checkDelegation,
		},
		{
			// Guards a wedged applier: dnsapply only signs when a zone
			// changes, so an untouched zone's signatures can march
			// toward expiry unnoticed.
			Name:        "dnssec-signatures",
			Title:       "DNSSEC signature freshness",
			Description: "Checks that the cryptographic signatures protecting your domain's DNS have not been allowed to go stale by the automatic re-signing. If they expire, resolvers that verify DNSSEC stop being able to look up your domain.",
			Category:    "dns", Locus: LocusNode, Tier: TierDaily,
			Enabled: zonesEnabled, Domains: zoneApexes,
			Run: checkRRSIGExpiry,
		},
		{
			Name:        "reverse-dns",
			Title:       "Reverse DNS",
			Description: "Checks that looking up this server's IP address returns its hostname. Many mail servers reject mail from addresses whose reverse DNS does not match, so a mismatch can get your outbound mail bounced.",
			Category:    "dns", Locus: LocusWorld, Tier: TierDaily,
			DependsOn: []string{"unbound"},
			Run:       checkReverseDNS,
		},
		{
			Name:        "mta-sts-policy",
			Title:       "MTA-STS policy",
			Description: "For domains that advertise the stricter mail-transport policy MTA-STS, checks that the policy file is actually reachable over HTTPS and matches what DNS says it should be. A missing or mismatched policy can make senders that already saw it refuse to deliver mail to you.",
			Category:    "mail", Locus: LocusWorld, Tier: TierHourly,
			DependsOn: []string{"unbound"},
			Enabled:   zonesEnabled, Domains: mtaSTSDomains,
			Run: checkMTASTSPolicy,
		},
		{
			Name:        "ip-blocklist",
			Title:       "IP blocklist",
			Description: "Checks whether this server's IP address appears on the Spamhaus block list, a widely used spam blacklist. If it is listed, the mail you send is probably being rejected by other servers.",
			Category:    "mail", Locus: LocusWorld, Tier: TierDaily,
			DependsOn: []string{"unbound"},
			Run:       checkIPBlocklist,
		},
		{
			Name:        "domain-blocklist",
			Title:       "Domain blocklist",
			Description: "Checks whether one of your mail domains appears on the Spamhaus domain block list. If it is listed, mail from that domain is probably being rejected by other servers.",
			Category:    "mail", Locus: LocusWorld, Tier: TierDaily,
			DependsOn: []string{"unbound"}, Domains: mailDomains,
			Run: checkDomainBlocklist,
		},
	}
}

func zoneApexes(ctx context.Context, d *Deps) ([]string, error) {
	zones, err := d.Zones(ctx)
	if err != nil {
		return nil, err
	}
	apexes := make([]string, 0, len(zones))
	for _, z := range zones {
		apexes = append(apexes, z.Apex)
	}
	return apexes, nil
}

func findZone(ctx context.Context, d *Deps, apex string) (*dnszone.Zone, error) {
	zones, err := d.Zones(ctx)
	if err != nil {
		return nil, err
	}
	for i := range zones {
		if zones[i].Apex == apex {
			return &zones[i], nil
		}
	}
	return nil, fmt.Errorf("zone %s no longer exists", apex)
}

// mailDomains lists the distinct domains of user accounts and alias
// sources, the same derivation dnsapply uses for MailDomains.
func mailDomains(ctx context.Context, d *Deps) ([]string, error) {
	emails, err := d.Store.User.Query().Select(entuser.FieldEmail).Strings(ctx)
	if err != nil {
		return nil, err
	}
	sources, err := d.Store.Alias.Query().Select(entalias.FieldSource).Strings(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, addr := range append(emails, sources...) {
		if _, domain, ok := strings.Cut(addr, "@"); ok && domain != "" && !seen[domain] {
			seen[domain] = true
			out = append(out, domain)
		}
	}
	sort.Strings(out)
	return out, nil
}

// mtaSTSDomains lists the domains whose generated zone advertises an
// MTA-STS policy (an _mta-sts TXT record exists).
func mtaSTSDomains(ctx context.Context, d *Deps) ([]string, error) {
	zones, err := d.Zones(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, z := range zones {
		for _, rec := range z.Records {
			if rec.Type != "TXT" || !strings.HasPrefix(rec.Value, "v=STSv1;") {
				continue
			}
			switch {
			case rec.Name == "_mta-sts":
				out = append(out, z.Apex)
			case strings.HasPrefix(rec.Name, "_mta-sts."):
				out = append(out, strings.TrimPrefix(rec.Name, "_mta-sts.")+"."+z.Apex)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// ---- zone differ ----

type rrKey struct{ name, rtype string }

// rrMismatch is one (name, type) group whose generated values were not
// all observed at a viewpoint.
type rrMismatch struct {
	fqdn     string
	rtype    string
	expected []string // generated values that were not observed
	observed []string // everything the viewpoint returned for the group
	category dnszone.Category
	err      error // query failure, if any
}

func (m rrMismatch) describe() string {
	if m.err != nil {
		return fmt.Sprintf("%s %s (query failed: %v)", m.fqdn, m.rtype, m.err)
	}
	return fmt.Sprintf("%s %s", m.fqdn, m.rtype)
}

// categoryRank orders zonebuild categories by importance.
func categoryRank(c dnszone.Category) int {
	switch c {
	case dnszone.CatRequired:
		return 4
	case dnszone.CatRecommended:
		return 3
	case dnszone.CatOptional:
		return 2
	case dnszone.CatHardening:
		return 1
	}
	return 0 // internal (ns1/ns2 addresses)
}

func fqdnOf(name, apex string) string {
	if name == "" {
		return apex + "."
	}
	return name + "." + apex + "."
}

func checkZoneRecords(ctx context.Context, d *Deps, apex string, r *Reporter) {
	zone, err := findZone(ctx, d, apex)
	if err != nil {
		r.Step("The generated zone is available", func(s *StepCtx) { s.Failf("%v", err) })
		return
	}

	// Group generated records into expected RRsets. NS at the apex is
	// excluded: delegation belongs to the registrar (dns-delegation
	// owns it), so the differ never double-reports it.
	groups := map[rrKey][]dnszone.ZoneRecord{}
	var order []rrKey
	for _, rec := range zone.Records {
		if rec.Name == "" && rec.Type == "NS" {
			continue
		}
		k := rrKey{rec.Name, rec.Type}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], rec)
	}

	authOK := true
	r.Step("This box's nameserver (nsd) serves the generated records", func(s *StepCtx) {
		misses := diffViewpoint(ctx, d, apex, order, groups,
			DNSQuery{Server: authAddr(d), Recurse: false})
		if len(misses) == 0 {
			return
		}
		authOK = false
		s.Expect(expectedLines(misses), observedLines(misses))
		s.Failf("nsd is not serving %d generated record group(s) for %s - the zone on disk is stale or nsd did not reload. First: %s.",
			len(misses), apex, misses[0].describe())
		s.Hint("service.restart nsd")
	})

	// One diff against the world's viewpoint, partitioned by category:
	// missing required records fail, lesser categories only warn.
	var required, lesser []rrMismatch
	r.Step("Required DNS records resolve publicly", func(s *StepCtx) {
		misses := diffViewpoint(ctx, d, apex, order, groups,
			DNSQuery{Server: resolverAddr(d), Recurse: true})
		sort.SliceStable(misses, func(i, j int) bool {
			return categoryRank(misses[i].category) > categoryRank(misses[j].category)
		})
		for _, m := range misses {
			if categoryRank(m.category) >= categoryRank(dnszone.CatRequired) {
				required = append(required, m)
			} else {
				lesser = append(lesser, m)
			}
		}
		if len(required) == 0 {
			return
		}
		s.Expect(expectedLines(required), observedLines(required))
		s.Failf("%s", publicDiffMessage(apex, required, authOK))
		if hint := recordFixHint(required[0], authOK); hint != "" {
			s.Hint(hint)
		}
	})

	r.Step("Recommended and optional records resolve publicly", func(s *StepCtx) {
		if len(lesser) == 0 {
			return
		}
		s.Expect(expectedLines(lesser), observedLines(lesser))
		s.Warnf("%s", publicDiffMessage(apex, lesser, authOK))
		if hint := recordFixHint(lesser[0], authOK); hint != "" {
			s.Hint(hint)
		}
	})
}

// diffViewpoint checks every generated RRset against one viewpoint,
// one-directionally: each generated value must appear in the live
// answer; extra live records are never policed.
func diffViewpoint(ctx context.Context, d *Deps, apex string, order []rrKey, groups map[rrKey][]dnszone.ZoneRecord, base DNSQuery) []rrMismatch {
	var out []rrMismatch
	for _, k := range order {
		recs := groups[k]
		qtype, ok := mdns.StringToType[k.rtype]
		if !ok {
			continue // unknown type: nothing we can query
		}
		q := base
		q.Name = fqdnOf(k.name, apex)
		q.Type = qtype

		reply, err := d.Query(ctx, q)
		if err != nil {
			out = append(out, rrMismatch{fqdn: q.Name, rtype: k.rtype,
				expected: recordValues(recs), category: worstCategory(recs), err: err})
			continue
		}
		observed := rdataStrings(reply.Answer, qtype)
		var missing []string
		worst := dnszone.CatInternal
		for _, rec := range recs {
			found := false
			for _, o := range observed {
				if valuesEqual(k.rtype, rec.Value, o) {
					found = true
					break
				}
			}
			if !found {
				missing = append(missing, rec.Value)
				if categoryRank(rec.Category) > categoryRank(worst) {
					worst = rec.Category
				}
			}
		}
		if len(missing) > 0 {
			out = append(out, rrMismatch{fqdn: q.Name, rtype: k.rtype,
				expected: missing, observed: observed, category: worst})
		}
	}
	return out
}

func recordValues(recs []dnszone.ZoneRecord) []string {
	var out []string
	for _, rec := range recs {
		out = append(out, rec.Value)
	}
	return out
}

func worstCategory(recs []dnszone.ZoneRecord) dnszone.Category {
	worst := dnszone.CatInternal
	for _, rec := range recs {
		if categoryRank(rec.Category) > categoryRank(worst) {
			worst = rec.Category
		}
	}
	return worst
}

// rdataStrings extracts the rdata text of every answer record of the
// queried type (CNAME chase results and RRSIGs of other types are
// ignored). TXT strings are joined across their 255-byte chunks.
func rdataStrings(answer []mdns.RR, qtype uint16) []string {
	var out []string
	for _, rr := range answer {
		if rr.Header().Rrtype != qtype {
			continue
		}
		if t, ok := rr.(*mdns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
			continue
		}
		out = append(out, rdataOf(rr))
	}
	return out
}

func rdataOf(rr mdns.RR) string {
	return strings.TrimSpace(strings.TrimPrefix(rr.String(), rr.Header().String()))
}

// valuesEqual compares a generated record value with observed rdata.
// TXT compares exactly (SPF/DKIM material is case-sensitive); other
// types compare case-insensitively after round-tripping both sides
// through the DNS presentation parser so formatting (hex case, IPv6
// forms, quoting) never causes a false mismatch.
func valuesEqual(rtype, generated, observed string) bool {
	if rtype == "TXT" {
		return generated == observed
	}
	return canonicalRdata(rtype, generated) == canonicalRdata(rtype, observed)
}

func canonicalRdata(rtype, value string) string {
	if rr, err := mdns.NewRR(fmt.Sprintf("x.example. 300 IN %s %s", rtype, value)); err == nil {
		value = rdataOf(rr)
	}
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func expectedLines(misses []rrMismatch) string {
	var b []string
	for _, m := range misses {
		b = append(b, fmt.Sprintf("%s %s %s", m.fqdn, m.rtype, strings.Join(m.expected, " / ")))
	}
	return strings.Join(b, "\n")
}

func observedLines(misses []rrMismatch) string {
	var b []string
	for _, m := range misses {
		switch {
		case m.err != nil:
			b = append(b, fmt.Sprintf("%s %s query failed: %v", m.fqdn, m.rtype, m.err))
		case len(m.observed) == 0:
			b = append(b, fmt.Sprintf("%s %s (no record)", m.fqdn, m.rtype))
		default:
			b = append(b, fmt.Sprintf("%s %s %s", m.fqdn, m.rtype, strings.Join(m.observed, " / ")))
		}
	}
	return strings.Join(b, "\n")
}

func publicDiffMessage(apex string, misses []rrMismatch, authOK bool) string {
	first := misses[0]
	msg := fmt.Sprintf("%d record group(s) of %s do not resolve publicly as generated. Most important: %s.",
		len(misses), apex, first.describe())
	if hint := recordHint(first); hint != "" {
		msg += " " + hint
	}
	if authOK {
		msg += " This box serves the correct records: if DNS for this domain is hosted elsewhere, add or update these records at your DNS host; otherwise check the delegation (dns-delegation) and allow for the record TTL."
	}
	return msg
}

// anyCloudflareIP reports whether any observed value is a Cloudflare
// proxy IP - the single most common identifiable cause of an A/AAAA
// record not resolving to this box.
func anyCloudflareIP(observed []string) bool {
	for _, v := range observed {
		if isCloudflareIP(v) {
			return true
		}
	}
	return false
}

// recordHint keeps the actionable consequence prose the legacy
// per-record checks had, for the record types where it matters.
func recordHint(m rrMismatch) string {
	value := ""
	if len(m.expected) > 0 {
		value = m.expected[0]
	}
	switch {
	case (m.rtype == "A" || m.rtype == "AAAA") && anyCloudflareIP(m.observed):
		return "The address on file is one of Cloudflare's proxy IPs (the \"orange cloud\"), which does not pass through mail protocols (SMTP/IMAP) and will break certificate issuance and mail delivery."
	case m.rtype == "MX":
		return "Mail is delivered to the servers named in the MX record; until it matches, mail for this domain will not reach this box."
	case m.rtype == "TLSA":
		return "DANE-validating mail servers refuse delivery when the TLSA record does not match the certificate key."
	case m.rtype == "TXT" && strings.HasPrefix(value, "v=spf1"):
		return "Without the SPF record, other mail servers may reject or junk mail sent from this domain."
	case m.rtype == "TXT" && strings.HasPrefix(value, "v=DKIM1;"):
		return "Without the DKIM public key, signatures on outbound mail cannot be verified."
	case m.rtype == "TXT" && strings.HasPrefix(value, "v=DMARC1;"):
		return "Without the DMARC record, receivers cannot apply this domain's mail authentication policy."
	case m.rtype == "TXT" && strings.HasPrefix(value, "v=STSv1;"):
		return "Senders cache MTA-STS by id; a stale id keeps them on an old policy."
	}
	return ""
}

// recordFixHint is the short fix action for the most important
// mismatch in a diff. When this box's own nsd is not serving the
// record correctly (!authOK), the fix is nsd-side and already
// carried as the hint on "This box's nameserver (nsd) serves the
// generated records" - repeating it here would be noise.
func recordFixHint(m rrMismatch, authOK bool) string {
	if !authOK {
		return ""
	}
	if (m.rtype == "A" || m.rtype == "AAAA") && anyCloudflareIP(m.observed) {
		return "Turn off Cloudflare's proxy (orange cloud)"
	}
	return "Update at your DNS host"
}

// ---- delegation / registrar ----

func checkDelegation(ctx context.Context, d *Deps, apex string, r *Reporter) {
	zone, err := findZone(ctx, d, apex)
	if err != nil {
		r.Step("The generated zone is available", func(s *StepCtx) { s.Failf("%v", err) })
		return
	}
	var expectedNS []string
	for _, rec := range zone.Records {
		if rec.Name == "" && rec.Type == "NS" {
			expectedNS = append(expectedNS, strings.ToLower(rec.Value))
		}
	}

	r.Step("Nameserver delegation points at this box", func(s *StepCtx) {
		reply, err := d.Query(ctx, DNSQuery{Server: resolverAddr(d), Name: apex + ".", Type: mdns.TypeNS, Recurse: true})
		if err != nil {
			s.Warnf("could not look up the NS records for %s: %v", apex, err)
			return
		}
		observed := lowerAll(rdataStrings(reply.Answer, mdns.TypeNS))
		s.Expect(strings.Join(expectedNS, " "), orNone(observed))
		present := 0
		for _, ns := range expectedNS {
			if contains(observed, ns) {
				present++
			}
		}
		switch {
		case present == len(expectedNS):
		case present == 0:
			s.Failf("The nameservers for %s are %s; they should be %s. If you intentionally host DNS elsewhere, make sure every generated record is mirrored there (see the dns-zone check).",
				apex, orNone(observed), strings.Join(expectedNS, ", "))
			s.Hint("Update NS records at registrar")
		default:
			s.Warnf("Only %d of %d of this box's nameservers are delegated for %s.",
				present, len(expectedNS), apex)
			s.Hint("Update NS records at registrar")
		}
	})

	// Glue only matters in the zone that contains ns1/ns2.<primary>.
	if apex == d.PrimaryHostname || strings.HasSuffix(d.PrimaryHostname, "."+apex) {
		r.Step("Nameserver glue records resolve to this box", func(s *StepCtx) {
			// AAAA glue is only expected when the box has a public
			// IPv6 address; without one it is never queried.
			type glueTarget struct {
				qtype uint16
				ip    string
			}
			wanted := []glueTarget{{mdns.TypeA, d.PublicIP}}
			if d.PublicIPv6 != "" {
				want6 := d.PublicIPv6
				if ip := net.ParseIP(want6); ip != nil {
					want6 = ip.String()
				}
				wanted = append(wanted, glueTarget{mdns.TypeAAAA, want6})
			}
			for _, host := range []string{"ns1." + d.PrimaryHostname, "ns2." + d.PrimaryHostname} {
				for _, w := range wanted {
					reply, err := d.Query(ctx, DNSQuery{Server: resolverAddr(d), Name: host + ".", Type: w.qtype, Recurse: true})
					if err != nil {
						s.Warnf("could not resolve %s: %v", host, err)
						continue
					}
					ips := rdataStrings(reply.Answer, w.qtype)
					if !contains(ips, w.ip) {
						s.Expect(w.ip, orNone(ips))
						s.Warnf("Nameserver glue for %s is incorrect: it resolves to %s but should be %s.",
							host, orNone(ips), w.ip)
						s.Hint("Update glue records at registrar")
					}
				}
			}
		})
	}

	// The DNSSEC chain in two phases: first that the zone's signing
	// state and the registrar's DS record agree at all, then that a
	// present DS record actually matches the signing keys.
	var ksks []*mdns.DNSKEY
	var liveDS []*mdns.DS
	var dsLookupErr error
	r.Step("Zone signing state and registrar DS agree", func(s *StepCtx) {
		keys, err := d.Query(ctx, DNSQuery{Server: authAddr(d), Name: apex + ".", Type: mdns.TypeDNSKEY, Recurse: false})
		if err != nil {
			s.Warnf("could not read the DNSKEY records from nsd: %v", err)
			return
		}
		for _, rr := range keys.Answer {
			if k, ok := rr.(*mdns.DNSKEY); ok && k.Flags&mdns.SEP != 0 {
				ksks = append(ksks, k)
			}
		}
		dsReply, dsErr := d.Query(ctx, DNSQuery{Server: resolverAddr(d), Name: apex + ".", Type: mdns.TypeDS, Recurse: true})
		dsLookupErr = dsErr
		if len(ksks) == 0 {
			if dsErr == nil && len(rdataStrings(dsReply.Answer, mdns.TypeDS)) > 0 {
				s.Failf("A DS record exists at the registrar for %s but the zone is not signed - the domain fails DNSSEC validation and may not resolve.", apex)
				s.Hint("Remove DS record at registrar")
			} else {
				s.Skipf("the zone is not signed")
			}
			return
		}
		if dsErr != nil {
			s.Warnf("could not look up the DS record for %s: %v", apex, dsErr)
			return
		}
		for _, rr := range dsReply.Answer {
			if ds, ok := rr.(*mdns.DS); ok {
				liveDS = append(liveDS, ds)
			}
		}
		if len(liveDS) == 0 {
			if want := ksks[0].ToDS(mdns.SHA256); want != nil {
				s.Expect(rdataOf(want), "no DS record")
			}
			s.Warnf("DNSSEC is set up on this box for %s but not active: no DS record exists at the registrar.", apex)
			s.Hint("Add DS record at registrar")
		}
	})

	r.Step("Registrar DS record matches the signing keys", func(s *StepCtx) {
		switch {
		case len(ksks) == 0:
			s.Skipf("the zone is not signed")
			return
		case dsLookupErr != nil:
			s.Skipf("the DS record could not be looked up")
			return
		case len(liveDS) == 0:
			s.Skipf("no DS record exists at the registrar")
			return
		}
		matched := false
		for _, ds := range liveDS {
			for _, k := range ksks {
				ours := k.ToDS(ds.DigestType)
				if ours != nil && ours.KeyTag == ds.KeyTag && strings.EqualFold(ours.Digest, ds.Digest) {
					matched = true
				}
			}
		}
		if matched {
			return
		}
		// Show our keys as DS records in the digest type(s) the live
		// records actually use, so the display reflects the exact
		// comparison that failed.
		var expected, observed []string
		seenDigest := map[uint8]bool{}
		for _, ds := range liveDS {
			observed = append(observed, rdataOf(ds))
			if seenDigest[ds.DigestType] {
				continue
			}
			seenDigest[ds.DigestType] = true
			for _, k := range ksks {
				if ours := k.ToDS(ds.DigestType); ours != nil {
					expected = append(expected, rdataOf(ours))
				}
			}
		}
		if len(expected) == 0 {
			// Only unsupported digest types live: show the SHA-256 DS
			// the registrar should carry instead.
			if want := ksks[0].ToDS(mdns.SHA256); want != nil {
				expected = append(expected, rdataOf(want))
			}
		}
		s.Expect(strings.Join(expected, "\n"), strings.Join(observed, "\n"))
		s.Failf("The DS record at the registrar for %s does not match this zone's signing keys - DNSSEC validation fails and the domain may not resolve.", apex)
		s.Hint("Update DS record at registrar")
	})

	// Secondaries: delegated NS names that are not this box's own.
	own := map[string]bool{
		"ns1." + strings.ToLower(d.PrimaryHostname) + ".": true,
		"ns2." + strings.ToLower(d.PrimaryHostname) + ".": true,
	}
	var secondaries []string
	for _, ns := range expectedNS {
		if !own[ns] {
			secondaries = append(secondaries, ns)
		}
	}
	if len(secondaries) > 0 {
		r.Step("Secondary nameservers are in sync", func(s *StepCtx) {
			reply, err := d.Query(ctx, DNSQuery{Server: authAddr(d), Name: apex + ".", Type: mdns.TypeSOA, Recurse: false})
			if err != nil {
				s.Warnf("could not read this box's SOA for %s: %v", apex, err)
				return
			}
			ours, ok := soaSerial(reply.Answer)
			if !ok {
				s.Warnf("nsd did not answer the SOA query for %s", apex)
				return
			}
			for _, ns := range secondaries {
				server := net.JoinHostPort(strings.TrimSuffix(ns, "."), "53")
				reply, err := d.Query(ctx, DNSQuery{Server: server, Name: apex + ".", Type: mdns.TypeSOA, Recurse: false})
				if err != nil {
					s.Warnf("secondary nameserver %s did not answer: %v", ns, err)
					continue
				}
				serial, ok := soaSerial(reply.Answer)
				if !ok {
					s.Warnf("secondary nameserver %s does not serve %s.", ns, apex)
					continue
				}
				if serial != ours {
					s.Expect(fmt.Sprintf("serial %d", ours), fmt.Sprintf("serial %d", serial))
					s.Warnf("Secondary nameserver %s serves serial %d for %s but this box serves %d - the zone transfer is lagging or broken.",
						ns, serial, apex, ours)
				}
			}
		})
	}
}

func soaSerial(answer []mdns.RR) (uint32, bool) {
	for _, rr := range answer {
		if soa, ok := rr.(*mdns.SOA); ok {
			return soa.Serial, true
		}
	}
	return 0, false
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func orNone(values []string) string {
	if len(values) == 0 {
		return "(none)"
	}
	return strings.Join(values, " ")
}

// ---- RRSIG expiry ----

func checkRRSIGExpiry(ctx context.Context, d *Deps, apex string, r *Reporter) {
	r.Step("Zone signatures are fresh", func(s *StepCtx) {
		reply, err := d.Query(ctx, DNSQuery{Server: authAddr(d), Name: apex + ".", Type: mdns.TypeSOA, Recurse: false, DNSSEC: true})
		if err != nil {
			s.Warnf("could not query nsd for %s: %v", apex, err)
			return
		}
		var sig *mdns.RRSIG
		for _, rr := range reply.Answer {
			if rs, ok := rr.(*mdns.RRSIG); ok && rs.TypeCovered == mdns.TypeSOA {
				sig = rs
			}
		}
		if sig == nil {
			s.Skipf("the zone is not signed")
			return
		}
		// The applier renews signatures ten days before expiry and is
		// kicked at least daily, so a healthy zone never gets below
		// nine days: five days means renewal has failed repeatedly.
		expires := time.Unix(int64(sig.Expiration), 0)
		left := expires.Sub(d.Now())
		s.Expect("signatures valid for more than 5 days",
			fmt.Sprintf("expire %s", expires.UTC().Format("2006-01-02")))
		switch {
		case left <= 0:
			s.Failf("The DNSSEC signatures for %s expired on %s - validating resolvers can no longer resolve the domain. Zone re-signing is failing; check the managerd log.",
				apex, expires.UTC().Format("2006-01-02"))
		case left < 2*24*time.Hour:
			s.Failf("The DNSSEC signatures for %s expire on %s - validating resolvers will stop resolving the domain. Zone re-signing is failing; check the managerd log.",
				apex, expires.UTC().Format("2006-01-02"))
		case left < 5*24*time.Hour:
			s.Warnf("The DNSSEC signatures for %s expire on %s and should have been renewed already. Zone re-signing is failing; check the managerd log.",
				apex, expires.UTC().Format("2006-01-02"))
		}
	})
}

// ---- reverse DNS ----

func checkReverseDNS(ctx context.Context, d *Deps, _ string, r *Reporter) {
	want := strings.ToLower(d.PrimaryHostname) + "."
	for _, ip := range []string{d.PublicIP, d.PublicIPv6} {
		if ip == "" {
			continue
		}
		ip := ip
		r.Step(fmt.Sprintf("Reverse DNS of %s points at this box", ip), func(s *StepCtx) {
			rev, err := mdns.ReverseAddr(ip)
			if err != nil {
				s.Warnf("cannot form the reverse name for %s: %v", ip, err)
				return
			}
			reply, err := d.Query(ctx, DNSQuery{Server: resolverAddr(d), Name: rev, Type: mdns.TypePTR, Recurse: true})
			if err != nil {
				s.Warnf("reverse DNS lookup for %s failed: %v", ip, err)
				return
			}
			ptrs := lowerAll(rdataStrings(reply.Answer, mdns.TypePTR))
			s.Expect(want, orNone(ptrs))
			if !contains(ptrs, want) {
				s.Warnf("Reverse DNS for %s is %s, but it should be %s. Many mail servers reject mail from hosts without matching reverse DNS.",
					ip, orNone(ptrs), d.PrimaryHostname)
				s.Hint("Set PTR record at hosting provider")
			}
		})
	}
}

// ---- MTA-STS policy ----

func checkMTASTSPolicy(ctx context.Context, d *Deps, domain string, r *Reporter) {
	var id, served string
	fetched := false
	r.Step("MTA-STS policy is reachable over HTTPS", func(s *StepCtx) {
		var err error
		id, err = advertisedSTSID(ctx, d, domain)
		if err != nil {
			s.Warnf("could not load the generated zones: %v", err)
			return
		}
		if id == "" {
			s.Skipf("no MTA-STS policy is advertised for %s", domain)
			return
		}
		url := "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			s.Warnf("%v", err)
			return
		}
		resp, err := d.HTTP.Do(req)
		if err != nil {
			s.Failf("DNS advertises an MTA-STS policy for %s but it could not be fetched (%v). Senders that cached the policy may refuse mail.",
				domain, err)
			s.Hint("service.restart nginx")
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if resp.StatusCode != http.StatusOK {
			s.Failf("DNS advertises an MTA-STS policy for %s but %s returned HTTP %d. Senders that cached the policy may refuse mail.",
				domain, url, resp.StatusCode)
			s.Hint("service.restart nginx")
			return
		}
		served = dnsapply.PolicyID(body)
		fetched = true
	})
	r.Step("MTA-STS policy id matches DNS", func(s *StepCtx) {
		if !fetched {
			s.Skipf("no served policy to compare")
			return
		}
		s.Expect("policy id "+id, "policy id "+served)
		if served != id {
			s.Warnf("The MTA-STS policy served for %s does not match the id advertised in DNS - the zone or the policy file is stale. Senders keep using the old policy until they match.", domain)
		}
	})
}

// advertisedSTSID returns the id in the generated _mta-sts TXT record
// for domain, or "" when none is advertised.
func advertisedSTSID(ctx context.Context, d *Deps, domain string) (string, error) {
	zones, err := d.Zones(ctx)
	if err != nil {
		return "", err
	}
	for _, z := range zones {
		for _, rec := range z.Records {
			if rec.Type != "TXT" || !strings.HasPrefix(rec.Value, "v=STSv1;") {
				continue
			}
			var name string
			switch {
			case rec.Name == "_mta-sts":
				name = z.Apex
			case strings.HasPrefix(rec.Name, "_mta-sts."):
				name = strings.TrimPrefix(rec.Name, "_mta-sts.") + "." + z.Apex
			default:
				continue
			}
			if name == domain {
				if _, id, ok := strings.Cut(rec.Value, "id="); ok {
					return strings.TrimSpace(id), nil
				}
			}
		}
	}
	return "", nil
}

// ---- Spamhaus blocklists ----

// dnsblLookup queries a DNSBL name through the local resolver. It
// returns the listing codes, or a skip reason when Spamhaus refused
// the query (public/open resolver or rate limiting; RFC 8904 style
// 127.255.255.x codes).
func dnsblLookup(ctx context.Context, d *Deps, qname string) (codes []string, skip string, err error) {
	reply, err := d.Query(ctx, DNSQuery{Server: resolverAddr(d), Name: qname, Type: mdns.TypeA, Recurse: true})
	if err != nil {
		return nil, "", err
	}
	for _, v := range rdataStrings(reply.Answer, mdns.TypeA) {
		if strings.HasPrefix(v, "127.255.255.") {
			return nil, "Spamhaus refused the query (rate limited or the resolver is considered public); try again later", nil
		}
		codes = append(codes, v)
	}
	return codes, "", nil
}

func checkIPBlocklist(ctx context.Context, d *Deps, _ string, r *Reporter) {
	r.Step("IPv4 address is not on the Spamhaus block list", func(s *StepCtx) {
		ip := net.ParseIP(d.PublicIP)
		if ip == nil || ip.To4() == nil {
			s.Skipf("no public IPv4 address")
			return
		}
		v4 := ip.To4()
		qname := fmt.Sprintf("%d.%d.%d.%d.zen.spamhaus.org.", v4[3], v4[2], v4[1], v4[0])
		blocklistVerdict(ctx, d, s, qname, d.PublicIP)
	})
	if d.PublicIPv6 == "" {
		return
	}
	r.Step("IPv6 address is not on the Spamhaus block list", func(s *StepCtx) {
		// ReverseAddr yields the nibble form Spamhaus expects; swap its
		// ip6.arpa. suffix for the ZEN zone.
		rev, err := mdns.ReverseAddr(d.PublicIPv6)
		if err != nil {
			s.Warnf("cannot form the lookup name for %s: %v", d.PublicIPv6, err)
			return
		}
		qname := strings.TrimSuffix(rev, "ip6.arpa.") + "zen.spamhaus.org."
		blocklistVerdict(ctx, d, s, qname, d.PublicIPv6)
	})
}

// blocklistVerdict runs one ZEN lookup and reports the verdict for addr.
func blocklistVerdict(ctx context.Context, d *Deps, s *StepCtx, qname, addr string) {
	codes, skip, err := dnsblLookup(ctx, d, qname)
	switch {
	case err != nil:
		s.Warnf("could not check the Spamhaus block list: %v", err)
	case skip != "":
		s.Skipf("%s", skip)
	case len(codes) > 0:
		s.Expect("not listed", strings.Join(codes, " "))
		s.Failf("The IP address of this box (%s) is listed in the Spamhaus Block List (%s). Mail you send is likely being rejected.",
			addr, strings.Join(codes, ", "))
		s.Hint("Request delisting at https://check.spamhaus.org")
	}
}

func checkDomainBlocklist(ctx context.Context, d *Deps, domain string, r *Reporter) {
	r.Step("Domain is not on the Spamhaus domain block list", func(s *StepCtx) {
		codes, skip, err := dnsblLookup(ctx, d, domain+".dbl.spamhaus.org.")
		listed := false
		for _, c := range codes {
			if strings.HasPrefix(c, "127.0.1.") {
				listed = true
			}
		}
		switch {
		case err != nil:
			s.Warnf("could not check the Spamhaus domain block list: %v", err)
		case skip != "":
			s.Skipf("%s", skip)
		case listed:
			s.Expect("not listed", strings.Join(codes, " "))
			s.Failf("The domain %s is listed in the Spamhaus Domain Block List (%s). Mail from this domain is likely being rejected.",
				domain, strings.Join(codes, ", "))
			s.Hint("Request delisting at https://check.spamhaus.org")
		}
	})
}
