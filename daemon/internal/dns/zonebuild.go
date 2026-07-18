package dns

import (
	"sort"
	"strings"
)

// This file ports build_zones/build_zone from the legacy Python
// (services/dns_update/zones.py) as a pure function over ZoneInput.
// Not yet emitted, pending inputs from later slices: SSHFP (needs
// host keys). TLSA and the MTA-STS TXT policy records are emitted
// when the caller supplies their certificate-derived inputs.

// Record is a custom DNS record with a fully qualified name.
type Record struct {
	QName string
	RType string
	Value string
}

// ZoneInput is everything zone generation depends on, gathered by the
// caller from the store, settings, and disk.
type ZoneInput struct {
	PrimaryHostname string
	PublicIP        string
	// PublicIPv6 empty means the box has no IPv6.
	PublicIPv6 string
	// MailDomains hold at least one address (user or alias);
	// UserDomains hold at least one login account and are the subset
	// that gets autoconfig/autodiscover names.
	MailDomains []string
	UserDomains []string
	// Custom records; A/AAAA values may be the "local" sentinel.
	Custom []Record
	// SecondaryNS is the secondary-nameserver setting verbatim;
	// "xfr:" entries are transfer-only and produce no NS records.
	SecondaryNS []string
	// DKIMRecord is the TXT value from the OpenDKIM key file, emitted
	// at DKIMSelector for every mail domain. Empty means no DKIM yet.
	DKIMSelector string
	DKIMRecord   string
	// SPFInclude adds an include: mechanism for an outbound relay.
	SPFInclude string
	// TLSARecord is the DANE TLSA value ("3 1 1 <sha256 of SPKI>")
	// of the certificate the mail services serve. Empty means no
	// certificate on disk yet; no TLSA records are emitted.
	TLSARecord string
	// MTASTSPolicyID content-addresses the served MTA-STS policy
	// file. Empty means no policy file; no MTA-STS records.
	MTASTSPolicyID string
	// MTASTSDomains are the mail domains safe to declare an MTA-STS
	// policy for: the primary hostname (the MX) and the domain's
	// mta-sts subdomain both serve valid signed certificates. A
	// policy pointing at a self-signed endpoint would make senders
	// distrust our own MX, so the caller gates on cert validity.
	MTASTSDomains map[string]bool
}

// Category labels why a record exists, for the external-DNS view:
// "required", "recommended", "optional", "hardening", or "" for
// records only relevant when this box serves its own DNS (ns1/ns2).
type Category string

const (
	CatRequired    Category = "required"
	CatRecommended Category = "recommended"
	CatOptional    Category = "optional"
	CatHardening   Category = "hardening"
	CatInternal    Category = ""
)

// ZoneRecord is one record within a zone. Name is relative to the
// apex; empty means the apex itself.
type ZoneRecord struct {
	Name     string
	Type     string
	Value    string
	Category Category
}

// Zone is a generated zone: apex plus its full record set.
type Zone struct {
	Apex    string
	Records []ZoneRecord
}

// domainProps mirrors the legacy per-domain attribute dict.
type domainProps struct {
	mail bool // addresses exist here: MX/SPF/DKIM/DMARC wanted
	auto bool // name exists only for the box's own services
}

// BuildZones generates every hosted zone. Deterministic: same input,
// same output, so the materializer can diff before writing.
func BuildZones(in ZoneInput) []Zone {
	zones := Zones(append(append([]string{}, in.MailDomains...), in.PrimaryHostname))

	props := map[string]domainProps{}
	for _, d := range in.MailDomains {
		props[d] = domainProps{mail: true}
	}
	if _, ok := props[in.PrimaryHostname]; !ok {
		props[in.PrimaryHostname] = domainProps{}
	}

	// Auto names for the box's own services. A custom A/AAAA/CNAME
	// pointing one of these elsewhere suppresses the auto name (the
	// operator hosts that function off-box); mail domains are never
	// suppressed.
	elsewhere := PointedElsewhere(in)
	addAuto := func(d string) {
		if _, exists := props[d]; !exists && !elsewhere[d] {
			props[d] = domainProps{auto: true}
		}
	}
	for _, z := range zones {
		addAuto("www." + z)
	}
	for _, d := range in.UserDomains {
		addAuto("autoconfig." + d)
		addAuto("autodiscover." + d)
	}
	for _, d := range in.MailDomains {
		addAuto("mta-sts." + d)
	}
	// ns1/ns2 must resolve when the box is its own nameserver. Always
	// present, even against a custom record pointing them away.
	for _, ns := range []string{"ns1.", "ns2."} {
		d := ns + in.PrimaryHostname
		if _, exists := props[d]; !exists {
			props[d] = domainProps{auto: true}
		}
	}

	out := make([]Zone, 0, len(zones))
	for _, z := range zones {
		out = append(out, Zone{Apex: z, Records: buildZone(z, props, in, true)})
	}
	return out
}

// PointedElsewhere reports which names the operator has pointed away
// from this box via custom records. Zone building suppresses auto
// names for them; the web slice drops their vhosts entirely (serving
// HTTPS for a domain that resolves elsewhere is useless). Exported for
// webapply, which derives its hostname set from the same rule.
func PointedElsewhere(in ZoneInput) map[string]bool {
	elsewhere := map[string]bool{}
	for _, r := range in.Custom {
		switch r.RType {
		case "CNAME":
			elsewhere[r.QName] = true
		case "A", "AAAA":
			if r.Value != LocalIP && r.Value != in.PublicIP && (in.PublicIPv6 == "" || r.Value != in.PublicIPv6) {
				elsewhere[r.QName] = true
			}
		}
	}
	return elsewhere
}

func buildZone(domain string, props map[string]domainProps, in ZoneInput, isZone bool) []ZoneRecord {
	var records []ZoneRecord

	if isZone {
		// Authoritative nameservers: always ns1 here, then the
		// configured secondaries or ns2 here.
		records = append(records, ZoneRecord{"", "NS", "ns1." + in.PrimaryHostname + ".", CatInternal})
		secondaries := []string{}
		for _, s := range in.SecondaryNS {
			if !strings.HasPrefix(s, "xfr:") {
				secondaries = append(secondaries, s)
			}
		}
		if len(secondaries) == 0 {
			secondaries = []string{"ns2." + in.PrimaryHostname}
		}
		for _, s := range secondaries {
			records = append(records, ZoneRecord{"", "NS", s + ".", CatInternal})
		}
	}

	// The box's own address records come first so nothing below (in
	// particular custom records) can override them.
	if domain == in.PrimaryHostname {
		records = append(records, ZoneRecord{"", "A", in.PublicIP, CatRequired})
		if in.PublicIPv6 != "" {
			records = append(records, ZoneRecord{"", "AAAA", in.PublicIPv6, CatRequired})
		}
		// DANE TLSA (RFC 6698, criteria 3 1 1: leaf certificate's
		// subject public key, SHA-256). Certificates renew against the
		// same system key, so the record survives renewals; only a key
		// rotation changes it. SMTP is the one that matters; the HTTPS
		// record is for browser extensions that check DANE.
		if in.TLSARecord != "" {
			records = append(records, ZoneRecord{"_25._tcp", "TLSA", in.TLSARecord, CatRecommended})
			records = append(records, ZoneRecord{"_443._tcp", "TLSA", in.TLSARecord, CatOptional})
		}
	}

	// Fold every known subdomain into this zone.
	if isZone {
		var subdomains []string
		for d := range props {
			if strings.HasSuffix(d, "."+domain) {
				subdomains = append(subdomains, d)
			}
		}
		sort.Strings(subdomains) // deterministic before the final sort
		for _, sub := range subdomains {
			rel := strings.TrimSuffix(sub, "."+domain)
			for _, r := range buildZone(sub, props, in, false) {
				name := rel
				if r.Name != "" {
					name = r.Name + "." + rel
				}
				records = append(records, ZoneRecord{name, r.Type, r.Value, r.Category})
			}
		}
	}

	// hasRec checks against a pinned snapshot so that, for example,
	// setting a default A record does not suppress the default AAAA.
	snapshot := records
	hasRec := func(name, rtype, prefix string) bool {
		for _, r := range snapshot {
			if r.Name == name && r.Type == rtype && (prefix == "" || strings.HasPrefix(r.Value, prefix)) {
				return true
			}
		}
		return false
	}

	// Custom records, unless they collide with anything generated
	// above. Multiple custom values for one name+type all land: the
	// snapshot is pinned before this loop.
	for _, r := range filterCustom(domain, in.Custom) {
		if hasRec(r.Name, r.Type, "") {
			continue
		}
		value := r.Value
		if r.Type == "A" && value == LocalIP {
			value = in.PublicIP
		}
		if r.Type == "AAAA" && value == LocalIP {
			if in.PublicIPv6 == "" {
				continue
			}
			value = in.PublicIPv6
		}
		records = append(records, ZoneRecord{r.Name, r.Type, value, CatOptional})
	}

	// Default address records, unless custom settings took the name. A
	// custom CNAME or A also suppresses the default AAAA: a name the
	// operator redefined should not half-resolve to this box.
	snapshot = records
	aCat := CatRequired
	if props[domain].auto {
		switch {
		case strings.HasPrefix(domain, "ns1.") || strings.HasPrefix(domain, "ns2."):
			aCat = CatInternal
		case strings.HasPrefix(domain, "www.") || strings.HasPrefix(domain, "mta-sts."):
			aCat = CatOptional
		case strings.HasPrefix(domain, "autoconfig.") || strings.HasPrefix(domain, "autodiscover."):
			aCat = CatRecommended
		}
	}
	if !hasRec("", "A", "") && !hasRec("", "CNAME", "") {
		records = append(records, ZoneRecord{"", "A", in.PublicIP, aCat})
	}
	if in.PublicIPv6 != "" && !hasRec("", "AAAA", "") && !hasRec("", "CNAME", "") && !hasRec("", "A", "") {
		records = append(records, ZoneRecord{"", "AAAA", in.PublicIPv6, CatOptional})
	}

	// Mail records; each yields to a custom record of the same shape.
	snapshot = records
	if props[domain].mail {
		if !hasRec("", "MX", "10 ") {
			records = append(records, ZoneRecord{"", "MX", "10 " + in.PrimaryHostname + ".", CatRequired})
		}
		if !hasRec("", "TXT", "v=spf1 ") {
			spf := "v=spf1 mx -all"
			if in.SPFInclude != "" {
				spf = "v=spf1 mx include:" + in.SPFInclude + " -all"
			}
			records = append(records, ZoneRecord{"", "TXT", spf, CatRecommended})
		}
		if in.DKIMRecord != "" && !hasRec(in.DKIMSelector, "TXT", "v=DKIM1; ") {
			records = append(records, ZoneRecord{in.DKIMSelector, "TXT", in.DKIMRecord, CatRecommended})
		}
		if !hasRec("_dmarc", "TXT", "v=DMARC1; ") {
			records = append(records, ZoneRecord{"_dmarc", "TXT", "v=DMARC1; p=quarantine;", CatRecommended})
		}
	}

	// MTA-STS (RFC 8461): the _mta-sts TXT signals that a policy is
	// served at https://mta-sts.<domain>. The id changes with the
	// policy file so senders re-fetch it. Only emitted for domains the
	// caller verified certificates for (MTASTSDomains); the mta-sts A
	// records above are unconditional so those certs CAN be
	// provisioned first.
	snapshot = records
	if props[domain].mail && in.MTASTSPolicyID != "" && in.MTASTSDomains[domain] &&
		!hasRec("_mta-sts", "TXT", "") {
		records = append(records, ZoneRecord{"_mta-sts", "TXT", "v=STSv1; id=" + in.MTASTSPolicyID, CatOptional})
	}

	// Hardening: every name that resolves but takes no mail declares
	// so (SPF hard fail, DMARC reject, null MX), covering non-mail
	// domains and custom names alike.
	if isZone {
		snapshot = records
		withA := map[string]bool{}
		withMX := map[string]bool{}
		for _, r := range records {
			switch r.Type {
			case "A", "AAAA":
				withA[r.Name] = true
			case "MX":
				withMX[r.Name] = true
			}
		}
		names := make([]string, 0, len(withA))
		for name := range withA {
			if !withMX[name] {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			dmarcName := "_dmarc"
			if name != "" {
				dmarcName = "_dmarc." + name
			}
			if !hasRec(name, "TXT", "v=spf1 ") {
				records = append(records, ZoneRecord{name, "TXT", "v=spf1 -all", CatHardening})
			}
			if !hasRec(dmarcName, "TXT", "v=DMARC1; ") {
				records = append(records, ZoneRecord{dmarcName, "TXT", "v=DMARC1; p=reject;", CatHardening})
			}
			if !hasRec(name, "MX", "") {
				records = append(records, ZoneRecord{name, "MX", "0 .", CatHardening})
			}
		}
	}

	// Apex records first, then grouped by name hierarchy: sort by the
	// reversed label sequence, stably so generation order breaks ties.
	sort.SliceStable(records, func(i, j int) bool {
		return reversedLabels(records[i].Name) < reversedLabels(records[j].Name)
	})
	return records
}

func reversedLabels(name string) string {
	if name == "" {
		return ""
	}
	labels := strings.Split(name, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, "\x00")
}

// filterCustom selects the custom records at or below domain and makes
// their names relative to it.
func filterCustom(domain string, custom []Record) []ZoneRecord {
	var out []ZoneRecord
	for _, r := range custom {
		switch {
		case r.QName == domain:
			out = append(out, ZoneRecord{"", r.RType, r.Value, CatOptional})
		case strings.HasSuffix(r.QName, "."+domain):
			out = append(out, ZoneRecord{strings.TrimSuffix(r.QName, "."+domain), r.RType, r.Value, CatOptional})
		}
	}
	return out
}
