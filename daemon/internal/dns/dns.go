// Package dns holds the DNS domain logic shared by the HTTP API and
// the zone generator: which zones the box hosts, and what makes a
// custom record valid. It knows nothing about storage or HTTP.
package dns

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/idna"
)

// idnaProfile converts internationalized names to their ASCII
// (punycode) form. StrictDomainName is off because DNS names may carry
// service labels (_dmarc, _25._tcp) and wildcards, which the default
// lookup profile rejects; the validators here enforce shape afterward.
var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.StrictDomainName(false),
)

// NormalizeName canonicalizes a DNS name for storage and comparison:
// trimmed, lowercased, no trailing dot, internationalized labels
// converted to punycode. Everything downstream handles ASCII only.
func NormalizeName(name string) (string, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return "", fmt.Errorf("empty name")
	}
	ascii, err := idnaProfile.ToASCII(name)
	if err != nil {
		return "", fmt.Errorf("not a valid domain name")
	}
	return ascii, nil
}

// Zones reduces the set of hosted domains to zone apexes: a domain that
// is a subdomain of another hosted domain folds into the parent's zone.
// The result is sorted for stable output.
func Zones(domains []string) []string {
	// Shorter names first so parents are seen before their subdomains.
	sorted := append([]string(nil), domains...)
	sort.Slice(sorted, func(i, j int) bool {
		if len(sorted[i]) != len(sorted[j]) {
			return len(sorted[i]) < len(sorted[j])
		}
		return sorted[i] < sorted[j]
	})
	var zones []string
	for _, d := range sorted {
		parent := false
		for _, z := range zones {
			// d == z covers an exact duplicate in the input (e.g. a mail
			// domain that is also the primary hostname) - without it,
			// the suffix check alone never matches a domain against
			// itself and the same zone is written twice.
			if d == z || strings.HasSuffix(d, "."+z) {
				parent = true
				break
			}
		}
		if !parent && d != "" {
			zones = append(zones, d)
		}
	}
	sort.Strings(zones)
	return zones
}

// ZoneFor returns the zone a name belongs to: the apex itself or any
// name under it.
func ZoneFor(qname string, zones []string) (string, bool) {
	for _, z := range zones {
		if qname == z || strings.HasSuffix(qname, "."+z) {
			return z, true
		}
	}
	return "", false
}

// recordLabel is one label of a record name. Underscores are allowed
// anywhere (service labels like _dmarc, _25); hyphens may not lead or
// trail a label.
var recordLabel = regexp.MustCompile(`^[a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9_])?$`)

// ValidRecordName reports whether name is usable as a DNS record name.
// Looser than a mail domain: wildcards ("*.example.com") and
// underscore labels are fine here because they are valid in DNS even
// though they are not valid hostnames.
func ValidRecordName(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for i, l := range labels {
		if i == 0 && l == "*" {
			continue
		}
		if len(l) > 63 || !recordLabel.MatchString(l) {
			return false
		}
	}
	// The TLD may not start with a digit.
	tld := labels[len(labels)-1]
	return tld[0] < '0' || tld[0] > '9'
}

// LocalIP is the sentinel value on A/AAAA records meaning "this box's
// public address", resolved when zones are generated. It lets a record
// track the box through IP changes.
const LocalIP = "local"

// maxValueLen bounds record values. Generous for concatenated TXT
// strings (a 4096-bit DKIM key is ~700 characters) while staying well
// inside index-size limits on every engine.
const maxValueLen = 1024

// ValidateValue checks a record value against its type and returns the
// canonical form to store (CNAME and NS targets gain a trailing dot).
// zone is the apex of the zone qname lives in.
func ValidateValue(qname, zone, rtype, value string) (string, error) {
	if len(value) > maxValueLen {
		return "", fmt.Errorf("record value is too long (max %d characters)", maxValueLen)
	}
	if strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("record value may not contain newlines")
	}
	switch rtype {
	case "A", "AAAA":
		if value == LocalIP {
			return value, nil
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return "", fmt.Errorf("not a valid IP address")
		}
		if rtype == "A" && !addr.Is4() {
			return "", fmt.Errorf("that's an IPv6 address; use an AAAA record")
		}
		if rtype == "AAAA" && addr.Is4() {
			return "", fmt.Errorf("that's an IPv4 address; use an A record")
		}
		return addr.String(), nil
	case "CNAME", "NS":
		if rtype == "NS" && qname == zone {
			return "", fmt.Errorf("NS records can only be set for subdomains")
		}
		target, err := NormalizeName(value)
		if err != nil || !ValidRecordName(target) {
			return "", fmt.Errorf("not a valid domain name")
		}
		return target + ".", nil
	case "TXT", "SRV", "MX", "SSHFP", "CAA":
		if value == "" {
			return "", fmt.Errorf("record value may not be empty")
		}
		return value, nil
	}
	return "", fmt.Errorf("unknown record type")
}

// ValidateSecondaryNameserver checks one secondary-nameserver entry
// and returns its canonical form: either a hostname (NS record target,
// resolved to transfer addresses at zone-generation time) or "xfr:"
// followed by an IP address or CIDR block that may pull zone transfers
// without appearing in NS records.
func ValidateSecondaryNameserver(entry string) (string, error) {
	if after, ok := strings.CutPrefix(entry, "xfr:"); ok {
		if _, err := netip.ParsePrefix(after); err == nil {
			return entry, nil
		}
		if _, err := netip.ParseAddr(after); err == nil {
			return entry, nil
		}
		return "", fmt.Errorf("%q is not a valid IP address or subnet", after)
	}
	host, err := NormalizeName(entry)
	if err != nil || strings.Contains(host, "*") || strings.Contains(host, "_") || !ValidRecordName(host) {
		return "", fmt.Errorf("%q is not a valid hostname", entry)
	}
	return host, nil
}
