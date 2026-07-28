package adminops

import (
	"context"
	"errors"
	"strings"

	"naust/daemon/internal/dns"
	"naust/daemon/internal/store/ent"
	entalias "naust/daemon/internal/store/ent/alias"
	entdnsrecord "naust/daemon/internal/store/ent/dnsrecord"
	entuser "naust/daemon/internal/store/ent/user"
)

// MaxDNSRecordsPerZone caps custom DNS per zone. Custom DNS has no natural
// bound from the domains/aliases that drive the other quotas, so without a
// cap a scripted admin session (or a migration) could grow a zone, and the
// zone files rendered from it, without limit.
const MaxDNSRecordsPerZone = 500

// ErrDNSRecordExists is returned by CreateDNSRecord when an identical
// qname/rtype/value record already exists.
var ErrDNSRecordExists = errors.New("that DNS record already exists")

// ErrZoneNotHosted is returned when a record's domain is not a zone this box
// hosts. Migration maps it to a skip-with-reason: Naust only serves DNS for
// domains it has mail for, so accounts must be migrated before DNS.
var ErrZoneNotHosted = errors.New("that name is not a domain or subdomain managed by this box")

// HostedZones derives the zone apexes this box hosts: every domain with a
// user or alias, plus the box's own hostname, subdomains folded into their
// parent. It is the single source of "what DNS does this box own", shared by
// the HTTP API and the migration path.
func HostedZones(ctx context.Context, client *ent.Client, primaryHostname string) ([]string, error) {
	emails, err := client.User.Query().Select(entuser.FieldEmail).Strings(ctx)
	if err != nil {
		return nil, err
	}
	sources, err := client.Alias.Query().Select(entalias.FieldSource).Strings(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var domains []string
	add := func(d string) {
		if d != "" && !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}
	add(primaryHostname)
	for _, addr := range append(emails, sources...) {
		if _, domain, ok := strings.Cut(addr, "@"); ok {
			add(domain)
		}
	}
	return dns.Zones(domains), nil
}

// ListDNSRecords returns every custom DNS record ordered by id.
func ListDNSRecords(ctx context.Context, client *ent.Client) ([]*ent.DNSRecord, error) {
	return client.DNSRecord.Query().Order(entdnsrecord.ByID()).All(ctx)
}

// CreateDNSRecord validates and creates one custom record (create-if-absent),
// applying the same rtype, hosted-zone, value, and cap rules the panel
// enforces. It returns the record and the zone it landed in. It writes the
// store only; the caller triggers DNS regeneration.
func CreateDNSRecord(ctx context.Context, client *ent.Client, tenantID int, primaryHostname, qname, rtype, value string) (*ent.DNSRecord, string, error) {
	rt := entdnsrecord.Rtype(strings.ToUpper(strings.TrimSpace(rtype)))
	if err := entdnsrecord.RtypeValidator(rt); err != nil {
		return nil, "", invalid("unknown record type: %s", rtype)
	}
	name, err := dns.NormalizeName(qname)
	if err != nil {
		return nil, "", invalid("the name is not a valid domain name")
	}
	zones, err := HostedZones(ctx, client, primaryHostname)
	if err != nil {
		return nil, "", err
	}
	zone, found := dns.ZoneFor(name, zones)
	if !found {
		return nil, "", ErrZoneNotHosted
	}
	// Zone apexes already proved themselves; anything below must look like a
	// DNS name (single-label zones would fail this check).
	if name != zone && !dns.ValidRecordName(name) {
		return nil, "", invalid("the name is not valid; use letters, numbers, hyphens, and dots only")
	}
	val, err := dns.ValidateValue(name, zone, string(rt), strings.TrimSpace(value))
	if err != nil {
		return nil, "", wrapValidation(err)
	}

	zoneCount, err := client.DNSRecord.Query().
		Where(entdnsrecord.Or(entdnsrecord.Qname(zone), entdnsrecord.QnameHasSuffix("."+zone))).
		Count(ctx)
	if err != nil {
		return nil, "", err
	}
	if zoneCount >= MaxDNSRecordsPerZone {
		return nil, "", invalid("at most %d custom DNS records per zone", MaxDNSRecordsPerZone)
	}

	rec, err := client.DNSRecord.Create().
		SetQname(name).
		SetRtype(rt).
		SetValue(val).
		SetTenantID(tenantID).
		Save(ctx)
	if ent.IsConstraintError(err) {
		return nil, "", ErrDNSRecordExists
	}
	if err != nil {
		return nil, "", err
	}
	return rec, zone, nil
}
