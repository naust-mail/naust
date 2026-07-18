package dns

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Zone file serialization. Pure text-out: the serial number and change
// detection live in the store (ZoneSerial rows), so generated files
// are never read back to recover state. The apply layer's flow is:
//
//	hash := ZoneHash(zone, primary, keysHash)
//	if hash == storedHash && !renewalDue { skip }
//	serial := NextSerial(storedSerial, now)
//	write RenderZone(zone, primary, keysHash, serial); store serial, hash

// RenderZone serializes a zone. keysHash is a fingerprint of the
// DNSSEC signing keys, embedded as a comment so a key rotation changes
// the zone content (and therefore its hash) and forces a re-sign.
func RenderZone(z Zone, primaryHostname, keysHash string, serial int64) string {
	var b strings.Builder
	// The $ORIGIN line must carry nothing after the domain: trailing
	// comments confuse ldns-signzone.
	fmt.Fprintf(&b, "$ORIGIN %s.\n", z.Apex)
	b.WriteString("$TTL 86400          ; default time to live\n\n")
	fmt.Fprintf(&b, "@ IN SOA ns1.%s. hostmaster.%s. (\n", primaryHostname, primaryHostname)
	fmt.Fprintf(&b, "           %d       ; serial number\n", serial)
	b.WriteString("           7200     ; Refresh (secondary nameserver update interval)\n")
	b.WriteString("           3600     ; Retry (when refresh fails, how often to try again, should be lower than the refresh)\n")
	b.WriteString("           1209600  ; Expire (when refresh fails, how long secondary nameserver will keep records around anyway)\n")
	b.WriteString("           86400    ; Negative TTL (how long negative responses are cached)\n")
	b.WriteString("           )\n")

	for _, r := range z.Records {
		if r.Name != "" {
			b.WriteString(r.Name)
		}
		b.WriteString("\tIN\t" + r.Type + "\t")
		if r.Type == "TXT" {
			b.WriteString(encodeTXT(r.Value))
		} else {
			b.WriteString(r.Value)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "\n; DNSSEC signing keys hash: %s\n", keysHash)
	return b.String()
}

// ZoneHash fingerprints a zone's semantic content: everything that
// would appear in the file except the serial number. Equal hashes mean
// the zone does not need a new serial or a rewrite.
func ZoneHash(z Zone, primaryHostname, keysHash string) string {
	sum := sha256.Sum256([]byte(RenderZone(z, primaryHostname, keysHash, 0)))
	return hex.EncodeToString(sum[:])
}

// NextSerial picks the serial for a changed zone: today's date-based
// number (YYYYMMDD00), unless the current serial is already there or
// beyond (several changes in one day), in which case it increments.
// current 0 means no serial has been published yet.
func NextSerial(current int64, now time.Time) int64 {
	today, _ := strconv.ParseInt(now.Format("2006010200"), 10, 64)
	if current >= today {
		return current + 1
	}
	return today
}

// encodeTXT splits a TXT value into quoted 255-byte substrings, the
// wire-format limit for a single character-string.
func encodeTXT(value string) string {
	value = strings.NewReplacer("\r", "", "\n", "").Replace(value)
	chunks := make([]string, 0, len(value)/255+1)
	for len(value) > 0 {
		n := min(len(value), 255)
		chunk := value[:n]
		value = value[n:]
		chunk = strings.ReplaceAll(chunk, `\`, `\\`)
		chunk = strings.ReplaceAll(chunk, `"`, `\"`)
		chunks = append(chunks, `"`+chunk+`"`)
	}
	return strings.Join(chunks, " ")
}

// rrsigSOARe extracts the 14-digit expiration timestamp from the
// RRSIG covering the SOA in a signed zone. Parsing here is legitimate:
// the signed file is ldns-signzone's output, external state we do not
// own.
var rrsigSOARe = regexp.MustCompile(`\sRRSIG\s+SOA\s+\d+\s+\d+\s\d+\s+(\d{14})`)

// SignatureNeedsRenewal reports whether the signed zone's signatures
// are missing or within ten days of expiring, in which case the zone
// must be republished (new serial, re-sign) even with no record
// changes. Signing grants 30 days; the ten-day margin keeps a healthy
// box (daily applier kick) far above the dnssec-signatures status
// check's alarm thresholds, so an alarm there means renewal has
// actually been failing for days.
func SignatureNeedsRenewal(signedZone string, now time.Time) bool {
	matches := rrsigSOARe.FindAllStringSubmatch(signedZone, -1)
	if len(matches) == 0 {
		return true
	}
	// All should agree; renew on the soonest.
	soonest := matches[0][1]
	for _, m := range matches[1:] {
		if m[1] < soonest {
			soonest = m[1]
		}
	}
	exp, err := time.Parse("20060102150405", soonest)
	if err != nil {
		return true
	}
	return exp.Sub(now) < 10*24*time.Hour
}

// RenderNSDConf writes the zone list for nsd.conf.d. xfrAllowed are
// the transfer-permitted addresses (IPs get notifies too; subnets only
// provide-xfr), already resolved from the secondary-NS setting.
func RenderNSDConf(zones []Zone, zonefileName func(apex string) string, xfrAllowed []string) string {
	var b strings.Builder
	for _, z := range zones {
		fmt.Fprintf(&b, "\nzone:\n\tname: %s\n\tzonefile: %s\n", z.Apex, zonefileName(z.Apex))
		for _, addr := range xfrAllowed {
			if !strings.Contains(addr, "/") {
				fmt.Fprintf(&b, "\n\tnotify: %s NOKEY", addr)
			}
			fmt.Fprintf(&b, "\n\tprovide-xfr: %s NOKEY\n", addr)
		}
	}
	return b.String()
}
