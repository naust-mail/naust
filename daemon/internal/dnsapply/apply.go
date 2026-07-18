// Package dnsapply converges the authoritative DNS state onto disk:
// zone files (signed when DNSSEC keys exist), the nsd zone list, and
// OpenDKIM tables, followed by the service reloads that pick them up.
// Like materialize, it is kicked after mutations and coalesces bursts;
// zone files are pure output - change detection and serial numbers
// live in the store (ZoneSerial rows), never parsed back from disk.
package dnsapply

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"naust/daemon/internal/atomicfile"
	"naust/daemon/internal/dns"
	"naust/daemon/internal/kickloop"
	"naust/daemon/internal/sslcert"
	"naust/daemon/internal/store/ent"
	entalias "naust/daemon/internal/store/ent/alias"
	entsetting "naust/daemon/internal/store/ent/setting"
	entuser "naust/daemon/internal/store/ent/user"
	entzoneserial "naust/daemon/internal/store/ent/zoneserial"
)

// Runner executes the ldns tools. Tests substitute a fake.
type Runner interface {
	Run(ctx context.Context, argv []string) error
	Output(ctx context.Context, argv []string) (string, error)
}

// ExecRunner runs commands for real.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, argv []string) error {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", argv[0], err, out)
	}
	return nil
}

func (ExecRunner) Output(ctx context.Context, argv []string) (string, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s: %w", argv[0], err)
	}
	return string(out), nil
}

const (
	settingSecondaryNS = "dns_secondary_nameservers"
	// settingSMTPRelay is written by the relay API (httpapi/relay.go);
	// only spf_include matters for zone building.
	settingSMTPRelay = "smtp_relay"
)

type Applier struct {
	Store *ent.Client
	// ZonesDir receives zone files; owned by the manager user, nsd
	// reads from it.
	ZonesDir string
	// NSDConfPath is the zone-list config nsd includes.
	NSDConfPath string
	// DNSSECDir holds signing key confs and key files; zones go
	// unsigned when it is absent or empty.
	DNSSECDir string
	// DKIMTxtPath is the DKIM public-key record file (mail.txt);
	// absent means no DKIM records yet.
	DKIMTxtPath string
	// OpenDKIMDir receives KeyTable/SigningTable; empty skips them
	// entirely (the rspamd stack signs without OpenDKIM).
	OpenDKIMDir string
	// DKIMKeyPath is the private key path written into the KeyTable.
	DKIMKeyPath string
	// SSLRoot is STORAGE_ROOT/ssl: the served-certificate symlink
	// there yields the TLSA record, and the installed certificates
	// gate MTA-STS. Empty skips both (tests that don't care).
	SSLRoot string
	// MTASTSPolicyPath is the policy file nginx serves at
	// /.well-known/mta-sts.txt; its hash is the policy id. Absent
	// file means no MTA-STS records.
	MTASTSPolicyPath string

	PrimaryHostname string
	PublicIP        string
	PublicIPv6      string

	Run Runner
	// Reload asks the helper to reload a service ("nsd", "unbound",
	// "opendkim"). Nil skips reloads (tests, pre-cutover runs).
	Reload func(ctx context.Context, service string) error
	// LookupHost resolves secondary-NS hostnames to transfer
	// addresses. Nil uses the system resolver.
	LookupHost func(ctx context.Context, host string) ([]string, error)
	// Now substitutes the clock in tests. Nil means time.Now.
	Now func() time.Time

	Log        *log.Logger
	RetryAfter time.Duration

	loop kickloop.Loop
}

// Kick requests a convergence run. Never blocks; kicks collapse.
func (a *Applier) Kick() { a.loop.Kick() }

// Start runs the convergence loop until ctx is cancelled. Call once.
func (a *Applier) Start(ctx context.Context) {
	// The tick makes time itself a kick source: DNSSEC signatures
	// expire by wall clock even when nothing changes (applyZone
	// renews via SignatureNeedsRenewal), and a replica that missed a
	// mutation converges within the hour.
	a.loop = kickloop.Loop{Name: "dnsapply", Do: a.Rebuild, Log: a.Log, RetryAfter: a.RetryAfter, Tick: time.Hour}
	a.loop.Start(ctx)
}

func (a *Applier) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Rebuild converges everything once: zones, nsd.conf, opendkim tables,
// reloads. Unchanged files are left untouched.
func (a *Applier) Rebuild(ctx context.Context) error {
	in, err := a.loadInput(ctx)
	if err != nil {
		return fmt.Errorf("load input: %w", err)
	}
	if err := os.MkdirAll(a.ZonesDir, 0o750); err != nil {
		return err
	}

	zones := dns.BuildZones(in)
	zonesChanged := false
	zonefileNames := map[string]string{}
	for _, z := range zones {
		name, changed, err := a.applyZone(ctx, z)
		if err != nil {
			return fmt.Errorf("zone %s: %w", z.Apex, err)
		}
		zonefileNames[z.Apex] = name
		zonesChanged = zonesChanged || changed
	}

	confChanged, err := a.applyNSDConf(ctx, zones, in.SecondaryNS, zonefileNames)
	if err != nil {
		return fmt.Errorf("nsd.conf: %w", err)
	}

	if zonesChanged || confChanged {
		if err := a.reload(ctx, "nsd"); err != nil {
			return err
		}
		// Flush the local recursive cache so this box resolves its own
		// new records immediately.
		if err := a.reload(ctx, "unbound"); err != nil {
			return err
		}
	}

	dkimChanged, err := a.applyOpenDKIM(in.MailDomains)
	if err != nil {
		return fmt.Errorf("opendkim: %w", err)
	}
	if dkimChanged {
		if err := a.reload(ctx, "opendkim"); err != nil {
			return err
		}
	}
	return nil
}

func (a *Applier) reload(ctx context.Context, service string) error {
	if a.Reload == nil {
		return nil
	}
	if err := a.Reload(ctx, service); err != nil {
		return fmt.Errorf("reload %s: %w", service, err)
	}
	return nil
}

// applyZone writes and signs one zone if its content changed or its
// signatures need renewal. Returns the zonefile basename nsd should
// serve (signed when keys exist) and whether anything was rewritten.
func (a *Applier) applyZone(ctx context.Context, z dns.Zone) (string, bool, error) {
	kh, err := keysHash(a.DNSSECDir, z.Apex)
	if err != nil {
		return "", false, err
	}
	signed := kh != "unsigned"
	plainName := z.Apex + ".txt"
	servedName := plainName
	if signed {
		servedName = plainName + ".signed"
	}
	servedPath := filepath.Join(a.ZonesDir, servedName)

	hash := dns.ZoneHash(z, a.PrimaryHostname, kh)
	row, err := a.Store.ZoneSerial.Query().
		Where(entzoneserial.Zone(z.Apex)).
		Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return "", false, err
	}

	// Unchanged content, served file present, signatures fresh: done.
	if row != nil && row.ContentHash == hash {
		if _, statErr := os.Stat(servedPath); statErr == nil {
			if !signed {
				return servedName, false, nil
			}
			signedText, readErr := os.ReadFile(servedPath)
			if readErr == nil && !dns.SignatureNeedsRenewal(string(signedText), a.now()) {
				return servedName, false, nil
			}
		}
	}

	var current int64
	if row != nil {
		current = row.Serial
	}
	serial := dns.NextSerial(current, a.now())
	plainPath := filepath.Join(a.ZonesDir, plainName)
	if err := atomicfile.WriteSync(plainPath, dns.RenderZone(z, a.PrimaryHostname, kh, serial), 0o640); err != nil {
		return "", false, err
	}
	if signed {
		if err := a.signZone(ctx, z.Apex, plainPath); err != nil {
			return "", false, err
		}
	}

	err = a.Store.ZoneSerial.Create().
		SetZone(z.Apex).
		SetSerial(serial).
		SetContentHash(hash).
		OnConflictColumns(entzoneserial.FieldZone).
		UpdateNewValues().
		Exec(ctx)
	if err != nil {
		return "", false, err
	}
	return servedName, true, nil
}

// signZone signs plainPath in place to plainPath.signed and writes the
// registrar DS records (all KSKs, three digest types) beside it.
func (a *Applier) signZone(ctx context.Context, apex, plainPath string) error {
	tmpDir, err := os.MkdirTemp("", "dnssec-sign-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	all, ksks, err := patchKeys(a.DNSSECDir, apex, tmpDir)
	if err != nil {
		return err
	}
	expiry := a.now().Add(30 * 24 * time.Hour).Format("20060102")
	argv := append([]string{"ldns-signzone", "-e", expiry, "-n", plainPath}, all...)
	if err := a.Run.Run(ctx, argv); err != nil {
		return err
	}

	var ds strings.Builder
	for _, ksk := range ksks {
		// 1=SHA1, 2=SHA256, 4=SHA384; the registrar needs only one,
		// but which one they accept varies.
		for _, digest := range []string{"-1", "-2", "-4"} {
			out, err := a.Run.Output(ctx, []string{"ldns-key2ds", "-n", digest, ksk + ".key"})
			if err != nil {
				return err
			}
			ds.WriteString(out)
		}
	}
	return atomicfile.WriteSync(plainPath+".ds", ds.String(), 0o640)
}

// applyNSDConf renders the zone list plus transfer permissions and
// writes it if changed.
func (a *Applier) applyNSDConf(ctx context.Context, zones []dns.Zone, secondaryNS []string, names map[string]string) (bool, error) {
	xfr, err := a.transferAddresses(ctx, secondaryNS)
	if err != nil {
		return false, err
	}
	conf := dns.RenderNSDConf(zones, func(apex string) string { return names[apex] }, xfr)
	return atomicfile.WriteIfChanged(a.NSDConfPath, conf, 0o644)
}

// transferAddresses resolves the secondary-NS setting into addresses
// allowed to pull zone transfers: xfr: entries verbatim, hostnames via
// DNS. Unresolvable hostnames are skipped, not fatal - the secondary
// simply cannot transfer until its name resolves.
func (a *Applier) transferAddresses(ctx context.Context, secondaryNS []string) ([]string, error) {
	lookup := a.LookupHost
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]string, error) {
			return net.DefaultResolver.LookupHost(ctx, host)
		}
	}
	var out []string
	for _, entry := range secondaryNS {
		if after, ok := strings.CutPrefix(entry, "xfr:"); ok {
			out = append(out, after)
			continue
		}
		addrs, err := lookup(ctx, entry)
		if err != nil {
			a.Log.Printf("dnsapply: secondary NS %s does not resolve, skipping transfer permission", entry)
			continue
		}
		out = append(out, addrs...)
	}
	return out, nil
}

// applyOpenDKIM writes the SigningTable and KeyTable when the OpenDKIM
// stack is in use.
func (a *Applier) applyOpenDKIM(mailDomains []string) (bool, error) {
	if a.OpenDKIMDir == "" {
		return false, nil
	}
	if _, err := os.Stat(a.DKIMKeyPath); err != nil {
		return false, nil // no key yet: nothing to sign with
	}
	var signing, key strings.Builder
	for _, d := range mailDomains {
		fmt.Fprintf(&signing, "*@%s %s\n", d, d)
		fmt.Fprintf(&key, "%s %s:mail:%s\n", d, d, a.DKIMKeyPath)
	}
	c1, err := atomicfile.WriteIfChanged(filepath.Join(a.OpenDKIMDir, "SigningTable"), signing.String(), 0o644)
	if err != nil {
		return false, err
	}
	c2, err := atomicfile.WriteIfChanged(filepath.Join(a.OpenDKIMDir, "KeyTable"), key.String(), 0o644)
	if err != nil {
		return false, err
	}
	return c1 || c2, nil
}

// dkimTXTRe parses OpenDKIM's mail.txt record file:
// selector._domainkey IN TXT ( "chunk" "chunk" ... )
var dkimTXTRe = regexp.MustCompile(`(?s)(\S+)\s+IN\s+TXT\s+\(\s*((?:"[^"]*"\s*)+)\)`)

var quotedRe = regexp.MustCompile(`"([^"]*)"`)

// loadInput gathers everything zone generation depends on.
// DesiredZones builds the zones the applier would write right now.
// The status checks diff these against what nsd serves and what the
// world resolves; sharing the construction guarantees they diff the
// same zones the applier writes.
func (a *Applier) DesiredZones(ctx context.Context) ([]dns.Zone, error) {
	in, err := a.loadInput(ctx)
	if err != nil {
		return nil, err
	}
	return dns.BuildZones(in), nil
}

func (a *Applier) loadInput(ctx context.Context) (dns.ZoneInput, error) {
	in := dns.ZoneInput{
		PrimaryHostname: a.PrimaryHostname,
		PublicIP:        a.PublicIP,
		PublicIPv6:      a.PublicIPv6,
	}

	emails, err := a.Store.User.Query().Select(entuser.FieldEmail).Strings(ctx)
	if err != nil {
		return in, err
	}
	sources, err := a.Store.Alias.Query().Select(entalias.FieldSource).Strings(ctx)
	if err != nil {
		return in, err
	}
	mailSeen, userSeen := map[string]bool{}, map[string]bool{}
	for _, addr := range emails {
		if _, domain, ok := strings.Cut(addr, "@"); ok && !userSeen[domain] {
			userSeen[domain] = true
			in.UserDomains = append(in.UserDomains, domain)
		}
	}
	for _, addr := range append(emails, sources...) {
		if _, domain, ok := strings.Cut(addr, "@"); ok && domain != "" && !mailSeen[domain] {
			mailSeen[domain] = true
			in.MailDomains = append(in.MailDomains, domain)
		}
	}

	records, err := a.Store.DNSRecord.Query().All(ctx)
	if err != nil {
		return in, err
	}
	for _, r := range records {
		in.Custom = append(in.Custom, dns.Record{QName: r.Qname, RType: string(r.Rtype), Value: r.Value})
	}

	row, err := a.Store.Setting.Query().Where(entsetting.Key(settingSecondaryNS)).Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return in, err
	}
	if row != nil {
		if err := json.Unmarshal([]byte(row.Value), &in.SecondaryNS); err != nil {
			return in, fmt.Errorf("%s setting: %w", settingSecondaryNS, err)
		}
	}

	if data, err := os.ReadFile(a.DKIMTxtPath); err == nil {
		if m := dkimTXTRe.FindStringSubmatch(string(data)); m != nil {
			in.DKIMSelector = m[1]
			var value strings.Builder
			for _, q := range quotedRe.FindAllStringSubmatch(m[2], -1) {
				value.WriteString(q[1])
			}
			in.DKIMRecord = value.String()
		}
	}

	a.tlsInputs(&in)

	row, err = a.Store.Setting.Query().Where(entsetting.Key(settingSMTPRelay)).Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return in, err
	}
	if row != nil {
		var relay struct {
			SPFInclude string `json:"spf_include"`
		}
		if err := json.Unmarshal([]byte(row.Value), &relay); err != nil {
			return in, fmt.Errorf("%s setting: %w", settingSMTPRelay, err)
		}
		in.SPFInclude = relay.SPFInclude
	}

	return in, nil
}

// tlsInputs fills the certificate-derived zone inputs: the TLSA record
// from the served certificate and the MTA-STS eligibility per mail
// domain. All failures degrade to "records absent" - a box without
// certificates still gets a working zone.
func (a *Applier) tlsInputs(in *dns.ZoneInput) {
	if a.SSLRoot == "" {
		return
	}
	in.TLSARecord = tlsaFromCert(filepath.Join(a.SSLRoot, "ssl_certificate.pem"))

	policy, err := os.ReadFile(a.MTASTSPolicyPath)
	if err != nil {
		return
	}
	in.MTASTSPolicyID = PolicyID(policy)

	// A policy is only declared when the MX (primary hostname) and
	// the policy host (mta-sts subdomain) both serve valid signed
	// certificates; senders hard-fail otherwise.
	certs, err := sslcert.Scan(a.SSLRoot, a.PrimaryHostname, a.now())
	if err != nil || !signedAndValid(certs, a.PrimaryHostname, a.now()) {
		return
	}
	in.MTASTSDomains = map[string]bool{}
	for _, d := range in.MailDomains {
		if signedAndValid(certs, "mta-sts."+d, a.now()) {
			in.MTASTSDomains[d] = true
		}
	}
}

// PolicyID content-addresses an MTA-STS policy file: up to 32
// alphanumerics per RFC 8461, stable until the policy changes, not
// security-sensitive. Same construction as the legacy Python so
// migrated boxes do not churn their zones. Exported so the status
// checks can verify the served policy matches the advertised id.
func PolicyID(policy []byte) string {
	sum := sha1.Sum(policy)
	id := base64.StdEncoding.EncodeToString(sum[:])
	id = strings.NewReplacer("+", "A", "/", "A").Replace(id)
	return id[:20]
}

// tlsaFromCert computes the DANE TLSA "3 1 1" value (leaf certificate,
// subject public key, SHA-256) from the first certificate in the file;
// "" when the file is missing or unparseable.
func tlsaFromCert(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "3 1 1 " + hex.EncodeToString(sum[:])
}

// signedAndValid reports whether the scan found a certificate for the
// domain that is currently valid and not self-signed. Wildcard
// matching mirrors what nginx actually serves (sslcert.Resolve),
// which the legacy exact-name check missed.
func signedAndValid(certs map[string]sslcert.Pair, domain string, now time.Time) bool {
	p, ok := certs[domain]
	if !ok {
		if i := strings.IndexByte(domain, '.'); i > 0 {
			p, ok = certs["*"+domain[i:]]
		}
	}
	return ok && !p.SelfSigned && p.Valid(now)
}
