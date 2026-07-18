// Package webapply converges the web tier: it derives the hostname
// set from the mail domain model, resolves app mounts against the
// registry and box configuration, folds in per-domain customizations
// from the store, renders the nginx fileset (internal/web), and hands
// it to helperd's web.sync_sites intent, which tests and reloads
// nginx. Like the other appliers it is kicked after mutations and
// coalesces bursts; the sync intent is idempotent, so spurious kicks
// are free.
package webapply

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"naust/daemon/internal/dns"
	"naust/daemon/internal/helper"
	"naust/daemon/internal/kickloop"
	"naust/daemon/internal/registry"
	"naust/daemon/internal/sslcert"
	"naust/daemon/internal/store/ent"
	entalias "naust/daemon/internal/store/ent/alias"
	entsetting "naust/daemon/internal/store/ent/setting"
	entuser "naust/daemon/internal/store/ent/user"
	"naust/daemon/internal/web"
)

// SettingMounts is the Setting row holding app placement overrides: a
// JSON object of registry role name -> mount path. Roles absent from
// the map mount at their service's DefaultMount. Written by the
// /api/web/mounts endpoint, read here.
const SettingMounts = "web_mounts"

// HelperClient is the slice of the helperd client the applier uses.
type HelperClient interface {
	Call(ctx context.Context, intent string, args map[string]string) (string, error)
}

// Input is the domain-model slice web generation depends on, gathered
// from the store by LoadInput. Derive is pure over it.
type Input struct {
	PrimaryHostname string
	PublicIP        string
	PublicIPv6      string
	MailDomains     []string
	UserDomains     []string
	Custom          []dns.Record
}

// Site is one derived web hostname. RedirectTo is set for the default
// www.-of-a-zone redirects and empty for content-serving hosts.
type Site struct {
	Domain     string
	RedirectTo string
}

// LoadInput gathers Input from the store. Shared by the applier and
// the /api/web handlers so both sides see the same hostname set.
func LoadInput(ctx context.Context, client *ent.Client, primaryHostname, publicIP, publicIPv6 string) (Input, error) {
	in := Input{PrimaryHostname: primaryHostname, PublicIP: publicIP, PublicIPv6: publicIPv6}

	emails, err := client.User.Query().Select(entuser.FieldEmail).Strings(ctx)
	if err != nil {
		return in, err
	}
	sources, err := client.Alias.Query().Select(entalias.FieldSource).Strings(ctx)
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
	records, err := client.DNSRecord.Query().All(ctx)
	if err != nil {
		return in, err
	}
	for _, r := range records {
		in.Custom = append(in.Custom, dns.Record{QName: r.Qname, RType: string(r.Rtype), Value: r.Value})
	}
	return in, nil
}

// Derive computes the web hostname set, mirroring the legacy
// get_web_domains: every mail domain, the box's own service names
// (autoconfig/autodiscover for login domains, mta-sts for mail
// domains), and a www. redirect per hosted zone - minus anything the
// operator points elsewhere with custom records. The primary hostname
// is always served and can never be pointed away.
func Derive(in Input) []Site {
	zi := dns.ZoneInput{PublicIP: in.PublicIP, PublicIPv6: in.PublicIPv6, Custom: in.Custom}
	elsewhere := dns.PointedElsewhere(zi)

	sites := map[string]string{in.PrimaryHostname: ""}
	add := func(domain, redirect string) {
		if _, dup := sites[domain]; !dup && !elsewhere[domain] {
			sites[domain] = redirect
		}
	}
	for _, d := range in.MailDomains {
		add(d, "")
	}
	for _, d := range in.UserDomains {
		add("autoconfig."+d, "")
		add("autodiscover."+d, "")
	}
	for _, d := range in.MailDomains {
		add("mta-sts."+d, "")
	}
	for _, zone := range dns.Zones(append(append([]string{}, in.MailDomains...), in.PrimaryHostname)) {
		add("www."+zone, zone)
	}

	out := make([]Site, 0, len(sites))
	for domain, redirect := range sites {
		out = append(out, Site{Domain: domain, RedirectTo: redirect})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

type Applier struct {
	Store *ent.Client
	// Conf resolves box configuration keys (boxconf.Conf.Get): the
	// component-selection flags the registry gates on plus the
	// per-app backend host variables.
	Conf func(key string) string

	PrimaryHostname string
	PublicIP        string
	PublicIPv6      string
	// StorageRoot anchors the ACME webroot, static site roots
	// (www/<domain>), per-domain include files (www/<domain>.conf),
	// and the default certificate pair (ssl/).
	StorageRoot string

	// PHPSocket overrides PHP-FPM socket discovery (tests). Empty
	// means glob /run/php/php*-fpm.sock.
	PHPSocket string

	Helper HelperClient

	Log        *log.Logger
	RetryAfter time.Duration

	loop kickloop.Loop
}

// Kick requests a convergence run. Never blocks; kicks collapse.
func (a *Applier) Kick() { a.loop.Kick() }

// Start runs the convergence loop until ctx is cancelled. Call once.
func (a *Applier) Start(ctx context.Context) {
	a.loop = kickloop.Loop{Name: "webapply", Do: a.Rebuild, Log: a.Log, RetryAfter: a.RetryAfter, Tick: time.Hour}
	a.loop.Start(ctx)
}

// Rebuild converges once: derive hosts, render, sync through the
// helper. User-owned files reported by the sync are logged; the panel
// reads the same inventory from the sync result at apply time.
func (a *Applier) Rebuild(ctx context.Context) error {
	in, err := LoadInput(ctx, a.Store, a.PrimaryHostname, a.PublicIP, a.PublicIPv6)
	if err != nil {
		return fmt.Errorf("load input: %w", err)
	}
	hosts, err := a.BuildHosts(ctx, in)
	if err != nil {
		return err
	}
	files, err := web.Render(a.renderConfig(), hosts)
	if err != nil {
		return fmt.Errorf("render: %w", err)
	}
	args, err := helper.EncodeSyncArgs(files)
	if err != nil {
		return err
	}
	result, err := a.Helper.Call(ctx, "web.sync_sites", args)
	if err != nil {
		return fmt.Errorf("sync_sites: %w", err)
	}
	res, err := helper.DecodeSyncResult(result)
	if err != nil {
		return fmt.Errorf("sync_sites result: %w", err)
	}
	for _, sk := range res.Skipped {
		if sk.TemplateVersion != 0 && sk.TemplateVersion != web.TemplateVersion {
			a.Log.Printf("webapply: user-owned %s is stamped v%d, templates are at v%d (stale eject)",
				sk.File, sk.TemplateVersion, web.TemplateVersion)
		}
	}
	return nil
}

func (a *Applier) renderConfig() web.Config {
	sock := a.PHPSocket
	if sock == "" {
		// Debian's php-fpm names its default pool socket
		// /run/php/php<ver>-fpm.sock; glob instead of hardcoding a
		// version.
		if matches, _ := filepath.Glob("/run/php/php*-fpm.sock"); len(matches) > 0 {
			sort.Strings(matches)
			sock = matches[0]
		} else {
			sock = "/run/php/php8.3-fpm.sock"
		}
	}
	return web.Config{
		ACMEWebroot: filepath.Join(a.StorageRoot, "ssl", "lets_encrypt", "webroot"),
		PHPSocket:   sock,
	}
}

// BuildHosts assembles the full []web.Host for rendering: derived
// sites x customization rows x resolved mounts.
func (a *Applier) BuildHosts(ctx context.Context, in Input) ([]web.Host, error) {
	sites := Derive(in)

	rows, err := a.Store.WebDomain.Query().WithRules().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("web domains: %w", err)
	}
	custom := map[string]*ent.WebDomain{}
	for _, row := range rows {
		custom[row.Domain] = row
	}

	mounts, err := a.resolveMounts(ctx)
	if err != nil {
		return nil, err
	}
	sslRoot := filepath.Join(a.StorageRoot, "ssl")
	certs, err := sslcert.Scan(sslRoot, a.PrimaryHostname, time.Now())
	if err != nil {
		return nil, fmt.Errorf("scan certificates: %w", err)
	}

	hosts := make([]web.Host, 0, len(sites))
	for _, site := range sites {
		h := web.Host{Domain: site.Domain, HSTS: "on"}
		h.CertFile, h.KeyFile = sslcert.Resolve(certs, sslRoot, a.PrimaryHostname, site.Domain)
		h.CertHash = hashFiles(h.KeyFile, h.CertFile)

		if site.RedirectTo != "" {
			h.RedirectTo = site.RedirectTo
			hosts = append(hosts, h)
			continue
		}

		h.Root = a.webRoot(site.Domain)
		if row := custom[site.Domain]; row != nil {
			h.HSTS = string(row.Hsts)
			if !row.ServeStatic {
				h.Root = ""
			}
			for _, r := range row.Edges.Rules {
				h.Rules = append(h.Rules, web.Rule{
					Kind:            string(r.Kind),
					Path:            r.Path,
					Target:          r.Target,
					PassHostHeader:  r.PassHostHeader,
					NoProxyRedirect: r.NoProxyRedirect,
					FrameSameOrigin: r.FrameSameOrigin,
					WebSockets:      r.WebSockets,
				})
			}
			sort.Slice(h.Rules, func(i, j int) bool { return h.Rules[i].Path < h.Rules[j].Path })
		}
		if inc := filepath.Join(a.StorageRoot, "www", site.Domain+".conf"); fileExists(inc) {
			h.Include = inc
		}
		if site.Domain == in.PrimaryHostname {
			h.Primary = true
			h.Mounts = mounts
		}
		hosts = append(hosts, h)
	}
	return hosts, nil
}

// resolveMounts turns the registry's enabled services plus the
// web_mounts setting into concrete mounts. Overrides that do not fit
// the enabled service (a PHP webmail forced off root) or collide with
// an already-taken path fall back to the service default; a default
// collision drops the mount with a log line. The API validates
// upfront, so fallbacks here are a safety net that keeps one bad
// setting from taking the whole web tier down.
func (a *Applier) resolveMounts(ctx context.Context) ([]web.Mount, error) {
	overrides := map[string]string{}
	row, err := a.Store.Setting.Query().Where(entsetting.Key(SettingMounts)).Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return nil, err
	}
	if row != nil {
		if err := json.Unmarshal([]byte(row.Value), &overrides); err != nil {
			return nil, fmt.Errorf("%s setting: %w", SettingMounts, err)
		}
	}

	var mounts []web.Mount
	taken := map[string]bool{}
	for _, svc := range registry.All() {
		if !svc.Enabled(a.Conf) {
			continue
		}
		path := svc.DefaultMount
		if p, ok := overrides[svc.RoleName()]; ok && mountAllowed(svc, p) && !taken[p] {
			path = p
		}
		if taken[path] {
			a.Log.Printf("webapply: mount path %s already taken, dropping %s", path, svc.Name)
			continue
		}
		taken[path] = true
		mounts = append(mounts, web.Mount{
			App:         svc.Name,
			Path:        path,
			BackendHost: a.backendHost(svc),
			BackendPort: svc.Port,
			AuthUser:    a.authUser(svc),
		})
	}
	return mounts, nil
}

// mountAllowed reports whether the enabled service can live at path.
func mountAllowed(svc registry.Service, path string) bool {
	if path == "/" {
		return svc.MountRoot
	}
	return svc.MountPath
}

func (a *Applier) backendHost(svc registry.Service) string {
	if svc.HostEnv == "" {
		return "127.0.0.1"
	}
	if host := a.Conf(svc.HostEnv); host != "" {
		return host
	}
	return "127.0.0.1"
}

// authUser supplies the trusted identity header for apps that log the
// admin in via a header nginx injects. Only beszel today; keyed by
// name like the renderer's app blocks.
func (a *Applier) authUser(svc registry.Service) string {
	if svc.Name != "beszel" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(a.StorageRoot, "beszel", "beszel-user"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// webRoot picks the static directory: the domain's own folder under
// www/ when the operator created one, else the shared default site.
func (a *Applier) webRoot(domain string) string {
	own := filepath.Join(a.StorageRoot, "www", domain)
	if fi, err := os.Stat(own); err == nil && fi.IsDir() {
		return own
	}
	return filepath.Join(a.StorageRoot, "www", "default")
}

// hashFiles fingerprints the cert pair contents so a renewal changes
// the rendered file and forces a sync (the paths alone stay stable).
func hashFiles(paths ...string) string {
	h := sha256.New()
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			fmt.Fprintf(h, "missing:%s", p)
			continue
		}
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}
