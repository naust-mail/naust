package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/idna"

	"naust/daemon/internal/api"
	"naust/daemon/internal/registry"
	"naust/daemon/internal/store/ent"
	entsetting "naust/daemon/internal/store/ent/setting"
	entwebdomain "naust/daemon/internal/store/ent/webdomain"
	entwebrule "naust/daemon/internal/store/ent/webrule"
	"naust/daemon/internal/webapply"
)

// Web-tier endpoints: hostname list with customizations, per-domain
// rule editing, and app placement. Mutations kick the web applier,
// which renders and syncs nginx through the helper.

const (
	maxWebRules      = 50
	maxRulePathLen   = 200
	maxRuleTargetLen = 500
)

var (
	// Prefix location paths (proxy and alias rules, mounts).
	webPathRE = regexp.MustCompile(`^/[A-Za-z0-9._~/-]*$`)
	// Redirect paths are nginx rewrite regexes; allow the pattern
	// characters but nothing that could terminate the directive.
	webRedirectPathRE = regexp.MustCompile(`^[/^][A-Za-z0-9._~/^$()*+?|\\\[\]-]*$`)
	// Mount paths are stricter: lowercase segments only.
	webMountPathRE = regexp.MustCompile(`^(/[a-z0-9._-]+)+$`)
)

func (s *Server) webDataChanged() {
	if s.OnWebDataChange != nil {
		s.OnWebDataChange()
	}
}

func (s *Server) handleWebStatus(w http.ResponseWriter, r *http.Request) {
	in, err := webapply.LoadInput(r.Context(), s.Store, s.PrimaryHostname, s.PublicIP, s.PublicIPv6)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "web state lookup failed")
		return
	}
	rows, err := s.Store.WebDomain.Query().WithRules().All(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "web state lookup failed")
		return
	}
	custom := map[string]*ent.WebDomain{}
	for _, row := range rows {
		custom[row.Domain] = row
	}

	resp := api.WebStatusResponse{Domains: []api.WebDomainInfo{}}
	for _, site := range webapply.Derive(in) {
		info := api.WebDomainInfo{
			Domain:      site.Domain,
			Primary:     site.Domain == s.PrimaryHostname,
			RedirectTo:  site.RedirectTo,
			HSTS:        "on",
			ServeStatic: true,
		}
		if row := custom[site.Domain]; row != nil {
			info.Customized = true
			info.HSTS = string(row.Hsts)
			info.ServeStatic = row.ServeStatic
			for _, rule := range row.Edges.Rules {
				info.Rules = append(info.Rules, apiWebRule(rule))
			}
			sort.Slice(info.Rules, func(i, j int) bool { return info.Rules[i].Path < info.Rules[j].Path })
		}
		resp.Domains = append(resp.Domains, info)
	}

	mounts, err := s.webMounts(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "web state lookup failed")
		return
	}
	resp.Mounts = mounts
	writeJSON(w, http.StatusOK, resp)
}

// webMounts summarizes app placement per registry role: the enabled
// implementation, its effective path, and whether it can move.
func (s *Server) webMounts(r *http.Request) ([]api.WebMountInfo, error) {
	overrides := map[string]string{}
	row, err := s.Store.Setting.Query().Where(entsetting.Key(webapply.SettingMounts)).Only(r.Context())
	if err != nil && !ent.IsNotFound(err) {
		return nil, err
	}
	if row != nil {
		if err := json.Unmarshal([]byte(row.Value), &overrides); err != nil {
			return nil, fmt.Errorf("%s setting: %w", webapply.SettingMounts, err)
		}
	}

	conf := s.confGet()
	var out []api.WebMountInfo
	seen := map[string]bool{}
	for _, svc := range registry.All() {
		role := svc.RoleName()
		if seen[role] {
			continue
		}
		seen[role] = true

		info := api.WebMountInfo{Role: role, Path: svc.DefaultMount, Fixed: true}
		for _, member := range registry.ByRole(role) {
			if member.MountRoot || member.MountPath {
				info.Fixed = false
			}
			if member.Enabled(conf) {
				info.App = member.Name
				info.Enabled = true
				info.Path = member.DefaultMount
			}
		}
		if p, ok := overrides[role]; ok && !info.Fixed {
			info.Path = p
		}
		out = append(out, info)
	}
	return out, nil
}

func (s *Server) confGet() func(string) string {
	if s.Conf != nil {
		return s.Conf
	}
	return func(string) string { return "" }
}

func (s *Server) handleWebDomainSet(w http.ResponseWriter, r *http.Request) {
	domain, err := normalizeDomain(r.PathValue("domain"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req api.WebDomainConfig
	body := http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if req.HSTS != "on" && req.HSTS != "preload" && req.HSTS != "off" {
		writeError(w, http.StatusBadRequest, "hsts must be on, preload, or off")
		return
	}
	if len(req.Rules) > maxWebRules {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("at most %d rules per domain", maxWebRules))
		return
	}
	paths := map[string]bool{}
	for _, rule := range req.Rules {
		if err := s.validateWebRule(rule); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if paths[rule.Path] {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("duplicate rule path %s", rule.Path))
			return
		}
		paths[rule.Path] = true
	}

	// Replace row and rule set in one transaction: rules have no
	// identity worth preserving across edits.
	tx, err := s.Store.Tx(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "transaction failed")
		return
	}
	err = func() error {
		row, err := tx.WebDomain.Query().Where(entwebdomain.Domain(domain)).Only(r.Context())
		if ent.IsNotFound(err) {
			row, err = tx.WebDomain.Create().SetDomain(domain).SetTenantID(s.TenantID).Save(r.Context())
		}
		if err != nil {
			return err
		}
		if _, err := row.Update().
			SetHsts(entwebdomain.Hsts(req.HSTS)).
			SetServeStatic(req.ServeStatic).
			Save(r.Context()); err != nil {
			return err
		}
		if _, err := tx.WebRule.Delete().
			Where(entwebrule.HasDomainWith(entwebdomain.ID(row.ID))).
			Exec(r.Context()); err != nil {
			return err
		}
		for _, rule := range req.Rules {
			if _, err := tx.WebRule.Create().
				SetKind(entwebrule.Kind(rule.Kind)).
				SetPath(rule.Path).
				SetTarget(rule.Target).
				SetPassHostHeader(rule.PassHostHeader).
				SetNoProxyRedirect(rule.NoProxyRedirect).
				SetFrameSameOrigin(rule.FrameSameOrigin).
				SetWebSockets(rule.WebSockets).
				SetDomain(row).
				Save(r.Context()); err != nil {
				return err
			}
		}
		return nil
	}()
	if err != nil {
		tx.Rollback()
		writeError(w, http.StatusInternalServerError, "saving web configuration failed")
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "saving web configuration failed")
		return
	}
	s.webDataChanged()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleWebDomainReset(w http.ResponseWriter, r *http.Request) {
	domain, err := normalizeDomain(r.PathValue("domain"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.Store.WebRule.Delete().
		Where(entwebrule.HasDomainWith(entwebdomain.Domain(domain))).
		Exec(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "reset failed")
		return
	}
	if _, err := s.Store.WebDomain.Delete().
		Where(entwebdomain.Domain(domain)).
		Exec(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "reset failed")
		return
	}
	s.webDataChanged()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleWebMountsSet(w http.ResponseWriter, r *http.Request) {
	var req api.WebMountsRequest
	body := http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	usedPaths := map[string]string{}
	for role, path := range req.Mounts {
		if err := validateMount(role, path); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if other, dup := usedPaths[path]; dup {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("roles %s and %s both mount at %s", other, role, path))
			return
		}
		usedPaths[path] = role
	}

	encoded, err := json.Marshal(req.Mounts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "saving mounts failed")
		return
	}
	if err := s.Store.Setting.Create().
		SetKey(webapply.SettingMounts).
		SetValue(string(encoded)).
		OnConflictColumns(entsetting.FieldKey).
		UpdateNewValues().
		Exec(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "saving mounts failed")
		return
	}
	s.webDataChanged()
	w.WriteHeader(http.StatusNoContent)
}

// validateMount checks one role -> path placement against the
// registry. Placement for roles whose component is not installed is
// accepted (dormant: it takes effect if the component is enabled
// later), so validation is capability-based, not enabled-based.
func validateMount(role, path string) error {
	members := registry.ByRole(role)
	if len(members) == 0 {
		return fmt.Errorf("unknown app role %q", role)
	}
	placeableRoot, placeablePath := false, false
	for _, svc := range members {
		placeableRoot = placeableRoot || svc.MountRoot
		placeablePath = placeablePath || svc.MountPath
	}
	if !placeableRoot && !placeablePath {
		return fmt.Errorf("%s cannot be moved", role)
	}
	if path == "/" {
		if !placeableRoot {
			return fmt.Errorf("%s cannot be mounted at the root", role)
		}
		return nil
	}
	if !placeablePath {
		return fmt.Errorf("%s can only be mounted at the root", role)
	}
	if len(path) > 64 || !webMountPathRE.MatchString(path) {
		return fmt.Errorf("invalid mount path %q", path)
	}
	// Fixed mounts and their subtrees are reserved (the admin panel is
	// the recovery path; radicale's path is baked into DAV clients).
	for _, svc := range registry.All() {
		if svc.MountRoot || svc.MountPath {
			continue
		}
		if path == svc.DefaultMount || strings.HasPrefix(path, svc.DefaultMount+"/") {
			return fmt.Errorf("path %s is reserved for %s", path, svc.Name)
		}
	}
	return nil
}

func (s *Server) validateWebRule(rule api.WebRule) error {
	if len(rule.Path) > maxRulePathLen || len(rule.Target) > maxRuleTargetLen {
		return errors.New("rule path or target too long")
	}
	// Belt and suspenders with the renderer's guard: nothing that
	// could terminate or open an nginx directive.
	if strings.ContainsAny(rule.Path+rule.Target, " ;{}\"'\n\r\t") {
		return errors.New("rule path or target contains forbidden characters")
	}
	switch rule.Kind {
	case "proxy":
		if !webPathRE.MatchString(rule.Path) {
			return fmt.Errorf("invalid proxy path %q", rule.Path)
		}
		return validateProxyTarget(rule.Target)
	case "redirect":
		if !webRedirectPathRE.MatchString(rule.Path) {
			return fmt.Errorf("invalid redirect pattern %q", rule.Path)
		}
		if !strings.HasPrefix(rule.Target, "/") &&
			!strings.HasPrefix(rule.Target, "http://") &&
			!strings.HasPrefix(rule.Target, "https://") {
			return errors.New("redirect target must be a path or an http(s) URL")
		}
		return nil
	case "alias":
		if !webPathRE.MatchString(rule.Path) {
			return fmt.Errorf("invalid alias path %q", rule.Path)
		}
		return s.validateAliasTarget(rule.Target)
	default:
		return fmt.Errorf("unknown rule kind %q", rule.Kind)
	}
}

// validateProxyTarget enforces the v1 tier: local and private backends
// only. Public targets need step-up re-authentication, which does not
// exist yet, so they are rejected outright rather than silently
// allowed.
func validateProxyTarget(target string) error {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("proxy target must be an http(s) URL")
	}
	host := u.Hostname()
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
			return nil
		}
		return errors.New("public proxy targets are not supported yet")
	}
	// A single-label name cannot be a public DNS name; it covers
	// localhost and Docker service names.
	if !strings.Contains(host, ".") {
		return nil
	}
	return errors.New("proxy targets must be a private IP or a local hostname")
}

// validateAliasTarget confines filesystem aliases to the operator's
// web directory. Panel admins are not system users; an unrestricted
// alias would let them publish any file nginx can read.
func (s *Server) validateAliasTarget(target string) error {
	if s.StorageRoot == "" {
		return errors.New("alias rules are not available")
	}
	wwwRoot := filepath.Join(s.StorageRoot, "www") + "/"
	if !strings.HasPrefix(target, "/") || filepath.Clean(target) != strings.TrimSuffix(target, "/") ||
		!strings.HasPrefix(filepath.Clean(target)+"/", wwwRoot) {
		return fmt.Errorf("alias targets must live under %s", wwwRoot)
	}
	return nil
}

// normalizeDomain lowercases and punycodes a hostname, rejecting
// anything that is not a plausible DNS name.
func normalizeDomain(raw string) (string, error) {
	ascii, err := idna.Lookup.ToASCII(strings.ToLower(strings.TrimSuffix(raw, ".")))
	if err != nil || len(ascii) > 253 || !strings.Contains(ascii, ".") {
		return "", fmt.Errorf("invalid domain name %q", raw)
	}
	return ascii, nil
}

func apiWebRule(r *ent.WebRule) api.WebRule {
	return api.WebRule{
		Kind:            string(r.Kind),
		Path:            r.Path,
		Target:          r.Target,
		PassHostHeader:  r.PassHostHeader,
		NoProxyRedirect: r.NoProxyRedirect,
		FrameSameOrigin: r.FrameSameOrigin,
		WebSockets:      r.WebSockets,
	}
}
