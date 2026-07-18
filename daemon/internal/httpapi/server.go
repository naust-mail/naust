// Package httpapi is managerd's HTTP surface. Handlers speak only the
// typed contract in internal/api and hold no state: everything lives in
// the store, so any replica can serve any request.
package httpapi

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"naust/daemon/internal/api"
	"naust/daemon/internal/auth"
	"naust/daemon/internal/dns"
	"naust/daemon/internal/registry"
	"naust/daemon/internal/store"
	"naust/daemon/internal/store/ent"
	entuser "naust/daemon/internal/store/ent/user"
)

type Server struct {
	Store *ent.Client
	Log   *log.Logger
	// TenantID is the tenant new tenant-owned rows (users, aliases,
	// web domains, DNS records, zone providers) are created under.
	// v1 is single-tenant: main.go passes the default tenant. v2
	// resolves this per request - and per the hard gate, query
	// scoping must exist before a second tenant can.
	TenantID int
	// PrimaryHostname is the box's own FQDN; it anchors the hosted DNS
	// zones alongside the user and alias domains.
	PrimaryHostname string
	// PublicIP and PublicIPv6 are the box's addresses; the web slice
	// uses them to spot domains pointed elsewhere by custom records.
	PublicIP   string
	PublicIPv6 string
	// StorageRoot is the user-data root; the web slice confines alias
	// rule targets to its www/ subtree.
	StorageRoot string
	// Conf resolves box configuration keys (boxconf.Conf.Get); the web
	// slice reads the component-selection flags through it. Nil reads
	// as all-defaults.
	Conf func(key string) string
	// OnMailDataChange fires after any mutation that affects the
	// materialized mail maps (users, aliases, passwords). Optional.
	OnMailDataChange func()
	// OnDNSDataChange fires after any mutation that affects generated
	// DNS zones (custom records, secondary nameservers, and the mail
	// mutations, which add and remove domains). Optional.
	OnDNSDataChange func()
	// OnWebDataChange fires after any mutation that affects the
	// rendered nginx config (web rules, mounts, and the DNS mutations,
	// which change the hosted hostname set). Optional.
	OnWebDataChange func()
	// OnCertConfigChange fires when certificate provisioning inputs
	// change (a DNS provider is configured), so the provisioner can
	// run promptly instead of waiting for its daily tick. Optional.
	OnCertConfigChange func()
	// Certs serves certificate status and the manual provisioning
	// trigger (normally *acmeprov.Provisioner). Nil panics on the
	// /api/ssl routes, which is a wiring bug.
	Certs CertProvisioner
	// Checks triggers status-check runs (normally *checks.Engine).
	// Nil panics on the /api/system/checks routes, a wiring bug.
	Checks CheckRunner
	// Zones returns the desired DNS zones (dnsapply DesiredZones);
	// the external-DNS view renders from it. Nil panics on
	// /api/dns/external, a wiring bug.
	Zones func(ctx context.Context) ([]dns.Zone, error)
	// Backup triggers backup runs (normally *backup.Engine). Nil
	// panics on the /api/system/backup routes, a wiring bug.
	Backup BackupRunner
	// RebootRequiredPath overrides /var/run/reboot-required in tests.
	RebootRequiredPath string

	// Helper invokes privileged operations on helperd. Tests substitute
	// a recorder; nil panics on the paths that need it, which is a bug.
	Helper HelperClient
	// RelayDir holds the relay SASL credential files
	// (STORAGE_ROOT/mail/relay). The manager owns it, so postmap runs
	// unprivileged here - see the ownership-vs-intent rule.
	RelayDir string
	// RunPostmap compiles a credential file into the Postfix lookup
	// table beside it. Tests fake it.
	RunPostmap func(ctx context.Context, path string) error
	// SubmitAddr is the SMTP address send-test and the welcome mail
	// submit through (the mail container in Docker). main.go always
	// sets it; when empty (tests), send-test falls back to
	// localhost:25 and the welcome mail is skipped.
	SubmitAddr string
	// WelcomeRetryDelay overrides the welcome mail's retry spacing in
	// tests. Zero means 15 seconds.
	WelcomeRetryDelay time.Duration
	// MailcryptKeyPath is the shared-secret file gating the internal
	// mail-key unwrap endpoint (Dovecot's Lua passdb holds the same
	// file). Empty disables the endpoint entirely (fails closed).
	MailcryptKeyPath string
	// BootstrapTokenPath is the setup-code file written by
	// "boxctl bootstrap"; the bootstrap endpoint is inert without it.
	// Empty disables bootstrap entirely (fails closed).
	BootstrapTokenPath string
	// AutodiscoverPath is the static Outlook autodiscover XML rendered
	// by setup. Missing file answers 404.
	AutodiscoverPath string
	// bootstrapMu serializes token-file reads and attempt updates.
	// Per-process is correct here: the token file is host-local by
	// design (a root-minted trust anchor, deliberately not store
	// state), so there is no cross-replica claim to coordinate.
	bootstrapMu sync.Mutex

	// Lazily built WebAuthn relying-party instance; see wa().
	waOnce sync.Once
	waInst *webauthn.WebAuthn
	waErr  error
}

// HelperClient is the slice of the helperd client the API server uses
// (satisfied by *helper.Client).
type HelperClient interface {
	Call(ctx context.Context, intent string, args map[string]string) (string, error)
}

func (s *Server) mailDataChanged() {
	if s.OnMailDataChange != nil {
		s.OnMailDataChange()
	}
	// Mail data drives zone contents too: domains appear and vanish
	// with their users and aliases.
	s.dnsDataChanged()
}

func (s *Server) dnsDataChanged() {
	if s.OnDNSDataChange != nil {
		s.OnDNSDataChange()
	}
	// Domain-set changes reshape the web tier too (vhosts appear and
	// vanish with domains and custom records). The web sync is
	// idempotent, so over-kicking is free.
	s.webDataChanged()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", s.handleHealthz)
	mux.HandleFunc("GET /api/meta", s.handleMeta)
	mux.HandleFunc("GET /api/auth/methods", s.handleAuthMethods)
	mux.HandleFunc("POST /api/bootstrap", s.handleBootstrap)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", s.requireSession(s.handleLogout))
	mux.HandleFunc("GET /api/auth/me", s.requireAuth(s.handleMe))
	// nginx auth_request target for admin-gated app mounts (netdata,
	// beszel, munin): only the status code matters to nginx. Lives
	// under /internal/, which nginx never proxies - only its own
	// auth_request subrequest reaches it.
	mux.HandleFunc("GET /internal/auth/admin", s.requireAdmin(s.handleMe))
	// Mail-user credential check for other on-box services (Radicale,
	// FileBrowser); see handleAuthVerify.
	mux.HandleFunc("POST /internal/auth/verify", s.handleAuthVerify)

	// Outlook autodiscover - Outlook POSTs an XML body, so nginx
	// proxies here instead of serving the file itself (nginx rejects
	// POST to static files). Both casings, clients vary.
	mux.HandleFunc("/autodiscover/autodiscover.xml", s.handleAutodiscover)
	mux.HandleFunc("/Autodiscover/Autodiscover.xml", s.handleAutodiscover)

	// Passkey login is its own two-step ceremony.
	mux.HandleFunc("POST /api/auth/webauthn/login/begin", s.handleWebAuthnLoginBegin)
	mux.HandleFunc("POST /api/auth/webauthn/login/complete", s.handleWebAuthnLoginComplete)

	// Credential management is deliberately session-only.
	mux.HandleFunc("GET /api/auth/mfa", s.requireSession(s.handleMFAState))
	mux.HandleFunc("POST /api/auth/totp/setup", s.requireSession(s.handleTOTPSetup))
	mux.HandleFunc("POST /api/auth/totp/enable", s.requireSession(s.handleTOTPEnable))
	mux.HandleFunc("POST /api/auth/webauthn/register/begin", s.requireSession(s.handleWebAuthnRegisterBegin))
	mux.HandleFunc("POST /api/auth/webauthn/register/complete", s.requireSession(s.handleWebAuthnRegisterComplete))
	mux.HandleFunc("DELETE /api/auth/mfa/{type}/{id}", s.requireSession(s.handleMFADisable))
	mux.HandleFunc("GET /api/user/encryption/status", s.requireEncryption(s.requireSession(s.handleEncryptionStatus)))
	mux.HandleFunc("POST /api/user/encryption/setup", s.requireEncryption(s.requireSession(s.handleEncryptionSetup)))
	mux.HandleFunc("POST /api/user/encryption/challenge", s.requireEncryption(s.requireSession(s.handleEncryptionChallenge)))
	mux.HandleFunc("POST /api/user/encryption/relink", s.requireEncryption(s.requireSession(s.handleEncryptionRelink)))
	mux.HandleFunc("POST /api/user/encryption/rotate-recovery", s.requireEncryption(s.requireSession(s.handleEncryptionRotateRecovery)))
	mux.HandleFunc("POST /api/user/encryption/rotate-recovery-confirm", s.requireEncryption(s.requireSession(s.handleEncryptionRotateConfirm)))
	mux.HandleFunc("POST /api/user/encryption/prf/enroll/begin", s.requireEncryption(s.requireSession(s.handlePRFEnrollBegin)))
	mux.HandleFunc("POST /api/user/encryption/prf/enroll/complete", s.requireEncryption(s.requireSession(s.handlePRFEnrollComplete)))
	mux.HandleFunc("POST /api/user/encryption/prf/relink/begin", s.requireEncryption(s.requireSession(s.handlePRFRelinkBegin)))
	mux.HandleFunc("POST /api/user/encryption/prf/relink/complete", s.requireEncryption(s.requireSession(s.handlePRFRelinkComplete)))
	// Dovecot's login-time unwrap: /internal/ is never proxied by
	// nginx and the handler checks the scoped key file itself.
	mux.HandleFunc("POST /internal/mailcrypt/unwrap", s.handleMailcryptUnwrap)

	mux.HandleFunc("GET /api/tokens", s.requireSession(s.handleListTokens))
	mux.HandleFunc("POST /api/tokens", s.requireSession(s.handleCreateToken))
	mux.HandleFunc("DELETE /api/tokens/{id}", s.requireSession(s.handleDeleteToken))

	mux.HandleFunc("POST /api/user/password", s.requireSession(s.handleChangeOwnPassword))

	mux.HandleFunc("GET /api/users", s.requireAdmin(s.handleListUsers))
	mux.HandleFunc("POST /api/users", s.requireAdmin(s.handleCreateUser))
	mux.HandleFunc("PATCH /api/users/{email}", s.requireAdmin(s.handleUpdateUser))
	mux.HandleFunc("PUT /api/users/{email}/password", s.requireAdmin(s.handleSetUserPassword))
	mux.HandleFunc("DELETE /api/users/{email}", s.requireAdmin(s.handleDeleteUser))

	mux.HandleFunc("GET /api/aliases", s.requireAdmin(s.handleListAliases))
	mux.HandleFunc("POST /api/aliases", s.requireAdmin(s.handleUpsertAlias))
	mux.HandleFunc("DELETE /api/aliases/{source}", s.requireAdmin(s.handleDeleteAlias))

	mux.HandleFunc("GET /api/dns/zones", s.requireAdmin(s.handleDNSZones))
	mux.HandleFunc("GET /api/dns/external", s.requireAdmin(s.handleDNSExternal))
	mux.HandleFunc("GET /api/dns/custom", s.requireAdmin(s.handleListDNSRecords))
	mux.HandleFunc("POST /api/dns/custom", s.requireAdmin(s.handleCreateDNSRecord))
	mux.HandleFunc("PUT /api/dns/custom/{qname}/{rtype}", s.requireAdmin(s.handleReplaceDNSRecords))
	mux.HandleFunc("DELETE /api/dns/custom/{qname}/{rtype}", s.requireAdmin(s.handleDeleteDNSRecords))
	mux.HandleFunc("GET /api/dns/secondary-nameserver", s.requireAdmin(s.handleGetSecondaryNS))
	mux.HandleFunc("PUT /api/dns/secondary-nameserver", s.requireAdmin(s.handleSetSecondaryNS))
	mux.HandleFunc("GET /api/dns/providers", s.requireAdmin(s.handleDNSProvidersList))
	mux.HandleFunc("PUT /api/dns/providers/{zone}", s.requireAdmin(s.handleDNSProviderSet))
	mux.HandleFunc("DELETE /api/dns/providers/{zone}", s.requireAdmin(s.handleDNSProviderDelete))

	mux.HandleFunc("GET /api/ssl", s.requireAdmin(s.handleSSLStatus))
	mux.HandleFunc("POST /api/ssl/provision", s.requireAdmin(s.handleSSLProvision))
	mux.HandleFunc("POST /api/ssl/csr", s.requireAdmin(s.handleSSLCSR))
	mux.HandleFunc("POST /api/ssl/install", s.requireAdmin(s.handleSSLInstall))

	mux.HandleFunc("GET /api/web", s.requireAdmin(s.handleWebStatus))
	mux.HandleFunc("PUT /api/web/domains/{domain}", s.requireAdmin(s.handleWebDomainSet))
	mux.HandleFunc("DELETE /api/web/domains/{domain}", s.requireAdmin(s.handleWebDomainReset))
	mux.HandleFunc("PUT /api/web/mounts", s.requireAdmin(s.handleWebMountsSet))

	mux.HandleFunc("POST /api/system/reboot", s.requireAdmin(s.handleReboot))
	mux.HandleFunc("GET /api/system/backup", s.requireAdmin(s.handleBackupStatus))
	mux.HandleFunc("PUT /api/system/backup/config", s.requireAdmin(s.handleBackupConfigSet))
	mux.HandleFunc("POST /api/system/backup/run", s.requireAdmin(s.handleBackupRun))
	mux.HandleFunc("GET /api/system/backup/key", s.requireAdmin(s.handleBackupKey))
	mux.HandleFunc("GET /api/system/checks", s.requireAdmin(s.handleChecksStatus))
	mux.HandleFunc("POST /api/system/checks/run", s.requireAdmin(s.handleChecksRun))
	mux.HandleFunc("GET /api/system/checks/config", s.requireAdmin(s.handleChecksConfigGet))
	mux.HandleFunc("PUT /api/system/checks/config", s.requireAdmin(s.handleChecksConfigSet))

	mux.HandleFunc("GET /api/system/relay", s.requireAdmin(s.handleRelayGet))
	mux.HandleFunc("PUT /api/system/relay", s.requireAdmin(s.handleRelaySet))
	mux.HandleFunc("POST /api/system/relay/test", s.requireAdmin(s.handleRelayTest))
	mux.HandleFunc("POST /api/system/relay/send-test", s.requireAdmin(s.handleRelaySendTest))
	return mux
}

type ctxKey int

const callerKey ctxKey = 0

// caller is the authenticated principal for one request: the user plus
// how they authenticated. Scope "full" means an interactive session;
// "read"/"write" mean an API token with that scope.
type caller struct {
	user  *ent.User
	scope string
}

func callerFrom(r *http.Request) caller {
	c, _ := r.Context().Value(callerKey).(caller)
	return c
}

func userFrom(r *http.Request) *ent.User {
	return callerFrom(r).user
}

// requireAuth resolves the bearer credential - an API token when it
// carries the token prefix, a session otherwise - and enforces token
// scope: read tokens may only GET.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := credentialFrom(r)
		if bearer == "" {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		var c caller
		if strings.HasPrefix(bearer, auth.TokenPrefix) {
			row, owner, err := auth.UserForAPIToken(r.Context(), s.Store, bearer)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "token lookup failed")
				return
			}
			if row == nil {
				writeError(w, http.StatusUnauthorized, "invalid API token")
				return
			}
			c = caller{user: owner, scope: string(row.Scope)}
		} else {
			u, err := auth.UserForToken(r.Context(), s.Store, bearer)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "session lookup failed")
				return
			}
			if u == nil {
				writeError(w, http.StatusUnauthorized, "invalid or expired session")
				return
			}
			c = caller{user: u, scope: "full"}
		}
		if c.scope == "read" && r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusForbidden, "this API token is read-only")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), callerKey, c)))
	}
}

// requireSession additionally rejects API tokens: credential and MFA
// management stays interactive, so a leaked automation token can never
// mint further credentials or weaken account security.
func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if callerFrom(r).scope != "full" {
			writeError(w, http.StatusForbidden, "this operation requires an interactive session")
			return
		}
		next(w, r)
	})
}

// requireAdmin gates a handler on an authenticated admin (session or
// API token).
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if userFrom(r).Role != entuser.RoleAdmin {
			writeError(w, http.StatusForbidden, "admin privileges required")
			return
		}
		next(w, r)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	// Prove the database round-trip, not just process liveness.
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if _, err := s.Store.User.Query().Count(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req api.LoginRequest
	body := http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	u, err := s.Store.User.Query().Where(entuser.Email(req.Email)).Only(r.Context())
	if ent.IsNotFound(err) {
		// Same cost and same response as a wrong password, so accounts
		// cannot be enumerated by timing or by message.
		auth.FakeVerify(req.Password)
		s.logFailedLogin(r)
		writeError(w, http.StatusForbidden, "invalid email or password")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user lookup failed")
		return
	}
	if !auth.VerifyPassword(u.PasswordHash, req.Password) {
		s.logFailedLogin(r)
		writeError(w, http.StatusForbidden, "invalid email or password")
		return
	}

	if ok, hints, err := s.checkTOTP(r, u, req.TOTPCode); err != nil {
		writeError(w, http.StatusInternalServerError, "MFA check failed")
		return
	} else if !ok {
		// A missing code is the normal first step of a 2FA login, not
		// an attack; only wrong codes count as failed attempts.
		if req.TOTPCode != "" {
			s.logFailedLogin(r)
		}
		writeJSON(w, http.StatusForbidden, api.ErrorResponse{
			Error: "two-factor authentication required",
			Hints: hints,
		})
		return
	}

	token, expires, err := auth.NewSession(r.Context(), s.Store, u, auth.DefaultSessionTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session creation failed")
		return
	}
	setSessionCookie(w, token, expires)
	writeJSON(w, http.StatusOK, api.LoginResponse{
		Token:     token,
		ExpiresAt: expires,
		User:      apiUser(u),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := auth.DeleteSession(r.Context(), s.Store, credentialFrom(r)); err != nil {
		writeError(w, http.StatusInternalServerError, "logout failed")
		return
	}
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// handleMeta serves the panel's single boot request: the pre-auth
// facts (hostname for the login screen, whether the box still awaits
// its first admin) plus the caller's account when the session cookie
// is valid. The pre-auth facts are already public - the hostname names
// the TLS certificate and the bootstrap endpoint is open exactly while
// no users exist - and an invalid session simply yields user null,
// never an error.
func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	count, err := s.Store.User.Query().Count(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "user count failed")
		return
	}
	resp := api.MetaResponse{
		Hostname:       s.PrimaryHostname,
		NeedsBootstrap: count == 0,
		Capabilities:   []string{},
	}
	if s.encryptionEnabled() {
		resp.Capabilities = append(resp.Capabilities, "encryption_at_rest")
	}
	// The monitoring capability mirrors the registry, so the panel
	// only offers a dashboard the web tier actually mounts.
	if s.Conf != nil {
		for _, svc := range registry.ByRole("monitoring") {
			if svc.Enabled(s.Conf) {
				resp.Capabilities = append(resp.Capabilities, "monitoring")
				break
			}
		}
	}
	// Only interactive sessions identify the caller here; API tokens
	// are for automation, which has no login screen to skip.
	if cred := credentialFrom(r); cred != "" && !strings.HasPrefix(cred, auth.TokenPrefix) {
		if u, err := auth.UserForToken(r.Context(), s.Store, cred); err == nil && u != nil {
			apiU := apiUser(u)
			resp.User = &apiU
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, apiUser(userFrom(r)))
}

func (s *Server) handleAutodiscover(w http.ResponseWriter, r *http.Request) {
	xml, err := os.ReadFile(s.AutodiscoverPath)
	if err != nil {
		http.Error(w, "Autodiscover not configured.", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Write(xml)
}

// logFailedLogin emits the exact line fail2ban matches; the format is
// load-bearing, see setup/conf/fail2ban/filter.d/naust-management-daemon.conf.
// The timestamp defeats syslog duplicate suppression.
func (s *Server) logFailedLogin(r *http.Request) {
	s.countAuthFailure(r.Context())
	s.Log.Printf("Naust Management Daemon: Failed login attempt from ip %s - timestamp %.6f",
		clientIP(r), float64(time.Now().UnixMicro())/1e6)
}

// countAuthFailure bumps the shared auth-failure counter the
// login-failures heuristic samples. Best-effort: the fail2ban log
// line is the authoritative record of the failure.
func (s *Server) countAuthFailure(ctx context.Context) {
	if err := store.IncrementCounter(ctx, s.Store, store.CounterAuthFailures); err != nil {
		s.Log.Printf("auth-failure counter: %v", err)
	}
}

// clientIP prefers X-Forwarded-For because nginx overwrites it with the
// real client address on every proxied request (spoofing is not
// possible through the proxy). Direct localhost calls lack the header
// and fall back to the socket peer.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func bearerToken(r *http.Request) string {
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return token
}

// sessionCookie is the browser panel's session transport: HttpOnly so
// XSS cannot exfiltrate the token, SameSite=Strict as the CSRF gate,
// and the __Host- prefix so a compromised app on a proxied subdomain
// cannot toss a cookie onto the panel origin. CLI and automation
// callers keep using the Authorization header instead.
const sessionCookie = "__Host-session"

func setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// credentialFrom returns the caller's credential: the Authorization
// header when present, otherwise the session cookie. The cookie is
// never allowed to carry an API token - a planted cookie holding a
// token would bypass SameSite (the attacker sets its attributes), so
// only interactive session tokens ride the cookie path.
func credentialFrom(r *http.Request) string {
	if bearer := bearerToken(r); bearer != "" {
		return bearer
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil || strings.HasPrefix(c.Value, auth.TokenPrefix) {
		return ""
	}
	return c.Value
}

func apiUser(u *ent.User) api.User {
	return api.User{
		Email:      u.Email,
		Role:       string(u.Role),
		QuotaBytes: u.QuotaBytes,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, api.ErrorResponse{Error: msg})
}
