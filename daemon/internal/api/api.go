// Package api defines the wire contract between managerd and its
// clients (the Vue admin frontend, boxctl, automation). Every request
// and response body crossing the HTTP boundary is a named struct here;
// handlers never marshal ad-hoc maps. TypeScript types for the frontend
// are generated from this package so the two sides cannot drift.
//
//go:generate go run ../../cmd/apigen -out ../../../frontend/src/api/types.gen.ts
package api

import (
	"encoding/json"
	"time"
)

// ErrorResponse is the body of every non-2xx response. Hints appears
// only on login failures where the caller can do something about it:
// "missing-totp-code" means retry login with TOTPCode set.
type ErrorResponse struct {
	Error string   `json:"error"`
	Hints []string `json:"hints,omitempty"`
}

// User is the client-visible view of a mail account. Password hashes
// and credential material never appear in the contract.
type User struct {
	Email string `json:"email"`
	// "admin" or "user".
	Role string `json:"role"`
	// 0 means unlimited.
	QuotaBytes int64 `json:"quota_bytes"`
}

// LoginRequest starts a session with email and password credentials.
// TOTPCode must accompany the password when the account has TOTP
// enabled (the initial attempt without it fails with a hint).
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code,omitempty"`
}

// LoginResponse carries the bearer token for subsequent requests. The
// token is shown exactly once; only its hash is stored server-side.
type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      User      `json:"user"`
}

// UsersResponse lists all mail accounts.
type UsersResponse struct {
	Users []User `json:"users"`
}

// CreateUserRequest adds a mail account. Role defaults to "user" and
// QuotaBytes to 0 (unlimited) when omitted.
type CreateUserRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	Role       string `json:"role,omitempty"`
	QuotaBytes int64  `json:"quota_bytes,omitempty"`
}

// UpdateUserRequest changes account attributes. Nil fields are left
// unchanged.
type UpdateUserRequest struct {
	Role       *string `json:"role,omitempty"`
	QuotaBytes *int64  `json:"quota_bytes,omitempty"`
}

// SetPasswordRequest replaces an account's password (admin reset).
// When the target account has encryption at rest enabled, the reset
// is refused with 409 unless AcknowledgeEncryption is set: without
// the old password the server cannot re-wrap the mail key, so the
// user will need a recovery code or an enrolled passkey to re-link
// before their mail decrypts again.
type SetPasswordRequest struct {
	Password              string `json:"password"`
	AcknowledgeEncryption bool   `json:"acknowledge_encryption,omitempty"`
}

// ChangePasswordRequest is the self-service password change. Knowing
// the current password lets the server rotate the encryption key slot
// in the same step, so encrypted mail stays readable.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// Alias is a mail forwarding rule. Auto rules are system-generated
// (postmaster@, abuse@, ...) and regenerate; they cannot be deleted,
// only overridden.
type Alias struct {
	Source           string   `json:"source"`
	Destinations     []string `json:"destinations"`
	PermittedSenders []string `json:"permitted_senders,omitempty"`
	Auto             bool     `json:"auto"`
}

// SystemRoute is one automatic system-mail route (postmaster@, abuse@,
// or root@ of a domain). Derived at request time from the oldest
// administrator, never stored: creating a user, alias, or catch-all at
// the source replaces it, and it re-derives when admins change.
type SystemRoute struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

// AliasesResponse lists all forwarding rules, plus the derived system
// routes so the automatic routing is visible next to the real rules.
type AliasesResponse struct {
	Aliases []Alias       `json:"aliases"`
	System  []SystemRoute `json:"system"`
}

// UpsertAliasRequest creates or replaces the alias for Source. A
// catch-all uses the "@domain.tld" source form.
type UpsertAliasRequest struct {
	Source           string   `json:"source"`
	Destinations     []string `json:"destinations"`
	PermittedSenders []string `json:"permitted_senders,omitempty"`
}

// DNSRecord is a custom DNS record. Zone is the hosted zone the record
// falls under, provided so clients can group records without
// re-deriving zone boundaries.
type DNSRecord struct {
	QName string `json:"qname"`
	RType string `json:"rtype"`
	// For A/AAAA the literal "local" means this box's public IP.
	Value string `json:"value"`
	Zone  string `json:"zone"`
}

// DNSRecordsResponse lists custom DNS records in creation order.
type DNSRecordsResponse struct {
	Records []DNSRecord `json:"records"`
}

// DNSZonesResponse lists the zone apexes this box hosts.
type DNSZonesResponse struct {
	Zones []string `json:"zones"`
}

// CreateDNSRecordRequest adds one custom record alongside any existing
// records for the same name and type. An empty Value on an A or AAAA
// record means the caller's own IP address (the dynamic-DNS idiom).
type CreateDNSRecordRequest struct {
	QName string `json:"qname"`
	RType string `json:"rtype"`
	Value string `json:"value"`
}

// ReplaceDNSRecordsRequest replaces every value for one qname and
// rtype pair with Values. An empty list removes the pair entirely.
type ReplaceDNSRecordsRequest struct {
	Values []string `json:"values"`
}

// SecondaryNameservers is both the response and the update request for
// the secondary-nameserver setting. Entries are hostnames, or
// "xfr:IP" / "xfr:CIDR" for transfer-only peers. An empty list clears
// the setting.
type SecondaryNameservers struct {
	Hostnames []string `json:"hostnames"`
}

// BootstrapRequest creates the very first admin account. Only valid
// while the box has no users at all; afterwards the endpoint is gone.
// Code is the setup code printed by "sudo boxctl bootstrap" - the
// endpoint refuses without a matching active code, so a scanner
// cannot claim a freshly installed box before its operator does.
type BootstrapRequest struct {
	Code     string `json:"code"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// MetaResponse is the single boot request of the panel: the public
// facts needed to render the login screen, plus the caller's account
// when the session cookie is valid (null otherwise), so no separate
// session probe is needed.
type MetaResponse struct {
	// The hostname this box presents to users and uses for its TLS
	// certificate.
	Hostname string `json:"hostname"`

	// True only while the system has no users and the first admin
	// account still needs to be created.
	NeedsBootstrap bool `json:"needs_bootstrap"`

	// The authenticated account, or null when no valid session
	// accompanied the request.
	User *User `json:"user"`

	// Box-level feature flags the panel gates navigation on:
	// "encryption_at_rest", "monitoring".
	Capabilities []string `json:"capabilities"`
}

// AuthMethodsResponse says how an account signs in, so the login page
// can route to the right ceremony before any credential is entered.
// Methods: "passkey", "password+totp", "password". Unknown accounts
// uniformly answer ["password"], so the endpoint does not reveal which
// addresses exist.
type AuthMethodsResponse struct {
	Methods []string `json:"methods"`
}

// APIToken is the client-visible view of an automation token. The
// secret appears only in CreateAPITokenResponse, exactly once.
type APIToken struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	// "read" (GET only) or "write" (all API operations; still cannot
	// manage tokens - that stays session-only).
	Scope     string     `json:"scope"`
	CreatedAt time.Time  `json:"created_at"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
}

// APITokensResponse lists the caller's tokens.
type APITokensResponse struct {
	Tokens []APIToken `json:"tokens"`
}

// CreateAPITokenRequest mints a token for the calling user.
type CreateAPITokenRequest struct {
	Name  string `json:"name"`
	Scope string `json:"scope"`
}

// CreateAPITokenResponse carries the plaintext token, shown exactly
// once; only its hash is stored server-side.
type CreateAPITokenResponse struct {
	Token    string   `json:"token"`
	Metadata APIToken `json:"metadata"`
}

// TOTPSetupResponse offers a fresh secret for enrollment. The client
// renders OTPAuthURI as a QR code; nothing is stored until the enable
// call proves the authenticator produces matching codes.
type TOTPSetupResponse struct {
	Secret     string `json:"secret"`
	OTPAuthURI string `json:"otpauth_uri"`
}

// EnableTOTPRequest completes enrollment: the secret from setup plus a
// current code from the authenticator app.
type EnableTOTPRequest struct {
	Secret string `json:"secret"`
	Code   string `json:"code"`
	Label  string `json:"label,omitempty"`
}

// MFACredential is one enrolled second factor. Type is "totp" (and
// "webauthn" once passkeys land). Secrets never appear.
type MFACredential struct {
	ID    int    `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label,omitempty"`
}

// MFAStateResponse lists the caller's enrolled second factors.
type MFAStateResponse struct {
	Credentials []MFACredential `json:"credentials"`
}

// WebAuthnBeginResponse starts a passkey ceremony: Options goes to
// navigator.credentials verbatim, Nonce comes back with the result so
// the server can find the ceremony it began.
type WebAuthnBeginResponse struct {
	Nonce   string          `json:"nonce"`
	Options json.RawMessage `json:"options"`
}

// WebAuthnRegisterCompleteRequest finishes passkey enrollment.
// Credential is the JSON of the browser's PublicKeyCredential result.
type WebAuthnRegisterCompleteRequest struct {
	Nonce      string          `json:"nonce"`
	Name       string          `json:"name,omitempty"`
	Credential json.RawMessage `json:"credential"`
}

// WebAuthnLoginBeginRequest asks for assertion options for an account.
type WebAuthnLoginBeginRequest struct {
	Email string `json:"email"`
}

// WebAuthnLoginCompleteRequest finishes a passkey login.
type WebAuthnLoginCompleteRequest struct {
	Nonce      string          `json:"nonce"`
	Credential json.RawMessage `json:"credential"`
}

// RelayConfig is the outbound SMTP relay configuration. PasswordSet
// reports whether a credential exists in the Postfix lookup table; the
// password itself is write-only and never returned.
type RelayConfig struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	User        string `json:"user"`
	PasswordSet bool   `json:"password_set"`
	// SPFInclude is the relay provider's SPF include hostname, folded
	// into every mail domain's SPF record (e.g. "sendgrid.net").
	SPFInclude string `json:"spf_include"`
}

// SetRelayRequest replaces the relay configuration. An empty Host
// removes the relay and restores direct delivery. An empty Password
// keeps the stored credential unchanged.
type SetRelayRequest struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user,omitempty"`
	Password   string `json:"password,omitempty"`
	SPFInclude string `json:"spf_include,omitempty"`
}

// RelayTestRequest probes connectivity (and optionally authentication)
// to a relay before saving it. Nothing is stored.
type RelayTestRequest struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
}

// MessageResponse carries a human-readable outcome for operations
// whose only result is a status message.
type MessageResponse struct {
	Message string `json:"message"`
}

// WebRule is one path rule on a web domain: a reverse proxy, a
// redirect, or a filesystem alias. The flag fields apply to proxies
// only. A rule at path "/" replaces static serving at the root.
type WebRule struct {
	Kind            string `json:"kind"` // "proxy", "redirect", "alias"
	Path            string `json:"path"`
	Target          string `json:"target"`
	PassHostHeader  bool   `json:"pass_host_header,omitempty"`
	NoProxyRedirect bool   `json:"no_proxy_redirect,omitempty"`
	FrameSameOrigin bool   `json:"frame_same_origin,omitempty"`
	WebSockets      bool   `json:"web_sockets,omitempty"`
}

// WebDomainConfig replaces one domain's web customizations wholesale:
// the HSTS level ("on", "preload", "off"), whether static files are
// served, and the full rule set.
type WebDomainConfig struct {
	HSTS        string    `json:"hsts"`
	ServeStatic bool      `json:"serve_static"`
	Rules       []WebRule `json:"rules,omitempty"`
}

// WebDomainInfo is one hostname the box serves web for, with its
// effective configuration. RedirectTo marks the default www redirects.
// Customized is true when a stored configuration row exists (DELETE
// returns the domain to defaults).
type WebDomainInfo struct {
	Domain      string    `json:"domain"`
	Primary     bool      `json:"primary,omitempty"`
	RedirectTo  string    `json:"redirect_to,omitempty"`
	Customized  bool      `json:"customized"`
	HSTS        string    `json:"hsts"`
	ServeStatic bool      `json:"serve_static"`
	Rules       []WebRule `json:"rules,omitempty"`
}

// WebMountInfo is one app slot on the primary domain. Role groups
// alternative implementations (the "webmail" role covers all four
// clients); App names the enabled one, empty when the component is not
// installed. Fixed mounts (admin, radicale, monitoring) cannot move.
type WebMountInfo struct {
	Role    string `json:"role"`
	App     string `json:"app,omitempty"`
	Path    string `json:"path"`
	Fixed   bool   `json:"fixed"`
	Enabled bool   `json:"enabled"`
}

// WebStatusResponse is the full web-tier state for the panel.
type WebStatusResponse struct {
	Domains []WebDomainInfo `json:"domains"`
	Mounts  []WebMountInfo  `json:"mounts"`
}

// WebMountsRequest replaces the app placement overrides: role name ->
// mount path. Roles absent from the map return to their defaults.
type WebMountsRequest struct {
	Mounts map[string]string `json:"mounts"`
}

// DNSZoneProviderInfo is one zone whose public DNS lives on an
// external provider, enabling DNS-01 certificate challenges for its
// domains. The API credential is never returned.
type DNSZoneProviderInfo struct {
	Zone     string `json:"zone"`
	Provider string `json:"provider"`
}

// DNSProvidersResponse lists the configured zone providers plus the
// provider names this build supports, for the panel's picker.
type DNSProvidersResponse struct {
	Available []string              `json:"available"`
	Zones     []DNSZoneProviderInfo `json:"zones"`
}

// DNSZoneProviderSetRequest configures (or replaces) the DNS provider
// for one zone. Token is the provider API credential, scoped as
// narrowly as the provider allows (e.g. a Cloudflare token limited to
// DNS edits on the zone).
type DNSZoneProviderSetRequest struct {
	Provider string `json:"provider"`
	Token    string `json:"token"`
}

// SSLDomainInfo is the certificate state of one hosted domain. Cert is
// the on-disk state: "valid", "expiring", "expired", "self-signed", or
// "missing". LastStatus and LastDetail echo this domain's outcome from
// the most recent provisioning run ("installed", "skipped", "error"),
// empty if no run covered it since startup.
type SSLDomainInfo struct {
	Domain     string     `json:"domain"`
	Cert       string     `json:"cert"`
	NotAfter   *time.Time `json:"not_after,omitempty"`
	LastStatus string     `json:"last_status,omitempty"`
	LastDetail string     `json:"last_detail,omitempty"`
}

// SSLStatusResponse is the certificate state for the panel. Running
// means a provisioning run is in flight (poll again for its results).
// LastError carries a run-level failure of the most recent run (one
// that aborted before reaching any domain); nil LastRunAt means no run
// has finished since startup.
type SSLStatusResponse struct {
	Domains   []SSLDomainInfo `json:"domains"`
	Running   bool            `json:"running"`
	LastRunAt *time.Time      `json:"last_run_at,omitempty"`
	LastError string          `json:"last_error,omitempty"`
}

// SSLProvisionRequest starts a provisioning run in the background. An
// empty Domains list covers every hosted domain.
type SSLProvisionRequest struct {
	Domains []string `json:"domains"`
}

// CheckStep is one phase of a status check, rendered like a CI job
// step. Expected and Observed carry the structured diff when the
// step compared something; FixHint may name a repair (possibly a
// helper intent) for a future fix button.
type CheckStep struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	Expected  string `json:"expected,omitempty"`
	Observed  string `json:"observed,omitempty"`
	FixHint   string `json:"fix_hint,omitempty"`
	ElapsedMs int64  `json:"elapsed_ms"`
}

// CheckResultInfo is the latest stored outcome of one status check
// (one domain instance for per-domain checks). Status: ok, warning,
// error, or skipped. FirstFailedAt says since when the check has been
// failing, nil when healthy.
type CheckResultInfo struct {
	Check         string      `json:"check"`
	Category      string      `json:"category"`
	Domain        string      `json:"domain,omitempty"`
	Status        string      `json:"status"`
	Message       string      `json:"message,omitempty"`
	Steps         []CheckStep `json:"steps"`
	RanAt         time.Time   `json:"ran_at"`
	ElapsedMs     int64       `json:"elapsed_ms"`
	FirstFailedAt *time.Time  `json:"first_failed_at,omitempty"`
}

// ChecksStatusResponse is the full status snapshot. It always renders
// instantly from stored results; Running true means a run is in
// flight and polling again will show fresher rows.
type ChecksStatusResponse struct {
	Results []CheckResultInfo `json:"results"`
	Running bool              `json:"running"`
}

// ChecksRunRequest starts a background run of matching checks. All
// zero fields = run everything. A manual run ignores cadences and
// the disabled flag.
type ChecksRunRequest struct {
	Checks   []string `json:"checks,omitempty"`
	Category string   `json:"category,omitempty"`
	Domain   string   `json:"domain,omitempty"`
}

// CheckOverrideConfig is one check's admin override: a cadence (fast,
// hourly, daily, weekly, off) replacing the default, and/or enabled
// false to stop scheduling it.
type CheckOverrideConfig struct {
	Cadence string `json:"cadence,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
}

// ChecksConfig is the administrator's status-check configuration.
// Report schedules the status-change digest email: off, daily, or
// weekly (empty = off).
type ChecksConfig struct {
	Checks map[string]CheckOverrideConfig `json:"checks,omitempty"`
	Report string                         `json:"report,omitempty"`
}

// CheckMeta describes one available check: identity plus the
// presentation metadata the status and config pages render (title,
// description for the info affordance, class for success visibility).
type CheckMeta struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category"`
	// standard (always shown) | quiet (hidden while ok) | metric
	// (shown with its reading even when ok)
	Class          string `json:"class"`
	DefaultCadence string `json:"default_cadence"`
}

// ChecksConfigResponse pairs the stored overrides with the check
// catalog so the config page can render every tunable row.
type ChecksConfigResponse struct {
	Config    ChecksConfig `json:"config"`
	Available []CheckMeta  `json:"available"`
}

// ExternalDNSRecord is one record the operator must create when DNS
// for the domain is hosted elsewhere. QName is fully qualified
// (no trailing dot). Category says how much it matters: required,
// recommended, optional, or hardening.
type ExternalDNSRecord struct {
	QName    string `json:"qname"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Category string `json:"category"`
}

// ExternalDNSZone groups the external records of one zone.
type ExternalDNSZone struct {
	Zone    string              `json:"zone"`
	Records []ExternalDNSRecord `json:"records"`
}

// ExternalDNSResponse is the full desired record set for hosting DNS
// outside this box - the same records the box would serve itself.
type ExternalDNSResponse struct {
	Zones []ExternalDNSZone `json:"zones"`
}

// SSLCSRRequest asks for a certificate signing request built on the
// box's system key, for buying a certificate from a commercial CA.
// CountryCode is optional (two uppercase letters).
type SSLCSRRequest struct {
	Domain      string `json:"domain"`
	CountryCode string `json:"country_code,omitempty"`
}

// SSLCSRResponse carries the PEM-encoded CSR.
type SSLCSRResponse struct {
	CSR string `json:"csr"`
}

// SSLInstallRequest installs an operator-provided certificate. Cert
// is the PEM leaf certificate; Chain optionally carries the PEM
// intermediates. The certificate must have been issued for a CSR from
// this box (the system key).
type SSLInstallRequest struct {
	Domain string `json:"domain"`
	Cert   string `json:"cert"`
	Chain  string `json:"chain,omitempty"`
}

// BackupTargetConfig says where backups go. Only the fields for the
// chosen type are used. Credentials (secret_key, app_key) are never
// returned by GET; leaving them empty on PUT keeps the stored values.
type BackupTargetConfig struct {
	Type string `json:"type"`

	// rsync (SFTP).
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	User string `json:"user,omitempty"`
	Path string `json:"path,omitempty"`

	// s3.
	Endpoint  string `json:"endpoint,omitempty"`
	Region    string `json:"region,omitempty"`
	Bucket    string `json:"bucket,omitempty"`
	AccessKey string `json:"access_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`

	// b2 (Bucket shared with s3).
	KeyID  string `json:"key_id,omitempty"`
	AppKey string `json:"app_key,omitempty"`
}

// BackupConfig is the administrator's backup configuration.
// KeepWithinDays is the retention window; with the duplicity backend
// deletion happens at chain granularity, so actual removal is chunky.
type BackupConfig struct {
	Target           BackupTargetConfig `json:"target"`
	KeepWithinDays   int                `json:"keep_within_days"`
	CheckAfterBackup bool               `json:"check_after_backup"`
}

// BackupRunInfo is one recorded backup run. Status: running, ok, or
// error. Warning carries non-fatal problems of a successful run
// (retention prune or integrity check failed).
type BackupRunInfo struct {
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Status     string     `json:"status"`
	Tool       string     `json:"tool"`
	Error      string     `json:"error,omitempty"`
	Warning    string     `json:"warning,omitempty"`
	SnapshotID string     `json:"snapshot_id,omitempty"`
	Size       int64      `json:"size,omitempty"`
	DataAdded  int64      `json:"data_added,omitempty"`
	FileCount  int64      `json:"file_count,omitempty"`
}

// BackupSnapshot is one restorable point in time from the cached
// inventory (refreshed after each successful run).
type BackupSnapshot struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Size      int64     `json:"size,omitempty"`
	DataAdded int64     `json:"data_added,omitempty"`
	FileCount int64     `json:"file_count,omitempty"`
	Full      bool      `json:"full,omitempty"`
}

// BackupStatusResponse is the backups page payload. KeySavedAt says
// when the restore sheet was first downloaded, nil if never - the
// passive key-custody signal.
type BackupStatusResponse struct {
	Config    BackupConfig     `json:"config"`
	Tool      string           `json:"tool"`
	Runs      []BackupRunInfo  `json:"runs"`
	Snapshots []BackupSnapshot `json:"snapshots"`
	// SSHPublicKey is the box's backup identity for rsync/sftp
	// targets (backup/ssh/id_rsa.pub), shown so the admin can
	// authorize it on the target host. Empty until setup creates it.
	SSHPublicKey string     `json:"ssh_public_key,omitempty"`
	KeySavedAt   *time.Time `json:"key_saved_at,omitempty"`
	Running      bool       `json:"running"`
}

// EncryptionStatusResponse reports a user's encryption-at-rest state:
// which slot types exist and whether mail is being encrypted (a
// password slot exists).
type EncryptionStatusResponse struct {
	Enabled    bool     `json:"enabled"`
	SlotTypes  []string `json:"slot_types"`
	HasPRFSlot bool     `json:"has_prf_slot"`
}

// EncryptionSetupRequest re-authenticates the ceremony that issues
// recovery codes (initial setup and recovery-code rotation).
type EncryptionSetupRequest struct {
	Password string `json:"password"`
}

// EncryptionSetupResponse returns the recovery codes exactly once;
// they are never stored server-side.
type EncryptionSetupResponse struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

// EncryptionChallengeRequest proves the user copied recovery code
// CodeIndex before anything is committed.
type EncryptionChallengeRequest struct {
	Code      string `json:"code"`
	CodeIndex int    `json:"code_index"`
}

// EncryptionEnabledResponse acknowledges a completed setup challenge.
type EncryptionEnabledResponse struct {
	Enabled bool `json:"enabled"`
}

// EncryptionRelinkRequest re-establishes the password slot from a
// recovery code after a password reset the system could not rotate.
type EncryptionRelinkRequest struct {
	Code     string `json:"code"`
	Password string `json:"password"`
}

// OKResponse is the generic success acknowledgement.
type OKResponse struct {
	Status string `json:"status"`
}

// MailcryptUnwrapResponse answers Dovecot's login-time unwrap call.
// MailKey is the hex dovecot subkey, or null for unknown user, no
// encryption, or wrong password (login proceeds without decryption).
type MailcryptUnwrapResponse struct {
	MailKey *string `json:"mail_key"`
}

// EncryptionPRFCompleteRequest finishes a PRF ceremony (enroll or
// relink). Credential is the browser's PublicKeyCredential JSON;
// PRFOutput is the 32-byte prf extension result, base64url, read by
// client JS from getClientExtensionResults(). Password is the login
// password: enroll needs it to unwrap the root key, relink to wrap
// the replacement slot under it.
type EncryptionPRFCompleteRequest struct {
	Nonce      string          `json:"nonce"`
	Credential json.RawMessage `json:"credential"`
	PRFOutput  string          `json:"prf_output"`
	Password   string          `json:"password"`
}
