package httpapi

import (
	"fmt"
	"regexp"
	"strings"

	"naust/daemon/internal/dns"
)

// Validation rules ported from management/mail/mailconfig/validation.py.
// Internationalized domains are punycoded at the API boundary (see
// asciiEmailDomain) so everything stored and materialized is ASCII.
// User account addresses stay ASCII-only by policy: they are login
// identifiers and maildir path components.

// User account addresses are restricted to what Dovecot handles
// predictably: lowercase letters, digits, underscore, dash, dot. The
// maildir path derives from the address, hence the tight charset and
// length cap.
var userEmailCharset = regexp.MustCompile(`^[a-z0-9_\-.@]+$`)

func validateUserEmail(email string) error {
	if len(email) > 255 || !userEmailCharset.MatchString(email) {
		return fmt.Errorf("invalid email address for a user account: %s", email)
	}
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || !validDotted(local) || !validDomain(domain) {
		return fmt.Errorf("invalid email address for a user account: %s", email)
	}
	return nil
}

// validateAliasSource additionally allows the empty local part
// ("@domain.tld"), Postfix's catch-all form.
func validateAliasSource(source string) error {
	if domain, ok := strings.CutPrefix(source, "@"); ok {
		if !validDomain(domain) {
			return fmt.Errorf("invalid catch-all domain: %s", source)
		}
		return nil
	}
	return validateEmailBasic(source)
}

// validateEmailBasic is the permissive structural check used for alias
// sources and forwarding destinations, which may be external addresses
// with mixed case and a wider local-part charset.
func validateEmailBasic(addr string) error {
	if len(addr) > 320 || strings.ContainsAny(addr, " \t\r\n") {
		return fmt.Errorf("invalid email address: %s", addr)
	}
	local, domain, ok := strings.Cut(addr, "@")
	if !ok || local == "" || len(local) > 64 || strings.Contains(domain, "@") || !validDomain(domain) {
		return fmt.Errorf("invalid email address: %s", addr)
	}
	return nil
}

// asciiEmailDomain converts an internationalized domain in an email
// address (or "@domain" catch-all) to punycode; the local part is left
// alone. Shape problems fall through to the validators, which see the
// converted form.
func asciiEmailDomain(addr string) string {
	local, domain, ok := strings.Cut(addr, "@")
	if !ok {
		return addr
	}
	ascii, err := dns.NormalizeName(domain)
	if err != nil {
		return addr
	}
	return local + "@" + ascii
}

func validDotted(s string) bool {
	return !strings.HasPrefix(s, ".") && !strings.HasSuffix(s, ".") && !strings.Contains(s, "..")
}

var domainLabelRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?$`)

func validDomain(domain string) bool {
	if len(domain) > 253 || !strings.Contains(domain, ".") {
		return false
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) > 63 || !domainLabelRe.MatchString(label) {
			return false
		}
	}
	// The TLD must not be all-numeric.
	return strings.ContainsFunc(labels[len(labels)-1], func(r rune) bool { return r < '0' || r > '9' })
}

// isDCVAddress reports whether the address is one commonly used for
// domain control validation; those may not become user accounts (an
// attacker who obtains such a mailbox can obtain certificates).
func isDCVAddress(email string) bool {
	email = strings.ToLower(email)
	for _, local := range []string{"admin", "administrator", "postmaster", "hostmaster", "webmaster", "abuse"} {
		if strings.HasPrefix(email, local+"@") || strings.HasPrefix(email, local+"+") {
			return true
		}
	}
	return false
}

func validatePassword(pw string) error {
	if strings.TrimSpace(pw) == "" {
		return fmt.Errorf("no password provided")
	}
	if len(pw) < 8 {
		return fmt.Errorf("passwords must be at least eight characters")
	}
	if len(pw) > 1024 {
		return fmt.Errorf("passwords must be at most 1024 characters")
	}
	return nil
}
