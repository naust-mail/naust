package registry

import (
	"regexp"
	"strings"
	"testing"
)

var nameRe = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// TestTableInvariants pins the structural rules every entry must obey,
// so a future addition cannot silently break mount validation.
func TestTableInvariants(t *testing.T) {
	names := map[string]bool{}
	for _, s := range All() {
		if !nameRe.MatchString(s.Name) {
			t.Errorf("%s: name not a safe id", s.Name)
		}
		if names[s.Name] {
			t.Errorf("%s: duplicate name", s.Name)
		}
		names[s.Name] = true

		if !strings.HasPrefix(s.DefaultMount, "/") {
			t.Errorf("%s: DefaultMount %q must start with /", s.Name, s.DefaultMount)
		}
		if s.DefaultMount == "/" && !s.MountRoot {
			t.Errorf("%s: defaults to root but MountRoot is false", s.Name)
		}
		if (s.EnabledWhen.Var == "") != (s.EnabledWhen.Value == "") {
			t.Errorf("%s: EnabledWhen must be fully set or zero", s.Name)
		}
		if s.Port < 0 || s.Port > 65535 {
			t.Errorf("%s: port %d out of range", s.Name, s.Port)
		}
	}

	// Services sharing a role are alternatives selected by one flag:
	// same Var and Default, distinct Values, so at most one can be
	// enabled at a time.
	roles := map[string][]Service{}
	for _, s := range All() {
		roles[s.RoleName()] = append(roles[s.RoleName()], s)
	}
	for role, members := range roles {
		if len(members) < 2 {
			continue
		}
		values := map[string]bool{}
		for _, s := range members {
			if s.EnabledWhen.Var != members[0].EnabledWhen.Var {
				t.Errorf("role %s: mixed gating vars", role)
			}
			if s.EnabledWhen.Default != members[0].EnabledWhen.Default {
				t.Errorf("role %s: mixed defaults", role)
			}
			if values[s.EnabledWhen.Value] {
				t.Errorf("role %s: two members enabled by value %q", role, s.EnabledWhen.Value)
			}
			values[s.EnabledWhen.Value] = true
		}
	}
}

func envLookup(env map[string]string) func(string) string {
	return func(k string) string { return env[k] }
}

func TestEnabled(t *testing.T) {
	enabledNames := func(env map[string]string) map[string]bool {
		out := map[string]bool{}
		for _, s := range All() {
			if s.Enabled(envLookup(env)) {
				out[s.Name] = true
			}
		}
		return out
	}

	// A bare environment gets the documented defaults: rav
	// webmail, filebrowser and radicale on, no monitoring.
	on := enabledNames(nil)
	for _, want := range []string{"admin", "webmail-rav", "filebrowser", "radicale"} {
		if !on[want] {
			t.Errorf("defaults: %s should be enabled", want)
		}
	}
	for _, off := range []string{"webmail-roundcube", "webmail-snappymail", "webmail-cypht", "netdata", "beszel"} {
		if on[off] {
			t.Errorf("defaults: %s should be disabled", off)
		}
	}

	// Selecting alternatives flips exactly the right entries.
	on = enabledNames(map[string]string{
		"WEBMAIL_CLIENT":     "roundcube",
		"MONITORING_TOOL":    "beszel",
		"ENABLE_FILEBROWSER": "false",
	})
	if !on["webmail-roundcube"] || on["webmail-rav"] {
		t.Error("WEBMAIL_CLIENT=roundcube not respected")
	}
	if !on["beszel"] || on["netdata"] {
		t.Error("MONITORING_TOOL=beszel not respected")
	}
	if on["filebrowser"] {
		t.Error("ENABLE_FILEBROWSER=false not respected")
	}

	// "none" disables a whole role.
	on = enabledNames(map[string]string{"WEBMAIL_CLIENT": "none"})
	for _, name := range []string{"webmail-rav", "webmail-roundcube", "webmail-snappymail", "webmail-cypht"} {
		if on[name] {
			t.Errorf("WEBMAIL_CLIENT=none: %s still enabled", name)
		}
	}

	// Under any of those environments, a role never has two enabled members.
	for _, env := range []map[string]string{
		nil,
		{"WEBMAIL_CLIENT": "snappymail", "MONITORING_TOOL": "netdata"},
		{"WEBMAIL_CLIENT": "cypht"},
	} {
		perRole := map[string]int{}
		for _, s := range All() {
			if s.Enabled(envLookup(env)) {
				perRole[s.RoleName()]++
			}
		}
		for role, n := range perRole {
			if n > 1 {
				t.Errorf("env %v: role %s has %d enabled members", env, role, n)
			}
		}
	}
}

func TestLookups(t *testing.T) {
	s, ok := ByName("filebrowser")
	if !ok || s.Port != 8080 || s.HostEnv != "FILEBROWSER_HOST" {
		t.Errorf("ByName(filebrowser) = %+v, %v", s, ok)
	}
	if _, ok := ByName("nope"); ok {
		t.Error("ByName(nope) should miss")
	}
	if got := len(ByRole("webmail")); got != 4 {
		t.Errorf("ByRole(webmail) = %d members, want 4", got)
	}
	if got := ByRole("radicale"); len(got) != 1 || got[0].Name != "radicale" {
		t.Errorf("ByRole(radicale) = %+v", got)
	}
	// The admin panel must never be placeable.
	admin, _ := ByName("admin")
	if admin.MountRoot || admin.MountPath || admin.DefaultMount != "/admin" {
		t.Errorf("admin mount facts changed: %+v", admin)
	}
}
