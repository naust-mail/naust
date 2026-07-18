package helper

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
	"unicode"
)

const (
	maxContentLen = 1 << 20 // 1MB cap on any file content argument
	maxValueLen   = 1024    // cap on postconf values
)

// intentDef is one entry in the fixed menu: how to validate its args and
// how to execute it. Validation never touches the system; execution only
// runs after validation passes.
type intentDef struct {
	timeout time.Duration
	// redact names args whose values must never appear in logs.
	redact map[string]bool
	// exact arg names this intent requires - no more, no fewer.
	args     []string
	validate func(args map[string]string) error
	execute  func(ctx context.Context, d Deps, args map[string]string) (string, error)
}

// Intents is the menu. Adding an entry here is a design decision - see
// the ownership-vs-intent rule in helper-intent-menu.md before extending.
var Intents = map[string]intentDef{
	"service.restart": serviceIntent("restart"),
	"service.reload":  serviceIntent("reload"),
	"service.stop":    serviceIntent("stop"),
	"service.disable": serviceIntent("disable"),

	"postfix.set": {
		timeout: 60 * time.Second,
		args:    []string{"key", "value"},
		validate: func(args map[string]string) error {
			if !postfixKeys[args["key"]] {
				return fmt.Errorf("postfix key %q not in allowlist", args["key"])
			}
			return validValue(args["value"])
		},
		execute: func(ctx context.Context, d Deps, args map[string]string) (string, error) {
			_, err := d.Run.Run(ctx, []string{"/usr/sbin/postconf", "-e", args["key"] + "=" + args["value"]}, nil)
			return "", err
		},
	},

	"config.write": {
		timeout: 30 * time.Second,
		args:    []string{"target", "content"},
		validate: func(args map[string]string) error {
			if _, ok := configTargets[args["target"]]; !ok {
				return fmt.Errorf("config target %q not in allowlist", args["target"])
			}
			if len(args["content"]) > maxContentLen {
				return fmt.Errorf("content exceeds %d bytes", maxContentLen)
			}
			return nil
		},
		execute: func(ctx context.Context, d Deps, args map[string]string) (string, error) {
			t := configTargets[args["target"]]
			return "", writeFileAtomic(filepath.Join(d.Root, t.path), []byte(args["content"]), t.mode)
		},
	},

	"web.sync_sites": webSyncIntent,

	// Read-only queue snapshot for the status checks. managerd runs
	// under NoNewPrivileges, so postqueue's setgid bit is ignored for
	// its children and the showq socket stays unreachable there; the
	// helper reads the queue instead and managerd gains no group or
	// file access. Output returns to the caller like the host intents.
	"postfix.queue": {
		timeout: 60 * time.Second,
		execute: func(ctx context.Context, d Deps, _ map[string]string) (string, error) {
			return d.Run.Run(ctx, []string{"/usr/sbin/postqueue", "-j"}, nil)
		},
	},

	// Exact argv from management/core/views/system_views.py.
	"host.apt_update": {
		timeout: 10 * time.Minute,
		execute: func(ctx context.Context, d Deps, _ map[string]string) (string, error) {
			return d.Run.Run(ctx, []string{"/usr/bin/apt-get", "-qq", "update"}, nil)
		},
	},
	"host.apt_upgrade": {
		timeout: 20 * time.Minute,
		execute: func(ctx context.Context, d Deps, _ map[string]string) (string, error) {
			return d.Run.Run(ctx, []string{"/usr/bin/apt-get", "-y", "upgrade"},
				[]string{"DEBIAN_FRONTEND=noninteractive"})
		},
	},
	"host.reboot": {
		timeout: 10 * time.Second,
		execute: func(ctx context.Context, d Deps, _ map[string]string) (string, error) {
			return d.Run.Run(ctx, []string{"/sbin/shutdown", "-r", "now"}, nil)
		},
	},

	// Generate a user's mail_crypt EC keypair, password-protected by
	// the supplied key (the Dovecot subkey of the user's mail root
	// key, never the root itself). The key is written to a 0600 temp
	// config and passed via doveadm -c so it never appears in argv.
	// The curve setting is set only in that temp config so mail_crypt
	// never auto-generates keys for non-opted-in users.
	//
	// Dialect (2.4 vs 2.3) is picked by checking which mail_crypt conf
	// file setup wrote, not by re-running `dovecot --version` here -
	// setup already made that call once; this just reads its answer.
	// See setup/components/defs/dovecot.py:_mailcrypt for the source
	// of truth this mirrors.
	"mailcrypt.keygen": {
		timeout: 60 * time.Second,
		args:    []string{"email", "key_hex"},
		redact:  map[string]bool{"key_hex": true},
		validate: func(args map[string]string) error {
			if err := validEmailArg(args["email"]); err != nil {
				return err
			}
			return validKeyHex(args["key_hex"])
		},
		execute: func(ctx context.Context, d Deps, args map[string]string) (string, error) {
			tmp, err := os.CreateTemp("", "naust-crypt-*.conf")
			if err != nil {
				return "", err
			}
			defer os.Remove(tmp.Name())
			var conf string
			if _, err := os.Stat(filepath.Join(d.Root, "/etc/dovecot/conf.d/96-mail-crypt.conf")); err == nil {
				// 2.3 dialect: legacy plugin{} block.
				conf = "!include /etc/dovecot/dovecot.conf\n" +
					"plugin {\n" +
					"  mail_crypt_curve = prime256v1\n" +
					"  mail_crypt_private_password = " + args["key_hex"] + "\n" +
					"}\n"
			} else {
				conf = "dovecot_config_version = 2.4.0\n" +
					"!include /etc/dovecot/dovecot.conf\n" +
					"crypt_user_key_curve = prime256v1\n" +
					"crypt_user_key_password = " + args["key_hex"] + "\n"
			}
			if err := tmp.Chmod(0o600); err != nil {
				tmp.Close()
				return "", err
			}
			if _, err := tmp.WriteString(conf); err != nil {
				tmp.Close()
				return "", err
			}
			if err := tmp.Close(); err != nil {
				return "", err
			}
			return d.Run.Run(ctx, []string{"/usr/bin/doveadm", "-c", tmp.Name(),
				"mailbox", "cryptokey", "generate", "-u", args["email"], "-U"}, nil)
		},
	},
}

// validEmailArg rejects anything that could not be a mail address or
// would break the doveadm invocation or the temp config.
func validEmailArg(email string) error {
	if len(email) == 0 || len(email) > 254 {
		return fmt.Errorf("email length invalid")
	}
	at := 0
	for _, r := range email {
		if r > unicode.MaxASCII || unicode.IsControl(r) || unicode.IsSpace(r) {
			return fmt.Errorf("email contains invalid character")
		}
		if r == '@' {
			at++
		}
	}
	if at != 1 || email[0] == '@' || email[len(email)-1] == '@' {
		return fmt.Errorf("email is not a plausible address")
	}
	return nil
}

// validKeyHex requires exactly 64 hex characters (a 32-byte key).
func validKeyHex(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("key_hex must be 64 hex characters")
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return fmt.Errorf("key_hex must be 64 hex characters")
		}
	}
	return nil
}

func serviceIntent(action string) intentDef {
	return intentDef{
		timeout: 90 * time.Second,
		args:    []string{"service"},
		validate: func(args map[string]string) error {
			if _, ok := services[args["service"]]; !ok {
				return fmt.Errorf("service %q not in allowlist", args["service"])
			}
			return nil
		},
		execute: func(ctx context.Context, d Deps, args map[string]string) (string, error) {
			name := args["service"]
			def := services[name]
			if action == "reload" && def.reload != nil {
				var err error
				for _, argv := range def.reload {
					if _, err = d.Run.Run(ctx, argv, nil); err != nil {
						break
					}
				}
				if err != nil && def.reloadFallback != nil {
					_, err = d.Run.Run(ctx, def.reloadFallback, nil)
				}
				return "", err
			}
			_, err := d.Run.Run(ctx, []string{"/usr/bin/systemctl", action, name}, nil)
			return "", err
		},
	}
}

// Dispatch validates a request against the menu and executes it. This is
// the single entry point the server uses.
func Dispatch(ctx context.Context, d Deps, req Request) (string, error) {
	def, ok := Intents[req.Intent]
	if !ok {
		return "", fmt.Errorf("unknown intent %q", req.Intent)
	}
	if err := checkArgNames(def.args, req.Args); err != nil {
		return "", err
	}
	if def.validate != nil {
		if err := def.validate(req.Args); err != nil {
			return "", err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, def.timeout)
	defer cancel()
	return def.execute(ctx, d, req.Args)
}

// checkArgNames enforces that exactly the declared args are present -
// unknown extras are rejected, missing ones too.
func checkArgNames(want []string, got map[string]string) error {
	if len(got) != len(want) {
		return argMismatch(want, got)
	}
	for _, name := range want {
		if _, ok := got[name]; !ok {
			return argMismatch(want, got)
		}
	}
	return nil
}

func argMismatch(want []string, got map[string]string) error {
	names := make([]string, 0, len(got))
	for k := range got {
		names = append(names, k)
	}
	sort.Strings(names)
	return fmt.Errorf("args %v do not match required %v", names, want)
}

// validValue rejects control characters (newlines in a postconf value
// would break main.cf parsing) and oversized values.
func validValue(v string) error {
	if len(v) > maxValueLen {
		return fmt.Errorf("value exceeds %d bytes", maxValueLen)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return fmt.Errorf("value contains control character")
		}
	}
	return nil
}

// writeFileAtomic writes content to a temp file in the target directory,
// then renames it into place so readers never see a partial file.
func writeFileAtomic(path string, content []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".helper-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
