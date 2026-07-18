package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fakeRunner records every argv and returns scripted errors.
type fakeRunner struct {
	calls [][]string
	env   [][]string
	// failOn maps argv[0] basename to an error to return.
	failOn map[string]error
}

func (f *fakeRunner) Run(_ context.Context, argv []string, extraEnv []string) (string, error) {
	f.calls = append(f.calls, argv)
	f.env = append(f.env, extraEnv)
	if err, ok := f.failOn[filepath.Base(argv[0])]; ok {
		return "", err
	}
	return "fake output", nil
}

func dispatch(t *testing.T, d Deps, intent string, args map[string]string) error {
	t.Helper()
	_, err := Dispatch(context.Background(), d, Request{Intent: intent, Args: args})
	return err
}

func TestValidationRejections(t *testing.T) {
	run := &fakeRunner{}
	d := Deps{Run: run, Root: t.TempDir()}

	cases := []struct {
		name   string
		intent string
		args   map[string]string
		want   string
	}{
		{"unknown intent", "shell.exec", map[string]string{"cmd": "id"}, "unknown intent"},
		{"unlisted service", "service.restart", map[string]string{"service": "sshd"}, "not in allowlist"},
		{"missing arg", "service.restart", map[string]string{}, "do not match"},
		{"extra arg", "service.restart", map[string]string{"service": "nginx", "path": "/etc"}, "do not match"},
		{"unlisted postfix key", "postfix.set", map[string]string{"key": "inet_interfaces", "value": "all"}, "not in allowlist"},
		{"newline in value", "postfix.set", map[string]string{"key": "relayhost", "value": "a\nb"}, "control character"},
		{"oversized value", "postfix.set", map[string]string{"key": "relayhost", "value": strings.Repeat("x", 2000)}, "exceeds"},
		{"removed map intent", "postfix.map", map[string]string{"map": "sasl_passwd", "content": "x"}, "unknown intent"},
		{"unlisted config target", "config.write", map[string]string{"target": "sudoers", "content": "x"}, "not in allowlist"},
		{"oversized content", "config.write", map[string]string{"target": "nginx_local", "content": strings.Repeat("x", maxContentLen+1)}, "exceeds"},
		{"args on no-arg intent", "host.reboot", map[string]string{"force": "1"}, "do not match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := dispatch(t, d, tc.intent, tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
	if len(run.calls) != 0 {
		t.Fatalf("validation failures must not execute anything; ran %v", run.calls)
	}
}

func TestServiceLifecycle(t *testing.T) {
	run := &fakeRunner{}
	d := Deps{Run: run}

	for _, action := range []string{"restart", "reload", "stop", "disable"} {
		if err := dispatch(t, d, "service."+action, map[string]string{"service": "nginx"}); err != nil {
			t.Fatalf("service.%s: %v", action, err)
		}
	}
	want := [][]string{
		{"/usr/bin/systemctl", "restart", "nginx"},
		{"/usr/bin/systemctl", "reload", "nginx"},
		{"/usr/bin/systemctl", "stop", "nginx"},
		{"/usr/bin/systemctl", "disable", "nginx"},
	}
	if !reflect.DeepEqual(run.calls, want) {
		t.Fatalf("got %v, want %v", run.calls, want)
	}
}

func TestNsdCustomReloadSequence(t *testing.T) {
	run := &fakeRunner{}
	d := Deps{Run: run}

	if err := dispatch(t, d, "service.reload", map[string]string{"service": "nsd"}); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"/usr/sbin/nsd-control", "reconfig"},
		{"/usr/sbin/nsd-control", "reload"},
	}
	if !reflect.DeepEqual(run.calls, want) {
		t.Fatalf("got %v, want %v", run.calls, want)
	}
}

func TestNsdReloadFallsBackToRestart(t *testing.T) {
	run := &fakeRunner{failOn: map[string]error{"nsd-control": errors.New("boom")}}
	d := Deps{Run: run}

	if err := dispatch(t, d, "service.reload", map[string]string{"service": "nsd"}); err != nil {
		t.Fatalf("fallback should succeed, got %v", err)
	}
	last := run.calls[len(run.calls)-1]
	want := []string{"/usr/bin/systemctl", "restart", "nsd"}
	if !reflect.DeepEqual(last, want) {
		t.Fatalf("last call %v, want fallback %v", last, want)
	}
}

func TestPostfixSet(t *testing.T) {
	run := &fakeRunner{}
	d := Deps{Run: run}

	if err := dispatch(t, d, "postfix.set", map[string]string{"key": "relayhost", "value": "[smtp.example.com]:587"}); err != nil {
		t.Fatal(err)
	}
	// Empty value must be allowed - disabling the relay sets relayhost=.
	if err := dispatch(t, d, "postfix.set", map[string]string{"key": "relayhost", "value": ""}); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"/usr/sbin/postconf", "-e", "relayhost=[smtp.example.com]:587"},
		{"/usr/sbin/postconf", "-e", "relayhost="},
	}
	if !reflect.DeepEqual(run.calls, want) {
		t.Fatalf("got %v, want %v", run.calls, want)
	}
}

func TestPostfixQueueReturnsOutput(t *testing.T) {
	run := &fakeRunner{}
	d := Deps{Run: run}

	out, err := Dispatch(context.Background(), d, Request{Intent: "postfix.queue"})
	if err != nil {
		t.Fatal(err)
	}
	// The queue listing must reach the caller - it is the whole point.
	if out != "fake output" {
		t.Fatalf("queue output = %q", out)
	}
	want := [][]string{{"/usr/sbin/postqueue", "-j"}}
	if !reflect.DeepEqual(run.calls, want) {
		t.Fatalf("got %v, want %v", run.calls, want)
	}
	// No-arg intent: extra args are rejected before execution.
	if err := dispatch(t, d, "postfix.queue", map[string]string{"flush": "1"}); err == nil {
		t.Fatal("args on postfix.queue must be rejected")
	}
}

func TestConfigWriteAtomicWithMode(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc/nginx/conf.d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	d := Deps{Run: &fakeRunner{}, Root: root}

	content := "server { listen 127.0.0.1:8080; }\n"
	if err := dispatch(t, d, "config.write", map[string]string{"target": "nginx_local", "content": content}); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "local.conf")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Fatalf("content mismatch: %q", got)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v, want 0644", fi.Mode().Perm())
	}
	// No temp files left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("stray files in %s: %v", dir, entries)
	}
}

func TestHostIntentsUseExactArgv(t *testing.T) {
	run := &fakeRunner{}
	d := Deps{Run: run}

	for _, intent := range []string{"host.apt_update", "host.apt_upgrade", "host.reboot"} {
		if err := dispatch(t, d, intent, nil); err != nil {
			t.Fatalf("%s: %v", intent, err)
		}
	}
	want := [][]string{
		{"/usr/bin/apt-get", "-qq", "update"},
		{"/usr/bin/apt-get", "-y", "upgrade"},
		{"/sbin/shutdown", "-r", "now"},
	}
	if !reflect.DeepEqual(run.calls, want) {
		t.Fatalf("got %v, want %v", run.calls, want)
	}
	if !reflect.DeepEqual(run.env[1], []string{"DEBIAN_FRONTEND=noninteractive"}) {
		t.Fatalf("apt_upgrade env %v, want noninteractive", run.env[1])
	}
}

func TestHostAptReturnsCommandOutput(t *testing.T) {
	d := Deps{Run: &fakeRunner{}}
	out, err := Dispatch(context.Background(), d, Request{Intent: "host.apt_upgrade"})
	if err != nil {
		t.Fatal(err)
	}
	if out != "fake output" {
		t.Fatalf("apt output must reach the caller, got %q", out)
	}
	// Non-host intents keep their output out of the response.
	out, err = Dispatch(context.Background(), d, Request{Intent: "service.reload", Args: map[string]string{"service": "nginx"}})
	if err != nil {
		t.Fatal(err)
	}
	if out != "" {
		t.Fatalf("service intents must not leak command output, got %q", out)
	}
}

func TestMailcryptKeygen(t *testing.T) {
	// The runner reads the temp config while it exists so the test can
	// verify content, mode, and that the key never appears in argv.
	var confContent string
	var confMode os.FileMode
	run := &confReadingRunner{onRun: func(argv []string) {
		if len(argv) >= 3 && argv[1] == "-c" {
			if b, err := os.ReadFile(argv[2]); err == nil {
				confContent = string(b)
			}
			if fi, err := os.Stat(argv[2]); err == nil {
				confMode = fi.Mode().Perm()
			}
		}
	}}
	d := Deps{Run: run}
	keyHex := strings.Repeat("ab", 32)

	if err := dispatch(t, d, "mailcrypt.keygen", map[string]string{
		"email": "user@example.com", "key_hex": keyHex,
	}); err != nil {
		t.Fatal(err)
	}
	if len(run.calls) != 1 {
		t.Fatalf("calls = %v", run.calls)
	}
	argv := run.calls[0]
	if argv[0] != "/usr/bin/doveadm" || argv[1] != "-c" {
		t.Fatalf("argv = %v", argv)
	}
	want := []string{"mailbox", "cryptokey", "generate", "-u", "user@example.com", "-U"}
	if !reflect.DeepEqual(argv[3:], want) {
		t.Fatalf("argv tail = %v", argv[3:])
	}
	for _, a := range argv {
		if strings.Contains(a, keyHex) {
			t.Fatal("key material leaked into argv")
		}
	}
	if !strings.Contains(confContent, "crypt_user_key_password = "+keyHex+"\n") ||
		!strings.Contains(confContent, "crypt_user_key_curve = prime256v1") ||
		!strings.Contains(confContent, "!include /etc/dovecot/dovecot.conf") {
		t.Errorf("temp conf = %q", confContent)
	}
	if confMode != 0o600 {
		t.Errorf("temp conf mode = %o", confMode)
	}
	if _, err := os.Stat(argv[2]); !os.IsNotExist(err) {
		t.Errorf("temp conf not removed: %v", err)
	}

	// Redaction: the audit line must never show the key.
	line := redactedArgs("mailcrypt.keygen", map[string]string{"email": "user@example.com", "key_hex": keyHex})
	if strings.Contains(line, keyHex) || !strings.Contains(line, "[redacted]") {
		t.Errorf("audit line leaks key: %s", line)
	}

	// Validation rejections.
	bad := []map[string]string{
		{"email": "no-at-sign", "key_hex": keyHex},
		{"email": "a b@example.com", "key_hex": keyHex},
		{"email": "user@example.com", "key_hex": "short"},
		{"email": "user@example.com", "key_hex": strings.Repeat("zz", 32)},
	}
	for _, args := range bad {
		if err := dispatch(t, d, "mailcrypt.keygen", args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
	if len(run.calls) != 1 {
		t.Fatalf("validation failures executed: %v", run.calls)
	}
}

// TestMailcryptKeygen23 covers the 2.3 dialect branch: same command, same
// safety properties (temp conf, redaction, cleanup), different setting
// names and no dovecot_config_version line. Dialect is picked by the
// presence of 96-mail-crypt.conf under d.Root, mirroring what
// setup/components/defs/dovecot.py:_mailcrypt writes for a 2.3 install.
func TestMailcryptKeygen23(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/dovecot/conf.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/dovecot/conf.d/96-mail-crypt.conf"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	var confContent string
	run := &confReadingRunner{onRun: func(argv []string) {
		if len(argv) >= 3 && argv[1] == "-c" {
			if b, err := os.ReadFile(argv[2]); err == nil {
				confContent = string(b)
			}
		}
	}}
	d := Deps{Run: run, Root: root}
	keyHex := strings.Repeat("cd", 32)

	if err := dispatch(t, d, "mailcrypt.keygen", map[string]string{
		"email": "user@example.com", "key_hex": keyHex,
	}); err != nil {
		t.Fatal(err)
	}
	if len(run.calls) != 1 {
		t.Fatalf("calls = %v", run.calls)
	}
	argv := run.calls[0]
	want := []string{"mailbox", "cryptokey", "generate", "-u", "user@example.com", "-U"}
	if !reflect.DeepEqual(argv[3:], want) {
		t.Fatalf("argv tail = %v", argv[3:])
	}
	for _, a := range argv {
		if strings.Contains(a, keyHex) {
			t.Fatal("key material leaked into argv")
		}
	}
	if !strings.Contains(confContent, "mail_crypt_private_password = "+keyHex+"\n") ||
		!strings.Contains(confContent, "mail_crypt_curve = prime256v1") ||
		!strings.Contains(confContent, "!include /etc/dovecot/dovecot.conf") ||
		strings.Contains(confContent, "dovecot_config_version") ||
		strings.Contains(confContent, "crypt_user_key_curve") {
		t.Errorf("temp conf = %q", confContent)
	}
	if _, err := os.Stat(argv[2]); !os.IsNotExist(err) {
		t.Errorf("temp conf not removed: %v", err)
	}
}

// confReadingRunner lets a test observe side effects that exist only
// while the command "runs" (the mailcrypt temp config).
type confReadingRunner struct {
	calls [][]string
	onRun func(argv []string)
}

func (f *confReadingRunner) Run(_ context.Context, argv []string, _ []string) (string, error) {
	f.calls = append(f.calls, argv)
	if f.onRun != nil {
		f.onRun(argv)
	}
	return "", nil
}
