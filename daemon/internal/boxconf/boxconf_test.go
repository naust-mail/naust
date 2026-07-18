package boxconf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	// Every writer's style in one file: wizard single quotes (with an
	// embedded quote), bare values, comments, duplicates, junk.
	conf := `# written by boxctl
PRIMARY_HOSTNAME='box.example.com'
WEBMAIL_CLIENT='rav'
STORAGE_ROOT=/home/user-data
PUBLIC_IP=1.2.3.4 extra ignored
QUOTED='it'\''s fine'
DOUBLE="dq value"
WEBMAIL_CLIENT='shadowed by first occurrence'
NOT A CONF LINE
EMPTY=
`
	path := filepath.Join(t.TempDir(), "naust.conf")
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	for k, want := range map[string]string{
		"PRIMARY_HOSTNAME": "box.example.com",
		"WEBMAIL_CLIENT":   "rav", // first occurrence wins
		"STORAGE_ROOT":     "/home/user-data",
		"PUBLIC_IP":        "1.2.3.4", // bare value cut at whitespace
		"QUOTED":           "it's fine",
		"DOUBLE":           "dq value",
		"EMPTY":            "",
	} {
		if got := c.Get(k); got != want {
			t.Errorf("Get(%s) = %q, want %q", k, got, want)
		}
	}
	if got := c.Get("MISSING"); got != "" {
		t.Errorf("Get(MISSING) = %q", got)
	}
}

func TestLoadMissingFile(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.conf"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if got := c.Get("ANYTHING"); got != "" {
		t.Errorf("empty conf Get = %q", got)
	}
}

func TestEnvPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "naust.conf")
	if err := os.WriteFile(path, []byte("BOXCONF_TEST_KEY='from file'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Get("BOXCONF_TEST_KEY"); got != "from file" {
		t.Errorf("without env: %q", got)
	}
	t.Setenv("BOXCONF_TEST_KEY", "from env")
	if got := c.Get("BOXCONF_TEST_KEY"); got != "from env" {
		t.Errorf("env should win: %q", got)
	}
}
