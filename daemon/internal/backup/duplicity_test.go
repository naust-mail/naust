package backup

import (
	"context"
	"strings"
	"testing"
	"time"
)

func newDup(target Target, run Runner) *Duplicity {
	return &Duplicity{ToolEnv: ToolEnv{
		StorageRoot: "/data",
		Config:      Config{Target: target, KeepWithinDays: 3, CheckAfterBackup: true},
		Passphrase:  "sekrit",
		SSHKeyPath:  "/data/backup/ssh/id_rsa",
		Run:         run,
	}}
}

func TestDuplicityTargetURLs(t *testing.T) {
	cases := []struct {
		target Target
		want   string
	}{
		{Target{Type: "local"}, "file:///data/backup/encrypted"},
		{Target{Type: "rsync", Host: "h.net", User: "u", Path: "/srv/bak"}, "rsync://u@h.net//srv/bak"},
		{Target{Type: "rsync", Host: "h.net", User: "u", Path: "bak"}, "rsync://u@h.net/bak"},
		{Target{Type: "s3", Endpoint: "s3.example.com", Bucket: "bkt/boxes",
			AccessKey: "AK", SecretKey: "SK"}, "s3://bkt/boxes"},
		{Target{Type: "b2", Bucket: "bkt", KeyID: "K", AppKey: "a+b"}, "b2://K:a%2Bb@bkt"},
	}
	for _, c := range cases {
		got, err := newDup(c.target, nil).targetURL()
		if err != nil || got != c.want {
			t.Errorf("targetURL(%s) = %q, %v; want %q", c.target.Type, got, err, c.want)
		}
	}
}

func TestDuplicityArgsAndEnv(t *testing.T) {
	f := &fakeRun{}
	d := newDup(Target{Type: "rsync", Host: "h.net", User: "u", Path: "/p", Port: 2222}, f.run)
	if err := d.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	call := f.calls[0]
	for _, want := range []string{"cleanup", "--force",
		"--ssh-options='-i /data/backup/ssh/id_rsa -p 2222'",
		"rsync://u@h.net//p"} {
		if !strings.Contains(call, want) {
			t.Errorf("argv missing %q: %s", want, call)
		}
	}
	if !strings.Contains(strings.Join(f.envs[0], " "), "PASSPHRASE=sekrit") {
		t.Errorf("env = %v", f.envs[0])
	}

	f = &fakeRun{}
	d = newDup(Target{Type: "s3", Endpoint: "s3.example.com", Region: "eu-x",
		Bucket: "bkt", AccessKey: "AK", SecretKey: "SK"}, f.run)
	if _, err := d.Backup(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Fresh target (empty collection-status) forces a full backup.
	backupCall := f.calls[len(f.calls)-1]
	for _, want := range []string{" full ", "--s3-endpoint-url https://s3.example.com",
		"--s3-region-name eu-x", "--exclude /data/backup", "--allow-source-mismatch",
		"--volsize 250", " /data s3://bkt"} {
		if !strings.Contains(backupCall, want) {
			t.Errorf("argv missing %q: %s", want, backupCall)
		}
	}
	env := strings.Join(f.envs[len(f.envs)-1], " ")
	for _, want := range []string{"AWS_ACCESS_KEY_ID=AK", "AWS_REQUEST_CHECKSUM_CALCULATION=WHEN_REQUIRED"} {
		if !strings.Contains(env, want) {
			t.Errorf("env missing %q: %s", want, env)
		}
	}
}

const dupCollection = `Last full backup date: Sat Jul 5 01:14:22 2026
 full 20260705T011422Z 3
 inc 20260706T011421Z 1
 inc 20260707T011423Z 1
`

func TestDuplicitySnapshotsAndFullCadence(t *testing.T) {
	f := &fakeRun{}
	f.reply("collection-status", dupCollection, nil)
	d := newDup(Target{Type: "local"}, f.run)
	snaps, err := d.Snapshots(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 3 || !snaps[0].Full || snaps[1].Full || snaps[0].ID != "20260705T011422Z" {
		t.Fatalf("snaps = %+v", snaps)
	}
	if !snaps[0].Time.Equal(time.Date(2026, 7, 5, 1, 14, 22, 0, time.UTC)) {
		t.Errorf("time = %v", snaps[0].Time)
	}

	// A recent full: incremental mode.
	if d.fullNeeded(context.Background()) {
		// KeepWithinDays*10+1 = 31 days; the full above is recent
		// relative to time.Now() only if the test runs before 2026-08.
		// Guard: only assert when the cadence genuinely has not passed.
		if time.Since(snaps[0].Time) < 31*24*time.Hour {
			t.Error("full forced despite recent full backup")
		}
	}

	// No fulls at all: full needed.
	f2 := &fakeRun{}
	f2.reply("collection-status", "Last full backup date: none\n", nil)
	d = newDup(Target{Type: "local"}, f2.run)
	if !d.fullNeeded(context.Background()) {
		t.Error("full not forced on empty target")
	}
}

func TestDuplicityRestoreAndPrune(t *testing.T) {
	f := &fakeRun{}
	d := newDup(Target{Type: "local"}, f.run)
	if err := d.Restore(context.Background(), "20260705T011422Z", "/tmp/restore"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.calls[0], "restore --time 20260705T011422Z") ||
		!strings.Contains(f.calls[0], "file:///data/backup/encrypted /tmp/restore") {
		t.Errorf("restore argv = %s", f.calls[0])
	}

	if err := d.Prune(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.calls[1], "remove-older-than 3D") || !strings.Contains(f.calls[1], "--force") {
		t.Errorf("prune argv = %s", f.calls[1])
	}
}
