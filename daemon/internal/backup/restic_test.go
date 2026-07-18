package backup

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeRun records invocations and replies from a script keyed by the
// first matching substring of the argv line.
type fakeRun struct {
	calls   []string
	envs    [][]string
	replies map[string]struct {
		out string
		err error
	}
}

func (f *fakeRun) run(_ context.Context, extraEnv []string, argv ...string) (string, error) {
	line := strings.Join(argv, " ")
	f.calls = append(f.calls, line)
	f.envs = append(f.envs, extraEnv)
	for key, rep := range f.replies {
		if strings.Contains(line, key) {
			return rep.out, rep.err
		}
	}
	return "", nil
}

func (f *fakeRun) reply(key, out string, err error) {
	if f.replies == nil {
		f.replies = map[string]struct {
			out string
			err error
		}{}
	}
	f.replies[key] = struct {
		out string
		err error
	}{out, err}
}

func newRestic(target Target, run Runner) *Restic {
	return &Restic{ToolEnv: ToolEnv{
		StorageRoot: "/data",
		Config:      Config{Target: target, KeepWithinDays: 3, CheckAfterBackup: true},
		Passphrase:  "sekrit",
		SSHKeyPath:  "/data/backup/ssh/id_rsa",
		Run:         run,
	}}
}

func TestResticRepoStrings(t *testing.T) {
	cases := []struct {
		target Target
		want   string
	}{
		{Target{Type: "local"}, "/data/backup/restic-repo"},
		{Target{Type: "rsync", Host: "backup.example.net", User: "u", Path: "/srv/backups"},
			"sftp:u@backup.example.net:/srv/backups"},
		{Target{Type: "s3", Endpoint: "s3.eu-central-1.amazonaws.com", Bucket: "bkt/boxes",
			AccessKey: "AK", SecretKey: "SK"},
			"s3:https://s3.eu-central-1.amazonaws.com/bkt/boxes"},
		{Target{Type: "b2", Bucket: "bkt", KeyID: "K", AppKey: "A"}, "b2:bkt:"},
	}
	for _, c := range cases {
		r := newRestic(c.target, nil)
		got, err := r.repo()
		if err != nil || got != c.want {
			t.Errorf("repo(%s) = %q, %v; want %q", c.target.Type, got, err, c.want)
		}
	}
	if _, err := newRestic(Target{Type: "off"}, nil).repo(); err == nil {
		t.Error("off target must not build a repo")
	}
}

func TestResticEnvAndArgs(t *testing.T) {
	f := &fakeRun{}
	r := newRestic(Target{Type: "s3", Endpoint: "e", Bucket: "b", Region: "eu-central-1",
		AccessKey: "AK", SecretKey: "SK"}, f.run)
	if _, err := r.run(context.Background(), "snapshots", "--json"); err != nil {
		t.Fatal(err)
	}
	env := strings.Join(f.envs[0], " ")
	for _, want := range []string{"RESTIC_PASSWORD=sekrit", "AWS_ACCESS_KEY_ID=AK",
		"AWS_SECRET_ACCESS_KEY=SK", "AWS_DEFAULT_REGION=eu-central-1"} {
		if !strings.Contains(env, want) {
			t.Errorf("env missing %s: %s", want, env)
		}
	}
	if !strings.Contains(f.calls[0], "--cache-dir /data/backup/restic-cache") {
		t.Errorf("cache dir missing: %s", f.calls[0])
	}

	f = &fakeRun{}
	r = newRestic(Target{Type: "rsync", Host: "h.net", User: "u", Path: "/p", Port: 2222}, f.run)
	if _, err := r.run(context.Background(), "unlock"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.calls[0], "sftp.command=ssh -i /data/backup/ssh/id_rsa -p 2222") {
		t.Errorf("sftp command missing: %s", f.calls[0])
	}
}

func TestResticPrepare(t *testing.T) {
	// Existing repo: unlock, no init.
	f := &fakeRun{}
	f.reply("snapshots --json", "[]", nil)
	r := newRestic(Target{Type: "local"}, f.run)
	if err := r.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.calls, "\n")
	if !strings.Contains(joined, "unlock") || strings.Contains(joined, "init") {
		t.Errorf("calls = %v", f.calls)
	}

	// First run: init.
	f = &fakeRun{}
	f.reply("snapshots --json", "Fatal: unable to open config file: <config/> does not exist\nIs there a repository at the following location?", errors.New("exit 1"))
	r = newRestic(Target{Type: "local"}, f.run)
	if err := r.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.calls, "\n"), "init") {
		t.Errorf("calls = %v", f.calls)
	}

	// Any other failure (wrong password, network) must NOT init.
	f = &fakeRun{}
	f.reply("snapshots --json", "Fatal: wrong password", errors.New("exit 1"))
	r = newRestic(Target{Type: "local"}, f.run)
	if err := r.Prepare(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "not usable") {
		t.Errorf("err = %v (calls %v)", err, f.calls)
	}
}

func TestResticBackupParsesSummary(t *testing.T) {
	f := &fakeRun{}
	f.reply(" backup ", `{"message_type":"status","percent_done":1}
{"message_type":"summary","snapshot_id":"abcdef1234567890","data_added":1024,"total_bytes_processed":4096,"total_files_processed":42}`, nil)
	r := newRestic(Target{Type: "local"}, f.run)
	stats, err := r.Backup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.SnapshotID != "abcdef1234567890" || stats.Size != 4096 ||
		stats.DataAdded != 1024 || stats.FileCount != 42 {
		t.Errorf("stats = %+v", stats)
	}
	call := f.calls[0]
	for _, want := range []string{"--exclude /data/backup", "--exclude /data/owncloud-backup", " /data"} {
		if !strings.Contains(call, want) {
			t.Errorf("backup argv missing %q: %s", want, call)
		}
	}
}

func TestResticPruneLockRetry(t *testing.T) {
	f := &fakeRun{}
	locked := true
	f.reply("forget", "", nil) // overridden below via custom runner
	run := func(ctx context.Context, env []string, argv ...string) (string, error) {
		line := strings.Join(argv, " ")
		f.calls = append(f.calls, line)
		if strings.Contains(line, "forget") && locked {
			return "repo already locked by PID 1", errors.New("exit 1")
		}
		if strings.Contains(line, "unlock") {
			locked = false
		}
		return "", nil
	}
	r := newRestic(Target{Type: "local"}, run)
	if err := r.Prune(context.Background()); err != nil {
		t.Fatalf("prune with lock retry = %v (calls %v)", err, f.calls)
	}
	joined := strings.Join(f.calls, "\n")
	if !strings.Contains(joined, "unlock") || strings.Count(joined, "forget --keep-within 3d --prune") != 2 {
		t.Errorf("calls = %v", f.calls)
	}

	// Non-lock failure: no retry, error out.
	f2 := &fakeRun{}
	f2.reply("forget", "Fatal: out of space", errors.New("exit 1"))
	r = newRestic(Target{Type: "local"}, f2.run)
	if err := r.Prune(context.Background()); err == nil {
		t.Error("prune failure swallowed")
	}
	if len(f2.calls) != 1 {
		t.Errorf("unexpected retry: %v", f2.calls)
	}
}

func TestResticSnapshots(t *testing.T) {
	f := &fakeRun{}
	f.reply("snapshots --json", `[
	 {"short_id":"aabbccdd","time":"2026-07-08T01:14:00Z","summary":{"total_bytes_processed":4096,"data_added":100,"total_files_processed":7}},
	 {"short_id":"11223344","time":"2026-07-07T01:14:00Z"}
	]`, nil)
	r := newRestic(Target{Type: "local"}, f.run)
	snaps, err := r.Snapshots(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 2 || snaps[0].ID != "aabbccdd" || snaps[0].Size != 4096 || !snaps[0].Full {
		t.Errorf("snaps = %+v", snaps)
	}
	if snaps[1].Size != 0 {
		t.Errorf("snap without summary = %+v", snaps[1])
	}
}

func TestConfigValidate(t *testing.T) {
	good := []Config{
		DefaultConfig(),
		{Target: Target{Type: "off"}, KeepWithinDays: 3},
		{Target: Target{Type: "rsync", Host: "h", User: "u", Path: "/p"}, KeepWithinDays: 30},
		{Target: Target{Type: "s3", Endpoint: "e", Bucket: "b", AccessKey: "a", SecretKey: "s"}, KeepWithinDays: 3},
		{Target: Target{Type: "b2", Bucket: "b", KeyID: "k", AppKey: "a"}, KeepWithinDays: 3},
	}
	for i, c := range good {
		if err := c.Validate(); err != nil {
			t.Errorf("good[%d]: %v", i, err)
		}
	}
	bad := []Config{
		{Target: Target{Type: "tape"}, KeepWithinDays: 3},
		{Target: Target{Type: "rsync", Host: "h"}, KeepWithinDays: 3},
		{Target: Target{Type: "s3", Endpoint: "e", Bucket: "b"}, KeepWithinDays: 3},
		{Target: Target{Type: "local"}, KeepWithinDays: 0},
		{Target: Target{Type: "rsync", Host: "h\nx", User: "u", Path: "/p"}, KeepWithinDays: 3},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("bad[%d] accepted: %+v", i, c)
		}
	}
	redacted := Config{Target: Target{Type: "s3", Endpoint: "e", Bucket: "b", AccessKey: "a", SecretKey: "s"}}.Redacted()
	if redacted.Target.SecretKey != "" || redacted.Target.AccessKey != "a" {
		t.Errorf("redacted = %+v", redacted.Target)
	}
}
