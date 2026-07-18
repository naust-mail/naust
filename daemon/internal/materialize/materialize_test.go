package materialize

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"naust/daemon/internal/store"
	"naust/daemon/internal/store/ent"
)

func TestRenderPrecedence(t *testing.T) {
	snap := Snapshot{
		Users: []UserRow{
			{Email: "bob@example.com", PasswordHash: "{BLF-CRYPT}x", QuotaBytes: 1 << 30},
			{Email: "carol@example.com", PasswordHash: "{BLF-CRYPT}y"},
		},
		Aliases: []AliasRow{
			// Forwards a real user's mail elsewhere: must beat bob's self-entry.
			{Source: "bob@example.com", Destinations: []string{"external@other.net"}},
			// Catch-all.
			{Source: "@example.com", Destinations: []string{"carol@example.com"}},
			// Permitted-senders-only: claims sender-login, not delivery.
			{Source: "noreply@example.com", PermittedSenders: []string{"carol@example.com"}},
			// Group alias without explicit senders: destinations may send.
			{Source: "sales@example.com", Destinations: []string{"bob@example.com", "carol@example.com"}},
		},
	}

	aliasMaps := RenderAliasMaps(snap)
	for _, want := range []string{
		"bob@example.com external@other.net\n",
		"carol@example.com carol@example.com\n",
		"@example.com carol@example.com\n",
		"sales@example.com bob@example.com,carol@example.com\n",
	} {
		if !strings.Contains(aliasMaps, want) {
			t.Errorf("alias maps missing %q; got:\n%s", want, aliasMaps)
		}
	}
	if strings.Contains(aliasMaps, "noreply@") {
		t.Error("permitted-senders-only alias must not claim delivery")
	}

	senderLogin := RenderSenderLoginMaps(snap)
	for _, want := range []string{
		"noreply@example.com carol@example.com\n",
		"sales@example.com bob@example.com,carol@example.com\n",
		"carol@example.com carol@example.com\n",
		// Alias over bob's address beats his self-entry here too.
		"bob@example.com external@other.net\n",
	} {
		if !strings.Contains(senderLogin, want) {
			t.Errorf("sender-login missing %q; got:\n%s", want, senderLogin)
		}
	}

	domains := RenderMailboxDomains(snap)
	if domains != "example.com 1\n" {
		t.Errorf("domains = %q", domains)
	}

	mailboxes := RenderMailboxMaps(snap)
	if strings.Contains(mailboxes, "sales@") || !strings.Contains(mailboxes, "bob@example.com 1\n") {
		t.Errorf("mailbox maps = %q", mailboxes)
	}
}

func TestRenderDovecotUsers(t *testing.T) {
	snap := Snapshot{Users: []UserRow{
		{Email: "bob@example.com", PasswordHash: "{BLF-CRYPT}$2b$hash", QuotaBytes: 1 << 30},
		{Email: "ann@example.com", PasswordHash: "{BLF-CRYPT}$2b$other"},
		{Email: "eve@example.com", PasswordHash: "{BLF-CRYPT}$2b$third", QuotaBytes: 1 << 20, MailCrypt: true},
		{Email: "dan@example.com", PasswordHash: "{BLF-CRYPT}$2b$fourth", MailCrypt: true},
	}}
	got := RenderDovecotUsers(snap, "/home/user-data")
	want := "ann@example.com:{BLF-CRYPT}$2b$other:mail:mail::/home/user-data/mail/mailboxes/example.com/ann::\n" +
		"bob@example.com:{BLF-CRYPT}$2b$hash:mail:mail::/home/user-data/mail/mailboxes/example.com/bob::userdb_quota_storage_size=1073741824\n" +
		"dan@example.com:{BLF-CRYPT}$2b$fourth:mail:mail::/home/user-data/mail/mailboxes/example.com/dan::userdb_crypt_user_key_curve=prime256v1\n" +
		"eve@example.com:{BLF-CRYPT}$2b$third:mail:mail::/home/user-data/mail/mailboxes/example.com/eve::userdb_quota_storage_size=1048576 userdb_crypt_user_key_curve=prime256v1\n"
	if got != want {
		t.Errorf("dovecot users:\ngot:  %q\nwant: %q", got, want)
	}
}

type fakeRunner struct {
	mu    sync.Mutex
	calls [][]string
}

func (f *fakeRunner) Run(_ context.Context, argv []string) error {
	f.mu.Lock()
	f.calls = append(f.calls, argv)
	f.mu.Unlock()
	// Behave like postmap: compile <source> into <source>.db.
	src := strings.TrimPrefix(argv[len(argv)-1], "hash:")
	return os.WriteFile(src+".db", []byte("compiled"), 0o640)
}

func (f *fakeRunner) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func testTenantID(t *testing.T, client *ent.Client) int {
	t.Helper()
	tenant, err := store.EnsureDefaultTenant(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	return tenant.ID
}

func newTestMaterializer(t *testing.T) (*Materializer, *fakeRunner, *ent.Client) {
	t.Helper()
	client, err := store.Open(store.EngineSQLite, filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if err := client.Schema.Create(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	m := &Materializer{
		Store:       client,
		Dir:         filepath.Join(t.TempDir(), "maps"),
		StorageRoot: "/home/user-data",
		Run:         runner,
		Log:         log.New(os.Stderr, "", 0),
	}
	return m, runner, client
}

func TestRebuildWritesAndSkipsUnchanged(t *testing.T) {
	m, runner, client := newTestMaterializer(t)
	ctx := context.Background()
	client.User.Create().SetEmail("bob@example.com").SetPasswordHash("{BLF-CRYPT}x").SetTenantID(testTenantID(t, client)).SaveX(ctx)

	if err := m.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	// All four postfix maps compiled on first build.
	if runner.count() != 4 {
		t.Fatalf("postmap calls = %d, want 4", runner.count())
	}
	content, err := os.ReadFile(filepath.Join(m.Dir, "virtual-mailbox-maps"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "bob@example.com 1\n" {
		t.Errorf("mailbox map = %q", content)
	}

	// Nothing changed: second rebuild must not rewrite or recompile.
	if err := m.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	if runner.count() != 4 {
		t.Errorf("postmap calls after no-op rebuild = %d, want still 4", runner.count())
	}

	// An alias change recompiles only the maps it affects (domains
	// content is unchanged: same domain).
	client.Alias.Create().SetSource("sales@example.com").SetDestinations([]string{"bob@example.com"}).SetTenantID(testTenantID(t, client)).SaveX(ctx)
	if err := m.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	if runner.count() != 6 {
		t.Errorf("postmap calls = %d, want 6 (alias-maps + sender-login only)", runner.count())
	}
}

func TestRebuildMarksMailCryptUsers(t *testing.T) {
	m, _, client := newTestMaterializer(t)
	ctx := context.Background()
	tenant := testTenantID(t, client)
	bob := client.User.Create().SetEmail("bob@example.com").SetPasswordHash("{BLF-CRYPT}x").SetTenantID(tenant).SaveX(ctx)
	ann := client.User.Create().SetEmail("ann@example.com").SetPasswordHash("{BLF-CRYPT}y").SetTenantID(tenant).SaveX(ctx)

	// Only a password-type slot marks an account encrypted; a stray
	// recovery slot alone (mid-enrollment state) must not.
	client.MailKeySlot.Create().SetSlotType("password").SetVersion(1).
		SetWrappedKey([]byte("w")).SetNonce([]byte("n")).SetKdfSalt([]byte("s")).
		SetUser(bob).SaveX(ctx)
	client.MailKeySlot.Create().SetSlotType("recovery_code").SetLabel("0").SetVersion(1).
		SetWrappedKey([]byte("w")).SetNonce([]byte("n")).SetKdfSalt([]byte("s")).
		SetUser(ann).SaveX(ctx)

	if err := m.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(m.Dir, dovecotUsersFile))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("dovecot-users lines = %d, want 2:\n%s", len(lines), content)
	}
	for _, line := range lines {
		hasCurve := strings.Contains(line, "userdb_crypt_user_key_curve=prime256v1")
		if strings.HasPrefix(line, "bob@") && !hasCurve {
			t.Errorf("bob has a password slot but no curve field: %q", line)
		}
		if strings.HasPrefix(line, "ann@") && hasCurve {
			t.Errorf("ann must not get the curve field: %q", line)
		}
	}
}

func TestRebuildAtomicSwapAndMissingDB(t *testing.T) {
	m, runner, client := newTestMaterializer(t)
	ctx := context.Background()
	client.User.Create().SetEmail("bob@example.com").SetPasswordHash("{BLF-CRYPT}x").SetTenantID(testTenantID(t, client)).SaveX(ctx)

	if err := m.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	// The compiled map Postfix reads must exist under its final name,
	// with no scratch files left behind.
	if _, err := os.Stat(filepath.Join(m.Dir, "virtual-mailbox-maps.db")); err != nil {
		t.Fatal(err)
	}
	for _, leftover := range []string{"virtual-mailbox-maps.new", "virtual-mailbox-maps.new.db"} {
		if _, err := os.Stat(filepath.Join(m.Dir, leftover)); err == nil {
			t.Errorf("scratch file %s left behind", leftover)
		}
	}

	// A vanished .db must be recompiled even though the text matches.
	if err := os.Remove(filepath.Join(m.Dir, "virtual-mailbox-maps.db")); err != nil {
		t.Fatal(err)
	}
	before := runner.count()
	if err := m.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	if runner.count() != before+1 {
		t.Errorf("postmap calls = %d, want %d (recompile the missing .db only)", runner.count(), before+1)
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "virtual-mailbox-maps.db")); err != nil {
		t.Error("missing .db was not recompiled")
	}
}

func TestKickCoalescesAndRebuilds(t *testing.T) {
	m, _, client := newTestMaterializer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.User.Create().SetEmail("bob@example.com").SetPasswordHash("{BLF-CRYPT}x").SetTenantID(testTenantID(t, client)).SaveX(ctx)

	m.Start(ctx)
	for range 50 {
		m.Kick() // burst must never block
	}

	deadline := time.Now().Add(5 * time.Second)
	target := filepath.Join(m.Dir, dovecotUsersFile)
	for {
		if content, err := os.ReadFile(target); err == nil && strings.Contains(string(content), "bob@example.com") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("rebuild did not produce dovecot-users within deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// flakyRunner fails every command while fail is set, otherwise
// behaves like the normal fake postmap.
type flakyRunner struct {
	fakeRunner
	fail bool
}

func (f *flakyRunner) Run(ctx context.Context, argv []string) error {
	if f.fail {
		return errors.New("postmap: permission denied")
	}
	return f.fakeRunner.Run(ctx, argv)
}

// Regression for the 2026-07-10 box outage: a permissions change made
// postmap fail inside managerd, and the failure must never replace the
// live maps with partial output - Postfix keeps serving the last good
// tables and Rebuild reports the error. Once postmap works again the
// next rebuild converges without manual repair.
func TestRebuildPostmapFailureKeepsLiveMaps(t *testing.T) {
	m, _, client := newTestMaterializer(t)
	runner := &flakyRunner{}
	m.Run = runner
	ctx := context.Background()
	client.User.Create().SetEmail("bob@example.com").SetPasswordHash("{BLF-CRYPT}x").
		SetTenantID(testTenantID(t, client)).SaveX(ctx)
	if err := m.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(m.Dir, "virtual-mailbox-maps"))
	if err != nil {
		t.Fatal(err)
	}

	runner.fail = true
	client.User.Create().SetEmail("eve@example.com").SetPasswordHash("{BLF-CRYPT}y").
		SetTenantID(testTenantID(t, client)).SaveX(ctx)
	if err := m.Rebuild(ctx); err == nil {
		t.Fatal("Rebuild succeeded although postmap failed")
	}
	after, err := os.ReadFile(filepath.Join(m.Dir, "virtual-mailbox-maps"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("live map changed under a failing postmap:\nbefore: %q\nafter:  %q", before, after)
	}

	runner.fail = false
	if err := m.Rebuild(ctx); err != nil {
		t.Fatalf("rebuild after recovery: %v", err)
	}
	healed, err := os.ReadFile(filepath.Join(m.Dir, "virtual-mailbox-maps"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(healed), "eve@example.com") {
		t.Errorf("recovered map missing the new user:\n%s", healed)
	}
}
