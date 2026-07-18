package materialize

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"os/user"
	"strconv"

	"naust/daemon/internal/atomicfile"
	"naust/daemon/internal/kickloop"
	"naust/daemon/internal/store"
	"naust/daemon/internal/store/ent"
	entslot "naust/daemon/internal/store/ent/mailkeyslot"
	enttenant "naust/daemon/internal/store/ent/tenant"
	entuser "naust/daemon/internal/store/ent/user"
)

// Runner executes postmap. Tests substitute a fake.
type Runner interface {
	Run(ctx context.Context, argv []string) error
}

// ExecRunner runs commands for real.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, argv []string) error {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", argv[0], err, out)
	}
	return nil
}

// Materializer rebuilds the map files from the store. Rebuilds are
// requested with Kick and coalesced: a burst of changes while a rebuild
// runs results in exactly one follow-up rebuild, so heavy API churn
// costs one file rewrite, not one per change.
type Materializer struct {
	Store *ent.Client
	// Dir receives the five map files.
	Dir string
	// StorageRoot anchors Dovecot home paths (mail/mailboxes/...).
	StorageRoot string
	// Hostname is the box's primary FQDN; system mail routing (system.go)
	// injects its role addresses. Empty adds no hostname entries.
	Hostname string
	Run      Runner
	Log      *log.Logger
	// RetryAfter delays the automatic retry when a rebuild fails
	// (transient postmap/disk errors self-heal without waiting for the
	// next mutation). Zero means 30 seconds.
	RetryAfter time.Duration

	loop kickloop.Loop
}

// Postfix map basenames within Dir. Postfix's main.cf references these
// as proxy:hash:<Dir>/<name> once the Go manager cutover rewires it.
var postfixMaps = map[string]func(Snapshot) string{
	"virtual-mailbox-domains": RenderMailboxDomains,
	"virtual-mailbox-maps":    RenderMailboxMaps,
	"virtual-alias-maps":      RenderAliasMaps,
	"sender-login-maps":       RenderSenderLoginMaps,
}

const dovecotUsersFile = "dovecot-users"

// Rebuild renders all files once. Files whose content is unchanged are
// left untouched (no rewrite, no postmap, no mtime bump - Dovecot only
// re-parses when something really changed).
func (m *Materializer) Rebuild(ctx context.Context) error {
	snap, err := m.load(ctx)
	if err != nil {
		return fmt.Errorf("load snapshot: %w", err)
	}
	snap = ApplySystemRouting(snap, m.Hostname)
	// 0755: Postfix's proxymap (user postfix) and Dovecot's auth process
	// (user dovecot) both traverse this directory on their own.
	if err := os.MkdirAll(m.Dir, 0o755); err != nil {
		return err
	}

	for name, render := range postfixMaps {
		if err := m.rebuildPostfixMap(ctx, name, render(snap)); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}

	dovecot := RenderDovecotUsers(snap, m.StorageRoot)
	usersPath := filepath.Join(m.Dir, dovecotUsersFile)
	if _, err := atomicfile.WriteIfChanged(usersPath, dovecot, 0o640); err != nil {
		return fmt.Errorf("%s: %w", dovecotUsersFile, err)
	}
	m.ensureDovecotGroup(usersPath)
	return nil
}

// ensureDovecotGroup hands the passwd-file's group to dovecot so its
// auth process can read password hashes that must not be world-readable.
// Works because the daemon's user is a member of the dovecot group; on
// hosts without one (tests, Docker builds) there is nothing to do.
func (m *Materializer) ensureDovecotGroup(path string) {
	g, err := user.LookupGroup("dovecot")
	if err != nil {
		return
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return
	}
	if err := os.Chown(path, -1, gid); err != nil {
		m.Log.Printf("materialize: cannot set dovecot group on %s: %v", path, err)
	}
}

// rebuildPostfixMap updates one map so that Postfix's view (the
// compiled .db) is replaced atomically: postmap compiles under a
// scratch name and the finished .db is renamed into place. Readers see
// the old complete map or the new complete map, never a partial one.
func (m *Materializer) rebuildPostfixMap(ctx context.Context, name, content string) error {
	path := filepath.Join(m.Dir, name)
	// Unchanged text with an existing .db means nothing to do. The .db
	// existence check matters: without it a deleted .db would never be
	// recompiled because the text still matches.
	if old, err := os.ReadFile(path); err == nil && string(old) == content {
		if _, err := os.Stat(path + ".db"); err == nil {
			return nil
		}
	}
	// 0644: postmap copies the source file's mode onto the .db, and
	// Postfix's proxymap reads it as the postfix user. These maps hold
	// routing data (domains, addresses), not secrets - the password
	// hashes live in the dovecot-users file, which stays group-scoped.
	scratch := path + ".new"
	if err := atomicfile.WriteSync(scratch, content, 0o644); err != nil {
		return err
	}
	if err := m.Run.Run(ctx, []string{"postmap", "hash:" + scratch}); err != nil {
		return err
	}
	if err := os.Rename(scratch+".db", path+".db"); err != nil {
		return err
	}
	return os.Rename(scratch, path)
}

// Kick requests a rebuild. Never blocks; multiple kicks collapse.
func (m *Materializer) Kick() { m.loop.Kick() }

// Start runs the rebuild loop until ctx is cancelled. Call exactly once.
func (m *Materializer) Start(ctx context.Context) {
	m.loop = kickloop.Loop{Name: "materialize", Do: m.Rebuild, Log: m.Log, RetryAfter: m.RetryAfter, Tick: time.Hour}
	m.loop.Start(ctx)
}

func (m *Materializer) load(ctx context.Context) (Snapshot, error) {
	return loadSnapshot(ctx, m.Store)
}

func loadSnapshot(ctx context.Context, client *ent.Client) (Snapshot, error) {
	var snap Snapshot
	// No column projection here: eager-loading the tenant edge needs the
	// FK column, which Select() would drop.
	users, err := client.User.Query().
		WithTenant().
		All(ctx)
	if err != nil {
		return snap, err
	}
	// A committed password slot is the per-user encryption switch: it
	// exists exactly for accounts that completed mail-crypt enrollment.
	cryptIDs, err := client.MailKeySlot.Query().
		Where(entslot.SlotTypeEQ(entslot.SlotTypePassword)).
		QueryUser().
		IDs(ctx)
	if err != nil {
		return snap, err
	}
	crypt := make(map[int]bool, len(cryptIDs))
	for _, id := range cryptIDs {
		crypt[id] = true
	}
	for _, u := range users {
		tenant, err := u.Edges.TenantOrErr()
		if err != nil {
			return snap, err
		}
		snap.Users = append(snap.Users, UserRow{
			Email:        u.Email,
			PasswordHash: u.PasswordHash,
			QuotaBytes:   u.QuotaBytes,
			MailCrypt:    crypt[u.ID],
			Admin:        u.Role == entuser.RoleAdmin,
			CreatedAt:    u.CreatedAt,
			TenantID:     tenant.ID,
		})
	}
	aliases, err := client.Alias.Query().WithTenant().All(ctx)
	if err != nil {
		return snap, err
	}
	for _, a := range aliases {
		tenant, err := a.Edges.TenantOrErr()
		if err != nil {
			return snap, err
		}
		snap.Aliases = append(snap.Aliases, AliasRow{
			Source:           a.Source,
			Destinations:     a.Destinations,
			PermittedSenders: a.PermittedSenders,
			TenantID:         tenant.ID,
		})
	}
	// The operator tenant anchors hostname routing. Absent only before
	// first store initialization, when there are no rows to route anyway.
	opID, err := client.Tenant.Query().
		Where(enttenant.NameEQ(store.DefaultTenantName)).
		OnlyID(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return snap, err
	}
	snap.OperatorTenant = opID
	return snap, nil
}
