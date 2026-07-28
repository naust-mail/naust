package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"naust/daemon/internal/webrender"
)

// The web.sync_sites intent: the manager sends the routing MODEL (the
// webrender.Config plus the resolved hosts), never rendered nginx. helperd
// renders it here, on the privileged side, then reconciles ONE fixed
// directory against the result, runs nginx -t, and reloads nginx only if
// the test passes. On test failure every change is rolled back, so disk
// always holds a config nginx can boot from. Files in the directory that
// do not start with webrender.ManagedMark are user-owned (ejected vhosts,
// hand-written config): they are never written or deleted, and the
// response inventories them so the manager can show drift warnings.
//
// Rendering behind the trust boundary is the whole point: nginx's master
// runs as root and its config can escalate (error_log, load_module, an
// access_log to any path), so the manager must never hand us raw config
// text. It supplies only data; webrender.Render - which validates every field -
// turns it into the fixed, safe directive set. See helper-intent-menu.md
// (ownership-vs-intent).

const (
	// sitesDir is the one directory web.sync_sites manages. nginx reads
	// it via an include line installed by setup; callers cannot choose
	// paths (invariant 1).
	sitesDir = "/etc/nginx/naust.d"

	// maxRenderedTotal caps the rendered fileset as a backstop. The
	// request line is already capped at 4MB and the rendered output is
	// bounded by the host count; this guards against a pathological
	// payload rendering to something huge.
	maxRenderedTotal = 3 << 20
)

var (
	siteFileRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*\.conf$`)
	templVersionRE = regexp.MustCompile(`(?m)^# template-version: ([0-9]+)$`)
)

// SkippedFile describes one user-owned file found in the sites
// directory and left untouched.
type SkippedFile struct {
	File string `json:"file"`
	// TemplateVersion is parsed from the file's version stamp: an
	// ejected copy keeps the stamp it was generated with, so the panel
	// can warn when our templates have moved on. 0 means no stamp
	// (fully hand-written file).
	TemplateVersion int `json:"template_version"`
}

// SyncResult is the decoded result of web.sync_sites.
type SyncResult struct {
	Skipped []SkippedFile `json:"skipped,omitempty"`
}

// EncodePayload packs the routing model into intent args. Manager-side
// counterpart of the intent's decoder: the manager sends data, never
// rendered nginx.
func EncodePayload(cfg webrender.Config, hosts []webrender.Host) (map[string]string, error) {
	buf, err := json.Marshal(webrender.SyncPayload{Config: cfg, Hosts: hosts})
	if err != nil {
		return nil, err
	}
	return map[string]string{"payload": string(buf)}, nil
}

// DecodeSyncResult parses the intent's result string.
func DecodeSyncResult(result string) (SyncResult, error) {
	var r SyncResult
	err := json.Unmarshal([]byte(result), &r)
	return r, err
}

// renderPayload decodes the routing model and renders it into the
// managed fileset. webrender.Render is the trust boundary: it validates every
// field before emitting a directive, so a hostile payload cannot inject
// nginx config. Rendered filenames and total size are checked as a
// backstop even though Render produces them from validated domains.
func renderPayload(arg string) (map[string]string, error) {
	var p webrender.SyncPayload
	if err := json.Unmarshal([]byte(arg), &p); err != nil {
		return nil, fmt.Errorf("payload is not a valid sync payload")
	}
	files, err := webrender.Render(p.Config, p.Hosts)
	if err != nil {
		return nil, err
	}
	total := 0
	for name, content := range files {
		if len(name) > 128 || !siteFileRE.MatchString(name) {
			return nil, fmt.Errorf("rendered unsafe filename %q", name)
		}
		total += len(content)
	}
	if total > maxRenderedTotal {
		return nil, fmt.Errorf("rendered fileset exceeds %d bytes", maxRenderedTotal)
	}
	return files, nil
}

var webSyncIntent = intentDef{
	timeout: 90 * time.Second,
	args:    []string{"payload"},
	validate: func(args map[string]string) error {
		_, err := renderPayload(args["payload"])
		return err
	},
	execute: execWebSync,
}

func execWebSync(ctx context.Context, d Deps, args map[string]string) (string, error) {
	files, err := renderPayload(args["payload"])
	if err != nil {
		return "", err
	}
	return reconcile(ctx, d, files)
}

// reconcile applies a rendered fileset to sitesDir: managed files are
// written, updated, or deleted; user-owned files are inventoried and
// left untouched; nginx -t gates the reload; and any failure rolls disk
// back to the pre-sync managed state.
func reconcile(ctx context.Context, d Deps, files map[string]string) (string, error) {
	dir := filepath.Join(d.Root, sitesDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	// Classify what is on disk: managed files (ours, snapshotted for
	// rollback) vs foreign files (user-owned, inventoried, untouched).
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	prior := map[string]string{}
	foreign := map[string]bool{}
	var skipped []SkippedFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(string(content), webrender.ManagedMark) {
			prior[e.Name()] = string(content)
		} else {
			foreign[e.Name()] = true
			skipped = append(skipped, SkippedFile{File: e.Name(), TemplateVersion: stampOf(string(content))})
		}
	}
	sort.Slice(skipped, func(i, j int) bool { return skipped[i].File < skipped[j].File })

	// rollback restores the pre-sync managed state: prior content back
	// in place, files we created removed. Foreign files were never
	// touched. The running nginx still has the old config loaded, so
	// after rollback disk and process agree again.
	rollback := func() {
		for name := range files {
			if foreign[name] {
				continue
			}
			p := filepath.Join(dir, name)
			if old, ok := prior[name]; ok {
				writeFileAtomic(p, []byte(old), 0o644)
			} else {
				os.Remove(p)
			}
		}
		for name, old := range prior {
			if _, incoming := files[name]; !incoming {
				writeFileAtomic(filepath.Join(dir, name), []byte(old), 0o644)
			}
		}
	}

	// Write the new set; names owned by a foreign file are skipped (the
	// eject flow: the user's copy wins until they delete it).
	changed := false
	for name, content := range files {
		if foreign[name] || prior[name] == content {
			continue
		}
		changed = true
		if err := writeFileAtomic(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			rollback()
			return "", err
		}
	}
	// Delete managed files not in the set.
	for name := range prior {
		if _, keep := files[name]; !keep {
			changed = true
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				rollback()
				return "", err
			}
		}
	}
	// An identical fileset is a no-op: sync is idempotent, so callers
	// may kick liberally without churning nginx.
	if !changed {
		result, err := json.Marshal(SyncResult{Skipped: skipped})
		if err != nil {
			return "", err
		}
		return string(result), nil
	}

	// Gate on nginx -t before touching the running process.
	if _, err := d.Run.Run(ctx, []string{"/usr/sbin/nginx", "-t"}, nil); err != nil {
		rollback()
		return "", fmt.Errorf("nginx -t failed, changes rolled back: %w", err)
	}
	if _, err := d.Run.Run(ctx, []string{"/usr/bin/systemctl", "reload", "nginx"}, nil); err != nil {
		// The config on disk is valid; nginx reads it on next start.
		// Surface the failure, keep the files.
		return "", fmt.Errorf("config synced but nginx reload failed: %w", err)
	}

	result, err := json.Marshal(SyncResult{Skipped: skipped})
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func stampOf(content string) int {
	m := templVersionRE.FindStringSubmatch(content)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}
