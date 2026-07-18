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
)

// The web.sync_sites intent: the manager sends the complete set of
// generated nginx site files; the helper reconciles ONE fixed directory
// against it, runs nginx -t, and reloads nginx only if the test passes.
// On test failure every change is rolled back, so disk always holds a
// config nginx can boot from. Files in the directory that do not start
// with ManagedMark are user-owned (ejected vhosts, hand-written config):
// they are never written or deleted, and the response inventories them
// so the manager can show drift warnings.
//
// Per the ownership-vs-intent rule this stays a helper intent forever:
// nginx's master runs as root and its config can escalate (error_log,
// load_module), so the manager may never own these files.

const (
	// sitesDir is the one directory web.sync_sites manages. nginx reads
	// it via an include line installed by setup; callers cannot choose
	// paths (invariant 1).
	sitesDir = "/etc/nginx/naust.d"

	// ManagedMark must be the first line of every synced file - it is
	// what separates our files from user-owned ones. Duplicated from
	// internal/web so helperd keeps zero non-stdlib dependencies; a test
	// in internal/web asserts the two constants stay identical.
	ManagedMark = "# MANAGED BY naust-web - do not edit; regenerated on every apply."

	// maxSyncTotal caps the whole fileset; the request line itself is
	// capped at 4MB, this leaves room for JSON escaping.
	maxSyncTotal = 3 << 20
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

// EncodeSyncArgs packs a rendered fileset (filename -> content) into
// intent args. Manager-side counterpart of the intent's decoder.
func EncodeSyncArgs(files map[string]string) (map[string]string, error) {
	buf, err := json.Marshal(files)
	if err != nil {
		return nil, err
	}
	return map[string]string{"files": string(buf)}, nil
}

// DecodeSyncResult parses the intent's result string.
func DecodeSyncResult(result string) (SyncResult, error) {
	var r SyncResult
	err := json.Unmarshal([]byte(result), &r)
	return r, err
}

func decodeSyncFiles(arg string) (map[string]string, error) {
	var files map[string]string
	if err := json.Unmarshal([]byte(arg), &files); err != nil {
		return nil, fmt.Errorf("files arg is not a JSON object of strings")
	}
	total := 0
	for name, content := range files {
		if len(name) > 128 || !siteFileRE.MatchString(name) {
			return nil, fmt.Errorf("unsafe site filename %q", name)
		}
		if len(content) > maxContentLen {
			return nil, fmt.Errorf("%s exceeds %d bytes", name, maxContentLen)
		}
		// Requiring the mark on input keeps reconciliation sound: every
		// file we write is one we may later overwrite or delete.
		if !strings.HasPrefix(content, ManagedMark+"\n") {
			return nil, fmt.Errorf("%s does not start with the managed mark", name)
		}
		total += len(content)
	}
	if total > maxSyncTotal {
		return nil, fmt.Errorf("fileset exceeds %d bytes", maxSyncTotal)
	}
	return files, nil
}

var webSyncIntent = intentDef{
	timeout: 90 * time.Second,
	args:    []string{"files"},
	validate: func(args map[string]string) error {
		_, err := decodeSyncFiles(args["files"])
		return err
	},
	execute: execWebSync,
}

func execWebSync(ctx context.Context, d Deps, args map[string]string) (string, error) {
	files, err := decodeSyncFiles(args["files"])
	if err != nil {
		return "", err
	}
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
		if strings.HasPrefix(string(content), ManagedMark) {
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
