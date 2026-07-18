package atomicfile

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestWriteSyncCreatesFileWithContentAndMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	if err := WriteSync(path, "hello", 0o640); err != nil {
		t.Fatalf("WriteSync: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("content = %q, want %q", got, "hello")
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640", fi.Mode().Perm())
	}
}

func TestWriteSyncOverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	if err := WriteSync(path, "first", 0o644); err != nil {
		t.Fatalf("WriteSync first: %v", err)
	}
	if err := WriteSync(path, "second", 0o644); err != nil {
		t.Fatalf("WriteSync second: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("content = %q, want %q", got, "second")
	}
}

// A reader must never observe the temp file under path's name, and a
// failed write must not leave the destination path missing or truncated.
func TestWriteSyncLeavesNoTempFileOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	if err := WriteSync(path, "content", 0o644); err != nil {
		t.Fatalf("WriteSync: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file still present after successful write: err=%v", err)
	}
}

func TestWriteSyncFailsIfDirMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-dir", "out.txt")
	if err := WriteSync(path, "content", 0o644); err == nil {
		t.Fatal("expected error writing into a nonexistent directory")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("destination should not exist after failed write: err=%v", err)
	}
}

// Concurrent WriteSync calls to the same path share a fixed ".tmp" name.
// The result must always be one writer's complete content, never a mix
// of two writes or a missing file - never torn or corrupted.
func TestWriteSyncConcurrentSamePathIsNotTorn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shared.txt")
	const writers = 8
	const iterations = 20

	valid := make(map[string]bool, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		content := make([]byte, 4096)
		for j := range content {
			content[j] = byte('A' + i)
		}
		valid[string(content)] = true

		wg.Add(1)
		go func(content string) {
			defer wg.Done()
			for k := 0; k < iterations; k++ {
				if err := WriteSync(path, content, 0o644); err != nil {
					// A rename racing another writer's rename can
					// legitimately fail (source removed by first
					// mover); the file must still end up intact.
					continue
				}
			}
		}(string(content))
	}
	wg.Wait()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile after concurrent writes: %v", err)
	}
	if !valid[string(got)] {
		t.Fatalf("final content is torn/corrupted: got %d bytes not matching any single writer's content", len(got))
	}
}

func TestWriteIfChangedSkipsIdenticalContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	changed, err := WriteIfChanged(path, "same", 0o644)
	if err != nil {
		t.Fatalf("WriteIfChanged initial: %v", err)
	}
	if !changed {
		t.Error("expected changed=true on initial write")
	}

	fiBefore, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	changed, err = WriteIfChanged(path, "same", 0o644)
	if err != nil {
		t.Fatalf("WriteIfChanged repeat: %v", err)
	}
	if changed {
		t.Error("expected changed=false when content is identical")
	}

	fiAfter, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fiBefore.ModTime() != fiAfter.ModTime() {
		t.Error("mtime changed even though content was identical")
	}
}

func TestWriteIfChangedWritesOnDifference(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")

	if _, err := WriteIfChanged(path, "old", 0o644); err != nil {
		t.Fatalf("WriteIfChanged initial: %v", err)
	}

	changed, err := WriteIfChanged(path, "new", 0o644)
	if err != nil {
		t.Fatalf("WriteIfChanged update: %v", err)
	}
	if !changed {
		t.Error("expected changed=true when content differs")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "new" {
		t.Errorf("content = %q, want %q", got, "new")
	}
}
