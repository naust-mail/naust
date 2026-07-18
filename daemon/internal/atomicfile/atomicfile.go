// Package atomicfile writes files so that readers never observe a
// partial one: content goes to a temp name, is fsynced, and is renamed
// into place. Used by every materializer that generates files other
// services read (mail maps, zone files, opendkim tables).
package atomicfile

import (
	"io/fs"
	"os"
)

// WriteSync writes content to path via a temp file, fsyncing before
// the rename so a crash or power loss can never install a truncated
// file.
func WriteSync(path, content string, mode fs.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// WriteIfChanged is WriteSync unless the file already holds exactly
// content; reports whether a write happened. Skipping preserves the
// mtime, which matters for readers that reload on mtime (Dovecot).
func WriteIfChanged(path, content string, mode fs.FileMode) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && string(old) == content {
		return false, nil
	}
	if err := WriteSync(path, content, mode); err != nil {
		return false, err
	}
	return true, nil
}
