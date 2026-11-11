// Package fileutil provides small filesystem helpers shared by the raft
// packages. All helpers enforce restrictive permissions suitable for private
// keys and Raft state.
package fileutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// EnsureDir0700 creates dir (and parents) with 0700 permissions and tightens
// an existing directory. A permission error while chmod-ing an existing
// directory (for example a mounted PVC owned by another UID) is tolerated
// because the files written inside are still created with 0600.
func EnsureDir0700(dir string) error {
	if dir == "" {
		return fmt.Errorf("ensure dir: empty path")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	//nolint:gosec // directory permissions are intentionally 0700
	if err := os.Chmod(dir, 0o700); err != nil && !errors.Is(err, os.ErrPermission) { // #nosec G302
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	return nil
}

// WriteFile0600 writes data to path with 0600 permissions, creating parent
// directories with 0700 permissions.
func WriteFile0600(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("write file: empty path")
	}
	if err := EnsureDir0700(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil && !errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

// AtomicWriteFile0600 writes data to a temporary file in the same directory
// and renames it into place, so readers never observe a partially written
// file.
func AtomicWriteFile0600(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("atomic write: empty path")
	}
	dir := filepath.Dir(path)
	if err := EnsureDir0700(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}
