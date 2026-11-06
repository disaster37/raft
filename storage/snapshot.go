package storage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	hraft "github.com/hashicorp/raft"
)

// NewSecureFileSnapshotStore creates a file snapshot store and tightens the
// snapshots directory to 0700.
func NewSecureFileSnapshotStore(dir string, retain int, logOutput io.Writer) (hraft.SnapshotStore, error) {
	if retain <= 0 {
		retain = 2
	}
	store, err := hraft.NewFileSnapshotStore(dir, retain, logOutput)
	if err != nil {
		return nil, fmt.Errorf("create file snapshot store: %w", err)
	}
	snapDir := filepath.Join(dir, "snapshots")
	//nolint:gosec // snapshot directory permissions are intentionally 0700
	if err := os.Chmod(snapDir, 0o700); err != nil && !os.IsNotExist(err) { // #nosec G302
		return nil, fmt.Errorf("chmod snapshots dir: %w", err)
	}
	return store, nil
}

// SnapshotDelayStore delays List calls, which is useful for tests that need
// to observe snapshot timing.
type SnapshotDelayStore struct {
	inner hraft.SnapshotStore
	delay time.Duration
}

// NewSnapshotDelayStore wraps inner with a List delay.
func NewSnapshotDelayStore(inner hraft.SnapshotStore, delay time.Duration) *SnapshotDelayStore {
	return &SnapshotDelayStore{inner: inner, delay: delay}
}

// List implements hraft.SnapshotStore.
func (s *SnapshotDelayStore) List() ([]*hraft.SnapshotMeta, error) {
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	return s.inner.List()
}

// Open implements hraft.SnapshotStore.
func (s *SnapshotDelayStore) Open(id string) (*hraft.SnapshotMeta, io.ReadCloser, error) {
	return s.inner.Open(id)
}

// Create implements hraft.SnapshotStore.
func (s *SnapshotDelayStore) Create(version hraft.SnapshotVersion, index, term uint64, configuration hraft.Configuration, configurationIndex uint64, trans hraft.Transport) (hraft.SnapshotSink, error) {
	return s.inner.Create(version, index, term, configuration, configurationIndex, trans)
}
