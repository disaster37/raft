package storage

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	hraft "github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"

	"github.com/disaster37/raft/config"
	"github.com/disaster37/raft/internal/fileutil"
)

// Backend bundles the Raft log, stable, and snapshot stores.
type Backend interface {
	LogStore() hraft.LogStore
	StableStore() hraft.StableStore
	SnapshotStore() hraft.SnapshotStore
	BoltDB() *bolt.DB
	IsRemovedFlag() (bool, error)
	SetRemovedFlag() error
	Close() error
}

// OpenBackend opens the configured storage backend.
func OpenBackend(dir, nodeID string, cfg config.StorageConfig, snapRetain int, cacheSize int, logOutput io.Writer) (Backend, error) {
	switch cfg.Backend {
	case config.StorageBackendInmem:
		return NewInmemBackend(), nil
	case config.StorageBackendSharedBolt:
		return NewSharedBoltStore(dir, nodeID, cfg, snapRetain, cacheSize, logOutput)
	case config.StorageBackendRaftBoltDB, "":
		return NewBoltStore(dir, cfg, snapRetain, cacheSize, logOutput)
	default:
		return nil, fmt.Errorf("unsupported storage backend %q", cfg.Backend)
	}
}

// InmemBackend is an in-memory Backend for tests.
type InmemBackend struct {
	logs    hraft.LogStore
	stable  hraft.StableStore
	snaps   hraft.SnapshotStore
	mu      sync.Mutex
	removed bool
}

// NewInmemBackend returns an in-memory backend.
func NewInmemBackend() Backend {
	store := hraft.NewInmemStore()
	return &InmemBackend{
		logs:   store,
		stable: store,
		snaps:  hraft.NewInmemSnapshotStore(),
	}
}

// LogStore implements Backend.
func (b *InmemBackend) LogStore() hraft.LogStore { return b.logs }

// StableStore implements Backend.
func (b *InmemBackend) StableStore() hraft.StableStore { return b.stable }

// SnapshotStore implements Backend.
func (b *InmemBackend) SnapshotStore() hraft.SnapshotStore { return b.snaps }

// BoltDB implements Backend.
func (b *InmemBackend) BoltDB() *bolt.DB { return nil }

// IsRemovedFlag implements Backend.
func (b *InmemBackend) IsRemovedFlag() (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.removed, nil
}

// SetRemovedFlag implements Backend.
func (b *InmemBackend) SetRemovedFlag() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.removed = true
	return nil
}

// Close implements Backend.
func (b *InmemBackend) Close() error { return nil }

// ClearRaftState removes persisted Raft state from dir. It returns true when
// at least one path was removed.
func ClearRaftState(dir, nodeID string) (bool, error) {
	if dir == "" {
		return false, fmt.Errorf("clear raft state: empty dir")
	}
	cleared := false
	paths := []string{
		filepath.Join(dir, "raft.db"),
		filepath.Join(dir, "peers.json"),
	}
	if nodeID != "" {
		paths = append(paths, filepath.Join(dir, fmt.Sprintf("%s.db", nodeID)))
	}
	for _, p := range paths {
		if err := os.Remove(p); err == nil {
			cleared = true
		} else if !os.IsNotExist(err) {
			return cleared, fmt.Errorf("remove %s: %w", p, err)
		}
	}
	snapDir := filepath.Join(dir, "snapshots")
	if err := os.RemoveAll(snapDir); err == nil {
		cleared = true
	} else {
		return cleared, fmt.Errorf("remove snapshots: %w", err)
	}
	return cleared, nil
}

// LoadOrGenerateNodeID returns the stable node ID persisted at <dir>/node-id,
// generating a UUIDv4 on first boot.
func LoadOrGenerateNodeID(dir string) (string, error) {
	if dir == "" {
		return randomUUID()
	}
	path := filepath.Join(dir, "node-id")
	//nolint:gosec // path is a fixed node-id file under the data dir
	if b, err := os.ReadFile(path); err == nil {
		id := strings.TrimSpace(string(b))
		if id != "" {
			return id, nil
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("read node-id: %w", err)
	}
	id, err := randomUUID()
	if err != nil {
		return "", err
	}
	if err := fileutil.WriteFile0600(path, []byte(id)); err != nil {
		return "", err
	}
	return id, nil
}

func randomUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate node id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	), nil
}
