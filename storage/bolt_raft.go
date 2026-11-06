package storage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	hraft "github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	bolt "go.etcd.io/bbolt"

	"github.com/disaster37/raft/config"
)

const removedKey = "removed"

// BoltStore is the raft-boltdb/v2 backend with an in-memory log cache.
type BoltStore struct {
	store         *raftboltdb.BoltStore
	logCache      *hraft.LogCache
	snapshotStore hraft.SnapshotStore
	path          string
}

var _ Backend = (*BoltStore)(nil)

// NewBoltStore opens <dir>/raft.db with Vault-tuned bbolt options.
func NewBoltStore(dir string, cfg config.StorageConfig, snapRetain, cacheSize int, logOutput io.Writer) (*BoltStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	path := filepath.Join(dir, "raft.db")
	opts := defaultBoltOptions(cfg)
	opts.Path = path
	store, err := raftboltdb.New(opts)
	if err != nil {
		return nil, fmt.Errorf("open raft bolt store: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil && !os.IsPermission(err) {
		_ = store.Close()
		return nil, fmt.Errorf("chmod raft.db: %w", err)
	}
	snapStore, err := NewSecureFileSnapshotStore(dir, snapRetain, logOutput)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	if cacheSize <= 0 {
		cacheSize = 512
	}
	cache, err := hraft.NewLogCache(cacheSize, store)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("create log cache: %w", err)
	}
	return &BoltStore{
		store:         store,
		logCache:      cache,
		snapshotStore: snapStore,
		path:          path,
	}, nil
}

func defaultBoltOptions(cfg config.StorageConfig) raftboltdb.Options {
	timeout := cfg.BoltTimeout
	if timeout <= 0 {
		timeout = time.Second
	}
	mmap := cfg.InitialMmapSize
	if mmap <= 0 {
		mmap = 100 * 1024 * 1024
	}
	return raftboltdb.Options{
		BoltOptions: &bolt.Options{
			Timeout:         timeout,
			NoFreelistSync:  cfg.NoFreelistSync,
			FreelistType:    bolt.FreelistMapType,
			InitialMmapSize: mmap,
		},
	}
}

// LogStore returns the cached log store.
func (b *BoltStore) LogStore() hraft.LogStore { return b.logCache }

// StableStore returns the Bolt stable store.
func (b *BoltStore) StableStore() hraft.StableStore { return b.store }

// SnapshotStore returns the file snapshot store.
func (b *BoltStore) SnapshotStore() hraft.SnapshotStore { return b.snapshotStore }

// BoltDB returns nil for the raft-boltdb backend.
func (b *BoltStore) BoltDB() *bolt.DB { return nil }

// IsRemovedFlag reports whether the removed flag is set.
func (b *BoltStore) IsRemovedFlag() (bool, error) {
	raw, err := b.store.Get([]byte(removedKey))
	if err != nil {
		return false, nil
	}
	return len(raw) > 0 && raw[0] == 1, nil
}

// SetRemovedFlag sets the removed flag.
func (b *BoltStore) SetRemovedFlag() error {
	if err := b.store.Set([]byte(removedKey), []byte{1}); err != nil {
		return fmt.Errorf("set removed flag: %w", err)
	}
	return nil
}

// Close closes the Bolt store.
func (b *BoltStore) Close() error {
	if b.store == nil {
		return nil
	}
	return b.store.Close()
}
