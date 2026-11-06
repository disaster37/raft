package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	hraft "github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	bolt "go.etcd.io/bbolt"

	"github.com/disaster37/raft/config"
)

const (
	logsBucketName    = "logs"
	stableBucketName  = "stable"
	fsmDataBucketName = "fsm_data"
	sysBucketName     = "_sys"
)

// SharedBoltStore stores logs, stable data, FSM data, and system state in a
// single bbolt file at <dir>/<nodeID>.db.
type SharedBoltStore struct {
	db            *bolt.DB
	logCache      *hraft.LogCache
	snapshotStore hraft.SnapshotStore
	path          string
}

var _ Backend = (*SharedBoltStore)(nil)

// NewSharedBoltStore opens the shared single-file bbolt backend.
func NewSharedBoltStore(dir, nodeID string, cfg config.StorageConfig, snapRetain, cacheSize int, logOutput io.Writer) (*SharedBoltStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if nodeID == "" {
		nodeID = "raft"
	}
	path := filepath.Join(dir, fmt.Sprintf("%s.db", nodeID))
	opts := defaultBoltOptions(cfg).BoltOptions
	db, err := bolt.Open(path, 0o600, opts)
	if err != nil {
		return nil, fmt.Errorf("open shared bolt db: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil && !os.IsPermission(err) {
		_ = db.Close()
		return nil, fmt.Errorf("chmod shared bolt db: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{logsBucketName, stableBucketName, fsmDataBucketName, sysBucketName} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	snapStore, err := NewSecureFileSnapshotStore(dir, snapRetain, logOutput)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if cacheSize <= 0 {
		cacheSize = 512
	}
	store := &SharedBoltStore{db: db, snapshotStore: snapStore, path: path}
	cache, err := hraft.NewLogCache(cacheSize, store)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create log cache: %w", err)
	}
	store.logCache = cache
	return store, nil
}

// LogStore returns the cached log store.
func (s *SharedBoltStore) LogStore() hraft.LogStore { return s.logCache }

// StableStore returns the shared stable store.
func (s *SharedBoltStore) StableStore() hraft.StableStore { return s }

// SnapshotStore returns the file snapshot store.
func (s *SharedBoltStore) SnapshotStore() hraft.SnapshotStore { return s.snapshotStore }

// BoltDB returns the underlying bbolt database.
func (s *SharedBoltStore) BoltDB() *bolt.DB { return s.db }

// IsRemovedFlag reports whether the removed flag is set.
func (s *SharedBoltStore) IsRemovedFlag() (bool, error) {
	raw, err := s.Get([]byte(removedKey))
	if err != nil {
		if errors.Is(err, raftboltdb.ErrKeyNotFound) {
			return false, nil
		}
		return false, err
	}
	return len(raw) > 0 && raw[0] == 1, nil
}

// SetRemovedFlag sets the removed flag.
func (s *SharedBoltStore) SetRemovedFlag() error {
	return s.Set([]byte(removedKey), []byte{1})
}

// Close closes the database.
func (s *SharedBoltStore) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// FirstIndex implements hraft.LogStore.
func (s *SharedBoltStore) FirstIndex() (uint64, error) {
	var idx uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(logsBucketName))
		if b == nil {
			return nil
		}
		k, _ := b.Cursor().First()
		if k != nil {
			idx = btoi(k)
		}
		return nil
	})
	return idx, err
}

// LastIndex implements hraft.LogStore.
func (s *SharedBoltStore) LastIndex() (uint64, error) {
	var idx uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(logsBucketName))
		if b == nil {
			return nil
		}
		k, _ := b.Cursor().Last()
		if k != nil {
			idx = btoi(k)
		}
		return nil
	})
	return idx, err
}

// GetLog implements hraft.LogStore.
func (s *SharedBoltStore) GetLog(idx uint64, log *hraft.Log) error {
	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(logsBucketName))
		if b == nil {
			return hraft.ErrLogNotFound
		}
		val := b.Get(itob(idx))
		if val == nil {
			return hraft.ErrLogNotFound
		}
		if err := json.Unmarshal(val, log); err != nil {
			return fmt.Errorf("decode log %d: %w", idx, err)
		}
		return nil
	})
}

// StoreLog implements hraft.LogStore.
func (s *SharedBoltStore) StoreLog(log *hraft.Log) error {
	return s.StoreLogs([]*hraft.Log{log})
}

// StoreLogs implements hraft.LogStore.
func (s *SharedBoltStore) StoreLogs(logs []*hraft.Log) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(logsBucketName))
		if b == nil {
			return fmt.Errorf("logs bucket not found")
		}
		for _, log := range logs {
			val, err := json.Marshal(log)
			if err != nil {
				return fmt.Errorf("encode log %d: %w", log.Index, err)
			}
			if err := b.Put(itob(log.Index), val); err != nil {
				return fmt.Errorf("store log %d: %w", log.Index, err)
			}
		}
		return nil
	})
}

// DeleteRange implements hraft.LogStore.
func (s *SharedBoltStore) DeleteRange(low, high uint64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(logsBucketName))
		if b == nil {
			return nil
		}
		for i := low; i <= high; i++ {
			if err := b.Delete(itob(i)); err != nil {
				return fmt.Errorf("delete log %d: %w", i, err)
			}
		}
		return nil
	})
}

// Set implements hraft.StableStore.
func (s *SharedBoltStore) Set(key, val []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(stableBucketName))
		if b == nil {
			return fmt.Errorf("stable bucket not found")
		}
		return b.Put(key, val)
	})
}

// Get implements hraft.StableStore.
func (s *SharedBoltStore) Get(key []byte) ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(stableBucketName))
		if b == nil {
			return nil
		}
		v := b.Get(key)
		if v != nil {
			out = make([]byte, len(v))
			copy(out, v)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, raftboltdb.ErrKeyNotFound
	}
	return out, nil
}

// SetUint64 implements hraft.StableStore.
func (s *SharedBoltStore) SetUint64(key []byte, val uint64) error {
	return s.Set(key, itob(val))
}

// GetUint64 implements hraft.StableStore.
func (s *SharedBoltStore) GetUint64(key []byte) (uint64, error) {
	val, err := s.Get(key)
	if err != nil {
		return 0, err
	}
	if len(val) != 8 {
		return 0, fmt.Errorf("stable key %q is not a uint64", string(key))
	}
	return btoi(val), nil
}

func itob(v uint64) []byte {
	b := make([]byte, 8)
	b[0] = byte(v >> 56)
	//nolint:gosec // explicit big-endian byte extraction
	b[1] = byte(v >> 48) // #nosec G115
	//nolint:gosec // explicit big-endian byte extraction
	b[2] = byte(v >> 40) // #nosec G115
	//nolint:gosec // explicit big-endian byte extraction
	b[3] = byte(v >> 32) // #nosec G115
	//nolint:gosec // explicit big-endian byte extraction
	b[4] = byte(v >> 24) // #nosec G115
	//nolint:gosec // explicit big-endian byte extraction
	b[5] = byte(v >> 16) // #nosec G115
	//nolint:gosec // explicit big-endian byte extraction
	b[6] = byte(v >> 8) // #nosec G115
	//nolint:gosec // explicit big-endian byte extraction
	b[7] = byte(v) // #nosec G115
	return b
}

func btoi(b []byte) uint64 {
	return uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
}
