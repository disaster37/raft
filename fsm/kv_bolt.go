package fsm

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	hraft "github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
)

const boltFSMBucket = "fsm_data"

// BoltKVFSM is a bbolt-backed transactional KV state machine.
type BoltKVFSM struct {
	db *bolt.DB
}

var _ hraft.FSM = (*BoltKVFSM)(nil)
var _ KVStore = (*BoltKVFSM)(nil)

// NewBoltKVFSM returns a Bolt-backed KV FSM using the fsm_data bucket.
func NewBoltKVFSM(db *bolt.DB) *BoltKVFSM {
	if db != nil {
		_ = db.Update(func(tx *bolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists([]byte(boltFSMBucket))
			return err
		})
	}
	return &BoltKVFSM{db: db}
}

// Apply implements hraft.FSM.
func (f *BoltKVFSM) Apply(log *hraft.Log) interface{} {
	cmd, err := (CommandCodec{}).Decode(log.Data)
	if err != nil {
		return err
	}
	switch cmd.Kind {
	case KindSet, KindSetJSON, KindCreate:
		var entry KVEntry
		if err := json.Unmarshal(cmd.Payload, &entry); err != nil {
			return fmt.Errorf("decode set payload: %w", err)
		}
		if cmd.Kind == KindCreate {
			entry.Create = true
		}
		return f.applyEntries([]KVEntry{entry})
	case KindDelete:
		var entry KVEntry
		if err := json.Unmarshal(cmd.Payload, &entry); err != nil {
			return fmt.Errorf("decode delete payload: %w", err)
		}
		entry.Delete = true
		return f.applyEntries([]KVEntry{entry})
	case KindSetMulti:
		var payload SetMultiPayload
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			return fmt.Errorf("decode set-multi payload: %w", err)
		}
		return f.applyEntries(payload.Entries)
	default:
		return fmt.Errorf("unknown command kind %d", cmd.Kind)
	}
}

func (f *BoltKVFSM) applyEntries(entries []KVEntry) interface{} {
	if f.db == nil {
		return fmt.Errorf("bolt FSM: nil database")
	}
	err := f.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(boltFSMBucket))
		if b == nil {
			return fmt.Errorf("bucket %s not found", boltFSMBucket)
		}
		for _, e := range entries {
			if e.Create && !e.Delete {
				if b.Get(compositeKey(e.Bucket, e.Key)) != nil {
					return fmt.Errorf("%w: %s", ErrConflict, e.Key)
				}
			}
		}
		for _, e := range entries {
			key := compositeKey(e.Bucket, e.Key)
			if e.Delete {
				if err := b.Delete(key); err != nil {
					return fmt.Errorf("delete %s: %w", e.Key, err)
				}
				continue
			}
			if err := b.Put(key, e.Value); err != nil {
				return fmt.Errorf("put %s: %w", e.Key, err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

// Snapshot implements hraft.FSM.
func (f *BoltKVFSM) Snapshot() (hraft.FSMSnapshot, error) {
	data := map[string][]byte{}
	if f.db != nil {
		err := f.db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(boltFSMBucket))
			if b == nil {
				return nil
			}
			return b.ForEach(func(k, v []byte) error {
				value := make([]byte, len(v))
				copy(value, v)
				data[string(k)] = value
				return nil
			})
		})
		if err != nil {
			return nil, fmt.Errorf("snapshot bolt FSM: %w", err)
		}
	}
	return &boltSnapshot{data: data}, nil
}

// Restore implements hraft.FSM.
func (f *BoltKVFSM) Restore(rc io.ReadCloser) error {
	defer func() { _ = rc.Close() }()
	var data map[string][]byte
	if err := json.NewDecoder(rc).Decode(&data); err != nil {
		return fmt.Errorf("decode bolt snapshot: %w", err)
	}
	if f.db == nil {
		return fmt.Errorf("bolt FSM: nil database")
	}
	return f.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(boltFSMBucket))
		if b == nil {
			var err error
			b, err = tx.CreateBucketIfNotExists([]byte(boltFSMBucket))
			if err != nil {
				return fmt.Errorf("create bucket: %w", err)
			}
		}
		keys := make([][]byte, 0)
		if err := b.ForEach(func(k, _ []byte) error {
			keys = append(keys, append([]byte(nil), k...))
			return nil
		}); err != nil {
			return err
		}
		for _, k := range keys {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		for k, v := range data {
			if err := b.Put([]byte(k), v); err != nil {
				return err
			}
		}
		return nil
	})
}

// Get implements KVStore.
func (f *BoltKVFSM) Get(bucket, key string) ([]byte, bool, error) {
	if f.db == nil {
		return nil, false, nil
	}
	var out []byte
	err := f.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(boltFSMBucket))
		if b == nil {
			return nil
		}
		v := b.Get(compositeKey(bucket, key))
		if v != nil {
			out = make([]byte, len(v))
			copy(out, v)
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, out != nil, nil
}

// ListPrefix implements KVStore.
func (f *BoltKVFSM) ListPrefix(bucket, prefix string) (map[string][]byte, error) {
	out := map[string][]byte{}
	if f.db == nil {
		return out, nil
	}
	compositePrefix := compositeKey(bucket, prefix)
	err := f.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(boltFSMBucket))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Seek(compositePrefix); k != nil && strings.HasPrefix(string(k), string(compositePrefix)); k, v = c.Next() {
			value := make([]byte, len(v))
			copy(value, v)
			out[stripBucket(bucket, string(k))] = value
		}
		return nil
	})
	return out, err
}

// HasData implements KVStore.
func (f *BoltKVFSM) HasData() (bool, error) {
	if f.db == nil {
		return false, nil
	}
	has := false
	err := f.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(boltFSMBucket))
		if b == nil {
			return nil
		}
		k, _ := b.Cursor().First()
		has = k != nil
		return nil
	})
	return has, err
}

func compositeKey(bucket, key string) []byte {
	if bucket == "" {
		return []byte(key)
	}
	return []byte(fmt.Sprintf("%s\x00%s", bucket, key))
}

func stripBucket(bucket, composite string) string {
	if bucket == "" {
		return composite
	}
	prefix := fmt.Sprintf("%s\x00", bucket)
	return strings.TrimPrefix(composite, prefix)
}

type boltSnapshot struct {
	data map[string][]byte
}

func (s *boltSnapshot) Persist(sink hraft.SnapshotSink) error {
	if err := json.NewEncoder(sink).Encode(s.data); err != nil {
		_ = sink.Cancel()
		return fmt.Errorf("encode bolt snapshot: %w", err)
	}
	return sink.Close()
}

func (s *boltSnapshot) Release() {}
