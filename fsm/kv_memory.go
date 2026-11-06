package fsm

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	hraft "github.com/hashicorp/raft"
)

const (
	sessionBucket      = "sessions"
	sessionTouchBucket = "sessions_touch"
)

// MemoryKVFSM is an in-memory transactional KV state machine.
type MemoryKVFSM struct {
	mu   sync.RWMutex
	data map[string]map[string][]byte
	sink SessionStateSink
	now  func() time.Time
}

var _ hraft.FSM = (*MemoryKVFSM)(nil)
var _ KVStore = (*MemoryKVFSM)(nil)

// NewMemoryKVFSM returns an empty in-memory KV FSM.
func NewMemoryKVFSM(sink SessionStateSink) *MemoryKVFSM {
	return &MemoryKVFSM{data: map[string]map[string][]byte{}, sink: sink, now: time.Now}
}

// Apply implements hraft.FSM.
func (f *MemoryKVFSM) Apply(log *hraft.Log) interface{} {
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

func (f *MemoryKVFSM) applyEntries(entries []KVEntry) interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range entries {
		if e.Create && !e.Delete {
			if bucket := f.data[e.Bucket]; bucket != nil {
				if _, ok := bucket[e.Key]; ok {
					return fmt.Errorf("%w: %s", ErrConflict, e.Key)
				}
			}
		}
	}
	for _, e := range entries {
		if e.Delete {
			if bucket := f.data[e.Bucket]; bucket != nil {
				delete(bucket, e.Key)
			}
			continue
		}
		bucket := f.data[e.Bucket]
		if bucket == nil {
			bucket = map[string][]byte{}
			f.data[e.Bucket] = bucket
		}
		value := make([]byte, len(e.Value))
		copy(value, e.Value)
		bucket[e.Key] = value
		f.notifySession(e, value)
	}
	return nil
}

func (f *MemoryKVFSM) notifySession(e KVEntry, value []byte) {
	if f.sink == nil {
		return
	}
	switch e.Bucket {
	case sessionBucket:
		f.sink.ApplySessionRegistered(e.Key, json.RawMessage(value), f.now())
	case sessionTouchBucket:
		f.sink.ApplySessionTouched(e.Key, f.now())
	}
}

// Snapshot implements hraft.FSM.
func (f *MemoryKVFSM) Snapshot() (hraft.FSMSnapshot, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	data := make(map[string]map[string][]byte, len(f.data))
	for bucket, entries := range f.data {
		copied := make(map[string][]byte, len(entries))
		for k, v := range entries {
			value := make([]byte, len(v))
			copy(value, v)
			copied[k] = value
		}
		data[bucket] = copied
	}
	return &memorySnapshot{data: data}, nil
}

// Restore implements hraft.FSM.
func (f *MemoryKVFSM) Restore(rc io.ReadCloser) error {
	defer func() { _ = rc.Close() }()
	var data map[string]map[string][]byte
	if err := json.NewDecoder(rc).Decode(&data); err != nil {
		return fmt.Errorf("decode memory snapshot: %w", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if data == nil {
		data = map[string]map[string][]byte{}
	}
	f.data = data
	return nil
}

// Get implements KVStore.
func (f *MemoryKVFSM) Get(bucket, key string) ([]byte, bool, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	entries := f.data[bucket]
	if entries == nil {
		return nil, false, nil
	}
	value, ok := entries[key]
	if !ok {
		return nil, false, nil
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out, true, nil
}

// ListPrefix implements KVStore.
func (f *MemoryKVFSM) ListPrefix(bucket, prefix string) (map[string][]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := map[string][]byte{}
	for k, v := range f.data[bucket] {
		if strings.HasPrefix(k, prefix) {
			value := make([]byte, len(v))
			copy(value, v)
			out[k] = value
		}
	}
	return out, nil
}

// HasData implements KVStore.
func (f *MemoryKVFSM) HasData() (bool, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, entries := range f.data {
		if len(entries) > 0 {
			return true, nil
		}
	}
	return false, nil
}

type memorySnapshot struct {
	data map[string]map[string][]byte
}

func (s *memorySnapshot) Persist(sink hraft.SnapshotSink) error {
	if err := json.NewEncoder(sink).Encode(s.data); err != nil {
		_ = sink.Cancel()
		return fmt.Errorf("encode memory snapshot: %w", err)
	}
	return sink.Close()
}

func (s *memorySnapshot) Release() {}
