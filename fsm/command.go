// Package fsm provides an envelope FSM for system state plus in-memory and
// Bolt-backed transactional KV state machines.
package fsm

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrConflict is returned when a create-only mutation targets an existing key.
	ErrConflict = errors.New("raft: key already exists")
	// ErrNotFound is returned when a requested key does not exist.
	ErrNotFound = errors.New("raft: key not found")
)

// Command kinds understood by the built-in KV FSMs.
const (
	KindSet      uint8 = 1
	KindSetJSON  uint8 = 2
	KindDelete   uint8 = 3
	KindSetMulti uint8 = 4
	KindCreate   uint8 = 5
)

// Command is one replicated KV mutation.
type Command struct {
	Kind    uint8           `json:"kind"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// CommandCodec encodes and decodes Command values.
type CommandCodec struct{}

// Encode marshals a command with the given kind and payload.
func (CommandCodec) Encode(kind uint8, payload any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal command payload: %w", err)
	}
	data, err := json.Marshal(Command{Kind: kind, Payload: raw})
	if err != nil {
		return nil, fmt.Errorf("marshal command: %w", err)
	}
	return data, nil
}

// Decode unmarshals a command.
func (CommandCodec) Decode(data []byte) (*Command, error) {
	var cmd Command
	if err := json.Unmarshal(data, &cmd); err != nil {
		return nil, fmt.Errorf("decode command: %w", err)
	}
	return &cmd, nil
}

// KVEntry is one mutation in an atomic multi-key write ("set-multi").
type KVEntry struct {
	Bucket string `json:"bucket,omitempty"`
	Key    string `json:"key"`
	Value  []byte `json:"value,omitempty"`
	Delete bool   `json:"delete,omitempty"`
	Create bool   `json:"create,omitempty"`
}

// SetMultiPayload carries the entries of a set-multi command.
type SetMultiPayload struct {
	Entries []KVEntry `json:"entries"`
}

// KVStore provides local read helpers against MemoryKVFSM or BoltKVFSM.
type KVStore interface {
	Get(bucket, key string) ([]byte, bool, error)
	ListPrefix(bucket, prefix string) (map[string][]byte, error)
	HasData() (bool, error)
}

// SessionStateSink mirrors dagger-kubernetes domain.SessionStateSink.
type SessionStateSink interface {
	ApplySessionRegistered(sessionID string, payload json.RawMessage, at time.Time)
	ApplySessionTouched(sessionID string, at time.Time)
}
