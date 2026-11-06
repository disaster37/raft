package fsm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	hraft "github.com/hashicorp/raft"

	"github.com/disaster37/raft/autopilot"
	"github.com/disaster37/raft/keyring"
)

// System command kinds reserved for EnvelopeFSM.
const (
	SysKindSetKeyring   uint8 = 0xFE
	SysKindFollowerEcho uint8 = 0xFF
)

var sysPrefix = []byte{0xFF, 'R', 'S', 'Y'}

var snapshotMagic = []byte{'R', 'S', 'N', '1'}

type snapshotHeader struct {
	Keyring *keyring.TLSKeyring             `json:"keyring,omitempty"`
	Echoes  map[string]autopilot.EchoUpdate `json:"echoes,omitempty"`
}

// EnvelopeFSM wraps a consumer raft.FSM so system state (TLSKeyring and
// follower applied-index echoes) is replicated and snapshotted alongside user
// state.
type EnvelopeFSM struct {
	inner     hraft.FSM
	onKeyring func(*keyring.TLSKeyring) error
	onEcho    func(autopilot.EchoUpdate)
	onRestore func(context.Context) error

	mu      sync.RWMutex
	keyring *keyring.TLSKeyring
	echoes  map[string]autopilot.EchoUpdate
}

var _ hraft.FSM = (*EnvelopeFSM)(nil)

// NewEnvelopeFSM wraps inner. Callbacks may be nil.
func NewEnvelopeFSM(inner hraft.FSM, onKeyring func(*keyring.TLSKeyring) error, onEcho func(autopilot.EchoUpdate), onRestore func(context.Context) error) *EnvelopeFSM {
	return &EnvelopeFSM{
		inner:     inner,
		onKeyring: onKeyring,
		onEcho:    onEcho,
		onRestore: onRestore,
		echoes:    map[string]autopilot.EchoUpdate{},
	}
}

// Apply intercepts system commands and forwards everything else to inner.
func (e *EnvelopeFSM) Apply(log *hraft.Log) interface{} {
	if len(log.Data) >= len(sysPrefix)+1 && bytes.HasPrefix(log.Data, sysPrefix) {
		kind := log.Data[len(sysPrefix)]
		payload := log.Data[len(sysPrefix)+1:]
		switch kind {
		case SysKindSetKeyring:
			var kr keyring.TLSKeyring
			if err := json.Unmarshal(payload, &kr); err != nil {
				return fmt.Errorf("decode keyring command: %w", err)
			}
			if e.onKeyring != nil {
				if err := e.onKeyring(kr.Clone()); err != nil {
					return fmt.Errorf("install keyring: %w", err)
				}
			}
			e.mu.Lock()
			e.keyring = kr.Clone()
			e.mu.Unlock()
			return nil
		case SysKindFollowerEcho:
			var echo autopilot.EchoUpdate
			if err := json.Unmarshal(payload, &echo); err != nil {
				return fmt.Errorf("decode follower echo: %w", err)
			}
			if e.onEcho != nil {
				e.onEcho(echo)
			}
			e.mu.Lock()
			e.echoes[echo.NodeID] = echo
			e.mu.Unlock()
			return nil
		default:
			return fmt.Errorf("unknown system command kind 0x%02x", kind)
		}
	}
	return e.inner.Apply(log)
}

// Snapshot returns a framed snapshot containing system state and inner state.
func (e *EnvelopeFSM) Snapshot() (hraft.FSMSnapshot, error) {
	innerSnap, err := e.inner.Snapshot()
	if err != nil {
		return nil, fmt.Errorf("inner snapshot: %w", err)
	}
	e.mu.RLock()
	header := snapshotHeader{Keyring: e.keyring.Clone(), Echoes: make(map[string]autopilot.EchoUpdate, len(e.echoes))}
	for k, v := range e.echoes {
		header.Echoes[k] = v
	}
	e.mu.RUnlock()
	return &envelopeSnapshot{header: header, inner: innerSnap}, nil
}

// Restore restores a framed snapshot, or passes a legacy snapshot through to
// the inner FSM.
func (e *EnvelopeFSM) Restore(rc io.ReadCloser) error {
	br := bufio.NewReader(rc)
	magic, err := br.Peek(len(snapshotMagic))
	if err == nil && bytes.Equal(magic, snapshotMagic) {
		if _, err := br.Discard(len(snapshotMagic)); err != nil {
			return fmt.Errorf("discard snapshot magic: %w", err)
		}
		var lenBuf [4]byte
		if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
			return fmt.Errorf("read snapshot header length: %w", err)
		}
		headerLen := binary.BigEndian.Uint32(lenBuf[:])
		headerBuf := make([]byte, headerLen)
		if _, err := io.ReadFull(br, headerBuf); err != nil {
			return fmt.Errorf("read snapshot header: %w", err)
		}
		var header snapshotHeader
		if err := json.Unmarshal(headerBuf, &header); err != nil {
			return fmt.Errorf("decode snapshot header: %w", err)
		}
		if header.Keyring != nil && e.onKeyring != nil {
			if err := e.onKeyring(header.Keyring.Clone()); err != nil {
				return fmt.Errorf("install restored keyring: %w", err)
			}
		}
		e.mu.Lock()
		e.keyring = header.Keyring.Clone()
		e.echoes = header.Echoes
		if e.echoes == nil {
			e.echoes = map[string]autopilot.EchoUpdate{}
		}
		e.mu.Unlock()
	}
	if err := e.inner.Restore(&readCloser{Reader: br, Closer: rc}); err != nil {
		return fmt.Errorf("inner restore: %w", err)
	}
	if e.onRestore != nil {
		if err := e.onRestore(context.Background()); err != nil {
			return fmt.Errorf("restore callback: %w", err)
		}
	}
	return nil
}

// Keyring returns the current replicated keyring.
func (e *EnvelopeFSM) Keyring() *keyring.TLSKeyring {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.keyring.Clone()
}

// Inner returns the wrapped FSM.
func (e *EnvelopeFSM) Inner() hraft.FSM { return e.inner }

type envelopeSnapshot struct {
	header snapshotHeader
	inner  hraft.FSMSnapshot
}

func (s *envelopeSnapshot) Persist(sink hraft.SnapshotSink) error {
	header, err := json.Marshal(s.header)
	if err != nil {
		_ = sink.Cancel()
		return fmt.Errorf("marshal snapshot header: %w", err)
	}
	if _, err := sink.Write(snapshotMagic); err != nil {
		_ = sink.Cancel()
		return fmt.Errorf("write snapshot magic: %w", err)
	}
	var lenBuf [4]byte
	//nolint:gosec // snapshot headers are small JSON documents
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(header)))
	if _, err := sink.Write(lenBuf[:]); err != nil {
		_ = sink.Cancel()
		return fmt.Errorf("write snapshot header length: %w", err)
	}
	if _, err := sink.Write(header); err != nil {
		_ = sink.Cancel()
		return fmt.Errorf("write snapshot header: %w", err)
	}
	if err := s.inner.Persist(&sinkWrapper{SnapshotSink: sink}); err != nil {
		return fmt.Errorf("persist inner snapshot: %w", err)
	}
	return nil
}

func (s *envelopeSnapshot) Release() { s.inner.Release() }

type sinkWrapper struct {
	hraft.SnapshotSink
}

func (w *sinkWrapper) Write(p []byte) (int, error) { return w.SnapshotSink.Write(p) }
func (w *sinkWrapper) Close() error                { return w.SnapshotSink.Close() }
func (w *sinkWrapper) Cancel() error               { return w.SnapshotSink.Cancel() }
func (w *sinkWrapper) ID() string                  { return w.SnapshotSink.ID() }

type readCloser struct {
	io.Reader
	io.Closer
}
