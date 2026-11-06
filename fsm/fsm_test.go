package fsm

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	hraft "github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"

	"github.com/disaster37/raft/autopilot"
	"github.com/disaster37/raft/keyring"
)

type memSink struct {
	registered map[string]json.RawMessage
	touched    map[string]time.Time
}

func (s *memSink) ApplySessionRegistered(id string, payload json.RawMessage, _ time.Time) {
	if s.registered == nil {
		s.registered = map[string]json.RawMessage{}
	}
	s.registered[id] = payload
}
func (s *memSink) ApplySessionTouched(id string, at time.Time) {
	if s.touched == nil {
		s.touched = map[string]time.Time{}
	}
	s.touched[id] = at
}

type memSnapshotSink struct {
	buf    bytes.Buffer
	closed bool
}

func (s *memSnapshotSink) Write(p []byte) (int, error) { return s.buf.Write(p) }
func (s *memSnapshotSink) Close() error                { s.closed = true; return nil }
func (s *memSnapshotSink) Cancel() error               { return nil }
func (s *memSnapshotSink) ID() string                  { return "test" }

func TestEnvelopeFSMSysAndUserCommands(t *testing.T) {
	inner := NewMemoryKVFSM(nil)
	var installed *keyring.TLSKeyring
	var echo autopilot.EchoUpdate
	env := NewEnvelopeFSM(inner, func(kr *keyring.TLSKeyring) error {
		installed = kr
		return nil
	}, func(u autopilot.EchoUpdate) {
		echo = u
	}, nil)

	userData, err := (CommandCodec{}).Encode(KindSet, KVEntry{Bucket: "b", Key: "k", Value: []byte("v")})
	if err != nil {
		t.Fatal(err)
	}
	if resp := env.Apply(&hraft.Log{Data: userData}); resp != nil {
		t.Fatalf("user apply resp = %v", resp)
	}
	if got, ok, _ := inner.Get("b", "k"); !ok || string(got) != "v" {
		t.Fatalf("inner value = %q ok=%v", got, ok)
	}

	kr := &keyring.TLSKeyring{Keys: []*keyring.TLSKey{{ID: "k1", PKIMode: "shared-ca", CertPEM: []byte("cert")}}, ActiveKeyID: "k1", Term: 1}
	krData, _ := json.Marshal(kr)
	sysData := append(append(append([]byte{}, sysPrefix...), SysKindSetKeyring), krData...)
	if resp := env.Apply(&hraft.Log{Data: sysData}); resp != nil {
		t.Fatalf("keyring apply resp = %v", resp)
	}
	if installed == nil || installed.ActiveKeyID != "k1" {
		t.Fatalf("installed = %+v", installed)
	}
	if env.Keyring() == nil || env.Keyring().Term != 1 {
		t.Fatal("keyring not stored")
	}

	echoData, _ := json.Marshal(autopilot.EchoUpdate{NodeID: "n1", AppliedIndex: 5})
	sysEcho := append(append(append([]byte{}, sysPrefix...), SysKindFollowerEcho), echoData...)
	if resp := env.Apply(&hraft.Log{Data: sysEcho}); resp != nil {
		t.Fatalf("echo apply resp = %v", resp)
	}
	if echo.NodeID != "n1" || echo.AppliedIndex != 5 {
		t.Fatalf("echo = %+v", echo)
	}

	bad := append(append(append([]byte{}, sysPrefix...), 0x01), []byte("{}")...)
	if resp := env.Apply(&hraft.Log{Data: bad}); resp == nil {
		t.Fatal("expected unknown system command error")
	}
	if env.Inner() != inner {
		t.Fatal("inner mismatch")
	}
}

func TestEnvelopeFSMKeyringCallbackFailureKeepsPreviousState(t *testing.T) {
	inner := NewMemoryKVFSM(nil)
	fail := false
	env := NewEnvelopeFSM(inner, func(*keyring.TLSKeyring) error {
		if fail {
			return errors.New("install rejected")
		}
		return nil
	}, nil, nil)

	first := &keyring.TLSKeyring{Keys: []*keyring.TLSKey{{ID: "k1", PKIMode: "shared-ca", CertPEM: []byte("cert")}}, ActiveKeyID: "k1", Term: 1}
	firstData, _ := json.Marshal(first)
	if resp := env.Apply(&hraft.Log{Data: append(append(append([]byte{}, sysPrefix...), SysKindSetKeyring), firstData...)}); resp != nil {
		t.Fatalf("first keyring apply: %v", resp)
	}

	fail = true
	second := &keyring.TLSKeyring{Keys: []*keyring.TLSKey{{ID: "k2", PKIMode: "shared-ca", CertPEM: []byte("cert")}}, ActiveKeyID: "k2", Term: 2}
	secondData, _ := json.Marshal(second)
	resp := env.Apply(&hraft.Log{Data: append(append(append([]byte{}, sysPrefix...), SysKindSetKeyring), secondData...)})
	if resp == nil {
		t.Fatal("expected callback error")
	}
	got := env.Keyring()
	if got == nil || got.Term != 1 || got.ActiveKeyID != "k1" {
		t.Fatalf("keyring mutated after failed callback: %+v", got)
	}
}

func TestEnvelopeFSMRestoreCallbackFailureKeepsPreviousState(t *testing.T) {
	inner := NewMemoryKVFSM(nil)
	fail := false
	env := NewEnvelopeFSM(inner, func(*keyring.TLSKeyring) error {
		if fail {
			return errors.New("install rejected")
		}
		return nil
	}, nil, nil)
	first := &keyring.TLSKeyring{Keys: []*keyring.TLSKey{{ID: "k1", PKIMode: "shared-ca", CertPEM: []byte("cert")}}, ActiveKeyID: "k1", Term: 1}
	firstData, _ := json.Marshal(first)
	env.Apply(&hraft.Log{Data: append(append(append([]byte{}, sysPrefix...), SysKindSetKeyring), firstData...)})

	snap, err := env.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSnapshotSink{}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}

	restored := NewEnvelopeFSM(NewMemoryKVFSM(nil), func(*keyring.TLSKeyring) error {
		return errors.New("install rejected")
	}, nil, nil)
	if err := restored.Restore(io.NopCloser(bytes.NewReader(sink.buf.Bytes()))); err == nil {
		t.Fatal("expected restore callback error")
	}
	if got := restored.Keyring(); got != nil {
		t.Fatalf("keyring installed after failed restore callback: %+v", got)
	}
}

func TestEnvelopeFSMSnapshotRestoreRoundTrip(t *testing.T) {
	inner := NewMemoryKVFSM(nil)
	env := NewEnvelopeFSM(inner, nil, nil, nil)
	userData, _ := (CommandCodec{}).Encode(KindSet, KVEntry{Bucket: "b", Key: "k", Value: []byte("v")})
	env.Apply(&hraft.Log{Data: userData})
	kr := &keyring.TLSKeyring{Keys: []*keyring.TLSKey{{ID: "k1", PKIMode: "shared-ca", CertPEM: []byte("cert")}}, ActiveKeyID: "k1", Term: 2}
	krData, _ := json.Marshal(kr)
	env.Apply(&hraft.Log{Data: append(append(append([]byte{}, sysPrefix...), SysKindSetKeyring), krData...)})

	snap, err := env.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	sink := &memSnapshotSink{}
	if err := snap.Persist(sink); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if !sink.closed {
		t.Fatal("sink not closed")
	}

	restoredInner := NewMemoryKVFSM(nil)
	var restoredKeyring *keyring.TLSKeyring
	restored := NewEnvelopeFSM(restoredInner, func(kr *keyring.TLSKeyring) error {
		restoredKeyring = kr
		return nil
	}, nil, nil)
	if err := restored.Restore(io.NopCloser(bytes.NewReader(sink.buf.Bytes()))); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got, ok, _ := restoredInner.Get("b", "k"); !ok || string(got) != "v" {
		t.Fatalf("restored value = %q ok=%v", got, ok)
	}
	if restoredKeyring == nil || restoredKeyring.Term != 2 {
		t.Fatalf("restored keyring = %+v", restoredKeyring)
	}
}

func TestEnvelopeFSMLegacySnapshot(t *testing.T) {
	inner := NewMemoryKVFSM(nil)
	env := NewEnvelopeFSM(inner, nil, nil, nil)
	legacy := []byte(`{"b":{"k":"dg=="}}`)
	if err := env.Restore(io.NopCloser(bytes.NewReader(legacy))); err != nil {
		t.Fatalf("legacy restore: %v", err)
	}
	if got, ok, _ := inner.Get("b", "k"); !ok || string(got) != "v" {
		t.Fatalf("legacy value = %q ok=%v", got, ok)
	}
}

func TestMemoryKVFSMCRUDAndSessionSink(t *testing.T) {
	sink := &memSink{}
	kv := NewMemoryKVFSM(sink)
	apply := func(kind uint8, payload any) interface{} {
		data, err := (CommandCodec{}).Encode(kind, payload)
		if err != nil {
			t.Fatal(err)
		}
		return kv.Apply(&hraft.Log{Data: data})
	}
	if resp := apply(KindSet, KVEntry{Bucket: "b", Key: "a", Value: []byte("1")}); resp != nil {
		t.Fatalf("set resp = %v", resp)
	}
	if resp := apply(KindCreate, KVEntry{Bucket: "b", Key: "a", Value: []byte("2")}); resp == nil {
		t.Fatal("expected conflict")
	}
	if resp := apply(KindSetMulti, SetMultiPayload{Entries: []KVEntry{
		{Bucket: "b", Key: "c", Value: []byte("3")},
		{Bucket: "b", Key: "d", Value: []byte("4")},
	}}); resp != nil {
		t.Fatalf("multi resp = %v", resp)
	}
	got, err := kv.ListPrefix("b", "")
	if err != nil || len(got) != 3 {
		t.Fatalf("list = %v err=%v", got, err)
	}
	if resp := apply(KindDelete, KVEntry{Bucket: "b", Key: "a"}); resp != nil {
		t.Fatalf("delete resp = %v", resp)
	}
	if _, ok, _ := kv.Get("b", "a"); ok {
		t.Fatal("key not deleted")
	}
	if has, _ := kv.HasData(); !has {
		t.Fatal("expected data")
	}
	apply(KindSet, KVEntry{Bucket: sessionBucket, Key: "s1", Value: []byte(`{"x":1}`)})
	apply(KindSet, KVEntry{Bucket: sessionTouchBucket, Key: "s1", Value: []byte("1")})
	if _, ok := sink.registered["s1"]; !ok {
		t.Fatal("session not registered")
	}
	if _, ok := sink.touched["s1"]; !ok {
		t.Fatal("session not touched")
	}
	if resp := apply(99, KVEntry{}); resp == nil {
		t.Fatal("expected unknown kind error")
	}
}

func TestBoltKVFSMSetMultiAtomicRollback(t *testing.T) {
	dir := t.TempDir()
	db, err := bolt.Open(filepath.Join(dir, "fsm.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	kv := NewBoltKVFSM(db)
	apply := func(kind uint8, payload any) interface{} {
		data, err := (CommandCodec{}).Encode(kind, payload)
		if err != nil {
			t.Fatal(err)
		}
		return kv.Apply(&hraft.Log{Data: data})
	}
	if resp := apply(KindSet, KVEntry{Bucket: "b", Key: "a", Value: []byte("1")}); resp != nil {
		t.Fatalf("set resp = %v", resp)
	}
	resp := apply(KindSetMulti, SetMultiPayload{Entries: []KVEntry{
		{Bucket: "b", Key: "b", Value: []byte("2")},
		{Bucket: "b", Key: "a", Value: []byte("3"), Create: true},
	}})
	if resp == nil {
		t.Fatal("expected conflict")
	}
	if _, ok, _ := kv.Get("b", "b"); ok {
		t.Fatal("partial write was not rolled back")
	}
	if got, ok, _ := kv.Get("b", "a"); !ok || string(got) != "1" {
		t.Fatalf("a = %q ok=%v", got, ok)
	}
	if resp := apply(KindSetMulti, SetMultiPayload{Entries: []KVEntry{
		{Bucket: "b", Key: "c", Value: []byte("3")},
		{Bucket: "b", Key: "d", Value: []byte("4")},
	}}); resp != nil {
		t.Fatalf("multi resp = %v", resp)
	}
	list, err := kv.ListPrefix("b", "")
	if err != nil || len(list) != 3 {
		t.Fatalf("list = %v err=%v", list, err)
	}
	if has, _ := kv.HasData(); !has {
		t.Fatal("expected data")
	}
	if resp := apply(KindDelete, KVEntry{Bucket: "b", Key: "c"}); resp != nil {
		t.Fatalf("delete resp = %v", resp)
	}
	if _, ok, _ := kv.Get("b", "c"); ok {
		t.Fatal("key not deleted")
	}
	if resp := apply(99, KVEntry{}); resp == nil {
		t.Fatal("expected unknown kind error")
	}

	snap, err := kv.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSnapshotSink{}
	if err := snap.Persist(sink); err != nil {
		t.Fatal(err)
	}
	restored := NewBoltKVFSM(db)
	if err := restored.Restore(io.NopCloser(bytes.NewReader(sink.buf.Bytes()))); err != nil {
		t.Fatal(err)
	}
	if got, ok, _ := restored.Get("b", "a"); !ok || string(got) != "1" {
		t.Fatalf("restored a = %q ok=%v", got, ok)
	}
}

func TestCommandCodecErrors(t *testing.T) {
	if _, err := (CommandCodec{}).Decode([]byte("bad")); err == nil {
		t.Fatal("expected decode error")
	}
	if _, err := (CommandCodec{}).Encode(KindSet, func() {}); err == nil {
		t.Fatal("expected encode error")
	}
	if !errors.Is(ErrConflict, ErrConflict) {
		t.Fatal("sentinel mismatch")
	}
}

func TestSnapshotReleaseAndSinkWrapper(t *testing.T) {
	inner := NewMemoryKVFSM(nil)
	env := NewEnvelopeFSM(inner, nil, nil, nil)
	snap, err := env.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	snap.Release()
	sink := &memSnapshotSink{}
	wrapper := &sinkWrapper{SnapshotSink: sink}
	if _, err := wrapper.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if wrapper.ID() != "test" {
		t.Fatalf("id = %q", wrapper.ID())
	}
	if err := wrapper.Cancel(); err != nil {
		t.Fatal(err)
	}
	if err := wrapper.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBoltKVFSMNilDatabase(t *testing.T) {
	kv := NewBoltKVFSM(nil)
	data, _ := (CommandCodec{}).Encode(KindSet, KVEntry{Bucket: "b", Key: "k", Value: []byte("v")})
	if resp := kv.Apply(&hraft.Log{Data: data}); resp == nil {
		t.Fatal("expected nil database error")
	}
	if _, ok, err := kv.Get("b", "k"); err != nil || ok {
		t.Fatalf("get = %v %v", ok, err)
	}
	if list, err := kv.ListPrefix("b", ""); err != nil || len(list) != 0 {
		t.Fatalf("list = %v err=%v", list, err)
	}
	if has, err := kv.HasData(); err != nil || has {
		t.Fatalf("has = %v err=%v", has, err)
	}
	if _, err := kv.Snapshot(); err != nil {
		t.Fatal(err)
	}
	if err := kv.Restore(io.NopCloser(bytes.NewReader([]byte("{}")))); err == nil {
		t.Fatal("expected nil database restore error")
	}
}

func TestMemoryKVFSMSnapshotRelease(t *testing.T) {
	kv := NewMemoryKVFSM(nil)
	snap, err := kv.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	snap.Release()
}

type failingSink struct{}

func (failingSink) Write([]byte) (int, error) { return 0, errors.New("write") }
func (failingSink) Close() error              { return nil }
func (failingSink) Cancel() error             { return nil }
func (failingSink) ID() string                { return "fail" }

func TestSnapshotPersistErrors(t *testing.T) {
	mem := NewMemoryKVFSM(nil)
	snap, _ := mem.Snapshot()
	if err := snap.Persist(failingSink{}); err == nil {
		t.Fatal("expected memory persist error")
	}
	dir := t.TempDir()
	db, err := bolt.Open(filepath.Join(dir, "fsm.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	boltKV := NewBoltKVFSM(db)
	boltSnap, _ := boltKV.Snapshot()
	if err := boltSnap.Persist(failingSink{}); err == nil {
		t.Fatal("expected bolt persist error")
	}
	env := NewEnvelopeFSM(mem, nil, nil, nil)
	envSnap, _ := env.Snapshot()
	if err := envSnap.Persist(failingSink{}); err == nil {
		t.Fatal("expected envelope persist error")
	}
}

func TestRestoreErrors(t *testing.T) {
	mem := NewMemoryKVFSM(nil)
	if err := mem.Restore(io.NopCloser(bytes.NewReader([]byte("bad")))); err == nil {
		t.Fatal("expected memory restore error")
	}
	dir := t.TempDir()
	db, err := bolt.Open(filepath.Join(dir, "fsm.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	boltKV := NewBoltKVFSM(db)
	if err := boltKV.Restore(io.NopCloser(bytes.NewReader([]byte("bad")))); err == nil {
		t.Fatal("expected bolt restore error")
	}
	env := NewEnvelopeFSM(mem, nil, nil, nil)
	if err := env.Restore(io.NopCloser(bytes.NewReader([]byte("RSN1\x00\x00\x00\x05bad")))); err == nil {
		t.Fatal("expected envelope restore error")
	}
}

func TestBoltCompositeKeys(t *testing.T) {
	if string(compositeKey("", "k")) != "k" {
		t.Fatal("empty bucket composite key")
	}
	if stripBucket("", "k") != "k" {
		t.Fatal("empty bucket strip")
	}
	if stripBucket("b", "b\x00k") != "k" {
		t.Fatal("strip bucket")
	}
}

type errorFSM struct {
	snapshotErr error
	restoreErr  error
}

func (e errorFSM) Apply(*hraft.Log) interface{} { return nil }
func (e errorFSM) Snapshot() (hraft.FSMSnapshot, error) {
	if e.snapshotErr != nil {
		return nil, e.snapshotErr
	}
	return noopSnapshot{}, nil
}
func (e errorFSM) Restore(io.ReadCloser) error { return e.restoreErr }

type noopSnapshot struct{}

func (noopSnapshot) Persist(sink hraft.SnapshotSink) error { return sink.Close() }
func (noopSnapshot) Release()                              {}

func TestEnvelopeFSMErrors(t *testing.T) {
	env := NewEnvelopeFSM(errorFSM{snapshotErr: errors.New("snapshot")}, nil, nil, nil)
	if _, err := env.Snapshot(); err == nil {
		t.Fatal("expected snapshot error")
	}
	env = NewEnvelopeFSM(errorFSM{restoreErr: errors.New("restore")}, nil, nil, nil)
	if err := env.Restore(io.NopCloser(bytes.NewReader([]byte("legacy")))); err == nil {
		t.Fatal("expected restore error")
	}
	env = NewEnvelopeFSM(NewMemoryKVFSM(nil), nil, nil, func(context.Context) error { return errors.New("callback") })
	if err := env.Restore(io.NopCloser(bytes.NewReader([]byte("{}")))); err == nil {
		t.Fatal("expected restore callback error")
	}
	badKeyring := append(append(append([]byte{}, sysPrefix...), SysKindSetKeyring), []byte("bad")...)
	if resp := env.Apply(&hraft.Log{Data: badKeyring}); resp == nil {
		t.Fatal("expected keyring decode error")
	}
	badEcho := append(append(append([]byte{}, sysPrefix...), SysKindFollowerEcho), []byte("bad")...)
	if resp := env.Apply(&hraft.Log{Data: badEcho}); resp == nil {
		t.Fatal("expected echo decode error")
	}
}

func TestKVFSMInvalidPayloads(t *testing.T) {
	mem := NewMemoryKVFSM(nil)
	for _, kind := range []uint8{KindSet, KindDelete, KindSetMulti} {
		data, _ := (CommandCodec{}).Encode(kind, "not-an-entry")
		if resp := mem.Apply(&hraft.Log{Data: data}); resp == nil {
			t.Fatalf("expected memory error for kind %d", kind)
		}
	}
	dir := t.TempDir()
	db, err := bolt.Open(filepath.Join(dir, "fsm.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	boltKV := NewBoltKVFSM(db)
	for _, kind := range []uint8{KindSet, KindDelete, KindSetMulti} {
		data, _ := (CommandCodec{}).Encode(kind, "not-an-entry")
		if resp := boltKV.Apply(&hraft.Log{Data: data}); resp == nil {
			t.Fatalf("expected bolt error for kind %d", kind)
		}
	}
	if err := mem.Restore(io.NopCloser(bytes.NewReader([]byte("null")))); err != nil {
		t.Fatalf("null restore: %v", err)
	}
}

func TestEnvelopeFSMRestoreRejectsOversizedHeader(t *testing.T) {
	env := NewEnvelopeFSM(NewMemoryKVFSM(nil), nil, nil, nil)
	var buf bytes.Buffer
	buf.Write(snapshotMagic)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], maxSnapshotHeaderSize+1)
	buf.Write(lenBuf[:])
	err := env.Restore(io.NopCloser(bytes.NewReader(buf.Bytes())))
	if err == nil {
		t.Fatal("expected oversized header error")
	}
	if !strings.Contains(err.Error(), "exceeds max") {
		t.Fatalf("err = %v", err)
	}
}

func TestBoltKVFSMListPrefixEmptyBucketIsolation(t *testing.T) {
	dir := t.TempDir()
	db, err := bolt.Open(filepath.Join(dir, "fsm.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	kv := NewBoltKVFSM(db)
	apply := func(entry KVEntry) {
		data, err := (CommandCodec{}).Encode(KindSet, entry)
		if err != nil {
			t.Fatal(err)
		}
		if resp := kv.Apply(&hraft.Log{Data: data}); resp != nil {
			t.Fatalf("apply resp = %v", resp)
		}
	}
	apply(KVEntry{Bucket: "users", Key: "u1", Value: []byte("named")})
	apply(KVEntry{Bucket: "", Key: "root", Value: []byte("root")})

	all, err := kv.ListPrefix("", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || string(all["root"]) != "root" {
		t.Fatalf("empty bucket list = %v", all)
	}
	prefixed, err := kv.ListPrefix("", "u")
	if err != nil {
		t.Fatal(err)
	}
	if len(prefixed) != 0 {
		t.Fatalf("empty bucket prefix leaked named bucket keys: %v", prefixed)
	}
	named, err := kv.ListPrefix("users", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(named) != 1 || string(named["u1"]) != "named" {
		t.Fatalf("named bucket list = %v", named)
	}
}
