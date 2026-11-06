package storage

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	hraft "github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"

	"github.com/disaster37/raft/config"
)

func TestBoltStoreBackend(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig().Storage
	store, err := NewBoltStore(dir, cfg, 2, 8, nil)
	if err != nil {
		t.Fatalf("NewBoltStore: %v", err)
	}
	defer store.Close()
	if store.BoltDB() != nil {
		t.Fatal("BoltDB should be nil for raft-boltdb")
	}
	testLogStore(t, store.LogStore())
	testStableStore(t, store.StableStore())
	if removed, err := store.IsRemovedFlag(); err != nil || removed {
		t.Fatalf("removed = %v err=%v", removed, err)
	}
	if err := store.SetRemovedFlag(); err != nil {
		t.Fatal(err)
	}
	if removed, err := store.IsRemovedFlag(); err != nil || !removed {
		t.Fatalf("removed = %v err=%v", removed, err)
	}
	info, err := os.Stat(filepath.Join(dir, "raft.db"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("raft.db mode = %o", info.Mode().Perm())
	}
}

func TestSharedBoltStoreBackend(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig().Storage
	store, err := NewSharedBoltStore(dir, "node-0", cfg, 2, 8, nil)
	if err != nil {
		t.Fatalf("NewSharedBoltStore: %v", err)
	}
	defer store.Close()
	if store.BoltDB() == nil {
		t.Fatal("BoltDB should be non-nil")
	}
	testLogStore(t, store.LogStore())
	testStableStore(t, store.StableStore())
	if err := store.SetRemovedFlag(); err != nil {
		t.Fatal(err)
	}
	if removed, err := store.IsRemovedFlag(); err != nil || !removed {
		t.Fatalf("removed = %v err=%v", removed, err)
	}
	info, err := os.Stat(filepath.Join(dir, "node-0.db"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("db mode = %o", info.Mode().Perm())
	}
}

func testLogStore(t *testing.T, store hraft.LogStore) {
	t.Helper()
	logs := []*hraft.Log{
		{Index: 1, Term: 1, Type: hraft.LogCommand, Data: []byte("one")},
		{Index: 2, Term: 1, Type: hraft.LogCommand, Data: []byte("two")},
		{Index: 3, Term: 1, Type: hraft.LogCommand, Data: []byte("three")},
	}
	for _, log := range logs {
		if err := store.StoreLog(log); err != nil {
			t.Fatalf("StoreLog: %v", err)
		}
	}
	first, err := store.FirstIndex()
	if err != nil || first != 1 {
		t.Fatalf("FirstIndex = %d err=%v", first, err)
	}
	last, err := store.LastIndex()
	if err != nil || last != 3 {
		t.Fatalf("LastIndex = %d err=%v", last, err)
	}
	var got hraft.Log
	if err := store.GetLog(2, &got); err != nil {
		t.Fatalf("GetLog: %v", err)
	}
	if string(got.Data) != "two" {
		t.Fatalf("data = %q", got.Data)
	}
	if err := store.DeleteRange(1, 2); err != nil {
		t.Fatalf("DeleteRange: %v", err)
	}
	if err := store.GetLog(1, &got); err == nil {
		t.Fatal("expected missing log error")
	}
}

func testStableStore(t *testing.T, store hraft.StableStore) {
	t.Helper()
	if err := store.Set([]byte("k"), []byte("v")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := store.Get([]byte("k"))
	if err != nil || string(got) != "v" {
		t.Fatalf("Get = %q err=%v", got, err)
	}
	if err := store.SetUint64([]byte("u"), 42); err != nil {
		t.Fatalf("SetUint64: %v", err)
	}
	u, err := store.GetUint64([]byte("u"))
	if err != nil || u != 42 {
		t.Fatalf("GetUint64 = %d err=%v", u, err)
	}
	if _, err := store.Get([]byte("missing")); err == nil {
		t.Fatal("expected missing key error")
	}
}

func TestSnapshotStorePermissions0700(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewSecureFileSnapshotStore(dir, 2, nil); err != nil {
		t.Fatalf("NewSecureFileSnapshotStore: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("snapshots mode = %o", info.Mode().Perm())
	}
}

func TestNodeIDPersistence0600(t *testing.T) {
	dir := t.TempDir()
	id, err := LoadOrGenerateNodeID(dir)
	if err != nil || id == "" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	id2, err := LoadOrGenerateNodeID(dir)
	if err != nil || id2 != id {
		t.Fatalf("id2=%q err=%v", id2, err)
	}
	info, err := os.Stat(filepath.Join(dir, "node-id"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("node-id mode = %o", info.Mode().Perm())
	}
}

func TestClearRaftState(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"raft.db", "node-0.db", "peers.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "snapshots"), 0o700); err != nil {
		t.Fatal(err)
	}
	cleared, err := ClearRaftState(dir, "node-0")
	if err != nil || !cleared {
		t.Fatalf("cleared=%v err=%v", cleared, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "raft.db")); !os.IsNotExist(err) {
		t.Fatal("raft.db still exists")
	}
	if _, err := ClearRaftState("", ""); err == nil {
		t.Fatal("expected error for empty dir")
	}
}

func TestAESGCMKeeperEncryptDecryptRotate(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "keys.json")
	if err := GenerateKeyFile(keyFile); err != nil {
		t.Fatalf("GenerateKeyFile: %v", err)
	}
	keeper, err := LoadAESGCMKeeper(keyFile, "test.aad")
	if err != nil {
		t.Fatalf("LoadAESGCMKeeper: %v", err)
	}
	if keeper.Timeout() <= 0 {
		t.Fatal("timeout should be positive")
	}
	sealed, err := keeper.SealString("secret")
	if err != nil {
		t.Fatalf("SealString: %v", err)
	}
	opened, err := keeper.OpenString(sealed)
	if err != nil || opened != "secret" {
		t.Fatalf("OpenString = %q err=%v", opened, err)
	}
	// Lazy plaintext migration.
	plain, err := keeper.OpenString("legacy-plaintext")
	if err != nil || plain != "legacy-plaintext" {
		t.Fatalf("plain = %q err=%v", plain, err)
	}
	if empty, err := keeper.OpenString(""); err != nil || empty != "" {
		t.Fatalf("empty = %q err=%v", empty, err)
	}
	// Rotation: old ciphertext opens with a keeper that has both keys.
	oldKey := keeper.keys[keeper.primary]
	newKey := bytes.Repeat([]byte{7}, 32)
	rotated, err := NewAESGCMKeeper("k2", map[string][]byte{"k1": oldKey, "k2": newKey}, "test.aad")
	if err != nil {
		t.Fatalf("NewAESGCMKeeper: %v", err)
	}
	if got, err := rotated.OpenString(sealed); err != nil || got != "secret" {
		t.Fatalf("rotated open = %q err=%v", got, err)
	}
	if _, err := NewAESGCMKeeper("missing", map[string][]byte{"k1": oldKey}, "aad"); err == nil {
		t.Fatal("expected error for missing primary")
	}
	if _, err := NewAESGCMKeeper("k1", map[string][]byte{"k1": []byte("short")}, "aad"); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestAESGCMKeeperErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAESGCMKeeper(bad, "aad"); err == nil {
		t.Fatal("expected parse error")
	}
	if _, err := LoadAESGCMKeeper(filepath.Join(dir, "missing"), "aad"); err == nil {
		t.Fatal("expected read error")
	}
	keeper, err := NewAESGCMKeeper("k1", map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)}, "aad")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keeper.Open(EncryptedValue{Alg: "bad", Ver: 1}); err == nil {
		t.Fatal("expected unsupported envelope error")
	}
	if _, err := keeper.Open(EncryptedValue{Alg: "A256GCM", Ver: 1, KID: "missing"}); err == nil {
		t.Fatal("expected unknown key error")
	}
	_ = time.Now()
}

func TestOpenBackendAndInmem(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig().Storage
	cfg.Backend = config.StorageBackendInmem
	backend, err := OpenBackend(dir, "node", cfg, 2, 8, nil)
	if err != nil {
		t.Fatalf("OpenBackend inmem: %v", err)
	}
	if backend.BoltDB() != nil {
		t.Fatal("inmem BoltDB should be nil")
	}
	if backend.LogStore() == nil || backend.StableStore() == nil || backend.SnapshotStore() == nil {
		t.Fatal("missing inmem stores")
	}
	if removed, err := backend.IsRemovedFlag(); err != nil || removed {
		t.Fatalf("removed = %v err=%v", removed, err)
	}
	if err := backend.SetRemovedFlag(); err != nil {
		t.Fatal(err)
	}
	if removed, _ := backend.IsRemovedFlag(); !removed {
		t.Fatal("removed flag not set")
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}

	cfg.Backend = config.StorageBackendRaftBoltDB
	backend, err = OpenBackend(dir, "node", cfg, 2, 8, nil)
	if err != nil {
		t.Fatalf("OpenBackend bolt: %v", err)
	}
	if backend.SnapshotStore() == nil {
		t.Fatal("missing snapshot store")
	}
	_ = backend.Close()

	cfg.Backend = config.StorageBackendSharedBolt
	backend, err = OpenBackend(dir, "node", cfg, 2, 8, nil)
	if err != nil {
		t.Fatalf("OpenBackend shared: %v", err)
	}
	if backend.SnapshotStore() == nil {
		t.Fatal("missing snapshot store")
	}
	_ = backend.Close()

	cfg.Backend = "bad"
	if _, err := OpenBackend(dir, "node", cfg, 2, 8, nil); err == nil {
		t.Fatal("expected unsupported backend error")
	}
}

func TestSnapshotDelayStore(t *testing.T) {
	dir := t.TempDir()
	inner, err := NewSecureFileSnapshotStore(dir, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	delay := NewSnapshotDelayStore(inner, time.Millisecond)
	if _, err := delay.List(); err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, _, err := delay.Open("missing"); err == nil {
		t.Fatal("expected open error")
	}
	if sink, err := delay.Create(hraft.SnapshotVersionMax, 1, 1, hraft.Configuration{}, 1, nil); err == nil {
		_ = sink.Cancel()
	}
}

func TestSharedBoltStoreGetMissingKey(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig().Storage
	store, err := NewSharedBoltStore(dir, "node", cfg, 2, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Get([]byte("missing")); !errors.Is(err, raftboltdb.ErrKeyNotFound) {
		t.Fatalf("Get missing err = %v, want ErrKeyNotFound", err)
	}
	if _, err := store.GetUint64([]byte("missing")); !errors.Is(err, raftboltdb.ErrKeyNotFound) {
		t.Fatalf("GetUint64 missing err = %v, want ErrKeyNotFound", err)
	}
	if removed, err := store.IsRemovedFlag(); err != nil || removed {
		t.Fatalf("removed = %v err=%v", removed, err)
	}
	if err := store.SetRemovedFlag(); err != nil {
		t.Fatal(err)
	}
	if removed, err := store.IsRemovedFlag(); err != nil || !removed {
		t.Fatalf("removed = %v err=%v", removed, err)
	}
}

func TestSharedBoltStoreStoreLog(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig().Storage
	store, err := NewSharedBoltStore(dir, "node", cfg, 2, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	log := &hraft.Log{Index: 1, Term: 1, Type: hraft.LogCommand, Data: []byte("x")}
	if err := store.StoreLog(log); err != nil {
		t.Fatalf("StoreLog: %v", err)
	}
	var got hraft.Log
	if err := store.GetLog(1, &got); err != nil || string(got.Data) != "x" {
		t.Fatalf("GetLog = %+v err=%v", got, err)
	}
	if err := store.GetLog(99, &got); err == nil {
		t.Fatal("expected missing log error")
	}
	if _, err := store.GetUint64([]byte("missing")); err == nil {
		t.Fatal("expected missing uint64 error")
	}
	if err := store.Set([]byte("bad"), []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetUint64([]byte("bad")); err == nil {
		t.Fatal("expected invalid uint64 error")
	}
}

func TestStorageErrorPaths(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig().Storage
	if _, err := NewBoltStore(file, cfg, 2, 8, nil); err == nil {
		t.Fatal("expected bolt store error")
	}
	if _, err := NewSharedBoltStore(file, "node", cfg, 2, 8, nil); err == nil {
		t.Fatal("expected shared bolt error")
	}
	if _, err := NewSecureFileSnapshotStore(file, 2, nil); err == nil {
		t.Fatal("expected snapshot store error")
	}
	if _, err := LoadOrGenerateNodeID(file); err == nil {
		t.Fatal("expected node id error")
	}
}

func TestAESGCMKeeperMissingPrimary(t *testing.T) {
	keeper := &AESGCMKeeper{keys: map[string][]byte{}, primary: "missing", aad: "aad"}
	if _, err := keeper.Seal([]byte("x")); err == nil {
		t.Fatal("expected seal error")
	}
	if _, err := keeper.SealString("x"); err == nil {
		t.Fatal("expected seal string error")
	}
	if got, err := keeper.OpenString("not-json"); err != nil || got != "not-json" {
		t.Fatalf("open string = %q err=%v", got, err)
	}
}

func TestBoltStoreClosedErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig().Storage
	store, err := NewBoltStore(dir, cfg, 2, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	if err := store.SetRemovedFlag(); err == nil {
		t.Fatal("expected set removed error after close")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultBoltOptionsZero(t *testing.T) {
	opts := defaultBoltOptions(config.StorageConfig{})
	if opts.BoltOptions.Timeout <= 0 || opts.BoltOptions.InitialMmapSize <= 0 {
		t.Fatalf("opts = %+v", opts.BoltOptions)
	}
}

func TestLoadOrGenerateNodeIDEmptyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "node-id"), []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := LoadOrGenerateNodeID(dir)
	if err != nil || id == "" {
		t.Fatalf("id = %q err=%v", id, err)
	}
}

func TestSharedBoltDeleteRangeMissingBucket(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig().Storage
	store, err := NewSharedBoltStore(dir, "node", cfg, 2, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.DeleteRange(1, 2); err != nil {
		t.Fatalf("DeleteRange: %v", err)
	}
}

func TestAESGCMKeeperOpenErrors(t *testing.T) {
	keeper, _ := NewAESGCMKeeper("k1", map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)}, "aad")
	sealed, _ := keeper.Seal([]byte("x"))
	badNonce := sealed
	badNonce.Non = "bad"
	if _, err := keeper.Open(badNonce); err == nil {
		t.Fatal("expected nonce error")
	}
	badCt := sealed
	badCt.Ct = "bad"
	if _, err := keeper.Open(badCt); err == nil {
		t.Fatal("expected ciphertext error")
	}
	badCtx := sealed
	badCtx.Ctx = "bad"
	if _, err := keeper.Open(badCtx); err == nil {
		t.Fatal("expected context error")
	}
	tampered := sealed
	tampered.Ct = "AAAA"
	if _, err := keeper.Open(tampered); err == nil {
		t.Fatal("expected decrypt error")
	}
}

func TestGenerateKeyFileError(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := GenerateKeyFile(filepath.Join(file, "keys.json")); err == nil {
		t.Fatal("expected key file error")
	}
}

func TestNilStoreClose(t *testing.T) {
	if err := (&BoltStore{}).Close(); err != nil {
		t.Fatal(err)
	}
	if err := (&SharedBoltStore{}).Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotStoreDefaultRetain(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewSecureFileSnapshotStore(dir, 0, nil); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAESGCMKeeperErrors(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"missing-primary": `{"keys":{"k1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`,
		"bad-base64":      `{"primary":"k1","keys":{"k1":"!!!"}}`,
		"short-key":       `{"primary":"k1","keys":{"k1":"AAAA"}}`,
		"primary-missing": `{"primary":"k2","keys":{"k1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`,
	}
	for name, content := range cases {
		path := filepath.Join(dir, fmt.Sprintf("%s.json", name))
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadAESGCMKeeper(path, "aad"); err == nil {
			t.Fatalf("expected error for %s", name)
		}
	}
}

func TestAESGCMKeeperBadKey(t *testing.T) {
	keeper := &AESGCMKeeper{keys: map[string][]byte{"k1": []byte("short")}, primary: "k1", aad: "aad"}
	if _, err := keeper.Seal([]byte("x")); err == nil {
		t.Fatal("expected cipher error")
	}
}

func TestSharedBoltStoreNodeIDPathError(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig().Storage
	if _, err := NewSharedBoltStore(dir, "a/b", cfg, 2, 8, nil); err == nil {
		t.Fatal("expected open error")
	}
}

func TestDeriveAESGCMKeyAndKeeper(t *testing.T) {
	secret := []byte("0123456789abcdef")
	if _, err := DeriveAESGCMKey([]byte("short"), ""); !errors.Is(err, ErrSecretTooShort) {
		t.Fatalf("short secret err = %v", err)
	}
	key1, err := DeriveAESGCMKey(secret, "")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	key2, err := DeriveAESGCMKey(secret, DefaultHKDFInfo)
	if err != nil {
		t.Fatalf("derive default info: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("default info is not deterministic")
	}
	key3, err := DeriveAESGCMKey(secret, "other-info")
	if err != nil {
		t.Fatalf("derive other info: %v", err)
	}
	if bytes.Equal(key1, key3) {
		t.Fatal("domain separation failed")
	}

	keeper, err := DeriveAESGCMKeeper(secret, "", "aad")
	if err != nil {
		t.Fatalf("derive keeper: %v", err)
	}
	sealed, err := keeper.SealString("secret-value")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	opened, err := keeper.OpenString(sealed)
	if err != nil || opened != "secret-value" {
		t.Fatalf("open = %q err=%v", opened, err)
	}
	if plain, err := keeper.OpenString("plaintext"); err != nil || plain != "plaintext" {
		t.Fatalf("lazy migration = %q err=%v", plain, err)
	}

	raw := []byte("0123456789abcdef0123456789abcdef")
	copied, err := NewAESGCMKeeper("k1", map[string][]byte{"k1": raw}, "aad")
	if err != nil {
		t.Fatalf("new keeper: %v", err)
	}
	sealed, err = copied.SealString("value")
	if err != nil {
		t.Fatalf("seal copied: %v", err)
	}
	for i := range raw {
		raw[i] = 0
	}
	if opened, err := copied.OpenString(sealed); err != nil || opened != "value" {
		t.Fatalf("defensive copy failed: %q err=%v", opened, err)
	}
}

func TestLoadOrDeriveAESGCMKeeper(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "keys.json")
	if err := GenerateKeyFile(jsonPath); err != nil {
		t.Fatalf("generate key file: %v", err)
	}
	rawPath := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(rawPath, []byte("0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	shortPath := filepath.Join(dir, "short.txt")
	if err := os.WriteFile(shortPath, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		cfg     config.StorageConfig
		wantNil bool
		wantErr bool
	}{
		{name: "json file", cfg: config.StorageConfig{AtRestKeyFile: jsonPath, AtRestKeyInfo: "info"}},
		{name: "raw file", cfg: config.StorageConfig{AtRestKeyFile: rawPath, AtRestKeyInfo: "info"}},
		{name: "raw key", cfg: config.StorageConfig{AtRestKey: "0123456789abcdef", AtRestKeyInfo: "info"}},
		{name: "none", cfg: config.StorageConfig{}, wantNil: true},
		{name: "short key", cfg: config.StorageConfig{AtRestKey: "short"}, wantErr: true},
		{name: "short file", cfg: config.StorageConfig{AtRestKeyFile: shortPath}, wantErr: true},
		{name: "missing file", cfg: config.StorageConfig{AtRestKeyFile: filepath.Join(dir, "missing")}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keeper, err := LoadOrDeriveAESGCMKeeper(tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNil {
				if keeper != nil {
					t.Fatal("expected nil keeper")
				}
				return
			}
			if keeper == nil {
				t.Fatal("expected keeper")
			}
			sealed, err := keeper.SealString("value")
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			if opened, err := keeper.OpenString(sealed); err != nil || opened != "value" {
				t.Fatalf("open = %q err=%v", opened, err)
			}
		})
	}
}
