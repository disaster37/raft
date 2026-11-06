package compat

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	hraft "github.com/hashicorp/raft"
	bolt "go.etcd.io/bbolt"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	raft "github.com/disaster37/raft"
	"github.com/disaster37/raft/config"
	"github.com/disaster37/raft/fsm"
	"github.com/disaster37/raft/k8s"
	"github.com/disaster37/raft/storage"
	"github.com/disaster37/raft/testutil"
)

func TestGohookbridgeCompat(t *testing.T) {
	cfg := config.FromGohookbridgeFlags(config.GohookbridgeFlags{
		Dir:             t.TempDir(),
		NodeID:          "node-0",
		BindAddr:        "127.0.0.1:0",
		Replicas:        1,
		TLSEnabled:      true,
		KeyringRotation: true,
	})
	if cfg.Storage.Backend != config.StorageBackendSharedBolt || cfg.TLS.AllowAutoCAMultiNode {
		t.Fatalf("adapter = %+v", cfg)
	}

	// BoltKVFSM set/delete/set-multi.
	db, err := bolt.Open(filepath.Join(t.TempDir(), "fsm.db"), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	kv := fsm.NewBoltKVFSM(db)
	apply := func(kind uint8, payload any) interface{} {
		data, err := (fsm.CommandCodec{}).Encode(kind, payload)
		if err != nil {
			t.Fatal(err)
		}
		return kv.Apply(&hraft.Log{Data: data})
	}
	if resp := apply(fsm.KindSet, fsm.KVEntry{Bucket: "users", Key: "u1", Value: []byte("user")}); resp != nil {
		t.Fatalf("set resp = %v", resp)
	}
	if resp := apply(fsm.KindSetMulti, fsm.SetMultiPayload{Entries: []fsm.KVEntry{
		{Bucket: "users", Key: "u2", Value: []byte("user2")},
		{Bucket: "index", Key: "u2", Value: []byte("u2")},
	}}); resp != nil {
		t.Fatalf("multi resp = %v", resp)
	}
	if got, ok, _ := kv.Get("users", "u2"); !ok || string(got) != "user2" {
		t.Fatalf("u2 = %q ok=%v", got, ok)
	}
	if resp := apply(fsm.KindDelete, fsm.KVEntry{Bucket: "users", Key: "u1"}); resp != nil {
		t.Fatalf("delete resp = %v", resp)
	}
	if _, ok, _ := kv.Get("users", "u1"); ok {
		t.Fatal("u1 not deleted")
	}

	// AESGCMKeeper sealing and lazy migration.
	keyFile := filepath.Join(t.TempDir(), "keys.json")
	if err := storage.GenerateKeyFile(keyFile); err != nil {
		t.Fatal(err)
	}
	keeper, err := storage.LoadAESGCMKeeper(keyFile, "gohookbridge.at-rest.v1")
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := keeper.SealString("secret")
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := keeper.OpenString(sealed); err != nil || opened != "secret" {
		t.Fatalf("opened = %q err=%v", opened, err)
	}
	if legacy, err := keeper.OpenString("plain"); err != nil || legacy != "plain" {
		t.Fatalf("legacy = %q err=%v", legacy, err)
	}
}

func TestGohookbridgeSingleNodeRecovery(t *testing.T) {
	replicas := int32(1)
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "ca", Namespace: "ns"},
			Data:       map[string][]byte{"generation": []byte("0")},
		},
		&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: "sts", Namespace: "ns"},
			Spec:       appsv1.StatefulSetSpec{Replicas: &replicas},
		},
	)
	genStore := k8s.NewGenerationStore(client, "ns", "ca")
	replicaReader := k8s.NewStatefulSetReplicaReader(client, "ns", "sts")
	dir := t.TempDir()

	start := func(singleNodeRecovery bool) *raft.Node {
		ln := testutil.FreeListener(t)
		addr := testutil.FreeAddrFromListener(t, ln)
		cfg := config.DefaultConfig()
		cfg.Dir = dir
		cfg.NodeID = "node-0"
		cfg.BindAddr = addr
		cfg.AdvertiseAddr = addr
		cfg.Storage.Backend = config.StorageBackendSharedBolt
		cfg.SingleNodeRecovery = singleNodeRecovery
		cfg.Autopilot.Enabled = false
		cfg.Join.Interval = 100 * time.Millisecond
		cfg.PerformanceMultiplier = 1.0
		n, err := raft.NewNode(context.Background(), &cfg, raft.NodeOptions{
			CustomListener:         ln,
			GenerationFencer:       genStore,
			ReplicaCountAuthorizer: replicaReader,
			Logger:                 discardLogger(),
		})
		if err != nil {
			t.Fatalf("NewNode: %v", err)
		}
		if err := n.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := n.WaitForLeader(ctx); err != nil {
			t.Fatalf("WaitForLeader: %v", err)
		}
		return n
	}

	n1 := start(false)
	if _, err := n1.ApplyCommand(context.Background(), fsm.KindSet, fsm.KVEntry{Bucket: "b", Key: "k", Value: []byte("v")}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := n1.Close(); err != nil {
		t.Fatal(err)
	}

	n2 := start(true)
	defer n2.Close()
	got, ok, err := n2.KV().Get("b", "k")
	if err != nil || !ok || string(got) != "v" {
		t.Fatalf("recovered = %q ok=%v err=%v", got, ok, err)
	}
	gen, ok := genStore.ReadClusterGeneration(context.Background())
	if !ok || gen != 1 {
		t.Fatalf("generation = %d ok=%v", gen, ok)
	}
}
