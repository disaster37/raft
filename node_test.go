package raft_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	hraft "github.com/hashicorp/raft"

	raft "github.com/disaster37/go-raft"
	"github.com/disaster37/go-raft/config"
	"github.com/disaster37/go-raft/discovery"
	"github.com/disaster37/go-raft/fsm"
	"github.com/disaster37/go-raft/keyring"
	"github.com/disaster37/go-raft/storage"
	"github.com/disaster37/go-raft/testutil"
)

func TestNewInmemNodeApplyAndKV(t *testing.T) {
	n, err := raft.NewInmemNode("node-inmem", nil, 5*time.Second, nil)
	if err != nil {
		t.Fatalf("NewInmemNode: %v", err)
	}
	defer n.Close()
	if !n.IsLeader() || !n.IsVoter() || !n.IsStarted() {
		t.Fatalf("leader=%v voter=%v started=%v", n.IsLeader(), n.IsVoter(), n.IsStarted())
	}
	if n.NodeID() != "node-inmem" {
		t.Fatalf("node id = %q", n.NodeID())
	}
	if n.LeaderAddress() == "" {
		t.Fatal("empty leader address")
	}
	if addr, id := n.LeaderWithID(); addr == "" || id == "" {
		t.Fatalf("leader with id = %q,%q", addr, id)
	}
	if n.Stats()["state"] != "Leader" {
		t.Fatalf("stats = %v", n.Stats())
	}
	if _, err := n.GetConfiguration(); err != nil {
		t.Fatalf("GetConfiguration: %v", err)
	}
	if n.AppliedIndex() == 0 || n.CommittedIndex() == 0 {
		t.Fatalf("indices = %d,%d", n.AppliedIndex(), n.CommittedIndex())
	}
	if n.FSM() == nil || n.KV() == nil || n.Storage() == nil || n.RawRaft() == nil {
		t.Fatal("missing components")
	}
	if n.TLSProvider() != nil || n.KeyringManager() != nil {
		t.Fatal("unexpected TLS components")
	}
	if n.Autopilot() == nil {
		t.Fatal("missing autopilot")
	}

	ctx := context.Background()
	if _, err := n.ApplyCommand(ctx, fsm.KindSet, fsm.KVEntry{Bucket: "b", Key: "k", Value: []byte("v")}); err != nil {
		t.Fatalf("ApplyCommand: %v", err)
	}
	got, ok, err := n.KV().Get("b", "k")
	if err != nil || !ok || string(got) != "v" {
		t.Fatalf("get = %q ok=%v err=%v", got, ok, err)
	}
	if err := n.ApplyMulti(ctx, []fsm.KVEntry{
		{Bucket: "b", Key: "a", Value: []byte("1")},
		{Bucket: "b", Key: "b", Value: []byte("2")},
	}); err != nil {
		t.Fatalf("ApplyMulti: %v", err)
	}
	list, err := n.KV().ListPrefix("b", "")
	if err != nil || len(list) != 3 {
		t.Fatalf("list = %v err=%v", list, err)
	}
	if has, _ := n.KV().HasData(); !has {
		t.Fatal("expected data")
	}
	if err := n.WaitForCleanState(ctx); err != nil {
		t.Fatalf("WaitForCleanState: %v", err)
	}
	if !n.IsCleanState() {
		t.Fatal("expected clean state")
	}
	if err := n.WaitForSelfLeadership(ctx); err != nil {
		t.Fatalf("WaitForSelfLeadership: %v", err)
	}
	if err := n.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := n.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := n.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestNewNodeInvalidConfig(t *testing.T) {
	if _, err := raft.NewNode(context.Background(), nil, raft.NodeOptions{}); !errors.Is(err, raft.ErrInvalidConfig) {
		t.Fatalf("err = %v", err)
	}
	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Storage.Backend = "bad"
	if _, err := raft.NewNode(context.Background(), &cfg, raft.NodeOptions{}); !errors.Is(err, raft.ErrInvalidConfig) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewNodeSharedBolt(t *testing.T) {
	ln := testutil.FreeListener(t)
	addr := testutil.FreeAddrFromListener(t, ln)
	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Dir = t.TempDir()
	cfg.NodeID = "shared-node"
	cfg.BindAddr = addr
	cfg.AdvertiseAddr = addr
	cfg.Storage.Backend = config.StorageBackendSharedBolt
	cfg.Autopilot.Enabled = false
	cfg.Join.Interval = 100 * time.Millisecond
	n, err := raft.NewNode(context.Background(), &cfg, raft.NodeOptions{CustomListener: ln})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer n.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.WaitForLeader(ctx); err != nil {
		t.Fatalf("WaitForLeader: %v", err)
	}
	if n.Storage().BoltDB() == nil {
		t.Fatal("expected shared bolt DB")
	}
	if n.KV() == nil {
		t.Fatal("expected BoltKVFSM")
	}
	if _, err := n.ApplyCommand(ctx, fsm.KindSet, fsm.KVEntry{Bucket: "b", Key: "k", Value: []byte("v")}); err != nil {
		t.Fatalf("ApplyCommand: %v", err)
	}
}

func TestNewNodeCustomFSM(t *testing.T) {
	ln := testutil.FreeListener(t)
	addr := testutil.FreeAddrFromListener(t, ln)
	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Dir = t.TempDir()
	cfg.NodeID = "custom-node"
	cfg.BindAddr = addr
	cfg.AdvertiseAddr = addr
	cfg.Storage.Backend = config.StorageBackendInmem
	cfg.Autopilot.Enabled = false
	cfg.Join.Interval = 100 * time.Millisecond
	custom := fsm.NewMemoryKVFSM(nil)
	n, err := raft.NewNode(context.Background(), &cfg, raft.NodeOptions{FSM: custom, CustomListener: ln})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer n.Close()
	if n.KV() != nil {
		t.Fatal("custom FSM should not expose KV")
	}
	if n.FSM() == nil {
		t.Fatal("missing FSM")
	}
}

func TestWaitForLeaderTimeout(t *testing.T) {
	ln := testutil.FreeListener(t)
	addr := testutil.FreeAddrFromListener(t, ln)
	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Dir = t.TempDir()
	cfg.NodeID = "timeout-node"
	cfg.BindAddr = addr
	cfg.AdvertiseAddr = addr
	cfg.Storage.Backend = config.StorageBackendInmem
	cfg.Autopilot.Enabled = false
	cfg.Join.Interval = time.Hour
	n, err := raft.NewNode(context.Background(), &cfg, raft.NodeOptions{CustomListener: ln})
	if err != nil {
		t.Fatal(err)
	}
	// Not started: WaitForLeader must time out.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := n.WaitForLeader(ctx); err == nil {
		t.Fatal("expected timeout")
	}
	if n.IsCleanState() {
		t.Fatal("not started node should not be clean")
	}
	if _, err := n.Apply(context.Background(), []byte("x")); !errors.Is(err, raft.ErrAlreadyClosed) {
		t.Fatalf("err = %v", err)
	}
}

func TestApplyOversizedEntry(t *testing.T) {
	n, err := raft.NewInmemNode("node-oversize", nil, 5*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	n.RawRaft()
	// MaxEntrySize defaults to 1 MiB; a 2 MiB payload must be rejected.
	big := make([]byte, 2*1024*1024)
	if _, err := n.Apply(context.Background(), big); err == nil {
		t.Fatal("expected oversized entry error")
	}
}

func TestRemovedNodeCallback(t *testing.T) {
	ln0 := testutil.FreeListener(t)
	ln1 := testutil.FreeListener(t)
	addr0 := testutil.FreeAddrFromListener(t, ln0)
	addr1 := testutil.FreeAddrFromListener(t, ln1)
	peers := []config.PeerConfig{{ID: "node-0", Address: addr0}, {ID: "node-1", Address: addr1}}
	start := func(id, addr string, ln net.Listener, callback func()) *raft.Node {
		cfg := config.DefaultConfig()
		cfg.PerformanceMultiplier = 0.2
		cfg.Dir = t.TempDir()
		cfg.NodeID = id
		cfg.BindAddr = addr
		cfg.AdvertiseAddr = addr
		cfg.Discovery.Peers = peers
		cfg.Discovery.Replicas = 2
		cfg.AllowInsecureMultiNode = true
		cfg.Storage.Backend = config.StorageBackendInmem
		cfg.Autopilot.Enabled = false
		cfg.Join.Interval = time.Hour
		n, err := raft.NewNode(context.Background(), &cfg, raft.NodeOptions{CustomListener: ln, RemovedCallback: callback})
		if err != nil {
			t.Fatalf("NewNode %s: %v", id, err)
		}
		if err := n.Start(context.Background()); err != nil {
			t.Fatalf("Start %s: %v", id, err)
		}
		return n
	}
	called := make(chan struct{}, 1)
	n0 := start("node-0", addr0, ln0, nil)
	defer n0.Close()
	n1 := start("node-1", addr1, ln1, func() { called <- struct{}{} })
	defer n1.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := n0.WaitForLeader(ctx); err != nil {
		t.Fatalf("WaitForLeader: %v", err)
	}
	if err := n0.AddVoter("node-1", addr1, 5*time.Second); err != nil {
		t.Fatalf("AddVoter: %v", err)
	}
	if err := n1.WaitForCleanState(ctx); err != nil {
		t.Fatalf("WaitForCleanState: %v", err)
	}
	time.Sleep(1500 * time.Millisecond)
	if err := n0.RemoveServer("node-1", 5*time.Second); err != nil {
		t.Fatalf("RemoveServer: %v", err)
	}
	for i := 0; i < 20; i++ {
		t.Logf("tick %d removed=%v voter=%v nonvoter=%v", i, n1.IsRemoved(), n1.IsVoter(), n1.IsNonVoter())
		select {
		case <-called:
			if !n1.IsRemoved() {
				t.Fatal("expected node to be removed")
			}
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
	t.Fatal("removed callback not invoked")
}

func ExampleNewNode() {
	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Dir = "/tmp/raft-example"
	cfg.NodeID = "example-node"
	cfg.BindAddr = "127.0.0.1:0"
	cfg.AdvertiseAddr = "127.0.0.1:0"
	cfg.Storage.Backend = config.StorageBackendInmem
	cfg.Autopilot.Enabled = false
	_ = cfg
	_ = hraft.ServerID("example-node")
	// Output:
}

func TestNodeMembershipAndLeadership(t *testing.T) {
	ln0 := testutil.FreeListener(t)
	ln1 := testutil.FreeListener(t)
	addr0 := testutil.FreeAddrFromListener(t, ln0)
	addr1 := testutil.FreeAddrFromListener(t, ln1)
	peers := []config.PeerConfig{{ID: "node-0", Address: addr0}, {ID: "node-1", Address: addr1}}
	start := func(id, addr string, ln net.Listener) *raft.Node {
		cfg := config.DefaultConfig()
		cfg.PerformanceMultiplier = 0.2
		cfg.Dir = t.TempDir()
		cfg.NodeID = id
		cfg.BindAddr = addr
		cfg.AdvertiseAddr = addr
		cfg.Discovery.Peers = peers
		cfg.Discovery.Replicas = 2
		cfg.AllowInsecureMultiNode = true
		cfg.Storage.Backend = config.StorageBackendInmem
		cfg.Autopilot.Enabled = false
		cfg.Join.Interval = time.Hour
		n, err := raft.NewNode(context.Background(), &cfg, raft.NodeOptions{CustomListener: ln})
		if err != nil {
			t.Fatalf("NewNode %s: %v", id, err)
		}
		if err := n.Start(context.Background()); err != nil {
			t.Fatalf("Start %s: %v", id, err)
		}
		return n
	}
	n0 := start("node-0", addr0, ln0)
	defer n0.Close()
	n1 := start("node-1", addr1, ln1)
	defer n1.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := n0.WaitForLeader(ctx); err != nil {
		t.Fatalf("WaitForLeader: %v", err)
	}
	if err := n0.AddVoter("node-1", addr1, 5*time.Second); err != nil {
		t.Fatalf("AddVoter: %v", err)
	}
	if err := n1.WaitForCleanState(ctx); err != nil {
		t.Fatalf("WaitForCleanState: %v", err)
	}
	if !n1.IsVoter() || n1.IsNonVoter() {
		t.Fatal("node-1 should be a voter")
	}
	if !n1.IsCleanState() {
		t.Fatal("node-1 should be clean")
	}
	if _, err := n1.Apply(ctx, []byte("x")); !errors.Is(err, raft.ErrNotLeader) {
		t.Fatalf("follower apply err = %v", err)
	}
	if _, err := n1.ApplyKeyring(ctx, &keyring.TLSKeyring{}); !errors.Is(err, raft.ErrNotLeader) {
		t.Fatalf("follower apply keyring err = %v", err)
	}
	if err := n0.AddNonvoter("nonvoter", "127.0.0.1:1", time.Second); err != nil {
		t.Fatalf("AddNonvoter: %v", err)
	}
	if err := n0.RemoveServer("nonvoter", time.Second); err != nil {
		t.Fatalf("RemoveServer nonvoter: %v", err)
	}
	added, updated, removed, err := n0.ReconcileMembership([]discovery.Peer{
		{ID: "node-0", Address: addr0},
		{ID: "node-1", Address: addr1},
		{ID: "bad", Address: "bad.invalid:1"},
	}, time.Second)
	if err != nil {
		t.Fatalf("ReconcileMembership: %v", err)
	}
	if len(added) != 0 || len(updated) != 0 || len(removed) != 0 {
		t.Fatalf("reconcile = %v %v %v", added, updated, removed)
	}
	if err := n0.TransferLeadership(ctx, 5*time.Second); err != nil {
		t.Fatalf("TransferLeadership: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if n1.IsLeader() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !n1.IsLeader() {
		t.Fatal("leadership was not transferred")
	}
	if err := n1.StepDown(ctx); err != nil {
		t.Fatalf("StepDown: %v", err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if n0.IsLeader() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := n0.LeaveCluster(ctx, 5*time.Second); err != nil {
		t.Fatalf("LeaveCluster: %v", err)
	}
}

func TestNodeKeyringApplierAndRecoveryHelpers(t *testing.T) {
	n, err := raft.NewInmemNode("node-keyring", nil, 5*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if n.MinFollowerAppliedIndex() == 0 {
		t.Fatal("expected local applied index")
	}
	if kr, err := n.ReadKeyring(); err != nil || kr != nil {
		t.Fatalf("keyring = %+v err=%v", kr, err)
	}
	if _, err := n.ApplyKeyring(context.Background(), nil); err == nil {
		t.Fatal("expected nil keyring error")
	}
	kr := &keyring.TLSKeyring{Keys: []*keyring.TLSKey{{ID: "k1", PKIMode: "shared-ca", CertPEM: []byte("cert")}}, ActiveKeyID: "k1", Term: 1}
	if _, err := n.ApplyKeyring(context.Background(), kr); err != nil {
		t.Fatalf("ApplyKeyring: %v", err)
	}
	got, err := n.ReadKeyring()
	if err != nil || got == nil || got.Term != 1 {
		t.Fatalf("ReadKeyring = %+v err=%v", got, err)
	}
	dir := t.TempDir()
	if err := raft.RecoverPeersJSON(dir, []hraft.Server{{ID: "a", Address: "a:1", Suffrage: hraft.Voter}}); err != nil {
		t.Fatalf("RecoverPeersJSON: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "peers.json")); err != nil {
		t.Fatal(err)
	}
	if err := raft.RecoverPeersJSON("", nil); err == nil {
		t.Fatal("expected empty dir error")
	}
	if err := raft.RecoverPeersJSON(dir, nil); err == nil {
		t.Fatal("expected no servers error")
	}
}

func TestNodeNonVoter(t *testing.T) {
	ln0 := testutil.FreeListener(t)
	ln1 := testutil.FreeListener(t)
	addr0 := testutil.FreeAddrFromListener(t, ln0)
	addr1 := testutil.FreeAddrFromListener(t, ln1)
	peers := []config.PeerConfig{{ID: "node-0", Address: addr0}, {ID: "node-1", Address: addr1}}
	start := func(id, addr string, ln net.Listener) *raft.Node {
		cfg := config.DefaultConfig()
		cfg.PerformanceMultiplier = 0.2
		cfg.Dir = t.TempDir()
		cfg.NodeID = id
		cfg.BindAddr = addr
		cfg.AdvertiseAddr = addr
		cfg.Discovery.Peers = peers
		cfg.Discovery.Replicas = 2
		cfg.AllowInsecureMultiNode = true
		cfg.Storage.Backend = config.StorageBackendInmem
		cfg.Autopilot.Enabled = false
		cfg.Join.Interval = time.Hour
		n, err := raft.NewNode(context.Background(), &cfg, raft.NodeOptions{CustomListener: ln})
		if err != nil {
			t.Fatalf("NewNode %s: %v", id, err)
		}
		if err := n.Start(context.Background()); err != nil {
			t.Fatalf("Start %s: %v", id, err)
		}
		return n
	}
	n0 := start("node-0", addr0, ln0)
	defer n0.Close()
	n1 := start("node-1", addr1, ln1)
	defer n1.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := n0.WaitForLeader(ctx); err != nil {
		t.Fatal(err)
	}
	if err := n0.AddNonvoter("node-1", addr1, 5*time.Second); err != nil {
		t.Fatalf("AddNonvoter: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if n1.IsNonVoter() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("node-1 should be a nonvoter")
}

func TestNodeAutoLoadsAtRestKeyFromConfig(t *testing.T) {
	ln := testutil.FreeListener(t)
	addr := testutil.FreeAddrFromListener(t, ln)
	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Dir = t.TempDir()
	cfg.NodeID = "at-rest-node"
	cfg.BindAddr = addr
	cfg.AdvertiseAddr = addr
	cfg.Storage.Backend = config.StorageBackendInmem
	cfg.Storage.AtRestKey = "0123456789abcdef0123456789abcdef"
	cfg.Storage.AtRestKeyInfo = storage.DefaultHKDFInfo
	cfg.TLS.Enabled = true
	cfg.TLS.KeyringRotationEnabled = true
	cfg.Autopilot.Enabled = false
	cfg.Join.Interval = 50 * time.Millisecond
	n, err := raft.NewNode(context.Background(), &cfg, raft.NodeOptions{CustomListener: ln})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer n.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.WaitForLeader(ctx); err != nil {
		t.Fatalf("WaitForLeader: %v", err)
	}
	var kr *keyring.TLSKeyring
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		kr, err = n.ReadKeyring()
		if err == nil && kr != nil && len(kr.Keys) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if kr == nil || len(kr.Keys) == 0 {
		t.Fatal("keyring was not seeded")
	}
	if !strings.Contains(kr.Keys[0].KeyPEM, `"alg":"A256GCM"`) {
		t.Fatalf("keyring private key is not sealed: %q", kr.Keys[0].KeyPEM)
	}
	keeper, err := storage.DeriveAESGCMKeeper([]byte(cfg.Storage.AtRestKey), cfg.Storage.AtRestKeyInfo, cfg.Storage.AtRestKeyInfo)
	if err != nil {
		t.Fatalf("derive keeper: %v", err)
	}
	plain, err := keeper.OpenString(kr.Keys[0].KeyPEM)
	if err != nil {
		t.Fatalf("open sealed key: %v", err)
	}
	if !strings.Contains(plain, "PRIVATE KEY") {
		t.Fatalf("unsealed key is not a PEM private key: %q", plain)
	}
}
