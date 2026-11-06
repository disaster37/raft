package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	raft "github.com/disaster37/raft"
	"github.com/disaster37/raft/config"
	"github.com/disaster37/raft/fsm"
	"github.com/disaster37/raft/k8s"
	"github.com/disaster37/raft/testutil"
)

type fakeFencer struct {
	gen   uint64
	bumps int
}

func (f *fakeFencer) ReadClusterGeneration(context.Context) (uint64, bool) {
	return f.gen, f.gen > 0
}

func (f *fakeFencer) BumpClusterGeneration(context.Context) (uint64, error) {
	f.gen++
	f.bumps++
	return f.gen, nil
}

func startNode(t *testing.T, dir, id string, peers []config.PeerConfig, singleNodeRecovery bool, fencer raft.GenerationFencer) *raft.Node {
	t.Helper()
	ln := testutil.FreeListener(t)
	addr := testutil.FreeAddrFromListener(t, ln)
	cfg := config.DefaultConfig()
	cfg.Dir = dir
	cfg.NodeID = id
	cfg.BindAddr = addr
	cfg.AdvertiseAddr = addr
	cfg.Discovery.Peers = peers
	cfg.Discovery.Replicas = len(peers)
	cfg.AllowInsecureMultiNode = true
	cfg.Storage.Backend = config.StorageBackendRaftBoltDB
	cfg.SingleNodeRecovery = singleNodeRecovery
	cfg.Autopilot.Enabled = false
	cfg.Join.Interval = 100 * time.Millisecond
	cfg.PerformanceMultiplier = 1.0
	n, err := raft.NewNode(context.Background(), &cfg, raft.NodeOptions{
		CustomListener:   ln,
		GenerationFencer: fencer,
		Logger:           discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewNode %s: %v", id, err)
	}
	if err := n.Start(context.Background()); err != nil {
		t.Fatalf("Start %s: %v", id, err)
	}
	return n
}

func waitLeader(t *testing.T, n *raft.Node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := n.WaitForLeader(ctx); err != nil {
		t.Fatalf("WaitForLeader: %v", err)
	}
}

func TestSingleNodeRecovery(t *testing.T) {
	dir := t.TempDir()
	fencer := &fakeFencer{}
	n1 := startNode(t, dir, "recover-node", nil, false, fencer)
	waitLeader(t, n1)
	if _, err := n1.ApplyCommand(context.Background(), fsm.KindSet, fsm.KVEntry{Bucket: "b", Key: "k", Value: []byte("v")}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := n1.Close(); err != nil {
		t.Fatalf("close n1: %v", err)
	}

	n2 := startNode(t, dir, "recover-node", nil, true, fencer)
	defer n2.Close()
	waitLeader(t, n2)
	if fencer.bumps != 1 {
		t.Fatalf("bumps = %d, want 1", fencer.bumps)
	}
	got, ok, err := n2.KV().Get("b", "k")
	if err != nil || !ok || string(got) != "v" {
		t.Fatalf("recovered value = %q ok=%v err=%v", got, ok, err)
	}
}

func TestGenerationFencingWipesStalePVC(t *testing.T) {
	staleDir := t.TempDir()
	stale := startNode(t, staleDir, "recover-node", nil, false, nil)
	waitLeader(t, stale)
	if _, err := stale.ApplyCommand(context.Background(), fsm.KindSet, fsm.KVEntry{Bucket: "b", Key: "stale", Value: []byte("stale")}); err != nil {
		t.Fatalf("apply stale: %v", err)
	}
	if err := stale.Close(); err != nil {
		t.Fatalf("close stale: %v", err)
	}
	if err := os.WriteFile(filepath.Join(staleDir, "generation"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The bootstrap node must advertise its real address; the peer list is
	// rewritten by the resolver using the actual listener addresses.
	lnA := testutil.FreeListener(t)
	addrA := testutil.FreeAddrFromListener(t, lnA)
	lnB := testutil.FreeListener(t)
	addrB := testutil.FreeAddrFromListener(t, lnB)
	peers := []config.PeerConfig{{ID: "aaa", Address: addrA}, {ID: "recover-node", Address: addrB}}

	cfgA := config.DefaultConfig()
	cfgA.Dir = t.TempDir()
	cfgA.NodeID = "aaa"
	cfgA.BindAddr = addrA
	cfgA.AdvertiseAddr = addrA
	cfgA.Discovery.Peers = peers
	cfgA.Discovery.Replicas = 2
	cfgA.AllowInsecureMultiNode = true
	cfgA.Storage.Backend = config.StorageBackendRaftBoltDB
	cfgA.Autopilot.Enabled = false
	cfgA.Join.Interval = time.Hour
	cfgA.PerformanceMultiplier = 1.0
	fencer := &fakeFencer{}
	a, err := raft.NewNode(context.Background(), &cfgA, raft.NodeOptions{CustomListener: lnA, GenerationFencer: fencer, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewNode a: %v", err)
	}
	if err := a.Start(context.Background()); err != nil {
		t.Fatalf("Start a: %v", err)
	}
	defer a.Close()
	waitLeader(t, a)
	if _, err := a.ApplyCommand(context.Background(), fsm.KindSet, fsm.KVEntry{Bucket: "b", Key: "fresh", Value: []byte("fresh")}); err != nil {
		t.Fatalf("apply fresh: %v", err)
	}

	cfgB := config.DefaultConfig()
	cfgB.Dir = staleDir
	cfgB.NodeID = "recover-node"
	cfgB.BindAddr = addrB
	cfgB.AdvertiseAddr = addrB
	cfgB.Discovery.Peers = peers
	cfgB.Discovery.Replicas = 2
	cfgB.AllowInsecureMultiNode = true
	cfgB.Storage.Backend = config.StorageBackendRaftBoltDB
	cfgB.Autopilot.Enabled = false
	cfgB.Join.Interval = time.Hour
	cfgB.PerformanceMultiplier = 1.0
	fencer.gen = 1
	b, err := raft.NewNode(context.Background(), &cfgB, raft.NodeOptions{CustomListener: lnB, GenerationFencer: fencer, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("NewNode b: %v", err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Start b: %v", err)
	}
	defer b.Close()
	if err := a.AddVoter("recover-node", addrB, 5*time.Second); err != nil {
		t.Fatalf("AddVoter b: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := b.WaitForCleanState(ctx); err != nil {
		t.Fatalf("WaitForCleanState b: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok, _ := b.KV().Get("b", "fresh"); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok, _ := b.KV().Get("b", "fresh"); !ok {
		t.Fatal("fresh data did not replicate to the fenced node")
	}
	if _, ok, _ := b.KV().Get("b", "stale"); ok {
		t.Fatal("stale state was not wiped")
	}
	gen, ok := k8s.ReadLocalGeneration(staleDir)
	if !ok || gen != 1 {
		t.Fatalf("local generation = %d ok=%v", gen, ok)
	}
}
