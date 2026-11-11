package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	raft "github.com/disaster37/go-raft"
	"github.com/disaster37/go-raft/config"
	"github.com/disaster37/go-raft/fsm"
)

func TestThreeNodeMTLSClusterBootstrapJoinReplicateFailover(t *testing.T) {
	nodes := newTestCluster(t, 3, true, false)
	leader := leaderOf(t, nodes)
	ctx := context.Background()
	if _, err := leader.node.ApplyCommand(ctx, fsm.KindSet, fsm.KVEntry{Bucket: "b", Key: "k", Value: []byte("v")}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	for i, n := range nodes {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			got, ok, err := n.node.KV().Get("b", "k")
			if err == nil && ok && string(got) == "v" {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		got, ok, err := n.node.KV().Get("b", "k")
		if err != nil || !ok || string(got) != "v" {
			t.Fatalf("node %d value = %q ok=%v err=%v", i, got, ok, err)
		}
	}

	// Kill the leader and verify the remaining nodes elect a new one.
	if err := leader.node.Close(); err != nil {
		t.Fatalf("close leader: %v", err)
	}
	leader.node = nil
	remaining := make([]*testNode, 0, len(nodes))
	for _, n := range nodes {
		if n.node != nil {
			remaining = append(remaining, n)
		}
	}
	newLeader := leaderOf(t, remaining)
	if _, err := newLeader.node.ApplyCommand(ctx, fsm.KindSet, fsm.KVEntry{Bucket: "b", Key: "k2", Value: []byte("v2")}); err != nil {
		t.Fatalf("apply after failover: %v", err)
	}
}

func TestSnapshotAndRestore(t *testing.T) {
	nodes := newTestClusterWithConfig(t, 4, 3, true, true, func(_ int, cfg *config.Config, _ *raft.NodeOptions) {
		cfg.TrailingLogs = 1
		cfg.TLS.RotationPeriod = time.Hour
		cfg.Autopilot.CleanupDeadServers = false
		cfg.Autopilot.DeadServerLastContactThreshold = time.Hour
	})
	leader := leaderOf(t, nodes[:3])
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		key := fmt.Sprintf("k-%d", i)
		if _, err := leader.node.ApplyCommand(ctx, fsm.KindSet, fsm.KVEntry{Bucket: "b", Key: key, Value: []byte(key)}); err != nil {
			t.Fatalf("apply %d: %v", i, err)
		}
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok, _ := leader.node.KV().Get("b", "k-49"); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok, _ := leader.node.KV().Get("b", "k-49"); !ok {
		t.Fatal("leader did not apply data")
	}

	// Wait for the in-band keyring to be seeded before snapshotting.
	for time.Now().Before(deadline) {
		if kr := leader.node.KeyringManager().CurrentKeyring(); kr != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	leaderKeyring := leader.node.KeyringManager().CurrentKeyring()
	if leaderKeyring == nil {
		t.Fatal("leader keyring was not seeded")
	}

	// Force a snapshot and compaction so the new node must install a snapshot
	// instead of replaying the full log.
	if err := leader.node.RawRaft().Snapshot().Error(); err != nil {
		t.Fatalf("force snapshot: %v", err)
	}
	first, err := leader.node.Storage().LogStore().FirstIndex()
	if err != nil {
		t.Fatalf("first index: %v", err)
	}
	if first <= 1 {
		t.Fatalf("logs were not compacted (first index %d)", first)
	}

	// Start the fourth node and add it as a voter.
	startTestNode(t, nodes[3])
	if err := leader.node.AddVoter(nodeID(3), nodes[3].addr, 5*time.Second); err != nil {
		t.Fatalf("add fourth voter: %v", err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := nodes[3].node.WaitForCleanState(waitCtx); err != nil {
		t.Fatalf("fourth node clean state: %v", err)
	}
	if got, ok, err := nodes[3].node.KV().Get("b", "k-49"); err != nil || !ok || string(got) != "k-49" {
		t.Fatalf("fourth node KV = %q ok=%v err=%v", got, ok, err)
	}
	restoredKeyring := nodes[3].node.KeyringManager().CurrentKeyring()
	if restoredKeyring == nil {
		t.Fatal("fourth node did not restore the keyring")
	}
	if restoredKeyring.Term != leaderKeyring.Term {
		t.Fatalf("restored keyring term = %d, want %d", restoredKeyring.Term, leaderKeyring.Term)
	}
	if restoredKeyring.ActiveKeyID != leaderKeyring.ActiveKeyID {
		t.Fatalf("restored active key = %q, want %q", restoredKeyring.ActiveKeyID, leaderKeyring.ActiveKeyID)
	}
}

func TestGracefulLeaveCluster(t *testing.T) {
	removed := make([]chan struct{}, 3)
	for i := range removed {
		removed[i] = make(chan struct{}, 1)
	}
	nodes := newTestClusterWithConfig(t, 3, 3, true, false, func(i int, cfg *config.Config, opts *raft.NodeOptions) {
		cfg.Autopilot.CleanupDeadServers = false
		opts.RemovedCallback = func() {
			select {
			case removed[i] <- struct{}{}:
			default:
			}
		}
	})
	leader := leaderOf(t, nodes)
	leaderIdx := -1
	for i, n := range nodes {
		if n == leader {
			leaderIdx = i
			break
		}
	}
	if leaderIdx < 0 {
		t.Fatal("leader not found in node list")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := leader.node.LeaveCluster(ctx, 5*time.Second); err != nil {
		t.Fatalf("LeaveCluster: %v", err)
	}
	select {
	case <-removed[leaderIdx]:
	case <-time.After(10 * time.Second):
		t.Fatal("RemovedCallback was not invoked for the leaving node")
	}
	if !leader.node.IsRemoved() {
		t.Fatal("leader was not removed")
	}

	remaining := make([]*testNode, 0, len(nodes)-1)
	for _, n := range nodes {
		if n != leader {
			remaining = append(remaining, n)
		}
	}
	newLeader := leaderOf(t, remaining)
	var applyErr error
	for attempt := 0; attempt < 20; attempt++ {
		_, applyErr = newLeader.node.ApplyCommand(ctx, fsm.KindSet, fsm.KVEntry{Bucket: "b", Key: "after-leave", Value: []byte("ok")})
		if applyErr == nil {
			break
		}
		if !errors.Is(applyErr, raft.ErrNotLeader) {
			t.Fatalf("apply after leave: %v", applyErr)
		}
		time.Sleep(50 * time.Millisecond)
		newLeader = leaderOf(t, remaining)
	}
	if applyErr != nil {
		t.Fatalf("apply after leave: %v", applyErr)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		all := true
		for _, n := range remaining {
			if got, ok, _ := n.node.KV().Get("b", "after-leave"); !ok || string(got) != "ok" {
				all = false
				break
			}
		}
		if all {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("write after leave did not replicate to remaining voters")
}
