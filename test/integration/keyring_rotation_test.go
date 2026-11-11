package integration

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hraft "github.com/hashicorp/raft"

	raft "github.com/disaster37/go-raft"
	"github.com/disaster37/go-raft/config"
	"github.com/disaster37/go-raft/fsm"
	"github.com/disaster37/go-raft/keyring"
)

func TestPhasedRotationSharedCAModeUnderConcurrentWrites(t *testing.T) {
	nodes := newTestCluster(t, 3, true, true)
	leader := leaderOf(t, nodes)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var failures atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			key := fmt.Sprintf("concurrent-%d", i)
			var err error
			for attempt := 0; attempt < 50; attempt++ {
				_, err = leader.node.ApplyCommand(ctx, fsm.KindSet, fsm.KVEntry{Bucket: "b", Key: key, Value: []byte(key)})
				if err == nil {
					break
				}
				if ctx.Err() != nil {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err != nil && ctx.Err() == nil {
				failures.Add(1)
			}
			i++
			time.Sleep(5 * time.Millisecond)
		}
	}()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		kr := leader.node.KeyringManager().CurrentKeyring()
		if kr != nil && kr.Term >= 4 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	wg.Wait()
	kr := leader.node.KeyringManager().CurrentKeyring()
	if kr == nil || kr.Term < 4 {
		t.Fatalf("keyring term = %+v", kr)
	}
	if failures.Load() != 0 {
		t.Fatalf("failed writes = %d", failures.Load())
	}
}

func TestPhasedRotationSelfSignedMode(t *testing.T) {
	nodes := newSelfSignedClusterWithConfig(t, 3, nil, func(_ int, cfg *config.Config, _ *raft.NodeOptions) {
		cfg.TLS.RotationPeriod = 5 * time.Second
		cfg.Autopilot.CleanupDeadServers = false
		cfg.Autopilot.DeadServerLastContactThreshold = time.Hour
	})
	leader := leaderOf(t, nodes)
	waitForKeyring(t, leader, func(kr *keyring.TLSKeyring) bool {
		return kr != nil && kr.Term == 1 && len(kr.Keys) == 1
	})

	var follower *testNode
	for _, n := range nodes {
		if n != leader {
			follower = n
			break
		}
	}
	if follower == nil {
		t.Fatal("no follower found")
	}
	followerID := follower.node.NodeID()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if state, ok := leader.node.Autopilot().GetFollowerState(hraft.ServerID(followerID)); ok && state.AppliedIndex > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Pause the follower by stopping it. Its last echo keeps the leader's
	// MinFollowerAppliedIndex behind the staged keyring index.
	if err := follower.node.Close(); err != nil {
		t.Fatalf("close follower: %v", err)
	}
	waitForKeyring(t, leader, func(kr *keyring.TLSKeyring) bool {
		return kr != nil && kr.Term == 2 && len(kr.Keys) == 2 && kr.AppliedIndex != 0
	})
	staged := leader.node.KeyringManager().CurrentKeyring()
	if staged == nil || staged.AppliedIndex == 0 {
		t.Fatalf("staged keyring = %+v", staged)
	}

	// Phase 2 must not promote or prune while the follower lags.
	time.Sleep(2 * time.Second)
	kr := leader.node.KeyringManager().CurrentKeyring()
	if kr == nil || kr.Term != 2 || len(kr.Keys) != 2 {
		t.Fatalf("phase 2 promoted while follower lagged: %+v", kr)
	}
	if min := leader.node.MinFollowerAppliedIndex(); min >= staged.AppliedIndex {
		t.Fatalf("expected lagging follower: min=%d staged=%d", min, staged.AppliedIndex)
	}

	// Resume the follower and let it catch up; Phase 2 should then complete.
	restartTestNode(t, follower)
	waitForKeyring(t, leader, func(kr *keyring.TLSKeyring) bool {
		return kr != nil && kr.Term >= 3 && len(kr.Keys) == 1
	})
	final := leader.node.KeyringManager().CurrentKeyring()
	if final.ActiveKeyID != staged.Keys[1].ID {
		t.Fatalf("old key was not pruned: active=%q want=%q", final.ActiveKeyID, staged.Keys[1].ID)
	}
}

func waitForKeyring(t *testing.T, node *testNode, ready func(*keyring.TLSKeyring) bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if ready(node.node.KeyringManager().CurrentKeyring()) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("keyring condition not met: %+v", node.node.KeyringManager().CurrentKeyring())
}
