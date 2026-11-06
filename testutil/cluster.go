package testutil

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	raft "github.com/disaster37/raft"
	"github.com/disaster37/raft/config"
)

// TestCluster is a loopback Raft cluster for tests. It uses the in-memory
// storage backend and fast timings, and closes every node in t.Cleanup.
type TestCluster struct {
	Nodes     []*raft.Node
	Addrs     []string
	Listeners []net.Listener
}

// NewTestCluster starts count loopback nodes with static peer discovery.
// When tlsEnabled is true, each node uses a local CA and mTLS.
func NewTestCluster(t *testing.T, count int, tlsEnabled bool) *TestCluster {
	t.Helper()
	if count < 1 {
		t.Fatalf("test cluster: count must be >= 1")
	}
	ctx := context.Background()
	cluster := &TestCluster{
		Nodes:     make([]*raft.Node, count),
		Addrs:     make([]string, count),
		Listeners: make([]net.Listener, count),
	}
	for i := 0; i < count; i++ {
		cluster.Listeners[i] = FreeListener(t)
		cluster.Addrs[i] = FreeAddrFromListener(t, cluster.Listeners[i])
	}
	peers := make([]config.PeerConfig, count)
	for i := 0; i < count; i++ {
		peers[i] = config.PeerConfig{ID: fmt.Sprintf("node-%d", i), Address: cluster.Addrs[i]}
	}
	for i := 0; i < count; i++ {
		cfg := config.DefaultConfig()
		cfg.Dir = t.TempDir()
		cfg.NodeID = fmt.Sprintf("node-%d", i)
		cfg.BindAddr = cluster.Addrs[i]
		cfg.AdvertiseAddr = cluster.Addrs[i]
		cfg.Discovery.Peers = peers
		cfg.Discovery.Replicas = count
		cfg.AllowInsecureMultiNode = true
		cfg.Storage.Backend = config.StorageBackendInmem
		cfg.PerformanceMultiplier = 1.0
		cfg.ApplyTimeout = 5 * time.Second
		cfg.Join.Interval = 100 * time.Millisecond
		cfg.Join.ReconcileTimeout = 2 * time.Second
		cfg.Autopilot.Enabled = true
		cfg.Autopilot.HeartbeatInterval = 100 * time.Millisecond
		cfg.Autopilot.DeadServerLastContactThreshold = 2 * time.Second
		cfg.Autopilot.MinQuorum = 1
		cfg.Autopilot.StabilizationTime = 100 * time.Millisecond
		cfg.TLS.Enabled = tlsEnabled
		cfg.TLS.AllowAutoCAMultiNode = true
		cfg.TLS.CASecret = "test-ca"
		cfg.TLS.KeyringRotationEnabled = false
		node, err := raft.NewNode(ctx, &cfg, raft.NodeOptions{CustomListener: cluster.Listeners[i]})
		if err != nil {
			t.Fatalf("test cluster: NewNode %d: %v", i, err)
		}
		if err := node.Start(ctx); err != nil {
			t.Fatalf("test cluster: Start %d: %v", i, err)
		}
		cluster.Nodes[i] = node
	}
	t.Cleanup(func() { cluster.Close() })
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for i, node := range cluster.Nodes {
		if err := node.WaitForLeader(waitCtx); err != nil {
			t.Fatalf("test cluster: node %d WaitForLeader: %v", i, err)
		}
	}
	for i, node := range cluster.Nodes {
		if err := node.WaitForCleanState(waitCtx); err != nil {
			t.Fatalf("test cluster: node %d WaitForCleanState: %v", i, err)
		}
	}
	return cluster
}

// Leader returns the current leader, or nil.
func (c *TestCluster) Leader() *raft.Node {
	for _, node := range c.Nodes {
		if node != nil && node.IsLeader() {
			return node
		}
	}
	return nil
}

// Close shuts down every node. It is safe to call more than once.
func (c *TestCluster) Close() {
	for _, node := range c.Nodes {
		if node != nil {
			_ = node.Close()
		}
	}
}
