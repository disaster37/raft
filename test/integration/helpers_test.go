package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	raft "github.com/disaster37/go-raft"
	"github.com/disaster37/go-raft/config"
	"github.com/disaster37/go-raft/keyring"
	"github.com/disaster37/go-raft/observ"
	"github.com/disaster37/go-raft/pki"
	"github.com/disaster37/go-raft/testutil"
)

type staticBootstrapProvider struct {
	mat *pki.BootstrapMaterial
}

func (p *staticBootstrapProvider) EnsureBootstrapMaterial(context.Context) (*pki.BootstrapMaterial, error) {
	return p.mat, nil
}

type testNode struct {
	node     *raft.Node
	addr     string
	dir      string
	listener net.Listener
	cfg      *config.Config
	opts     raft.NodeOptions
}

func discardLogger() observ.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return observ.NewLogrusAdapter(l)
}

func newTestCluster(t *testing.T, count int, tlsEnabled, rotation bool) []*testNode {
	t.Helper()
	return newTestClusterWithConfig(t, count, count, tlsEnabled, rotation, nil)
}

func newTestClusterWithConfig(t *testing.T, count, startCount int, tlsEnabled, rotation bool, mutate func(i int, cfg *config.Config, opts *raft.NodeOptions)) []*testNode {
	t.Helper()
	ctx := context.Background()
	listeners := make([]net.Listener, count)
	addrs := make([]string, count)
	for i := 0; i < count; i++ {
		listeners[i] = testutil.FreeListener(t)
		addrs[i] = listeners[i].Addr().String()
	}

	var ca *pki.MintingCA
	var caPEM, caKeyPEM []byte
	if tlsEnabled {
		var err error
		ca, err = pki.NewMintingCA("test-ca", "test-org", 365*24*time.Hour)
		if err != nil {
			t.Fatalf("create CA: %v", err)
		}
		caPEM, caKeyPEM, err = ca.EncodePEM()
		if err != nil {
			t.Fatalf("encode CA: %v", err)
		}
	}

	peers := make([]config.PeerConfig, count)
	for i := 0; i < count; i++ {
		peers[i] = config.PeerConfig{ID: nodeID(i), Address: addrs[i]}
	}

	nodes := make([]*testNode, count)
	for i := 0; i < count; i++ {
		dir := t.TempDir()
		cfg := config.DefaultConfig()
		cfg.Dir = dir
		cfg.NodeID = nodeID(i)
		cfg.BindAddr = addrs[i]
		cfg.AdvertiseAddr = addrs[i]
		cfg.Discovery.Peers = peers
		cfg.Discovery.Replicas = count
		cfg.PerformanceMultiplier = 0.2
		cfg.ApplyTimeout = 5 * time.Second
		cfg.SnapshotThreshold = 20
		cfg.SnapshotInterval = 200 * time.Millisecond
		cfg.Join.Interval = 100 * time.Millisecond
		cfg.Join.ReconcileTimeout = 2 * time.Second
		cfg.Autopilot.Enabled = true
		cfg.Autopilot.HeartbeatInterval = 100 * time.Millisecond
		cfg.Autopilot.DeadServerLastContactThreshold = 2 * time.Second
		cfg.Autopilot.MinQuorum = 1
		cfg.Autopilot.StabilizationTime = 100 * time.Millisecond
		cfg.TLS.Enabled = tlsEnabled
		cfg.AllowInsecureMultiNode = true
		cfg.TLS.AllowAutoCAMultiNode = true
		cfg.TLS.CASecret = "test-ca"
		cfg.TLS.KeyringRotationEnabled = rotation
		cfg.TLS.RotationPeriod = 300 * time.Millisecond
		cfg.TLS.RotationCheckInterval = 50 * time.Millisecond
		cfg.TLS.Validity = time.Hour
		cfg.TLS.SafetyMargin = time.Minute

		opts := raft.NodeOptions{CustomListener: listeners[i], Logger: discardLogger()}
		if tlsEnabled {
			leafCert, leafKey, err := ca.IssuePeerCertificate(nodeID(i), "test-org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
			if err != nil {
				t.Fatalf("issue leaf: %v", err)
			}
			opts.BootstrapProvider = &staticBootstrapProvider{mat: &pki.BootstrapMaterial{
				CACertPEM:   caPEM,
				CAKeyPEM:    caKeyPEM,
				LeafCertPEM: leafCert,
				LeafKeyPEM:  leafKey,
			}}
			// Persist the manual files too so the file watcher path is exercised.
			tlsDir := filepath.Join(dir, "tls")
			if err := os.MkdirAll(tlsDir, 0o700); err != nil {
				t.Fatal(err)
			}
			_ = os.WriteFile(filepath.Join(tlsDir, "ca.crt"), caPEM, 0o600)
			_ = os.WriteFile(filepath.Join(tlsDir, "node.crt"), leafCert, 0o600)
			_ = os.WriteFile(filepath.Join(tlsDir, "node.key"), leafKey, 0o600)
		}
		if mutate != nil {
			mutate(i, &cfg, &opts)
		}
		node, err := raft.NewNode(ctx, &cfg, opts)
		if err != nil {
			t.Fatalf("NewNode %d: %v", i, err)
		}
		nodes[i] = &testNode{node: node, addr: addrs[i], dir: dir, listener: listeners[i], cfg: &cfg, opts: opts}
		if i < startCount {
			if err := node.Start(ctx); err != nil {
				t.Fatalf("Start %d: %v", i, err)
			}
		}
	}

	t.Cleanup(func() {
		for _, n := range nodes {
			if n != nil && n.node != nil {
				_ = n.node.Close()
			}
		}
	})

	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for i := 0; i < startCount; i++ {
		if err := nodes[i].node.WaitForLeader(waitCtx); err != nil {
			t.Fatalf("node %d WaitForLeader: %v", i, err)
		}
	}
	for i := 0; i < startCount; i++ {
		if err := nodes[i].node.WaitForCleanState(waitCtx); err != nil {
			t.Fatalf("node %d WaitForCleanState: %v", i, err)
		}
	}
	return nodes
}

func startTestNode(t *testing.T, n *testNode) {
	t.Helper()
	if err := n.node.Start(context.Background()); err != nil {
		t.Fatalf("start node %s: %v", n.addr, err)
	}
}

func restartTestNode(t *testing.T, n *testNode) {
	t.Helper()
	ln, err := net.Listen("tcp", n.addr)
	if err != nil {
		t.Fatalf("rebind %s: %v", n.addr, err)
	}
	opts := n.opts
	opts.CustomListener = ln
	node, err := raft.NewNode(context.Background(), n.cfg, opts)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("restart NewNode %s: %v", n.addr, err)
	}
	if err := node.Start(context.Background()); err != nil {
		_ = ln.Close()
		t.Fatalf("restart Start %s: %v", n.addr, err)
	}
	n.node = node
	n.listener = ln
}

func nodeID(i int) string {
	return fmt.Sprintf("node-%d", i)
}

func leaderOf(t *testing.T, nodes []*testNode) *testNode {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			if n != nil && n.node != nil && n.node.IsLeader() {
				return n
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no leader found")
	return nil
}

func newSelfSignedClusterWithConfig(t *testing.T, count int, wrap func(i int, ln net.Listener) net.Listener, mutate func(i int, cfg *config.Config, opts *raft.NodeOptions)) []*testNode {
	t.Helper()
	ctx := context.Background()
	listeners := make([]net.Listener, count)
	addrs := make([]string, count)
	for i := 0; i < count; i++ {
		listeners[i] = testutil.FreeListener(t)
		addrs[i] = listeners[i].Addr().String()
	}
	sharedKey, err := keyring.GenerateTLSKeyWithGoca(config.PKIModeSelfSigned, "shared", "test-org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour, nil, time.Now())
	if err != nil {
		t.Fatalf("generate self-signed key: %v", err)
	}
	peers := make([]config.PeerConfig, count)
	for i := 0; i < count; i++ {
		peers[i] = config.PeerConfig{ID: nodeID(i), Address: addrs[i]}
	}
	nodes := make([]*testNode, count)
	for i := 0; i < count; i++ {
		dir := t.TempDir()
		cfg := config.DefaultConfig()
		cfg.Dir = dir
		cfg.NodeID = nodeID(i)
		cfg.BindAddr = addrs[i]
		cfg.AdvertiseAddr = addrs[i]
		cfg.Discovery.Peers = peers
		cfg.Discovery.Replicas = count
		cfg.PerformanceMultiplier = 0.2
		cfg.ApplyTimeout = 5 * time.Second
		cfg.Join.Interval = 100 * time.Millisecond
		cfg.Join.ReconcileTimeout = 2 * time.Second
		cfg.Autopilot.Enabled = true
		cfg.Autopilot.HeartbeatInterval = 100 * time.Millisecond
		cfg.Autopilot.DeadServerLastContactThreshold = 2 * time.Second
		cfg.Autopilot.MinQuorum = 1
		cfg.Autopilot.StabilizationTime = 100 * time.Millisecond
		cfg.TLS.Enabled = true
		cfg.AllowInsecureMultiNode = true
		cfg.TLS.PKIMode = config.PKIModeSelfSigned
		cfg.TLS.AllowAutoCAMultiNode = true
		cfg.TLS.CASecret = "test-ca"
		cfg.TLS.KeyringRotationEnabled = true
		cfg.TLS.RotationPeriod = 2 * time.Second
		cfg.TLS.RotationCheckInterval = 100 * time.Millisecond
		cfg.TLS.Validity = time.Hour
		cfg.TLS.SafetyMargin = time.Minute
		ln := listeners[i]
		if wrap != nil {
			ln = wrap(i, ln)
		}
		opts := raft.NodeOptions{
			CustomListener: ln,
			Logger:         discardLogger(),
			BootstrapProvider: &staticBootstrapProvider{mat: &pki.BootstrapMaterial{
				CACertPEM:   sharedKey.CertPEM,
				CAKeyPEM:    []byte(sharedKey.KeyPEM),
				LeafCertPEM: sharedKey.CertPEM,
				LeafKeyPEM:  []byte(sharedKey.KeyPEM),
			}},
		}
		if mutate != nil {
			mutate(i, &cfg, &opts)
		}
		node, err := raft.NewNode(ctx, &cfg, opts)
		if err != nil {
			t.Fatalf("NewNode %d: %v", i, err)
		}
		if err := node.Start(ctx); err != nil {
			t.Fatalf("Start %d: %v", i, err)
		}
		nodes[i] = &testNode{node: node, addr: addrs[i], dir: dir, listener: ln, cfg: &cfg, opts: opts}
	}
	t.Cleanup(func() {
		for _, n := range nodes {
			if n != nil && n.node != nil {
				_ = n.node.Close()
			}
		}
	})
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for i, n := range nodes {
		if err := n.node.WaitForLeader(waitCtx); err != nil {
			t.Fatalf("node %d WaitForLeader: %v", i, err)
		}
	}
	for i, n := range nodes {
		if err := n.node.WaitForCleanState(waitCtx); err != nil {
			t.Fatalf("node %d WaitForCleanState: %v", i, err)
		}
	}
	return nodes
}
