package raft

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	hraft "github.com/hashicorp/raft"

	"github.com/disaster37/raft/autopilot"
	"github.com/disaster37/raft/config"
	"github.com/disaster37/raft/discovery"
	"github.com/disaster37/raft/fsm"
	"github.com/disaster37/raft/keyring"
	"github.com/disaster37/raft/observ"
	"github.com/disaster37/raft/pki"
	"github.com/disaster37/raft/storage"
	"github.com/disaster37/raft/transport"
)

// GenerationFencer coordinates cluster generation fencing across recoveries.
type GenerationFencer interface {
	ReadClusterGeneration(ctx context.Context) (uint64, bool)
	BumpClusterGeneration(ctx context.Context) (uint64, error)
}

// ReplicaCountAuthorizer reports the authoritative desired replica count.
type ReplicaCountAuthorizer interface {
	Replicas(ctx context.Context) (int32, bool)
}

// NodeOptions configures optional dependencies injected into NewNode.
type NodeOptions struct {
	FSM                    hraft.FSM
	Resolver               discovery.PeerResolver
	BootstrapProvider      pki.BootstrapProvider
	GenerationFencer       GenerationFencer
	ReplicaCountAuthorizer ReplicaCountAuthorizer
	Sealer                 storage.Sealer
	SessionSink            fsm.SessionStateSink
	Logger                 observ.Logger
	Metrics                observ.MetricsCollector
	RemovedCallback        func()
	RestoreCallback        func(ctx context.Context) error
	CustomListener         net.Listener
}

// Node manages the full lifecycle of a HashiCorp Raft instance, storage
// backend, dynamic mTLS transport, in-band TLS keyring rotation, membership
// join loop, and autopilot.
type Node struct {
	cfg     *config.Config
	opts    NodeOptions
	logger  observ.Logger
	metrics observ.MetricsCollector

	resolver        discovery.PeerResolver
	nodeID          string
	shouldBootstrap bool
	advertise       string

	backend           storage.Backend
	fsm               *fsm.EnvelopeFSM
	kv                fsm.KVStore
	raft              *hraft.Raft
	transport         hraft.Transport
	transportCloser   io.Closer
	tlsProvider       *transport.DynamicTLSProvider
	fileWatcher       *transport.FileWatcher
	fileWatcherCancel context.CancelFunc
	keyringManager    *keyring.Manager
	autopilot         *autopilot.Autopilot
	rotator           *keyring.PhasedRotator
	bootstrap         *pki.BootstrapMaterial

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	tempDir string

	closeOnce sync.Once
	closeErr  error
	closed    atomic.Bool

	started          atomic.Bool
	removed          atomic.Bool
	wasMember        atomic.Bool
	keyringReady     atomic.Bool
	bootstrapDropped atomic.Bool
}

// NewNode constructs a Node. Start must be called to open storage and start
// Raft.
func NewNode(ctx context.Context, cfg *config.Config, opts NodeOptions) (*Node, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: config is nil", ErrInvalidConfig)
	}
	cfgCopy := *cfg
	config.ApplyDefaults(&cfgCopy)
	if err := config.Validate(&cfgCopy, opts.BootstrapProvider != nil); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	logger := opts.Logger
	if logger == nil {
		logger = observ.NewNoopLogger()
	}
	metrics := opts.Metrics
	if metrics == nil {
		metrics = observ.NewNoopMetrics()
	}
	resolver := opts.Resolver
	if resolver == nil {
		resolver = discovery.NewPeerResolver(discoveryConfig(&cfgCopy))
	}
	n := &Node{
		cfg:      &cfgCopy,
		opts:     opts,
		logger:   logger,
		metrics:  metrics,
		resolver: resolver,
	}
	n.ctx, n.cancel = context.WithCancel(ctx)
	return n, nil
}

// NewInmemNode creates and starts a single-node in-memory Raft node.
func NewInmemNode(nodeID string, userFSM hraft.FSM, applyTimeout time.Duration, logger observ.Logger) (*Node, error) {
	if nodeID == "" {
		nodeID = "test-node"
	}
	if applyTimeout <= 0 {
		applyTimeout = 5 * time.Second
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("reserve inmem listener: %w", err)
	}
	addr := ln.Addr().String()
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("raft-inmem-%s-*", nodeID))
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("create inmem temp dir: %w", err)
	}
	cfg := config.DefaultConfig()
	cfg.Dir = tmpDir
	cfg.PerformanceMultiplier = 0.1
	cfg.NodeID = nodeID
	cfg.BindAddr = addr
	cfg.AdvertiseAddr = addr
	cfg.ApplyTimeout = applyTimeout
	cfg.Storage.Backend = config.StorageBackendInmem
	cfg.Discovery.Replicas = 1
	cfg.TLS.Enabled = false
	cfg.Autopilot.Enabled = false
	cfg.Join.Interval = 100 * time.Millisecond
	cfg.SnapshotInterval = time.Minute
	cfg.SnapshotThreshold = 1000
	n, err := NewNode(context.Background(), &cfg, NodeOptions{FSM: userFSM, Logger: logger, CustomListener: ln})
	if err != nil {
		_ = ln.Close()
		_ = os.RemoveAll(tmpDir)
		return nil, err
	}
	n.tempDir = tmpDir
	if err := n.Start(context.Background()); err != nil {
		_ = ln.Close()
		_ = n.Close()
		return nil, err
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.WaitForLeader(waitCtx); err != nil {
		_ = n.Close()
		return nil, err
	}
	return n, nil
}

// Start opens storage, bootstraps or recovers the cluster, and starts Raft.
func (n *Node) Start(ctx context.Context) (err error) {
	if n.closed.Load() {
		return ErrAlreadyClosed
	}
	if n.started.Swap(true) {
		return nil
	}
	if n.ctx == nil {
		n.ctx, n.cancel = context.WithCancel(ctx)
	}
	defer func() {
		if err != nil {
			n.stopFileWatcher()
			_ = n.Close()
		}
	}()
	dir := n.cfg.Dir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir data dir %s: %w", dir, err)
	}
	//nolint:gosec // data directory permissions are intentionally 0700
	if err := os.Chmod(dir, 0o700); err != nil && !os.IsPermission(err) { // #nosec G302
		return fmt.Errorf("chmod data dir %s: %w", dir, err)
	}

	nodeID, shouldBootstrap, err := discovery.ResolveBootstrapState(discoveryConfig(n.cfg), n.resolver, dir)
	if err != nil {
		return fmt.Errorf("resolve bootstrap state: %w", err)
	}
	n.nodeID = nodeID
	n.shouldBootstrap = shouldBootstrap

	effectiveRecovery, clusterGen, err := n.applyGenerationFencing(ctx)
	if err != nil {
		return err
	}
	if n.cfg.RecoveryMode || effectiveRecovery {
		if _, err := storage.ClearRaftState(dir, nodeID); err != nil {
			return fmt.Errorf("clear raft state: %w", err)
		}
		n.logger.Warn("cleared stale raft state", map[string]any{"dir": dir, "recovery": true})
	}

	if n.opts.Sealer == nil {
		sealer, err := storage.LoadOrDeriveAESGCMKeeper(n.cfg.Storage)
		if err != nil {
			return fmt.Errorf("init at-rest sealer: %w", err)
		}
		if sealer != nil {
			n.opts.Sealer = sealer
		}
	}

	if err := n.setupTLS(ctx); err != nil {
		return err
	}

	logOutput := observ.NewHclogWriter(n.logger)
	backend, err := storage.OpenBackend(dir, nodeID, n.cfg.Storage, n.cfg.SnapshotRetain, n.cfg.RaftLogCacheSize, logOutput)
	if err != nil {
		return err
	}
	n.backend = backend

	if n.opts.GenerationFencer != nil {
		if err := n.writeLocalGeneration(clusterGen); err != nil {
			_ = backend.Close()
			return err
		}
	}

	inner, kv := n.buildInnerFSM()
	n.kv = kv
	n.fsm = fsm.NewEnvelopeFSM(inner, n.onKeyring, n.onEcho, n.opts.RestoreCallback)

	transportOpts := transport.TransportOptions{
		BindAddr:                n.cfg.BindAddr,
		AdvertiseAddr:           n.cfg.AdvertiseAddr,
		AdvertiseResolveTimeout: n.cfg.AdvertiseResolveTimeout,
		MaxPool:                 n.cfg.Transport.MaxPool,
		Timeout:                 n.cfg.Transport.Timeout,
		MaxDialRetries:          n.cfg.Transport.MaxDialRetries,
		DialRetryBackoff:        n.cfg.Transport.DialRetryBase,
		TLSProvider:             n.tlsProvider,
		CustomListener:          n.opts.CustomListener,
		LogOutput:               logOutput,
		Metrics:                 n.metrics,
		EchoHandler:             n.handleEcho,
		EchoMaxConcurrent:       n.cfg.Transport.EchoMaxConcurrent,
		EchoPeekTimeout:         n.cfg.Transport.EchoPeekTimeout,
	}
	tr, closer, advertise, err := transport.NewStreamTransport(transportOpts)
	if err != nil {
		_ = backend.Close()
		return err
	}
	n.transport = tr
	n.transportCloser = closer
	n.advertise = advertise

	raftConfig := hraft.DefaultConfig()
	raftConfig.LocalID = hraft.ServerID(nodeID)
	raftConfig.SnapshotThreshold = n.cfg.SnapshotThreshold
	raftConfig.SnapshotInterval = n.cfg.SnapshotInterval
	raftConfig.TrailingLogs = n.cfg.TrailingLogs
	raftConfig.LogOutput = logOutput
	raftConfig.LogLevel = "WARN"
	raftConfig.NoSnapshotRestoreOnStart = n.cfg.NoSnapshotRestoreOnStart
	raftConfig.BatchApplyCh = n.cfg.BatchApplyCh
	raftConfig.MaxAppendEntries = n.cfg.MaxAppendEntries
	applyPerformanceMultiplier(raftConfig, n.cfg.PerformanceMultiplier)

	configuration := hraft.Configuration{Servers: []hraft.Server{{
		Suffrage: hraft.Voter,
		ID:       hraft.ServerID(nodeID),
		Address:  hraft.ServerAddress(advertise),
	}}}

	hasState, stateErr := hraft.HasExistingState(backend.LogStore(), backend.StableStore(), backend.SnapshotStore())
	if stateErr != nil {
		_ = closer.Close()
		_ = backend.Close()
		return fmt.Errorf("check existing raft state: %w", stateErr)
	}
	if n.cfg.SingleNodeRecovery && n.shouldBootstrap && !n.cfg.RecoveryMode && hasState {
		if n.recoveryAuthorized(ctx) {
			if err := hraft.RecoverCluster(raftConfig, n.fsm, backend.LogStore(), backend.StableStore(), backend.SnapshotStore(), n.transport, configuration); err != nil {
				_ = closer.Close()
				_ = backend.Close()
				return fmt.Errorf("recover cluster: %w", err)
			}
			n.logger.Warn("recovered single-node cluster", map[string]any{"node_id": nodeID})
		}
	} else if n.shouldBootstrap {
		if err := hraft.BootstrapCluster(raftConfig, backend.LogStore(), backend.StableStore(), backend.SnapshotStore(), n.transport, configuration); err != nil && !errors.Is(err, hraft.ErrCantBootstrap) {
			_ = closer.Close()
			_ = backend.Close()
			return fmt.Errorf("bootstrap cluster: %w", err)
		}
	}

	r, err := hraft.NewRaft(raftConfig, n.fsm, backend.LogStore(), backend.StableStore(), backend.SnapshotStore(), n.transport)
	if err != nil {
		_ = closer.Close()
		_ = backend.Close()
		return fmt.Errorf("create raft node: %w", err)
	}
	n.raft = r

	n.autopilot = autopilot.New(n.cfg.Autopilot, r, nodeID, r.LeaderCh(), n.logger, n.metrics)
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.autopilot.Start(n.ctx)
	}()

	if n.keyringManager != nil && n.cfg.TLS.KeyringRotationEnabled {
		n.rotator = keyring.NewPhasedRotator(keyring.RotatorConfig{
			PKIMode:        n.cfg.TLS.PKIMode,
			CommonName:     n.commonName(),
			Organization:   n.cfg.TLS.Organization,
			DNSNames:       n.dnsNames(),
			IPAddrs:        n.ipAddrs(),
			Validity:       n.cfg.TLS.Validity,
			RotationPeriod: n.cfg.TLS.RotationPeriod,
			CheckInterval:  n.cfg.TLS.RotationCheckInterval,
			Sealer:         n.opts.Sealer,
			Manager:        n.keyringManager,
			Applier:        n,
			Logger:         n.logger,
			Metrics:        n.metrics,
			Seed:           n.seedKeyring,
		})
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			n.rotator.Start(n.ctx)
		}()
	}

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.startJoinLoop(n.ctx)
	}()
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.startRemovedChecker(n.ctx)
	}()
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.startFollowerEchoLoop(n.ctx)
	}()

	return nil
}

func (n *Node) buildInnerFSM() (hraft.FSM, fsm.KVStore) {
	if n.opts.FSM != nil {
		return n.opts.FSM, nil
	}
	if n.backend.BoltDB() != nil {
		kv := fsm.NewBoltKVFSM(n.backend.BoltDB())
		return kv, kv
	}
	kv := fsm.NewMemoryKVFSM(n.opts.SessionSink)
	return kv, kv
}

func (n *Node) setupTLS(ctx context.Context) error {
	if !n.cfg.TLS.Enabled {
		return nil
	}
	tlsDir := n.cfg.TLS.Dir
	if tlsDir == "" {
		tlsDir = filepath.Join(n.cfg.Dir, "tls")
	}
	provider := n.opts.BootstrapProvider
	manual := n.cfg.TLS.CACertPath != "" || n.cfg.TLS.CertPath != "" || n.cfg.TLS.KeyPath != ""
	if manual {
		provider = pki.NewFileBootstrapProvider(n.cfg.TLS.CACertPath, n.cfg.TLS.CertPath, n.cfg.TLS.KeyPath)
	} else if provider == nil {
		provider = pki.NewLocalBootstrapProvider(tlsDir, "raft-ca", n.cfg.TLS.Organization, n.cfg.TLS.CAValidity)
	}
	mat, err := provider.EnsureBootstrapMaterial(ctx)
	if err != nil {
		return fmt.Errorf("ensure bootstrap material: %w", err)
	}
	n.bootstrap = mat

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(mat.CACertPEM) {
		return fmt.Errorf("bootstrap CA PEM contains no certificate")
	}
	caCert, err := pki.ParsePEMCert(mat.CACertPEM)
	if err != nil {
		return fmt.Errorf("parse bootstrap CA: %w", err)
	}

	if manual {
		watcher, err := transport.NewFileWatcher(n.cfg.TLS.CertPath, n.cfg.TLS.KeyPath, n.cfg.TLS.CACertPath, n.cfg.TLS.ReloadPollInterval, pki.DefaultSafetyMargin, n.cfg.TLS.ClientAuth, n.logger)
		if err != nil {
			return fmt.Errorf("start file watcher: %w", err)
		}
		n.fileWatcher = watcher
		n.tlsProvider = watcher.Provider()
		watcherCtx, watcherCancel := context.WithCancel(n.ctx)
		n.fileWatcherCancel = watcherCancel
		n.wg.Add(1)
		go func() {
			defer n.wg.Done()
			watcher.Start(watcherCtx)
		}()
	} else {
		var leaf tls.Certificate
		if len(mat.LeafCertPEM) > 0 && len(mat.LeafKeyPEM) > 0 {
			leaf, err = tls.X509KeyPair(mat.LeafCertPEM, mat.LeafKeyPEM)
			if err != nil {
				return fmt.Errorf("parse bootstrap leaf: %w", err)
			}
		} else {
			if len(mat.CAKeyPEM) == 0 {
				return fmt.Errorf("bootstrap material has neither a leaf nor a CA private key")
			}
			ca, err := pki.NewMintingCAFromPEM(mat.CACertPEM, mat.CAKeyPEM, n.cfg.TLS.Validity)
			if err != nil {
				return fmt.Errorf("load bootstrap CA: %w", err)
			}
			certPEM, keyPEM, err := pki.IssueOrReuseNodeCert(tlsDir, ca, n.commonName(), n.cfg.TLS.Organization, n.dnsNames(), n.ipAddrs(), n.cfg.TLS.Validity, n.cfg.TLS.SafetyMargin)
			if err != nil {
				return err
			}
			leaf, err = tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				return fmt.Errorf("parse node leaf: %w", err)
			}
		}
		n.tlsProvider = transport.NewDynamicTLSProvider(leaf, pool, pool, n.cfg.TLS.ClientAuth)
	}

	manager, err := keyring.NewManager(keyring.ManagerConfig{
		Dir:              tlsDir,
		PKIMode:          n.cfg.TLS.PKIMode,
		NodeCommonName:   n.commonName(),
		Organization:     n.cfg.TLS.Organization,
		DNSNames:         n.dnsNames(),
		IPAddrs:          n.ipAddrs(),
		LeafValidity:     n.cfg.TLS.Validity,
		SafetyMargin:     n.cfg.TLS.SafetyMargin,
		Sealer:           n.opts.Sealer,
		TLSProvider:      n.tlsProvider,
		BootstrapCACert:  caCert,
		DisconnectOnSwap: n.closeIdleConnections,
		Logger:           n.logger,
		Metrics:          n.metrics,
	})
	if err != nil {
		n.stopFileWatcher()
		return err
	}
	n.keyringManager = manager
	return nil
}

func (n *Node) stopFileWatcher() {
	if n.fileWatcherCancel != nil {
		n.fileWatcherCancel()
		n.fileWatcherCancel = nil
	}
}

func (n *Node) closeIdleConnections() {
	if closer, ok := n.transportCloser.(transport.IdleCloser); ok {
		closer.CloseIdleConnections()
	}
}

func (n *Node) onKeyring(kr *keyring.TLSKeyring) error {
	if n.keyringManager == nil {
		return nil
	}
	if err := n.keyringManager.SetTLSKeyring(kr); err != nil {
		return err
	}
	n.keyringReady.Store(true)
	return nil
}

func (n *Node) onEcho(u autopilot.EchoUpdate) {
	if n.autopilot != nil {
		n.autopilot.RecordEcho(u)
	}
}

func (n *Node) applyGenerationFencing(ctx context.Context) (bool, uint64, error) {
	if n.opts.GenerationFencer == nil {
		return false, 0, nil
	}
	clusterGen, _ := n.opts.GenerationFencer.ReadClusterGeneration(ctx)
	localGen, _ := n.readLocalGeneration()
	if n.shouldBootstrap && (n.cfg.RecoveryMode || n.cfg.SingleNodeRecovery) {
		next, err := n.opts.GenerationFencer.BumpClusterGeneration(ctx)
		if err != nil {
			return false, 0, fmt.Errorf("bump cluster generation: %w", err)
		}
		clusterGen = next
		localGen = next
	}
	effectiveRecovery := !n.shouldBootstrap && clusterGen > localGen
	if effectiveRecovery {
		n.logger.Warn("cluster generation advanced; wiping stale local state", map[string]any{
			"cluster_generation": clusterGen,
			"local_generation":   localGen,
		})
	}
	return effectiveRecovery, clusterGen, nil
}

func (n *Node) readLocalGeneration() (uint64, bool) {
	raw, err := os.ReadFile(filepath.Join(n.cfg.Dir, "generation"))
	if err != nil {
		return 0, false
	}
	var gen uint64
	if _, err := fmt.Sscanf(string(raw), "%d", &gen); err != nil {
		return 0, false
	}
	return gen, true
}

func (n *Node) writeLocalGeneration(gen uint64) error {
	if gen == 0 {
		return nil
	}
	path := filepath.Join(n.cfg.Dir, "generation")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%d", gen)), 0o600); err != nil {
		return fmt.Errorf("write local generation: %w", err)
	}
	return nil
}

func (n *Node) recoveryAuthorized(ctx context.Context) bool {
	if n.opts.ReplicaCountAuthorizer == nil {
		return true
	}
	replicas, ok := n.opts.ReplicaCountAuthorizer.Replicas(ctx)
	if !ok {
		return false
	}
	return replicas == 1
}

func (n *Node) commonName() string {
	hostname, _ := os.Hostname()
	return discovery.NodeCommonName(n.cfg.NodeID, n.resolver, hostname)
}

func (n *Node) dnsNames() []string {
	hostname, _ := os.Hostname()
	dns, _ := discovery.PodSANs(discoveryConfig(n.cfg), hostname)
	return append(dns, n.cfg.TLS.ExtraSANs...)
}

func (n *Node) ipAddrs() []net.IP {
	hostname, _ := os.Hostname()
	_, ips := discovery.PodSANs(discoveryConfig(n.cfg), hostname)
	return ips
}

func discoveryConfig(cfg *config.Config) *discovery.Config {
	peers := make([]discovery.Peer, 0, len(cfg.Discovery.Peers))
	for _, p := range cfg.Discovery.Peers {
		peers = append(peers, discovery.Peer{ID: p.ID, Address: p.Address, NonVoter: p.NonVoter})
	}
	peers = append(peers, discovery.ParseLegacyPeers(cfg.Discovery.LegacyPeers)...)
	if cfg.NonVoter {
		for i := range peers {
			if (cfg.NodeID != "" && peers[i].ID == cfg.NodeID) || (cfg.AdvertiseAddr != "" && peers[i].Address == cfg.AdvertiseAddr) {
				peers[i].NonVoter = true
			}
		}
	}
	hostname, _ := os.Hostname()
	return &discovery.Config{
		NodeID:          cfg.NodeID,
		AdvertiseAddr:   cfg.AdvertiseAddr,
		BindAddr:        cfg.BindAddr,
		Peers:           peers,
		Replicas:        cfg.Discovery.Replicas,
		StatefulSetName: cfg.Discovery.StatefulSetName,
		HeadlessService: cfg.Discovery.HeadlessService,
		Namespace:       cfg.Discovery.Namespace,
		ClusterDomain:   cfg.Discovery.ClusterDomain,
		RaftPort:        cfg.Discovery.RaftPort,
		Hostname:        hostname,
	}
}

func applyPerformanceMultiplier(cfg *hraft.Config, multiplier float64) {
	if multiplier <= 0 {
		multiplier = 1.0
	}
	scale := func(d time.Duration) time.Duration {
		scaled := time.Duration(float64(d) * multiplier)
		if scaled < 5*time.Millisecond {
			return 5 * time.Millisecond
		}
		return scaled
	}
	cfg.ElectionTimeout = scale(cfg.ElectionTimeout)
	cfg.HeartbeatTimeout = scale(cfg.HeartbeatTimeout)
	cfg.LeaderLeaseTimeout = scale(cfg.LeaderLeaseTimeout)
}

// WaitForLeader blocks until a leader exists.
func (n *Node) WaitForLeader(ctx context.Context) error {
	return n.waitFor(ctx, "wait for raft leader", func() bool { return n.raft != nil && n.raft.Leader() != "" })
}

// WaitForSelfLeadership blocks until this node is the leader.
func (n *Node) WaitForSelfLeadership(ctx context.Context) error {
	return n.waitFor(ctx, "wait for self leadership", n.IsLeader)
}

// WaitForCleanState blocks until IsCleanState reports true.
func (n *Node) WaitForCleanState(ctx context.Context) error {
	return n.waitFor(ctx, "wait for raft clean state", n.IsCleanState)
}

func (n *Node) waitFor(ctx context.Context, label string, ready func() bool) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ready() {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s: %w", label, ctx.Err())
		case <-ticker.C:
		}
	}
}

// IsLeader reports whether this node is the Raft leader.
func (n *Node) IsLeader() bool { return n.raft != nil && n.raft.State() == hraft.Leader }

// IsVoter reports whether this node is a voting member.
func (n *Node) IsVoter() bool {
	cfg, err := n.GetConfiguration()
	if err != nil {
		return false
	}
	for _, srv := range cfg.Servers {
		if string(srv.ID) == n.nodeID && srv.Suffrage == hraft.Voter {
			return true
		}
	}
	return false
}

// IsNonVoter reports whether this node is a non-voting member.
func (n *Node) IsNonVoter() bool {
	cfg, err := n.GetConfiguration()
	if err != nil {
		return false
	}
	for _, srv := range cfg.Servers {
		if string(srv.ID) == n.nodeID && srv.Suffrage == hraft.Nonvoter {
			return true
		}
	}
	return false
}

// IsStarted reports whether the node has joined the cluster.
func (n *Node) IsStarted() bool { return n.IsLeader() || n.IsVoter() || n.IsNonVoter() }

// IsRemoved reports whether this node is absent from the configuration.
func (n *Node) IsRemoved() bool {
	cfg, err := n.GetConfiguration()
	if err != nil {
		return false
	}
	for _, srv := range cfg.Servers {
		if string(srv.ID) == n.nodeID {
			return false
		}
	}
	return true
}

// IsCleanState reports whether the Raft layer is settled.
func (n *Node) IsCleanState() bool {
	if n.raft == nil {
		return false
	}
	stats := n.raft.Stats()
	state := stats["state"]
	if state != "Leader" && state != "Follower" {
		return false
	}
	if stats["commit_index"] != stats["applied_index"] {
		return false
	}
	if stats["fsm_pending"] != "0" {
		return false
	}
	if state == "Follower" {
		if stats["commit_index"] == "0" {
			return false
		}
		lastContact := stats["last_contact"]
		if lastContact == "never" || lastContact == "" {
			return false
		}
		d, err := time.ParseDuration(lastContact)
		if err != nil || d > n.cfg.FollowerLastContactMax {
			return false
		}
	}
	return true
}

// NodeID returns the stable node ID.
func (n *Node) NodeID() string { return n.nodeID }

// LeaderAddress returns the current leader's transport address.
func (n *Node) LeaderAddress() string {
	if n.raft == nil {
		return ""
	}
	return string(n.raft.Leader())
}

// LeaderWithID returns the leader address and ID.
func (n *Node) LeaderWithID() (address string, id string) {
	if n.raft == nil {
		return "", ""
	}
	addr, serverID := n.raft.LeaderWithID()
	return string(addr), string(serverID)
}

// AppliedIndex returns the FSM applied index.
func (n *Node) AppliedIndex() uint64 {
	if n.raft == nil {
		return 0
	}
	return n.raft.AppliedIndex()
}

// CommittedIndex returns the last committed index.
func (n *Node) CommittedIndex() uint64 {
	if n.raft == nil {
		return 0
	}
	return n.raft.CommitIndex()
}

// Stats returns the raw Raft stats.
func (n *Node) Stats() map[string]string {
	if n.raft == nil {
		return map[string]string{}
	}
	return n.raft.Stats()
}

// GetConfiguration returns the current cluster configuration.
func (n *Node) GetConfiguration() (hraft.Configuration, error) {
	if n.raft == nil {
		return hraft.Configuration{}, fmt.Errorf("raft node is not started")
	}
	future := n.raft.GetConfiguration()
	if err := future.Error(); err != nil {
		return hraft.Configuration{}, fmt.Errorf("get configuration: %w", err)
	}
	return future.Configuration(), nil
}

// Apply applies raw bytes to the FSM.
func (n *Node) Apply(ctx context.Context, data []byte) (interface{}, error) {
	if n.raft == nil {
		return nil, ErrAlreadyClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if n.cfg.MaxEntrySize > 0 && uint64(len(data)) > n.cfg.MaxEntrySize {
		return nil, fmt.Errorf("raft entry size %d exceeds max %d", len(data), n.cfg.MaxEntrySize)
	}
	if !n.IsLeader() {
		return nil, ErrNotLeader
	}
	future := n.raft.Apply(data, n.cfg.ApplyTimeout)
	if err := future.Error(); err != nil {
		return nil, mapApplyError(err)
	}
	return future.Response(), nil
}

// ApplyCommand encodes and applies a typed command.
func (n *Node) ApplyCommand(ctx context.Context, kind uint8, payload any) (interface{}, error) {
	data, err := (fsm.CommandCodec{}).Encode(kind, payload)
	if err != nil {
		return nil, err
	}
	return n.Apply(ctx, data)
}

// ApplyMulti applies an atomic multi-key write.
func (n *Node) ApplyMulti(ctx context.Context, entries []fsm.KVEntry) error {
	resp, err := n.ApplyCommand(ctx, fsm.KindSetMulti, fsm.SetMultiPayload{Entries: entries})
	if err != nil {
		return err
	}
	if respErr, ok := resp.(error); ok && respErr != nil {
		return respErr
	}
	return nil
}

func mapApplyError(err error) error {
	switch {
	case errors.Is(err, hraft.ErrNotLeader), errors.Is(err, hraft.ErrLeadershipLost):
		return ErrNotLeader
	case errors.Is(err, hraft.ErrEnqueueTimeout), errors.Is(err, context.DeadlineExceeded):
		return ErrRaftTimeout
	default:
		return fmt.Errorf("raft apply: %w", err)
	}
}

// FSM returns the envelope FSM.
func (n *Node) FSM() hraft.FSM { return n.fsm }

// KV returns the built-in KV store, or nil for a custom FSM.
func (n *Node) KV() fsm.KVStore { return n.kv }

// Storage returns the storage backend.
func (n *Node) Storage() storage.Backend { return n.backend }

// TLSProvider returns the dynamic TLS provider.
func (n *Node) TLSProvider() *transport.DynamicTLSProvider { return n.tlsProvider }

// KeyringManager returns the keyring manager.
func (n *Node) KeyringManager() *keyring.Manager { return n.keyringManager }

// Autopilot returns the autopilot.
func (n *Node) Autopilot() *autopilot.Autopilot { return n.autopilot }

// RawRaft returns the underlying HashiCorp Raft instance.
func (n *Node) RawRaft() *hraft.Raft { return n.raft }

// Close shuts down the node. It is idempotent.
func (n *Node) Close() error {
	n.closeOnce.Do(func() {
		n.closed.Store(true)
		n.stopFileWatcher()
		if n.cancel != nil {
			n.cancel()
		}
		n.wg.Wait()
		if n.raft != nil {
			if err := n.raft.Shutdown().Error(); err != nil && !errors.Is(err, hraft.ErrRaftShutdown) {
				n.closeErr = err
			}
		}
		if n.transportCloser != nil {
			_ = n.transportCloser.Close()
		}
		if n.backend != nil {
			_ = n.backend.Close()
		}
		if n.tempDir != "" {
			_ = os.RemoveAll(n.tempDir)
		}
	})
	return n.closeErr
}

// Shutdown is an alias for Close.
func (n *Node) Shutdown() error { return n.Close() }

// MinFollowerAppliedIndex implements keyring.KeyringApplier.
func (n *Node) MinFollowerAppliedIndex() uint64 {
	if n.autopilot != nil {
		return n.autopilot.MinFollowerAppliedIndex()
	}
	return n.AppliedIndex()
}

// ReadKeyring implements keyring.KeyringApplier.
func (n *Node) ReadKeyring() (*keyring.TLSKeyring, error) {
	if n.fsm == nil {
		return nil, nil
	}
	return n.fsm.Keyring(), nil
}

// ApplyKeyring implements keyring.KeyringApplier.
func (n *Node) ApplyKeyring(ctx context.Context, kr *keyring.TLSKeyring) (uint64, error) {
	if kr == nil {
		return 0, fmt.Errorf("apply keyring: nil keyring")
	}
	payload, err := json.Marshal(kr)
	if err != nil {
		return 0, fmt.Errorf("marshal keyring: %w", err)
	}
	data := make([]byte, 0, len(sysPrefix)+1+len(payload))
	data = append(data, sysPrefix...)
	data = append(data, fsm.SysKindSetKeyring)
	data = append(data, payload...)
	if n.raft == nil {
		return 0, ErrAlreadyClosed
	}
	if !n.IsLeader() {
		return 0, ErrNotLeader
	}
	future := n.raft.Apply(data, n.cfg.ApplyTimeout)
	if err := future.Error(); err != nil {
		return 0, mapApplyError(err)
	}
	return future.Index(), nil
}

var sysPrefix = []byte{0xFF, 'R', 'S', 'Y'}

func (n *Node) handleEcho(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var rw io.Reader = conn
	if n.tlsProvider != nil {
		tlsConn := tls.Server(conn, n.tlsProvider.ServerTLSConfig())
		if err := tlsConn.Handshake(); err != nil {
			n.logger.Warn("echo handler: tls handshake failed", map[string]any{"error": err.Error()})
			return
		}
		rw = tlsConn
	}
	var echo autopilot.EchoUpdate
	if err := json.NewDecoder(rw).Decode(&echo); err != nil {
		n.logger.Warn("echo handler: decode failed", map[string]any{"error": err.Error()})
		return
	}
	n.onEcho(echo)
}

func (n *Node) startFollowerEchoLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n.IsLeader() || n.raft == nil {
				continue
			}
			n.sendEcho()
		}
	}
}

func (n *Node) sendEcho() {
	leaderAddr := n.LeaderAddress()
	if leaderAddr == "" {
		return
	}
	host, _, err := net.SplitHostPort(leaderAddr)
	if err != nil {
		return
	}
	raw, err := net.DialTimeout("tcp", leaderAddr, 5*time.Second)
	if err != nil {
		n.logger.Warn("send echo: dial failed", map[string]any{"error": err.Error()})
		return
	}
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := raw.Write(transport.EchoMagic); err != nil {
		n.logger.Warn("send echo: write magic failed", map[string]any{"error": err.Error()})
		return
	}
	var w io.Writer = raw
	if n.tlsProvider != nil {
		tlsConn := tls.Client(raw, n.tlsProvider.DialTLSConfig(host))
		if err := tlsConn.Handshake(); err != nil {
			n.logger.Warn("send echo: tls handshake failed", map[string]any{"error": err.Error()})
			return
		}
		w = tlsConn
	}
	echo := autopilot.EchoUpdate{
		NodeID:       n.nodeID,
		AppliedIndex: n.AppliedIndex(),
		Term:         n.currentTerm(),
		Timestamp:    time.Now(),
	}
	_ = json.NewEncoder(w).Encode(echo)
}

func (n *Node) currentTerm() uint64 {
	if n.raft == nil {
		return 0
	}
	var term uint64
	_, _ = fmt.Sscanf(n.raft.Stats()["term"], "%d", &term)
	return term
}
