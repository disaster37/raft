package raft

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	hraft "github.com/hashicorp/raft"

	"github.com/disaster37/raft/autopilot"
	"github.com/disaster37/raft/config"
	"github.com/disaster37/raft/discovery"
	"github.com/disaster37/raft/fsm"
	"github.com/disaster37/raft/k8s"
	"github.com/disaster37/raft/keyring"
	"github.com/disaster37/raft/observ"
	"github.com/disaster37/raft/pki"
	"github.com/disaster37/raft/transport"
)

type internalFencer struct {
	gen   uint64
	bumps int
}

func (f *internalFencer) ReadClusterGeneration(context.Context) (uint64, bool) {
	return f.gen, f.gen > 0
}
func (f *internalFencer) BumpClusterGeneration(context.Context) (uint64, error) {
	f.gen++
	f.bumps++
	return f.gen, nil
}

type internalAuthorizer struct {
	replicas int32
	ok       bool
}

func (a internalAuthorizer) Replicas(context.Context) (int32, bool) { return a.replicas, a.ok }

func newInternalNode(t *testing.T) *Node {
	t.Helper()
	n, err := NewInmemNode("internal-node", nil, 5*time.Second, nil)
	if err != nil {
		t.Fatalf("NewInmemNode: %v", err)
	}
	t.Cleanup(func() { _ = n.Close() })
	return n
}

func TestInternalNodeHelpers(t *testing.T) {
	n := newInternalNode(t)
	if n.commonName() == "" {
		t.Fatal("empty common name")
	}
	if len(n.dnsNames()) == 0 {
		t.Fatal("empty dns names")
	}
	if len(n.ipAddrs()) == 0 {
		t.Fatal("empty ip addrs")
	}
	if err := n.writeLocalGeneration(3); err != nil {
		t.Fatal(err)
	}
	if gen, ok := n.readLocalGeneration(); !ok || gen != 3 {
		t.Fatalf("gen = %d ok=%v", gen, ok)
	}
	if err := n.writeLocalGeneration(0); err != nil {
		t.Fatal(err)
	}
	if n.recoveryAuthorized(context.Background()) != true {
		t.Fatal("nil authorizer should authorize")
	}
	n.opts.ReplicaCountAuthorizer = internalAuthorizer{replicas: 1, ok: true}
	if !n.recoveryAuthorized(context.Background()) {
		t.Fatal("replicas=1 should authorize")
	}
	n.opts.ReplicaCountAuthorizer = internalAuthorizer{replicas: 3, ok: true}
	if n.recoveryAuthorized(context.Background()) {
		t.Fatal("replicas=3 should not authorize")
	}
	n.opts.ReplicaCountAuthorizer = internalAuthorizer{ok: false}
	if n.recoveryAuthorized(context.Background()) {
		t.Fatal("missing replicas should not authorize")
	}
	n.closeIdleConnections()
	if kr, err := n.seedKeyring(context.Background()); err != nil || kr != nil {
		t.Fatalf("expected nil seed without bootstrap: %+v %v", kr, err)
	}
}

func TestInternalMapApplyError(t *testing.T) {
	if !errors.Is(mapApplyError(hraft.ErrNotLeader), ErrNotLeader) {
		t.Fatal("expected not leader")
	}
	if !errors.Is(mapApplyError(hraft.ErrLeadershipLost), ErrNotLeader) {
		t.Fatal("expected not leader")
	}
	if !errors.Is(mapApplyError(hraft.ErrEnqueueTimeout), ErrRaftTimeout) {
		t.Fatal("expected timeout")
	}
	if !errors.Is(mapApplyError(context.DeadlineExceeded), ErrRaftTimeout) {
		t.Fatal("expected timeout")
	}
	if mapApplyError(errors.New("other")) == nil {
		t.Fatal("expected wrapped error")
	}
}

func TestInternalSetupTLSAndKeyring(t *testing.T) {
	ln := freeListener(t)
	addr := ln.Addr().String()
	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Dir = t.TempDir()
	cfg.NodeID = "tls-node"
	cfg.BindAddr = addr
	cfg.AdvertiseAddr = addr
	cfg.TLS.Enabled = true
	cfg.TLS.KeyringRotationEnabled = true
	cfg.Autopilot.Enabled = false
	n, err := NewNode(context.Background(), &cfg, NodeOptions{CustomListener: ln})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := n.setupTLS(context.Background()); err != nil {
		t.Fatalf("setupTLS: %v", err)
	}
	if n.tlsProvider == nil || n.keyringManager == nil || n.bootstrap == nil {
		t.Fatal("missing TLS components")
	}
	seeded, err := n.seedKeyring(context.Background())
	if err != nil || seeded == nil {
		t.Fatalf("seedKeyring = %+v err=%v", seeded, err)
	}
	n.ensureKeyring(context.Background())
	if err := n.onKeyring(seeded); err != nil {
		t.Fatalf("onKeyring: %v", err)
	}
	if !n.keyringReady.Load() {
		t.Fatal("keyring not marked ready")
	}
	term3 := seeded.Clone()
	term3.Term = 3
	if err := n.onKeyring(term3); err != nil {
		t.Fatalf("onKeyring term3: %v", err)
	}
	n.ensureKeyring(context.Background())
	n.closeIdleConnections()
	_ = n.Close()
}

func TestInternalGenerationFencing(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Dir = t.TempDir()
	cfg.NodeID = "gen-node"
	cfg.Storage.Backend = config.StorageBackendInmem
	cfg.Autopilot.Enabled = false
	fencer := &internalFencer{}
	n, err := NewNode(context.Background(), &cfg, NodeOptions{GenerationFencer: fencer})
	if err != nil {
		t.Fatal(err)
	}
	n.shouldBootstrap = true
	n.cfg.RecoveryMode = true
	effective, gen, err := n.applyGenerationFencing(context.Background())
	if err != nil || effective || gen != 1 || fencer.bumps != 1 {
		t.Fatalf("effective=%v gen=%d bumps=%d err=%v", effective, gen, fencer.bumps, err)
	}
	n.shouldBootstrap = false
	n.cfg.RecoveryMode = false
	fencer.gen = 2
	effective, gen, err = n.applyGenerationFencing(context.Background())
	if err != nil || !effective || gen != 2 {
		t.Fatalf("effective=%v gen=%d err=%v", effective, gen, err)
	}
}

func TestInternalMembershipAndApply(t *testing.T) {
	n := newInternalNode(t)
	ctx := context.Background()
	if err := n.StepDown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := n.TransferLeadership(ctx, time.Second); err != nil {
		t.Fatal(err)
	}
	desired, _ := n.resolver.Resolve()
	added, updated, removed, err := n.ReconcileMembership(desired, time.Second)
	if err != nil || len(added) != 0 || len(updated) != 0 || len(removed) != 0 {
		t.Fatalf("reconcile = %v %v %v err=%v", added, updated, removed, err)
	}
	if err := n.AddVoter(n.nodeID, n.advertise, time.Second); err != nil {
		t.Fatalf("AddVoter self: %v", err)
	}
	if err := n.AddNonvoter("nonvoter", "127.0.0.1:1", 100*time.Millisecond); err != nil {
		t.Fatalf("AddNonvoter: %v", err)
	}
	if err := n.RemoveServer("nonvoter", 100*time.Millisecond); err != nil {
		t.Fatalf("RemoveServer: %v", err)
	}
	if _, err := n.ApplyCommand(ctx, fsm.KindSet, fsm.KVEntry{Bucket: "b", Key: "k", Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	if err := n.ApplyMulti(ctx, []fsm.KVEntry{{Bucket: "b", Key: "a", Value: []byte("1")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := n.ApplyCommand(ctx, fsm.KindSet, func() {}); err == nil {
		t.Fatal("expected encode error")
	}
	if _, err := n.Apply(ctx, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if n.LeaderAddress() == "" || n.AppliedIndex() == 0 || n.CommittedIndex() == 0 {
		t.Fatal("missing leader/index state")
	}
	if n.Stats()["state"] == "" {
		t.Fatal("missing stats")
	}
	if _, err := n.GetConfiguration(); err != nil {
		t.Fatal(err)
	}
	if _, id := n.LeaderWithID(); id == "" {
		t.Fatal("missing leader id")
	}
	if n.IsNonVoter() {
		t.Fatal("should not be nonvoter")
	}
	if n.MinFollowerAppliedIndex() == 0 {
		t.Fatal("missing min index")
	}
	if kr, err := n.ReadKeyring(); err != nil || kr != nil {
		t.Fatalf("keyring = %+v err=%v", kr, err)
	}
	joinCtx, joinCancel := context.WithCancel(ctx)
	n.StartJoinLoop(joinCtx)
	joinCancel()
}

func TestInternalHandleEcho(t *testing.T) {
	ca, _ := pki.NewMintingCA("ca", "org", time.Hour)
	certPEM, keyPEM, _ := ca.IssuePeerCertificate("node", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	leaf, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	provider := transport.NewDynamicTLSProvider(leaf, ca.CertPool(), ca.CertPool(), true)
	n := &Node{tlsProvider: provider, logger: observ.NewNoopLogger(), autopilot: nil}
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		n.handleEcho(server)
	}()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	// The handler expects a TLS handshake; a plain write should fail and return.
	_, _ = client.Write([]byte("not tls"))
	time.Sleep(10 * time.Millisecond)
}

func TestInternalSendEchoNoLeader(t *testing.T) {
	n := &Node{logger: observ.NewNoopLogger()}
	n.sendEcho()
}

func TestInternalRecoverPeersJSON(t *testing.T) {
	dir := t.TempDir()
	if err := RecoverPeersJSON(dir, []hraft.Server{{ID: "a", Address: "a:1", Suffrage: hraft.Voter}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "peers.json")); err != nil {
		t.Fatal(err)
	}
}

func TestInternalDiscoveryConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Discovery.Peers = []config.PeerConfig{{ID: "a", Address: "a:1"}}
	cfg.Discovery.LegacyPeers = []string{"b=b:1"}
	dc := discoveryConfig(&cfg)
	if len(dc.Peers) != 2 {
		t.Fatalf("peers = %v", dc.Peers)
	}
	_ = discovery.Peer{}
	_ = keyring.TLSKeyring{}
}

func TestInternalNilRaftMethods(t *testing.T) {
	n := &Node{cfg: &config.Config{}, logger: observ.NewNoopLogger()}
	if n.AppliedIndex() != 0 || n.CommittedIndex() != 0 {
		t.Fatal("expected zero indices")
	}
	if len(n.Stats()) != 0 {
		t.Fatal("expected empty stats")
	}
	if _, err := n.GetConfiguration(); err == nil {
		t.Fatal("expected configuration error")
	}
	if n.LeaderAddress() != "" {
		t.Fatal("expected empty leader")
	}
	if addr, id := n.LeaderWithID(); addr != "" || id != "" {
		t.Fatal("expected empty leader with id")
	}
	if n.IsVoter() || n.IsNonVoter() || n.IsRemoved() || n.IsCleanState() {
		t.Fatal("unexpected state")
	}
	if _, err := n.Apply(context.Background(), []byte("x")); !errors.Is(err, ErrAlreadyClosed) {
		t.Fatalf("apply err = %v", err)
	}
	if _, err := n.ApplyCommand(context.Background(), fsm.KindSet, fsm.KVEntry{}); !errors.Is(err, ErrAlreadyClosed) {
		t.Fatalf("apply command err = %v", err)
	}
	if err := n.ApplyMulti(context.Background(), nil); !errors.Is(err, ErrAlreadyClosed) {
		t.Fatalf("apply multi err = %v", err)
	}
	if n.MinFollowerAppliedIndex() != 0 {
		t.Fatal("expected zero min index")
	}
	if kr, err := n.ReadKeyring(); err != nil || kr != nil {
		t.Fatalf("keyring = %+v err=%v", kr, err)
	}
	if _, err := n.ApplyKeyring(context.Background(), &keyring.TLSKeyring{}); !errors.Is(err, ErrAlreadyClosed) {
		t.Fatalf("apply keyring err = %v", err)
	}
	if err := n.AddVoter("a", "a:1", time.Second); !errors.Is(err, ErrAlreadyClosed) {
		t.Fatalf("add voter err = %v", err)
	}
	if err := n.AddNonvoter("a", "a:1", time.Second); !errors.Is(err, ErrAlreadyClosed) {
		t.Fatalf("add nonvoter err = %v", err)
	}
	if err := n.RemoveServer("a", time.Second); !errors.Is(err, ErrAlreadyClosed) {
		t.Fatalf("remove server err = %v", err)
	}
	if err := n.StepDown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := n.TransferLeadership(context.Background(), time.Second); err != nil {
		t.Fatal(err)
	}
	if err := n.LeaveCluster(context.Background(), time.Second); !errors.Is(err, ErrNotLeader) {
		t.Fatalf("leave err = %v", err)
	}
	n.sendEcho()
	if n.currentTerm() != 0 {
		t.Fatal("expected zero term")
	}
	if err := n.onKeyring(&keyring.TLSKeyring{}); err != nil {
		t.Fatal(err)
	}
	n.closeIdleConnections()
}

func TestInternalReconcileMembershipBranches(t *testing.T) {
	n := newInternalNode(t)
	desired := []discovery.Peer{
		{ID: n.nodeID, Address: n.advertise},
		{ID: "nv", Address: "127.0.0.1:1", NonVoter: true},
	}
	added, _, _, err := n.ReconcileMembership(desired, time.Second)
	if err != nil || len(added) != 1 || added[0] != "nv" {
		t.Fatalf("added = %v err=%v", added, err)
	}
	desired[1].Address = "127.0.0.1:2"
	_, updated, _, err := n.ReconcileMembership(desired, time.Second)
	if err != nil || len(updated) != 1 || updated[0] != "nv" {
		t.Fatalf("updated = %v err=%v", updated, err)
	}
	_, _, removed, err := n.ReconcileMembership([]discovery.Peer{{ID: n.nodeID, Address: n.advertise}}, time.Second)
	if err != nil || len(removed) != 1 || removed[0] != "nv" {
		t.Fatalf("removed = %v err=%v", removed, err)
	}
	if !n.peerResolvable("127.0.0.1:1") {
		t.Fatal("IP should be resolvable")
	}
	if n.peerResolvable("bad") {
		t.Fatal("bad address should not be resolvable")
	}
	if n.peerResolvable("bad.invalid:1") {
		t.Fatal("invalid host should not be resolvable")
	}
}

func TestInternalSetupTLSManual(t *testing.T) {
	dir := t.TempDir()
	ca, _ := pki.NewMintingCA("ca", "org", time.Hour)
	certPEM, keyPEM, _ := ca.IssuePeerCertificate("node", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	caPEM, _, _ := ca.EncodePEM()
	certFile := filepath.Join(dir, "node.crt")
	keyFile := filepath.Join(dir, "node.key")
	caFile := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(certFile, certPEM, 0o600)
	_ = os.WriteFile(keyFile, keyPEM, 0o600)
	_ = os.WriteFile(caFile, caPEM, 0o600)
	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Dir = t.TempDir()
	cfg.NodeID = "manual-node"
	cfg.TLS.Enabled = true
	cfg.TLS.CACertPath = caFile
	cfg.TLS.CertPath = certFile
	cfg.TLS.KeyPath = keyFile
	cfg.TLS.KeyringRotationEnabled = false
	n, err := NewNode(context.Background(), &cfg, NodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.setupTLS(context.Background()); err != nil {
		t.Fatalf("setupTLS manual: %v", err)
	}
	if n.fileWatcher == nil || n.tlsProvider == nil {
		t.Fatal("missing manual TLS components")
	}
	_ = n.Close()
}

func TestInternalStartTLSAndRecovery(t *testing.T) {
	ln := freeListener(t)
	addr := ln.Addr().String()
	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Dir = t.TempDir()
	cfg.NodeID = "start-tls-node"
	cfg.BindAddr = addr
	cfg.AdvertiseAddr = addr
	cfg.TLS.Enabled = true
	cfg.TLS.KeyringRotationEnabled = false
	cfg.Autopilot.Enabled = false
	cfg.Join.Interval = time.Hour
	n, err := NewNode(context.Background(), &cfg, NodeOptions{CustomListener: ln})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(context.Background()); err != nil {
		t.Fatalf("Start TLS: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.WaitForLeader(ctx); err != nil {
		t.Fatalf("WaitForLeader: %v", err)
	}
	if err := n.WaitForCleanState(ctx); err != nil {
		t.Fatalf("WaitForCleanState: %v", err)
	}
	n.sendEcho()
	time.Sleep(50 * time.Millisecond)
	_ = n.Close()

	// Recovery mode clears state and bootstraps fresh.
	ln2 := freeListener(t)
	cfg2 := config.DefaultConfig()
	cfg2.PerformanceMultiplier = 0.2
	cfg2.Dir = t.TempDir()
	cfg2.NodeID = "recovery-node"
	cfg2.BindAddr = ln2.Addr().String()
	cfg2.AdvertiseAddr = ln2.Addr().String()
	cfg2.Storage.Backend = config.StorageBackendInmem
	cfg2.RecoveryMode = true
	cfg2.Autopilot.Enabled = false
	cfg2.Join.Interval = time.Hour
	n2, err := NewNode(context.Background(), &cfg2, NodeOptions{CustomListener: ln2})
	if err != nil {
		t.Fatal(err)
	}
	if err := n2.Start(context.Background()); err != nil {
		t.Fatalf("Start recovery: %v", err)
	}
	_ = n2.Close()
}

func TestInternalHandleEchoSuccess(t *testing.T) {
	ca, _ := pki.NewMintingCA("ca", "org", time.Hour)
	certPEM, keyPEM, _ := ca.IssuePeerCertificate("node", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	leaf, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	provider := transport.NewDynamicTLSProvider(leaf, ca.CertPool(), ca.CertPool(), true)
	ap := autopilot.New(config.AutopilotConfig{Enabled: true}, nil, "local", nil, nil, nil)
	n := &Node{tlsProvider: provider, logger: observ.NewNoopLogger(), autopilot: ap}
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go n.handleEcho(server)
	go func() {
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		tlsConn := tls.Client(client, provider.DialTLSConfig("127.0.0.1"))
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		_ = json.NewEncoder(tlsConn).Encode(autopilot.EchoUpdate{NodeID: "n1", AppliedIndex: 1})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := ap.GetFollowerState("n1"); ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("echo was not recorded")
}

func TestInternalGenerationErrors(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	n := &Node{cfg: &config.Config{Dir: file}, logger: observ.NewNoopLogger()}
	if err := n.writeLocalGeneration(1); err == nil {
		t.Fatal("expected write generation error")
	}
	if _, ok := n.readLocalGeneration(); ok {
		t.Fatal("expected read generation error")
	}
	if err := RecoverPeersJSON(file, []hraft.Server{{ID: "a"}}); err == nil {
		t.Fatal("expected peers json write error")
	}
}

func TestInternalApplyPerformanceMultiplier(t *testing.T) {
	cfg := hraft.DefaultConfig()
	applyPerformanceMultiplier(cfg, 0.5)
	if cfg.ElectionTimeout <= 0 {
		t.Fatal("invalid election timeout")
	}
}

type flakyResolver struct {
	mu   sync.Mutex
	fail bool
	self discovery.Peer
}

func (r *flakyResolver) Resolve() ([]discovery.Peer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return nil, errors.New("resolve")
	}
	return []discovery.Peer{r.self}, nil
}

func (r *flakyResolver) Self() (discovery.Peer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.self, nil
}

func (r *flakyResolver) setFail() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fail = true
}

func TestInternalStartJoinLoopError(t *testing.T) {
	ln := freeListener(t)
	addr := ln.Addr().String()
	resolver := &flakyResolver{self: discovery.Peer{ID: "flaky", Address: addr}}
	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Dir = t.TempDir()
	cfg.NodeID = "flaky"
	cfg.BindAddr = addr
	cfg.AdvertiseAddr = addr
	cfg.Storage.Backend = config.StorageBackendInmem
	cfg.Autopilot.Enabled = false
	cfg.Join.Interval = time.Hour
	n, err := NewNode(context.Background(), &cfg, NodeOptions{CustomListener: ln, Resolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.WaitForLeader(ctx); err != nil {
		t.Fatal(err)
	}
	resolver.setFail()
	loopCtx, loopCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer loopCancel()
	n.startJoinLoop(loopCtx)
}

func TestInternalLeaveClusterSingleNode(t *testing.T) {
	n := newInternalNode(t)
	if err := n.LeaveCluster(context.Background(), time.Second); err != nil {
		t.Fatalf("LeaveCluster single node: %v", err)
	}
}

func TestInternalSetupTLSErrors(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Dir = t.TempDir()
	cfg.NodeID = "bad-tls"
	cfg.TLS.Enabled = true
	n, err := NewNode(context.Background(), &cfg, NodeOptions{BootstrapProvider: &badBootstrapProvider{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.setupTLS(context.Background()); err == nil {
		t.Fatal("expected invalid CA error")
	}
	n2, err := NewNode(context.Background(), &cfg, NodeOptions{BootstrapProvider: &emptyBootstrapProvider{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := n2.setupTLS(context.Background()); err == nil {
		t.Fatal("expected missing leaf/key error")
	}
}

type badBootstrapProvider struct{}

func (badBootstrapProvider) EnsureBootstrapMaterial(context.Context) (*pki.BootstrapMaterial, error) {
	return &pki.BootstrapMaterial{CACertPEM: []byte("bad")}, nil
}

type emptyBootstrapProvider struct{}

func (emptyBootstrapProvider) EnsureBootstrapMaterial(context.Context) (*pki.BootstrapMaterial, error) {
	return &pki.BootstrapMaterial{CACertPEM: []byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")}, nil
}

func TestInternalApplyMultiConflict(t *testing.T) {
	n := newInternalNode(t)
	ctx := context.Background()
	if _, err := n.ApplyCommand(ctx, fsm.KindSet, fsm.KVEntry{Bucket: "b", Key: "k", Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	if err := n.ApplyMulti(ctx, []fsm.KVEntry{{Bucket: "b", Key: "k", Value: []byte("v"), Create: true}}); err == nil {
		t.Fatal("expected conflict")
	}
}

func TestInternalReadGenerationParseError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "generation"), []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	n := &Node{cfg: &config.Config{Dir: dir}, logger: observ.NewNoopLogger()}
	if _, ok := n.readLocalGeneration(); ok {
		t.Fatal("expected parse error")
	}
}

func TestInternalEnsureKeyringSeedsAndDrops(t *testing.T) {
	ln := freeListener(t)
	addr := ln.Addr().String()
	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Dir = t.TempDir()
	cfg.NodeID = "keyring-node"
	cfg.BindAddr = addr
	cfg.AdvertiseAddr = addr
	cfg.TLS.Enabled = true
	cfg.TLS.KeyringRotationEnabled = true
	cfg.TLS.RotationPeriod = time.Hour
	cfg.TLS.RotationCheckInterval = 10 * time.Millisecond
	cfg.Autopilot.Enabled = false
	cfg.Join.Interval = time.Hour
	n, err := NewNode(context.Background(), &cfg, NodeOptions{CustomListener: ln})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.WaitForLeader(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if kr, _ := n.ReadKeyring(); kr != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	kr, err := n.ReadKeyring()
	if err != nil || kr == nil || kr.Term != 1 {
		t.Fatalf("keyring = %+v err=%v", kr, err)
	}
	term3 := kr.Clone()
	term3.Term = 3
	if _, err := n.ApplyKeyring(context.Background(), term3); err != nil {
		t.Fatal(err)
	}
	n.ensureKeyring(context.Background())
	if !n.bootstrapDropped.Load() {
		t.Fatal("bootstrap trust was not dropped")
	}
	bad := &keyring.TLSKeyring{Keys: []*keyring.TLSKey{{ID: "bad", PKIMode: "shared-ca", CertPEM: []byte("bad")}}, ActiveKeyID: "bad", Term: 4}
	if err := n.onKeyring(bad); err == nil {
		t.Fatal("expected manager error")
	}
}

func TestInternalStartSingleNodeRecovery(t *testing.T) {
	dir := t.TempDir()
	start := func(singleNodeRecovery bool, fencer GenerationFencer) *Node {
		ln := freeListener(t)
		cfg := config.DefaultConfig()
		cfg.PerformanceMultiplier = 0.2
		cfg.Dir = dir
		cfg.NodeID = "recover-internal"
		cfg.BindAddr = ln.Addr().String()
		cfg.AdvertiseAddr = ln.Addr().String()
		cfg.Storage.Backend = config.StorageBackendRaftBoltDB
		cfg.SingleNodeRecovery = singleNodeRecovery
		cfg.Autopilot.Enabled = false
		cfg.Join.Interval = time.Hour
		n, err := NewNode(context.Background(), &cfg, NodeOptions{CustomListener: ln, GenerationFencer: fencer})
		if err != nil {
			t.Fatal(err)
		}
		if err := n.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := n.WaitForLeader(ctx); err != nil {
			t.Fatal(err)
		}
		return n
	}
	fencer := &internalFencer{}
	n1 := start(false, fencer)
	if _, err := n1.ApplyCommand(context.Background(), fsm.KindSet, fsm.KVEntry{Bucket: "b", Key: "k", Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	_ = n1.Close()
	n2 := start(true, fencer)
	defer n2.Close()
	if fencer.bumps != 1 {
		t.Fatalf("bumps = %d", fencer.bumps)
	}
	if got, ok, _ := n2.KV().Get("b", "k"); !ok || string(got) != "v" {
		t.Fatalf("recovered = %q ok=%v", got, ok)
	}
}

func TestInternalMembershipErrors(t *testing.T) {
	n := newInternalNode(t)
	if err := n.AddVoter("", "", time.Second); err == nil {
		t.Fatal("expected add voter error")
	}
	if err := n.AddNonvoter("", "", time.Second); err == nil {
		t.Fatal("expected add nonvoter error")
	}
	_ = n.RemoveServer("", time.Second)
}

func TestInternalReconcileMembershipError(t *testing.T) {
	n := newInternalNode(t)
	n.cfg.Join.CheckPeerResolvable = false
	desired := []discovery.Peer{{ID: n.nodeID, Address: n.advertise}, {ID: "bad", Address: ""}}
	if _, _, _, err := n.ReconcileMembership(desired, time.Second); err == nil {
		t.Fatal("expected reconcile error")
	}
}

func TestInternalSetupTLSManualError(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Dir = t.TempDir()
	cfg.NodeID = "manual-error"
	cfg.TLS.Enabled = true
	cfg.TLS.CACertPath = missing
	cfg.TLS.CertPath = missing
	cfg.TLS.KeyPath = missing
	n, err := NewNode(context.Background(), &cfg, NodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.setupTLS(context.Background()); err == nil {
		t.Fatal("expected manual TLS error")
	}
}

func TestInternalStartGenerationFencing(t *testing.T) {
	// Bootstrap node A.
	lnA := freeListener(t)
	addrA := lnA.Addr().String()
	lnB := freeListener(t)
	addrB := lnB.Addr().String()
	peers := []config.PeerConfig{{ID: "aaa", Address: addrA}, {ID: "bbb", Address: addrB}}
	fencer := &internalFencer{}
	cfgA := config.DefaultConfig()
	cfgA.PerformanceMultiplier = 0.2
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
	a, err := NewNode(context.Background(), &cfgA, NodeOptions{CustomListener: lnA, GenerationFencer: fencer})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.WaitForLeader(ctx); err != nil {
		t.Fatal(err)
	}
	// Stale node B with local generation 0 and cluster generation 1.
	dirB := t.TempDir()
	if err := os.WriteFile(filepath.Join(dirB, "generation"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	fencer.gen = 1
	cfgB := config.DefaultConfig()
	cfgB.PerformanceMultiplier = 0.2
	cfgB.Dir = dirB
	cfgB.NodeID = "bbb"
	cfgB.BindAddr = addrB
	cfgB.AdvertiseAddr = addrB
	cfgB.Discovery.Peers = peers
	cfgB.Discovery.Replicas = 2
	cfgB.AllowInsecureMultiNode = true
	cfgB.Storage.Backend = config.StorageBackendRaftBoltDB
	cfgB.Autopilot.Enabled = false
	cfgB.Join.Interval = time.Hour
	b, err := NewNode(context.Background(), &cfgB, NodeOptions{CustomListener: lnB, GenerationFencer: fencer})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := a.AddVoter("bbb", addrB, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := b.WaitForCleanState(ctx); err != nil {
		t.Fatal(err)
	}
	if gen, ok := k8s.ReadLocalGeneration(dirB); !ok || gen != 1 {
		t.Fatalf("local generation = %d ok=%v", gen, ok)
	}
}

func TestInternalTransferLeadershipError(t *testing.T) {
	ln0 := freeListener(t)
	ln1 := freeListener(t)
	addr0 := ln0.Addr().String()
	addr1 := ln1.Addr().String()
	peers := []config.PeerConfig{{ID: "node-0", Address: addr0}, {ID: "node-1", Address: addr1}}
	start := func(id, addr string, ln net.Listener) *Node {
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
		n, err := NewNode(context.Background(), &cfg, NodeOptions{CustomListener: ln})
		if err != nil {
			t.Fatal(err)
		}
		if err := n.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		return n
	}
	n0 := start("node-0", addr0, ln0)
	defer n0.Close()
	n1 := start("node-1", addr1, ln1)
	defer n1.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n0.WaitForLeader(ctx); err != nil {
		t.Fatal(err)
	}
	if err := n0.AddVoter("node-1", addr1, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := n1.WaitForCleanState(ctx); err != nil {
		t.Fatal(err)
	}
	if err := n1.RemoveServer("x", time.Second); err == nil {
		t.Fatal("expected non-leader remove error")
	}
	_ = n1.Close()
	if n0.IsLeader() {
		if err := n0.TransferLeadership(ctx, 100*time.Millisecond); err == nil {
			t.Fatal("expected transfer error")
		}
	}
}

func TestInternalStartSingleNodeRecoveryUnauthorized(t *testing.T) {
	dir := t.TempDir()
	start := func(singleNodeRecovery bool, authorizer ReplicaCountAuthorizer) *Node {
		ln := freeListener(t)
		cfg := config.DefaultConfig()
		cfg.PerformanceMultiplier = 0.2
		cfg.Dir = dir
		cfg.NodeID = "recover-unauth"
		cfg.BindAddr = ln.Addr().String()
		cfg.AdvertiseAddr = ln.Addr().String()
		cfg.Storage.Backend = config.StorageBackendRaftBoltDB
		cfg.SingleNodeRecovery = singleNodeRecovery
		cfg.Autopilot.Enabled = false
		cfg.Join.Interval = time.Hour
		n, err := NewNode(context.Background(), &cfg, NodeOptions{CustomListener: ln, ReplicaCountAuthorizer: authorizer})
		if err != nil {
			t.Fatal(err)
		}
		if err := n.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := n.WaitForLeader(ctx); err != nil {
			t.Fatal(err)
		}
		return n
	}
	n1 := start(false, nil)
	if _, err := n1.ApplyCommand(context.Background(), fsm.KindSet, fsm.KVEntry{Bucket: "b", Key: "k", Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	_ = n1.Close()
	n2 := start(true, internalAuthorizer{replicas: 3, ok: true})
	defer n2.Close()
}

func TestInternalStartManualTLS(t *testing.T) {
	dir := t.TempDir()
	ca, _ := pki.NewMintingCA("ca", "org", time.Hour)
	certPEM, keyPEM, _ := ca.IssuePeerCertificate("node", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	caPEM, _, _ := ca.EncodePEM()
	certFile := filepath.Join(dir, "node.crt")
	keyFile := filepath.Join(dir, "node.key")
	caFile := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(certFile, certPEM, 0o600)
	_ = os.WriteFile(keyFile, keyPEM, 0o600)
	_ = os.WriteFile(caFile, caPEM, 0o600)
	ln := freeListener(t)
	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Dir = t.TempDir()
	cfg.NodeID = "manual-start"
	cfg.BindAddr = ln.Addr().String()
	cfg.AdvertiseAddr = ln.Addr().String()
	cfg.TLS.Enabled = true
	cfg.TLS.CACertPath = caFile
	cfg.TLS.CertPath = certFile
	cfg.TLS.KeyPath = keyFile
	cfg.TLS.KeyringRotationEnabled = false
	cfg.Autopilot.Enabled = false
	cfg.Join.Interval = time.Hour
	n, err := NewNode(context.Background(), &cfg, NodeOptions{CustomListener: ln})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(context.Background()); err != nil {
		t.Fatalf("Start manual TLS: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := n.WaitForLeader(ctx); err != nil {
		t.Fatal(err)
	}
	_ = n.Close()
}

func TestInternalNewInmemNodeErrors(t *testing.T) {
	if _, err := NewInmemNode("bad\x00id", nil, time.Second, nil); err == nil {
		t.Fatal("expected invalid dir error")
	}
	n, err := NewInmemNode("", nil, 0, nil)
	if err != nil {
		t.Fatalf("default inmem node: %v", err)
	}
	_ = n.Close()
}

func TestInternalStartFailureStopsFileWatcher(t *testing.T) {
	dir := t.TempDir()
	ca, _ := pki.NewMintingCA("ca", "org", time.Hour)
	certPEM, keyPEM, _ := ca.IssuePeerCertificate("node", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	caPEM, _, _ := ca.EncodePEM()
	certFile := filepath.Join(dir, "node.crt")
	keyFile := filepath.Join(dir, "node.key")
	caFile := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(certFile, certPEM, 0o600)
	_ = os.WriteFile(keyFile, keyPEM, 0o600)
	_ = os.WriteFile(caFile, caPEM, 0o600)

	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Dir = t.TempDir()
	cfg.NodeID = "watcher-fail"
	cfg.BindAddr = "127.0.0.1:0"
	cfg.AdvertiseAddr = "invalid.invalid:1"
	cfg.AdvertiseResolveTimeout = 10 * time.Millisecond
	cfg.Storage.Backend = config.StorageBackendInmem
	cfg.TLS.Enabled = true
	cfg.TLS.CACertPath = caFile
	cfg.TLS.CertPath = certFile
	cfg.TLS.KeyPath = keyFile
	cfg.TLS.KeyringRotationEnabled = false
	cfg.Autopilot.Enabled = false
	cfg.Join.Interval = time.Hour
	n, err := NewNode(context.Background(), &cfg, NodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(context.Background()); err == nil {
		t.Fatal("expected Start failure")
	}
	if n.fileWatcher == nil {
		t.Fatal("file watcher was not started")
	}
	select {
	case <-n.fileWatcher.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("file watcher goroutine leaked after failed Start")
	}
	if n.fileWatcherCancel != nil {
		t.Fatal("file watcher cancel was not cleared")
	}
}

func TestInternalStartErrors(t *testing.T) {
	// Unresolvable advertise address.
	cfg2 := config.DefaultConfig()
	cfg2.PerformanceMultiplier = 0.2
	cfg2.Dir = t.TempDir()
	cfg2.NodeID = "bad-advertise"
	cfg2.BindAddr = "127.0.0.1:0"
	cfg2.AdvertiseAddr = "invalid.invalid:1"
	cfg2.AdvertiseResolveTimeout = 10 * time.Millisecond
	cfg2.Storage.Backend = config.StorageBackendInmem
	cfg2.Autopilot.Enabled = false
	n2, err := NewNode(context.Background(), &cfg2, NodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := n2.Start(context.Background()); err == nil {
		t.Fatal("expected advertise error")
	}

	// TLS bootstrap error.
	cfg3 := config.DefaultConfig()
	cfg3.PerformanceMultiplier = 0.2
	cfg3.Dir = t.TempDir()
	cfg3.NodeID = "bad-bootstrap"
	cfg3.BindAddr = "127.0.0.1:0"
	cfg3.AdvertiseAddr = "127.0.0.1:0"
	cfg3.TLS.Enabled = true
	cfg3.Storage.Backend = config.StorageBackendInmem
	cfg3.Autopilot.Enabled = false
	n3, err := NewNode(context.Background(), &cfg3, NodeOptions{BootstrapProvider: badBootstrapProvider{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := n3.Start(context.Background()); err == nil {
		t.Fatal("expected bootstrap error")
	}
}

// freeListener mirrors testutil.FreeListener without importing testutil,
// which would create an import cycle because testutil imports this package.
func freeListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve listener: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func TestNodeManualTLSFileWatcherHotReload(t *testing.T) {
	dir := t.TempDir()
	ca1, err := pki.NewMintingCA("ca1", "org", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := pki.NewMintingCA("ca2", "org", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert1, key1, err := ca1.IssuePeerCertificate("node", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert2, key2, err := ca2.IssuePeerCertificate("node", "org", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caPEM1, _, err := ca1.EncodePEM()
	if err != nil {
		t.Fatal(err)
	}
	caPEM2, _, err := ca2.EncodePEM()
	if err != nil {
		t.Fatal(err)
	}
	leaf1, err := tls.X509KeyPair(cert1, key1)
	if err != nil {
		t.Fatal(err)
	}
	leaf2, err := tls.X509KeyPair(cert2, key2)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "node.crt")
	keyFile := filepath.Join(dir, "node.key")
	caFile := filepath.Join(dir, "ca.crt")
	writeFiles := func(certPEM, keyPEM, caPEM []byte) {
		t.Helper()
		if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFiles(cert1, key1, caPEM1)

	cfg := config.DefaultConfig()
	cfg.PerformanceMultiplier = 0.2
	cfg.Dir = t.TempDir()
	cfg.NodeID = "manual-reload"
	cfg.TLS.Enabled = true
	cfg.TLS.CACertPath = caFile
	cfg.TLS.CertPath = certFile
	cfg.TLS.KeyPath = keyFile
	cfg.TLS.KeyringRotationEnabled = false
	cfg.Autopilot.Enabled = false
	n, err := NewNode(context.Background(), &cfg, NodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = n.Close() }()
	if err := n.setupTLS(context.Background()); err != nil {
		t.Fatalf("setupTLS: %v", err)
	}
	if n.fileWatcher == nil || n.tlsProvider == nil {
		t.Fatal("missing manual TLS components")
	}
	if n.tlsProvider != n.fileWatcher.Provider() {
		t.Fatal("node provider is not bound to the file watcher provider")
	}
	initial, err := n.tlsProvider.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(initial.Certificate[0], leaf1.Certificate[0]) {
		t.Fatal("initial certificate mismatch")
	}

	writeFiles(cert2, key2, caPEM2)
	if err := n.fileWatcher.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	updated, err := n.tlsProvider.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(updated.Certificate[0], leaf2.Certificate[0]) {
		t.Fatal("hot reload did not update the node provider certificate")
	}
	parsed, err := x509.ParseCertificate(leaf2.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: n.tlsProvider.CurrentCertPool(), DNSName: "localhost"}); err != nil {
		t.Fatalf("reloaded CA does not trust the new leaf: %v", err)
	}
}
