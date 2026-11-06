package discovery

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestDNSPeerResolverFQDNAndShortSvc(t *testing.T) {
	cfg := &Config{
		NodeID:          "sts-0",
		Replicas:        3,
		StatefulSetName: "sts",
		HeadlessService: "headless",
		Namespace:       "ns",
		ClusterDomain:   "cluster.local",
		RaftPort:        8081,
		Hostname:        "sts-0",
	}
	r := NewPeerResolver(cfg)
	peers, err := r.Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(peers) != 3 {
		t.Fatalf("peers = %d", len(peers))
	}
	want := "sts-0.headless.ns.svc.cluster.local:8081"
	if peers[0].Address != want {
		t.Fatalf("address = %q, want %q", peers[0].Address, want)
	}
	self, err := r.Self()
	if err != nil {
		t.Fatalf("Self: %v", err)
	}
	if self.ID != "sts-0" {
		t.Fatalf("self = %+v", self)
	}

	cfg.ClusterDomain = ""
	r = NewPeerResolver(cfg)
	peers, err = r.Resolve()
	if err != nil {
		t.Fatalf("Resolve short: %v", err)
	}
	if peers[0].Address != "sts-0.headless.ns.svc:8081" {
		t.Fatalf("short address = %q", peers[0].Address)
	}
}

func TestDNSPeerResolverErrors(t *testing.T) {
	tests := []Config{
		{Replicas: 0, StatefulSetName: "sts", HeadlessService: "h", Namespace: "n"},
		{Replicas: 1, HeadlessService: "h", Namespace: "n"},
		{Replicas: 1, StatefulSetName: "sts", Namespace: "n"},
		{Replicas: 1, StatefulSetName: "sts", HeadlessService: "h"},
	}
	for _, cfg := range tests {
		r := &DNSPeerResolver{cfg: cfg}
		if _, err := r.Resolve(); err == nil {
			t.Fatalf("expected error for %+v", cfg)
		}
	}
	r := &DNSPeerResolver{cfg: Config{StatefulSetName: "sts"}, hostname: "other"}
	if _, err := r.Self(); err == nil {
		t.Fatal("expected self error")
	}
	r.cfg.AdvertiseAddr = "1.2.3.4:1"
	if self, err := r.Self(); err != nil || self.Address != "1.2.3.4:1" {
		t.Fatalf("self = %+v err=%v", self, err)
	}
}

func TestStaticPeerResolverDeterministicSort(t *testing.T) {
	peers := []Peer{
		{ID: "c", Address: "c:1"},
		{ID: "a", Address: "a:1"},
	}
	cfgA := &Config{NodeID: "b", AdvertiseAddr: "b:1", Peers: peers}
	cfgB := &Config{NodeID: "b", AdvertiseAddr: "b:1", Peers: []Peer{peers[1], peers[0]}}
	rA := NewPeerResolver(cfgA)
	rB := NewPeerResolver(cfgB)
	resA, err := rA.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	resB, err := rB.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if len(resA) != 3 || len(resB) != 3 {
		t.Fatalf("lengths = %d,%d", len(resA), len(resB))
	}
	for i := range resA {
		if resA[i].ID != resB[i].ID {
			t.Fatalf("order mismatch at %d: %q vs %q", i, resA[i].ID, resB[i].ID)
		}
	}
	if resA[0].ID != "a" {
		t.Fatalf("first peer = %q, want a", resA[0].ID)
	}
}

func TestStaticPeerResolverSelf(t *testing.T) {
	r := &StaticPeerResolver{cfg: Config{NodeID: "a", Peers: []Peer{{ID: "a", Address: "a:1"}}}}
	self, err := r.Self()
	if err != nil || self.ID != "a" {
		t.Fatalf("self = %+v err=%v", self, err)
	}
	r = &StaticPeerResolver{cfg: Config{AdvertiseAddr: "a:1", Peers: []Peer{{ID: "a", Address: "a:1"}}}}
	if _, err := r.Self(); err != nil {
		t.Fatalf("self by address: %v", err)
	}
	r = &StaticPeerResolver{cfg: Config{}}
	if _, err := r.Self(); err == nil {
		t.Fatal("expected error")
	}
}

func TestSingleNodeResolver(t *testing.T) {
	r := NewPeerResolver(&Config{NodeID: "n0", BindAddr: "0.0.0.0:9000"})
	peers, err := r.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].ID != "n0" || peers[0].Address != "127.0.0.1:9000" {
		t.Fatalf("peers = %+v", peers)
	}
}

func TestDeriveAdvertiseAddr(t *testing.T) {
	cfg := &Config{AdvertiseAddr: "explicit:1"}
	if got, _ := DeriveAdvertiseAddr(cfg, "sts-0"); got != "explicit:1" {
		t.Fatalf("got %q", got)
	}
	cfg = &Config{StatefulSetName: "sts", HeadlessService: "h", Namespace: "n", ClusterDomain: "cluster.local", RaftPort: 8081}
	if got, _ := DeriveAdvertiseAddr(cfg, "sts-0"); got != "sts-0.h.n.svc.cluster.local:8081" {
		t.Fatalf("got %q", got)
	}
	cfg = &Config{BindAddr: "0.0.0.0:9000"}
	if got, _ := DeriveAdvertiseAddr(cfg, "other"); got != "127.0.0.1:9000" {
		t.Fatalf("got %q", got)
	}
}

func TestPodSANs(t *testing.T) {
	cfg := &Config{StatefulSetName: "sts", HeadlessService: "h", Namespace: "n", ClusterDomain: "cluster.local"}
	dns, ips := PodSANs(cfg, "sts-0")
	want := []string{
		"sts-0", "localhost", "sts-0.h", "sts-0.h.n", "sts-0.h.n.svc", "sts-0.h.n.svc.cluster.local",
	}
	if len(dns) != len(want) {
		t.Fatalf("dns = %v", dns)
	}
	for i := range want {
		if dns[i] != want[i] {
			t.Fatalf("dns[%d] = %q, want %q", i, dns[i], want[i])
		}
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("ips = %v", ips)
	}
}

func TestServerCertFQDNSANs(t *testing.T) {
	cfg := &Config{HeadlessService: "h", Namespace: "n", ClusterDomain: "cluster.local"}
	got := ServerCertFQDNSANs(cfg, "sts-0")
	if len(got) != 2 || got[0] != "sts-0.h.n.svc.cluster.local" || got[1] != "sts-0.h.n.svc" {
		t.Fatalf("got %v", got)
	}
	cfg.ClusterDomain = ""
	got = ServerCertFQDNSANs(cfg, "sts-0")
	if len(got) != 1 || got[0] != "sts-0.h.n.svc" {
		t.Fatalf("got %v", got)
	}
	if ServerCertFQDNSANs(cfg, "") != nil {
		t.Fatal("expected nil")
	}
}

func TestResolveBootstrapState(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{NodeID: "a", Peers: []Peer{{ID: "a", Address: "a:1"}, {ID: "b", Address: "b:1"}}}
	resolver := NewPeerResolver(cfg)
	id, bootstrap, err := ResolveBootstrapState(cfg, resolver, dir)
	if err != nil {
		t.Fatal(err)
	}
	if id != "a" || !bootstrap {
		t.Fatalf("id=%q bootstrap=%v", id, bootstrap)
	}
	cfg.NodeID = "b"
	resolver = NewPeerResolver(cfg)
	id, bootstrap, err = ResolveBootstrapState(cfg, resolver, dir)
	if err != nil {
		t.Fatal(err)
	}
	if id != "b" || bootstrap {
		t.Fatalf("id=%q bootstrap=%v", id, bootstrap)
	}
	// Generated node ID is persisted.
	cfg = &Config{}
	resolver = NewPeerResolver(cfg)
	id, _, err = ResolveBootstrapState(cfg, resolver, dir)
	if err != nil || id == "" {
		t.Fatalf("generated id=%q err=%v", id, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "node-id")); err != nil {
		t.Fatalf("node-id not persisted: %v", err)
	}
}

func TestShouldCABootstrap(t *testing.T) {
	if !ShouldCABootstrap(true, true, "sts-1") {
		t.Fatal("force should bootstrap")
	}
	if !ShouldCABootstrap(false, false, "sts-1") {
		t.Fatal("single node should bootstrap")
	}
	if !ShouldCABootstrap(false, true, "sts-0") {
		t.Fatal("ordinal 0 should bootstrap")
	}
	if ShouldCABootstrap(false, true, "sts-1") {
		t.Fatal("ordinal 1 should not bootstrap")
	}
}

func TestParseLegacyPeersAndOrdinal(t *testing.T) {
	peers := ParseLegacyPeers([]string{"a=1.2.3.4:1", "b", "", "c=5.6.7.8:2"})
	if len(peers) != 3 || peers[0].ID != "a" || peers[1].ID != "b" || peers[2].Address != "5.6.7.8:2" {
		t.Fatalf("peers = %+v", peers)
	}
	if n, ok := PodOrdinal("sts-3", "sts"); !ok || n != 3 {
		t.Fatalf("ordinal = %d,%v", n, ok)
	}
	if _, ok := PodOrdinal("other-3", "sts"); ok {
		t.Fatal("unexpected ordinal match")
	}
	if _, ok := PodOrdinal("sts-x", "sts"); ok {
		t.Fatal("unexpected ordinal match")
	}
	if _, ok := PodOrdinal("sts-", "sts"); ok {
		t.Fatal("unexpected ordinal match")
	}
}

func TestNodeCommonName(t *testing.T) {
	if got := NodeCommonName("configured", nil, "host"); got != "configured" {
		t.Fatalf("got %q", got)
	}
	r := NewPeerResolver(&Config{NodeID: "self", BindAddr: "127.0.0.1:1"})
	if got := NodeCommonName("", r, "host"); got != "self" {
		t.Fatalf("got %q", got)
	}
	if got := NodeCommonName("", nil, "host"); got != "host" {
		t.Fatalf("got %q", got)
	}
}

func TestNewPeerResolverSelection(t *testing.T) {
	if _, ok := NewPeerResolver(&Config{Peers: []Peer{{ID: "a", Address: "a:1"}}}).(*StaticPeerResolver); !ok {
		t.Fatal("expected static resolver")
	}
	if _, ok := NewPeerResolver(&Config{StatefulSetName: "sts", HeadlessService: "h"}).(*DNSPeerResolver); !ok {
		t.Fatal("expected dns resolver")
	}
	if _, ok := NewPeerResolver(&Config{}).(*SingleNodeResolver); !ok {
		t.Fatal("expected single resolver")
	}
}

func TestResolveBootstrapStateErrors(t *testing.T) {
	cfg := &Config{Replicas: 0, StatefulSetName: "sts", HeadlessService: "h", Namespace: "n"}
	resolver := NewPeerResolver(cfg)
	if _, _, err := ResolveBootstrapState(cfg, resolver, t.TempDir()); err == nil {
		t.Fatal("expected resolve error")
	}
	cfg = &Config{NodeID: "a", Peers: []Peer{{ID: "a", Address: "a:1"}}}
	resolver = NewPeerResolver(cfg)
	if _, _, err := ResolveBootstrapState(cfg, resolver, t.TempDir()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStaticPeerResolverResolveError(t *testing.T) {
	r := &StaticPeerResolver{cfg: Config{}}
	if _, err := r.Resolve(); err == nil {
		t.Fatal("expected resolve error")
	}
}

func TestPodSANsEmptyHeadless(t *testing.T) {
	dns, ips := PodSANs(&Config{}, "host")
	if len(dns) != 2 || dns[0] != "host" || dns[1] != "localhost" {
		t.Fatalf("dns = %v", dns)
	}
	if len(ips) != 1 {
		t.Fatalf("ips = %v", ips)
	}
}

func TestNodeCommonNameResolverError(t *testing.T) {
	r := &StaticPeerResolver{cfg: Config{}}
	if got := NodeCommonName("", r, "host"); got != "host" {
		t.Fatalf("got %q", got)
	}
}

func TestLoadOrGenerateNodeIDExistingAndErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "node-id"), []byte("persisted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	resolver := NewPeerResolver(cfg)
	id, _, err := ResolveBootstrapState(cfg, resolver, dir)
	if err != nil || id != "persisted" {
		t.Fatalf("id = %q err=%v", id, err)
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveBootstrapState(cfg, resolver, file); err == nil {
		t.Fatal("expected read error")
	}
}

func TestStaticSynthesizeSelf(t *testing.T) {
	r := &StaticPeerResolver{cfg: Config{AdvertiseAddr: "a:1"}}
	self, err := r.Self()
	if err != nil || self.Address != "a:1" {
		t.Fatalf("self = %+v err=%v", self, err)
	}
	r = &StaticPeerResolver{cfg: Config{NodeID: "n", BindAddr: "0.0.0.0:9000"}}
	self, err = r.Self()
	if err != nil || self.Address != "127.0.0.1:9000" {
		t.Fatalf("self = %+v err=%v", self, err)
	}
}

func TestDNSSelfUsesHostname(t *testing.T) {
	r := &DNSPeerResolver{cfg: Config{StatefulSetName: "sts", HeadlessService: "h", Namespace: "n", AdvertiseAddr: "a:1"}}
	self, err := r.Self()
	if err != nil || self.Address != "a:1" {
		t.Fatalf("self = %+v err=%v", self, err)
	}
}
