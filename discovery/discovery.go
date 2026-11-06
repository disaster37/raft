// Package discovery resolves the Raft peer set for DNS, static, and
// single-node deployments and derives certificate SANs.
package discovery

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Peer is one Raft cluster member.
type Peer struct {
	ID       string `json:"id" mapstructure:"id"`
	Address  string `json:"address" mapstructure:"address"`
	NonVoter bool   `json:"non_voter,omitempty" mapstructure:"non_voter"`
}

// PeerResolver computes the full peer list and identifies this node.
type PeerResolver interface {
	Resolve() ([]Peer, error)
	Self() (Peer, error)
}

// Config drives peer discovery.
type Config struct {
	NodeID          string
	AdvertiseAddr   string
	BindAddr        string
	Peers           []Peer
	Replicas        int
	StatefulSetName string
	HeadlessService string
	Namespace       string
	ClusterDomain   string
	RaftPort        int
	Hostname        string
}

// NewPeerResolver selects a resolver: explicit peers, DNS StatefulSet
// discovery, or single-node.
func NewPeerResolver(cfg *Config) PeerResolver {
	switch {
	case len(cfg.Peers) > 0:
		return &StaticPeerResolver{cfg: *cfg}
	case cfg.StatefulSetName != "" && cfg.HeadlessService != "":
		return &DNSPeerResolver{cfg: *cfg, clusterDomain: cfg.ClusterDomain, hostname: cfg.Hostname}
	default:
		return &SingleNodeResolver{cfg: *cfg}
	}
}

// ParseLegacyPeers parses "id=host:port" entries. Entries without "=" use the
// address as both ID and address.
func ParseLegacyPeers(entries []string) []Peer {
	peers := make([]Peer, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		id, addr, found := strings.Cut(entry, "=")
		if !found {
			peers = append(peers, Peer{ID: entry, Address: entry})
			continue
		}
		id = strings.TrimSpace(id)
		addr = strings.TrimSpace(addr)
		if id == "" && addr == "" {
			continue
		}
		peers = append(peers, Peer{ID: id, Address: addr})
	}
	return peers
}

// PodOrdinal reports whether host matches "<statefulSet>-<n>" and returns n.
func PodOrdinal(host, statefulSetName string) (int, bool) {
	prefix := statefulSetName + "-"
	if statefulSetName == "" || !strings.HasPrefix(host, prefix) {
		return 0, false
	}
	suffix := strings.TrimPrefix(host, prefix)
	if suffix == "" {
		return 0, false
	}
	n, err := strconv.Atoi(suffix)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// DeriveAdvertiseAddr computes this node's advertise address.
func DeriveAdvertiseAddr(cfg *Config, hostname string) (string, error) {
	if cfg.AdvertiseAddr != "" {
		return cfg.AdvertiseAddr, nil
	}
	if _, ok := PodOrdinal(hostname, cfg.StatefulSetName); ok && cfg.HeadlessService != "" && cfg.Namespace != "" {
		return podAddress(cfg, cfg.ClusterDomain, hostname), nil
	}
	return deriveBindHost(cfg.BindAddr, raftPort(cfg)), nil
}

// PodSANs returns the DNS and IP SANs for this pod's leaf certificate.
func PodSANs(cfg *Config, hostname string) (dnsNames []string, ipAddrs []net.IP) {
	names := []string{hostname, "localhost"}
	if cfg.HeadlessService != "" {
		base := fmt.Sprintf("%s.%s", hostname, cfg.HeadlessService)
		names = append(names, base)
		if cfg.Namespace != "" {
			baseNS := fmt.Sprintf("%s.%s", base, cfg.Namespace)
			names = append(names, baseNS, fmt.Sprintf("%s.svc", baseNS))
			if cfg.ClusterDomain != "" {
				names = append(names, fmt.Sprintf("%s.svc.%s", baseNS, cfg.ClusterDomain))
			}
		}
	}
	seen := make(map[string]bool, len(names))
	deduped := make([]string, 0, len(names))
	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		deduped = append(deduped, n)
	}
	return deduped, []net.IP{net.ParseIP("127.0.0.1")}
}

// ServerCertFQDNSANs returns this pod's exact DNS SANs (no wildcard).
func ServerCertFQDNSANs(cfg *Config, hostname string) []string {
	if hostname == "" || cfg.HeadlessService == "" || cfg.Namespace == "" {
		return nil
	}
	base := fmt.Sprintf("%s.%s.%s.svc", hostname, cfg.HeadlessService, cfg.Namespace)
	if cfg.ClusterDomain != "" {
		return []string{fmt.Sprintf("%s.%s", base, cfg.ClusterDomain), base}
	}
	return []string{base}
}

// ResolveBootstrapState computes the stable node ID and whether this node
// seeds the initial single-voter cluster. Only the first resolved peer
// bootstraps, preventing split-brain (CWE-693).
func ResolveBootstrapState(cfg *Config, resolver PeerResolver, dir string) (nodeID string, shouldBootstrap bool, err error) {
	shouldBootstrap = true
	if resolver != nil {
		resolved, resolveErr := resolver.Resolve()
		if resolveErr != nil {
			return "", false, fmt.Errorf("resolve peers: %w", resolveErr)
		}
		if self, selfErr := resolver.Self(); selfErr == nil && len(resolved) > 0 {
			shouldBootstrap = self.ID == resolved[0].ID
		}
	}
	nodeID = cfg.NodeID
	if nodeID == "" && resolver != nil {
		if self, selfErr := resolver.Self(); selfErr == nil {
			nodeID = self.ID
		}
	}
	if nodeID == "" {
		nodeID, err = loadOrGenerateNodeID(dir)
		if err != nil {
			return "", false, err
		}
	}
	return nodeID, shouldBootstrap, nil
}

// NodeCommonName returns the configured node ID, else the resolver's self ID,
// else the hostname.
func NodeCommonName(configuredNodeID string, resolver PeerResolver, hostname string) string {
	if configuredNodeID != "" {
		return configuredNodeID
	}
	if resolver != nil {
		if self, err := resolver.Self(); err == nil && self.ID != "" {
			return self.ID
		}
	}
	return hostname
}

// ShouldCABootstrap reports whether this node should create the bootstrap CA.
func ShouldCABootstrap(forceBootstrap bool, isMultiNode bool, hostname string) bool {
	return forceBootstrap || !isMultiNode || strings.HasSuffix(hostname, "-0")
}

func raftPort(cfg *Config) int {
	if cfg.RaftPort != 0 {
		return cfg.RaftPort
	}
	if _, portStr, err := net.SplitHostPort(cfg.BindAddr); err == nil {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
			return p
		}
	}
	return 8081
}

func podAddress(cfg *Config, clusterDomain, host string) string {
	name := fmt.Sprintf("%s.%s.%s.svc", host, cfg.HeadlessService, cfg.Namespace)
	if clusterDomain != "" {
		name = fmt.Sprintf("%s.%s", name, clusterDomain)
	}
	return fmt.Sprintf("%s:%d", name, raftPort(cfg))
}

func deriveBindHost(bindAddr string, port int) string {
	host, portStr, err := net.SplitHostPort(bindAddr)
	if err != nil {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, portStr)
}

func loadOrGenerateNodeID(dir string) (string, error) {
	if dir == "" {
		return randomUUID()
	}
	path := filepath.Join(dir, "node-id")
	//nolint:gosec // path is a fixed node-id file under the data dir
	if b, err := os.ReadFile(path); err == nil {
		id := strings.TrimSpace(string(b))
		if id != "" {
			return id, nil
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("read node-id: %w", err)
	}
	id, err := randomUUID()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(id), 0o600); err != nil {
		return "", fmt.Errorf("write node-id: %w", err)
	}
	return id, nil
}

func randomUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate node id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	), nil
}

// sortPeers sorts peers deterministically by ID.
func sortPeers(peers []Peer) {
	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })
}
