package discovery

import (
	"fmt"
	"os"
)

// DNSPeerResolver derives peers from
// <statefulSet>-<i>.<headless>.<namespace>.svc[.<clusterDomain>]:<port>.
type DNSPeerResolver struct {
	cfg           Config
	clusterDomain string
	hostname      string
}

// Resolve returns the full ordered peer list.
func (r *DNSPeerResolver) Resolve() ([]Peer, error) {
	cfg := r.cfg
	if cfg.Replicas < 1 {
		return nil, fmt.Errorf("discovery: replicas must be >= 1, got %d", cfg.Replicas)
	}
	if cfg.StatefulSetName == "" {
		return nil, fmt.Errorf("discovery: statefulset_name is required")
	}
	if cfg.HeadlessService == "" {
		return nil, fmt.Errorf("discovery: headless_service is required")
	}
	if cfg.Namespace == "" {
		return nil, fmt.Errorf("discovery: namespace is required")
	}
	peers := make([]Peer, 0, cfg.Replicas)
	for i := 0; i < cfg.Replicas; i++ {
		host := fmt.Sprintf("%s-%d", cfg.StatefulSetName, i)
		peers = append(peers, Peer{ID: host, Address: podAddress(&cfg, r.clusterDomain, host)})
	}
	return peers, nil
}

// Self returns this node's peer entry.
func (r *DNSPeerResolver) Self() (Peer, error) {
	host := r.hostname
	if host == "" {
		host, _ = os.Hostname()
	}
	return r.selfFor(host)
}

func (r *DNSPeerResolver) selfFor(host string) (Peer, error) {
	if _, ok := PodOrdinal(host, r.cfg.StatefulSetName); ok {
		return Peer{ID: host, Address: podAddress(&r.cfg, r.clusterDomain, host)}, nil
	}
	if r.cfg.AdvertiseAddr != "" {
		return Peer{ID: r.cfg.NodeID, Address: r.cfg.AdvertiseAddr}, nil
	}
	return Peer{}, fmt.Errorf("discovery: hostname %q does not match <statefulset>-<ordinal> and advertise_addr is unset", host)
}
