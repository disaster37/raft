package discovery

import "fmt"

// StaticPeerResolver returns an explicit peer list. When self is not present
// in the list it is synthesized and the whole list is sorted by ID so every
// node computes the same first peer (and exactly one node bootstraps).
type StaticPeerResolver struct {
	cfg Config
}

// Resolve returns the explicit peers, inserting self when missing.
func (r *StaticPeerResolver) Resolve() ([]Peer, error) {
	peers := make([]Peer, 0, len(r.cfg.Peers)+1)
	peers = append(peers, r.cfg.Peers...)
	if _, err := r.matchSelf(); err == nil {
		return peers, nil
	}
	self, err := r.synthesizeSelf()
	if err != nil {
		return nil, err
	}
	peers = append(peers, self)
	sortPeers(peers)
	return peers, nil
}

// Self returns this node's peer entry.
func (r *StaticPeerResolver) Self() (Peer, error) {
	if p, err := r.matchSelf(); err == nil {
		return p, nil
	}
	return r.synthesizeSelf()
}

func (r *StaticPeerResolver) matchSelf() (Peer, error) {
	cfg := r.cfg
	for _, p := range cfg.Peers {
		if cfg.NodeID != "" && p.ID == cfg.NodeID {
			return p, nil
		}
	}
	if cfg.AdvertiseAddr != "" {
		for _, p := range cfg.Peers {
			if p.Address == cfg.AdvertiseAddr {
				return p, nil
			}
		}
	}
	return Peer{}, fmt.Errorf("discovery: self not found in explicit peers")
}

func (r *StaticPeerResolver) synthesizeSelf() (Peer, error) {
	cfg := r.cfg
	if cfg.NodeID == "" && cfg.AdvertiseAddr == "" {
		return Peer{}, fmt.Errorf("discovery: cannot identify self without node_id or advertise_addr")
	}
	addr := cfg.AdvertiseAddr
	if addr == "" {
		addr = deriveBindHost(cfg.BindAddr, raftPort(&cfg))
	}
	return Peer{ID: cfg.NodeID, Address: addr}, nil
}
