package discovery

// SingleNodeResolver represents a one-voter cluster (self only).
type SingleNodeResolver struct {
	cfg Config
}

// Resolve returns the single self peer.
func (r *SingleNodeResolver) Resolve() ([]Peer, error) {
	self, err := r.Self()
	if err != nil {
		return nil, err
	}
	return []Peer{self}, nil
}

// Self returns this node's peer entry.
func (r *SingleNodeResolver) Self() (Peer, error) {
	addr := r.cfg.AdvertiseAddr
	if addr == "" {
		addr = deriveBindHost(r.cfg.BindAddr, raftPort(&r.cfg))
	}
	return Peer{ID: r.cfg.NodeID, Address: addr}, nil
}
