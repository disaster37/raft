package raft

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	hraft "github.com/hashicorp/raft"

	"github.com/disaster37/go-raft/discovery"
	"github.com/disaster37/go-raft/keyring"
)

// AddVoter adds a voting member. Leader-only.
func (n *Node) AddVoter(id, address string, timeout time.Duration) error {
	if n.raft == nil {
		return ErrAlreadyClosed
	}
	if err := n.raft.AddVoter(hraft.ServerID(id), hraft.ServerAddress(address), 0, timeout).Error(); err != nil {
		return fmt.Errorf("add voter %s: %w", id, err)
	}
	return nil
}

// AddNonvoter adds a non-voting member. Leader-only.
func (n *Node) AddNonvoter(id, address string, timeout time.Duration) error {
	if n.raft == nil {
		return ErrAlreadyClosed
	}
	if err := n.raft.AddNonvoter(hraft.ServerID(id), hraft.ServerAddress(address), 0, timeout).Error(); err != nil {
		return fmt.Errorf("add nonvoter %s: %w", id, err)
	}
	return nil
}

// RemoveServer removes a member. Leader-only.
func (n *Node) RemoveServer(id string, timeout time.Duration) error {
	if n.raft == nil {
		return ErrAlreadyClosed
	}
	if err := n.raft.RemoveServer(hraft.ServerID(id), 0, timeout).Error(); err != nil {
		return fmt.Errorf("remove server %s: %w", id, err)
	}
	return nil
}

// ReconcileMembership makes the cluster configuration match desired.
func (n *Node) ReconcileMembership(desired []discovery.Peer, timeout time.Duration) (added, updated, removed []string, err error) {
	if !n.IsLeader() {
		return nil, nil, nil, ErrNotLeader
	}
	current, err := n.GetConfiguration()
	if err != nil {
		return nil, nil, nil, err
	}
	sort.Slice(desired, func(i, j int) bool { return desired[i].ID < desired[j].ID })

	currentByID := make(map[string]hraft.Server, len(current.Servers))
	for _, srv := range current.Servers {
		currentByID[string(srv.ID)] = srv
	}
	desiredByID := make(map[string]discovery.Peer, len(desired))
	for _, p := range desired {
		if p.ID != "" {
			desiredByID[p.ID] = p
		}
	}

	for _, p := range desired {
		if _, ok := currentByID[p.ID]; ok {
			continue
		}
		if n.cfg.Join.CheckPeerResolvable && !n.peerResolvable(p.Address) {
			n.logger.Warn("skipping unresolvable peer", map[string]any{"peer_id": p.ID, "address": p.Address})
			continue
		}
		if p.NonVoter {
			err = n.AddNonvoter(p.ID, p.Address, timeout)
		} else {
			err = n.AddVoter(p.ID, p.Address, timeout)
		}
		if err != nil {
			return added, updated, removed, err
		}
		added = append(added, p.ID)
	}

	for _, p := range desired {
		srv, ok := currentByID[p.ID]
		if !ok {
			continue
		}
		if string(srv.Address) == p.Address {
			continue
		}
		if n.cfg.Join.CheckPeerResolvable && !n.peerResolvable(p.Address) {
			continue
		}
		if err := n.RemoveServer(p.ID, timeout); err != nil {
			return added, updated, removed, err
		}
		if p.NonVoter {
			err = n.AddNonvoter(p.ID, p.Address, timeout)
		} else {
			err = n.AddVoter(p.ID, p.Address, timeout)
		}
		if err != nil {
			return added, updated, removed, err
		}
		updated = append(updated, p.ID)
	}

	for id := range currentByID {
		if _, ok := desiredByID[id]; ok {
			continue
		}
		if err := n.RemoveServer(id, timeout); err != nil {
			return added, updated, removed, err
		}
		removed = append(removed, id)
	}
	return added, updated, removed, nil
}

func (n *Node) peerResolvable(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	return err == nil && len(ips) > 0
}

// StartJoinLoop starts the membership reconciliation loop.
func (n *Node) StartJoinLoop(ctx context.Context) {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.startJoinLoop(ctx)
	}()
}

func (n *Node) startJoinLoop(ctx context.Context) {
	ticker := time.NewTicker(n.cfg.Join.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !n.IsLeader() {
				continue
			}
			n.ensureKeyring(ctx)
			desired, err := n.resolver.Resolve()
			if err != nil {
				n.metrics.IncJoinFailures()
				n.logger.Warn("resolve peers failed", map[string]any{"error": err.Error()})
				continue
			}
			n.metrics.IncJoinAttempts()
			if _, _, _, err := n.ReconcileMembership(desired, n.cfg.Join.ReconcileTimeout); err != nil && !errors.Is(err, ErrNotLeader) {
				n.metrics.IncJoinFailures()
				n.logger.Warn("reconcile membership failed", map[string]any{"error": err.Error()})
			}
		}
	}
}

func (n *Node) seedKeyring(context.Context) (*keyring.TLSKeyring, error) {
	if n.bootstrap == nil || len(n.bootstrap.CAKeyPEM) == 0 {
		return nil, nil
	}
	return keyring.KeyringFromBootstrapCA(n.cfg.TLS.PKIMode, n.bootstrap, n.opts.Sealer, time.Now())
}

func (n *Node) ensureKeyring(ctx context.Context) {
	if !n.cfg.TLS.KeyringRotationEnabled || n.keyringManager == nil || n.fsm == nil {
		return
	}
	kr := n.fsm.Keyring()
	if kr == nil {
		seeded, err := n.seedKeyring(ctx)
		if err != nil {
			n.logger.Warn("seed keyring failed", map[string]any{"error": err.Error()})
			return
		}
		if seeded == nil {
			return
		}
		if _, err := n.ApplyKeyring(ctx, seeded); err != nil {
			n.logger.Warn("apply initial keyring failed", map[string]any{"error": err.Error()})
			return
		}
		n.logger.Info("seeded in-band TLS keyring", map[string]any{"term": seeded.Term})
		return
	}
	if kr.Term >= 3 && !n.bootstrapDropped.Swap(true) {
		n.keyringManager.DropBootstrapTrust()
	}
}

func (n *Node) startRemovedChecker(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n.IsVoter() || n.IsNonVoter() {
				n.wasMember.Store(true)
				continue
			}
			if n.wasMember.Load() && n.IsRemoved() && !n.removed.Swap(true) {
				n.logger.Warn("node removed from cluster", map[string]any{"node_id": n.nodeID})
				if n.opts.RemovedCallback != nil {
					n.opts.RemovedCallback()
				}
			}
		}
	}
}

// StepDown transfers leadership when possible.
func (n *Node) StepDown(ctx context.Context) error {
	if !n.IsLeader() {
		return nil
	}
	cfg, err := n.GetConfiguration()
	if err != nil {
		return err
	}
	otherVoters := 0
	for _, srv := range cfg.Servers {
		if srv.Suffrage == hraft.Voter && string(srv.ID) != n.nodeID {
			otherVoters++
		}
	}
	if otherVoters == 0 {
		return nil
	}
	if err := n.raft.LeadershipTransfer().Error(); err != nil {
		if errors.Is(err, hraft.ErrNotLeader) {
			return nil
		}
		return fmt.Errorf("step down: %w", err)
	}
	return nil
}

// TransferLeadership transfers leadership to another voter.
func (n *Node) TransferLeadership(ctx context.Context, timeout time.Duration) error {
	if !n.IsLeader() {
		return nil
	}
	cfg, err := n.GetConfiguration()
	if err != nil {
		return err
	}
	otherVoters := 0
	for _, srv := range cfg.Servers {
		if srv.Suffrage == hraft.Voter && string(srv.ID) != n.nodeID {
			otherVoters++
		}
	}
	if otherVoters == 0 {
		return nil
	}
	if err := n.raft.LeadershipTransfer().Error(); err != nil {
		if errors.Is(err, hraft.ErrNotLeader) {
			return nil
		}
		return fmt.Errorf("transfer leadership: %w", err)
	}
	n.metrics.IncLeadershipTransfers()
	return nil
}

// LeaveCluster removes this node from the voter configuration. The node must
// be the leader: removing the leader causes Raft to elect a new leader from
// the remaining voters. Transferring leadership first would leave this node
// unable to remove itself (RemoveServer is leader-only).
func (n *Node) LeaveCluster(ctx context.Context, timeout time.Duration) error {
	if !n.IsLeader() {
		return ErrNotLeader
	}
	cfg, err := n.GetConfiguration()
	if err != nil {
		return err
	}
	otherVoters := 0
	for _, srv := range cfg.Servers {
		if srv.Suffrage == hraft.Voter && string(srv.ID) != n.nodeID {
			otherVoters++
		}
	}
	if otherVoters == 0 {
		return nil
	}
	n.wasMember.Store(true)
	if err := n.RemoveServer(n.nodeID, timeout); err != nil {
		return fmt.Errorf("leave cluster: %w", err)
	}
	n.logger.Info("left raft cluster", map[string]any{"node_id": n.nodeID})
	return nil
}
