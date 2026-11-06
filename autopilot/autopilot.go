// Package autopilot tracks follower health and removes dead servers while
// respecting quorum and stabilization guards.
package autopilot

import (
	"context"
	"fmt"
	"sync"
	"time"

	hraft "github.com/hashicorp/raft"

	"github.com/disaster37/raft/config"
	"github.com/disaster37/raft/observ"
)

// FollowerState tracks the health of a single follower.
type FollowerState struct {
	ID                hraft.ServerID
	Address           hraft.ServerAddress
	AppliedIndex      uint64
	AppliedIndexDelta int64
	Term              uint64
	LastHeartbeat     time.Time
	Healthy           bool
	IsDead            bool
}

// EchoUpdate is a follower's periodic applied-index report.
type EchoUpdate struct {
	NodeID       string    `json:"node_id"`
	AppliedIndex uint64    `json:"applied_index"`
	Term         uint64    `json:"term"`
	Timestamp    time.Time `json:"timestamp"`
}

// Autopilot manages follower tracking and dead-server cleanup.
type Autopilot struct {
	cfg      config.AutopilotConfig
	r        *hraft.Raft
	localID  string
	leaderCh <-chan bool
	logger   observ.Logger
	metrics  observ.MetricsCollector
	now      func() time.Time

	mu         sync.RWMutex
	followers  map[hraft.ServerID]*FollowerState
	lastChange time.Time
}

// New returns an Autopilot.
func New(cfg config.AutopilotConfig, r *hraft.Raft, localID string, leaderCh <-chan bool, logger observ.Logger, metrics observ.MetricsCollector) *Autopilot {
	if logger == nil {
		logger = observ.NewNoopLogger()
	}
	if metrics == nil {
		metrics = observ.NewNoopMetrics()
	}
	return &Autopilot{
		cfg:       cfg,
		r:         r,
		localID:   localID,
		leaderCh:  leaderCh,
		logger:    logger,
		metrics:   metrics,
		now:       time.Now,
		followers: map[hraft.ServerID]*FollowerState{},
	}
}

// Start runs the autopilot loop until ctx is cancelled.
func (a *Autopilot) Start(ctx context.Context) {
	if !a.cfg.Enabled {
		return
	}
	heartbeatInterval := a.cfg.HeartbeatInterval
	if heartbeatInterval <= 0 {
		heartbeatInterval = time.Second
	}
	heartbeatTicker := time.NewTicker(heartbeatInterval)
	defer heartbeatTicker.Stop()
	cleanupTicker := time.NewTicker(30 * time.Second)
	defer cleanupTicker.Stop()

	isLeader := false
	for {
		select {
		case <-ctx.Done():
			return
		case leader, ok := <-a.leaderCh:
			if !ok {
				return
			}
			isLeader = leader
			if isLeader {
				a.stabilize()
			}
		case <-heartbeatTicker.C:
			if isLeader {
				a.heartbeatTracker()
			}
		case <-cleanupTicker.C:
			if isLeader && a.cfg.CleanupDeadServers {
				if err := a.RemoveDeadServers(ctx); err != nil {
					a.logger.Warn("autopilot: remove dead servers failed", map[string]any{"error": err.Error()})
				}
			}
		}
	}
}

// RecordEcho records a follower applied-index report.
func (a *Autopilot) RecordEcho(u EchoUpdate) {
	if u.NodeID == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	id := hraft.ServerID(u.NodeID)
	state, ok := a.followers[id]
	if !ok {
		state = &FollowerState{ID: id}
		a.followers[id] = state
	}
	if state.AppliedIndex > 0 {
		//nolint:gosec // applied indexes are monotonic and fit in int64 for practical clusters
		state.AppliedIndexDelta = int64(u.AppliedIndex) - int64(state.AppliedIndex)
	}
	state.AppliedIndex = u.AppliedIndex
	state.Term = u.Term
	state.LastHeartbeat = u.Timestamp
	if state.LastHeartbeat.IsZero() {
		state.LastHeartbeat = a.now()
	}
	state.Healthy = true
	state.IsDead = false
	a.metrics.ObserveAppliedIndexDelta(u.NodeID, float64(state.AppliedIndexDelta))
}

// GetFollowerState returns a follower's state.
func (a *Autopilot) GetFollowerState(id hraft.ServerID) (*FollowerState, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	state, ok := a.followers[id]
	if !ok {
		return nil, false
	}
	copied := *state
	return &copied, true
}

// GetAllFollowerStates returns copies of all follower states.
func (a *Autopilot) GetAllFollowerStates() map[hraft.ServerID]*FollowerState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make(map[hraft.ServerID]*FollowerState, len(a.followers))
	for id, state := range a.followers {
		copied := *state
		out[id] = &copied
	}
	return out
}

// MinFollowerAppliedIndex returns the minimum applied index across followers.
// A single-node cluster returns the local applied index.
func (a *Autopilot) MinFollowerAppliedIndex() uint64 {
	if a.r == nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	min := ^uint64(0)
	found := false
	for id, state := range a.followers {
		if string(id) == a.localID {
			continue
		}
		found = true
		idx := state.AppliedIndex
		if idx < min {
			min = idx
		}
	}
	if !found {
		return a.r.AppliedIndex()
	}
	return min
}

// DeadServers returns the IDs of servers considered dead.
func (a *Autopilot) DeadServers() []hraft.ServerID {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.deadServersLocked()
}

func (a *Autopilot) deadServersLocked() []hraft.ServerID {
	dead := make([]hraft.ServerID, 0)
	for id, state := range a.followers {
		// The local node is never a candidate for removal.
		if string(id) == a.localID {
			continue
		}
		if a.isDead(state) {
			dead = append(dead, id)
		}
	}
	return dead
}

// RemoveDeadServers removes dead servers while respecting MinQuorum and
// StabilizationTime.
func (a *Autopilot) RemoveDeadServers(ctx context.Context) error {
	if a.r == nil {
		return fmt.Errorf("autopilot: nil raft instance")
	}
	cfgFuture := a.r.GetConfiguration()
	if err := cfgFuture.Error(); err != nil {
		return fmt.Errorf("get configuration: %w", err)
	}
	currentVoters := 0
	for _, srv := range cfgFuture.Configuration().Servers {
		if srv.Suffrage == hraft.Voter {
			currentVoters++
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	dead := a.deadServersLocked()
	if len(dead) == 0 {
		return nil
	}
	if currentVoters-len(dead) < a.cfg.MinQuorum {
		a.logger.Warn("autopilot: refusing to remove dead servers below min quorum", map[string]any{
			"current_voters": currentVoters,
			"dead":           len(dead),
			"min_quorum":     a.cfg.MinQuorum,
		})
		return nil
	}
	if a.now().Sub(a.lastChange) < a.cfg.StabilizationTime {
		return nil
	}
	for _, id := range dead {
		if err := a.r.RemoveServer(id, 0, 0).Error(); err != nil {
			a.logger.Warn("autopilot: remove dead server failed", map[string]any{"server_id": string(id), "error": err.Error()})
			continue
		}
		delete(a.followers, id)
		a.metrics.IncDeadServersDetected()
	}
	a.lastChange = a.now()
	return nil
}

func (a *Autopilot) stabilize() {
	a.mu.Lock()
	a.lastChange = a.now()
	a.mu.Unlock()
}

func (a *Autopilot) heartbeatTracker() {
	if a.r == nil {
		return
	}
	cfgFuture := a.r.GetConfiguration()
	if err := cfgFuture.Error(); err != nil {
		return
	}
	config := cfgFuture.Configuration()
	currentVoters := make(map[hraft.ServerID]bool, len(config.Servers))
	for _, srv := range config.Servers {
		if srv.Suffrage == hraft.Voter {
			currentVoters[srv.ID] = true
		}
	}
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, srv := range config.Servers {
		if srv.Suffrage != hraft.Voter {
			continue
		}
		state, exists := a.followers[srv.ID]
		if !exists {
			// Newly discovered followers start healthy with a fresh heartbeat;
			// RecordEcho subsequently updates LastHeartbeat with real contact.
			state = &FollowerState{ID: srv.ID, Address: srv.Address, LastHeartbeat: now, Healthy: true}
			a.followers[srv.ID] = state
		}
		state.Address = srv.Address
		a.metrics.ObserveFollowerHeartbeat(string(srv.ID), 0)
	}
	for id, state := range a.followers {
		if !currentVoters[id] {
			state.Healthy = false
		}
	}
}

func (a *Autopilot) isDead(state *FollowerState) bool {
	if state == nil {
		return false
	}
	if !state.Healthy {
		return true
	}
	threshold := a.cfg.DeadServerLastContactThreshold
	if threshold <= 0 {
		threshold = 24 * time.Hour
	}
	return a.now().Sub(state.LastHeartbeat) > threshold
}
