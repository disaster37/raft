package autopilot

import (
	"context"
	"io"
	"testing"
	"time"

	hraft "github.com/hashicorp/raft"

	"github.com/disaster37/raft/config"
)

type noopFSM struct{}

func (noopFSM) Apply(*hraft.Log) interface{}         { return nil }
func (noopFSM) Snapshot() (hraft.FSMSnapshot, error) { return noopSnapshot{}, nil }
func (noopFSM) Restore(rc io.ReadCloser) error       { return rc.Close() }

type noopSnapshot struct{}

func (noopSnapshot) Persist(sink hraft.SnapshotSink) error { return sink.Close() }
func (noopSnapshot) Release()                              {}

func newTestRaft(t *testing.T) *hraft.Raft {
	t.Helper()
	cfg := hraft.DefaultConfig()
	cfg.LocalID = "local"
	cfg.HeartbeatTimeout = 50 * time.Millisecond
	cfg.ElectionTimeout = 100 * time.Millisecond
	cfg.LeaderLeaseTimeout = 50 * time.Millisecond
	cfg.CommitTimeout = 10 * time.Millisecond
	cfg.LogOutput = nil
	logs := hraft.NewInmemStore()
	stable := hraft.NewInmemStore()
	snaps := hraft.NewInmemSnapshotStore()
	_, transport := hraft.NewInmemTransport(hraft.NewInmemAddr())
	configuration := hraft.Configuration{Servers: []hraft.Server{{
		Suffrage: hraft.Voter,
		ID:       cfg.LocalID,
		Address:  transport.LocalAddr(),
	}}}
	if err := hraft.BootstrapCluster(cfg, logs, stable, snaps, transport, configuration); err != nil && err != hraft.ErrCantBootstrap {
		t.Fatalf("bootstrap: %v", err)
	}
	r, err := hraft.NewRaft(cfg, noopFSM{}, logs, stable, snaps, transport)
	if err != nil {
		t.Fatalf("NewRaft: %v", err)
	}
	t.Cleanup(func() { _ = r.Shutdown().Error() })
	deadline := time.Now().Add(5 * time.Second)
	for r.Leader() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	return r
}

func TestAutopilotHeartbeatTracking(t *testing.T) {
	r := newTestRaft(t)
	a := New(config.AutopilotConfig{Enabled: true, HeartbeatInterval: time.Millisecond, DeadServerLastContactThreshold: time.Hour, MinQuorum: 1, StabilizationTime: time.Millisecond}, r, "local", r.LeaderCh(), nil, nil)
	a.heartbeatTracker()
	states := a.GetAllFollowerStates()
	if len(states) != 1 {
		t.Fatalf("states = %v", states)
	}
	if _, ok := a.GetFollowerState("local"); !ok {
		t.Fatal("missing local state")
	}
	if _, ok := a.GetFollowerState("missing"); ok {
		t.Fatal("unexpected state")
	}
	if len(a.DeadServers()) != 0 {
		t.Fatalf("dead = %v", a.DeadServers())
	}
}

func TestAutopilotMinFollowerAppliedIndex(t *testing.T) {
	r := newTestRaft(t)
	a := New(config.AutopilotConfig{Enabled: true, DeadServerLastContactThreshold: time.Hour, MinQuorum: 1}, r, "local", r.LeaderCh(), nil, nil)
	// No followers: local applied index.
	if got := a.MinFollowerAppliedIndex(); got != r.AppliedIndex() {
		t.Fatalf("min = %d, want %d", got, r.AppliedIndex())
	}
	a.RecordEcho(EchoUpdate{NodeID: "f1", AppliedIndex: 10, Timestamp: time.Now()})
	a.RecordEcho(EchoUpdate{NodeID: "f2", AppliedIndex: 5, Timestamp: time.Now()})
	if got := a.MinFollowerAppliedIndex(); got != 5 {
		t.Fatalf("min = %d, want 5", got)
	}
	state, ok := a.GetFollowerState("f1")
	if !ok || state.AppliedIndex != 10 || !state.Healthy {
		t.Fatalf("state = %+v", state)
	}
	a.RecordEcho(EchoUpdate{NodeID: "f1", AppliedIndex: 12, Timestamp: time.Now()})
	state, _ = a.GetFollowerState("f1")
	if state.AppliedIndexDelta != 2 {
		t.Fatalf("delta = %d", state.AppliedIndexDelta)
	}
	a.RecordEcho(EchoUpdate{})
}

func TestAutopilotRemoveDeadServersRespectsMinQuorumAndStabilization(t *testing.T) {
	r := newTestRaft(t)
	a := New(config.AutopilotConfig{
		Enabled:                        true,
		CleanupDeadServers:             true,
		DeadServerLastContactThreshold: time.Millisecond,
		MinQuorum:                      2,
		StabilizationTime:              time.Hour,
	}, r, "local", r.LeaderCh(), nil, nil)
	a.RecordEcho(EchoUpdate{NodeID: "dead", AppliedIndex: 1, Timestamp: time.Now().Add(-time.Hour)})
	if len(a.DeadServers()) != 1 {
		t.Fatalf("dead = %v", a.DeadServers())
	}
	if err := a.RemoveDeadServers(context.Background()); err != nil {
		t.Fatalf("RemoveDeadServers: %v", err)
	}
	if _, ok := a.GetFollowerState("dead"); !ok {
		t.Fatal("dead server should not be removed below min quorum")
	}
	// Lower quorum but keep stabilization guard.
	a.cfg.MinQuorum = 0
	a.stabilize()
	if err := a.RemoveDeadServers(context.Background()); err != nil {
		t.Fatalf("RemoveDeadServers: %v", err)
	}
	if _, ok := a.GetFollowerState("dead"); !ok {
		t.Fatal("dead server should not be removed during stabilization")
	}
	// Disable stabilization; removal is attempted (and may fail for a fake ID).
	a.cfg.StabilizationTime = 0
	if err := a.RemoveDeadServers(context.Background()); err != nil {
		t.Fatalf("RemoveDeadServers: %v", err)
	}
}

func TestAutopilotStartStops(t *testing.T) {
	r := newTestRaft(t)
	a := New(config.AutopilotConfig{Enabled: false}, r, "local", r.LeaderCh(), nil, nil)
	a.Start(context.Background())
	a = New(config.AutopilotConfig{Enabled: true, HeartbeatInterval: time.Millisecond, DeadServerLastContactThreshold: time.Hour, MinQuorum: 1, StabilizationTime: time.Millisecond}, r, "local", r.LeaderCh(), nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		a.Start(ctx)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("autopilot did not stop")
	}
}

func TestAutopilotIsDeadBranches(t *testing.T) {
	a := New(config.AutopilotConfig{DeadServerLastContactThreshold: time.Millisecond}, nil, "local", nil, nil, nil)
	if a.isDead(nil) {
		t.Fatal("nil state should not be dead")
	}
	if !a.isDead(&FollowerState{Healthy: false}) {
		t.Fatal("unhealthy should be dead")
	}
	if !a.isDead(&FollowerState{Healthy: true, LastHeartbeat: time.Now().Add(-time.Hour)}) {
		t.Fatal("stale heartbeat should be dead")
	}
	if a.isDead(&FollowerState{Healthy: true, LastHeartbeat: time.Now()}) {
		t.Fatal("fresh heartbeat should not be dead")
	}
}

func TestAutopilotRemoveDeadServersNilRaft(t *testing.T) {
	a := New(config.AutopilotConfig{}, nil, "local", nil, nil, nil)
	if err := a.RemoveDeadServers(context.Background()); err == nil {
		t.Fatal("expected nil raft error")
	}
}

func TestAutopilotStartClosedLeaderCh(t *testing.T) {
	ch := make(chan bool)
	close(ch)
	a := New(config.AutopilotConfig{Enabled: true, HeartbeatInterval: time.Millisecond}, nil, "local", ch, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		a.Start(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("autopilot did not stop on closed leader channel")
	}
}
