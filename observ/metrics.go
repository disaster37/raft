package observ

import (
	"errors"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// MetricsCollector is the metrics surface used by the raft packages.
type MetricsCollector interface {
	UpdateFromRaftStats(stats map[string]string)
	IncLeaderChanges()
	ObserveFollowerHeartbeat(followerID string, ageMs float64)
	ObserveAppliedIndexDelta(followerID string, delta float64)
	IncJoinAttempts()
	IncJoinFailures()
	IncDNSResolutionFailures()
	IncDialRetries()
	IncLeadershipTransfers()
	IncDeadServersDetected()
	SetKeyringTerm(term uint64)
	SetKeyringActiveKeyAgeSeconds(seconds float64)
	IncKeyringRotations(status string)
}

// NoopMetrics discards every metric update.
type NoopMetrics struct{}

// NewNoopMetrics returns a MetricsCollector that discards all updates.
func NewNoopMetrics() MetricsCollector { return NoopMetrics{} }

func (NoopMetrics) UpdateFromRaftStats(map[string]string)    {}
func (NoopMetrics) IncLeaderChanges()                        {}
func (NoopMetrics) ObserveFollowerHeartbeat(string, float64) {}
func (NoopMetrics) ObserveAppliedIndexDelta(string, float64) {}
func (NoopMetrics) IncJoinAttempts()                         {}
func (NoopMetrics) IncJoinFailures()                         {}
func (NoopMetrics) IncDNSResolutionFailures()                {}
func (NoopMetrics) IncDialRetries()                          {}
func (NoopMetrics) IncLeadershipTransfers()                  {}
func (NoopMetrics) IncDeadServersDetected()                  {}
func (NoopMetrics) SetKeyringTerm(uint64)                    {}
func (NoopMetrics) SetKeyringActiveKeyAgeSeconds(float64)    {}
func (NoopMetrics) IncKeyringRotations(string)               {}

// PrometheusMetrics is the Prometheus-backed MetricsCollector.
type PrometheusMetrics struct {
	state              prometheus.Gauge
	term               prometheus.Gauge
	lastLogIndex       prometheus.Gauge
	commitIndex        prometheus.Gauge
	appliedIndex       prometheus.Gauge
	fsmPending         prometheus.Gauge
	numPeers           prometheus.Gauge
	leaderChanges      prometheus.Counter
	joinAttempts       prometheus.Counter
	joinFailures       prometheus.Counter
	dnsFailures        prometheus.Counter
	dialRetries        prometheus.Counter
	leadershipTransfer prometheus.Counter
	deadServers        prometheus.Counter
	followerHeartbeat  *prometheus.GaugeVec
	appliedIndexDelta  *prometheus.GaugeVec
	keyringTerm        prometheus.Gauge
	keyringActiveAge   prometheus.Gauge
	keyringRotations   *prometheus.CounterVec
}

// NewPrometheusMetrics creates and registers the raft metrics on reg. A nil
// registry uses prometheus.DefaultRegisterer. Already-registered collectors
// are reused so multiple nodes in one process do not panic.
func NewPrometheusMetrics(reg prometheus.Registerer) *PrometheusMetrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	m := &PrometheusMetrics{
		state: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "raft_state",
			Help: "Current Raft state (0=Follower, 1=Candidate, 2=Leader).",
		}),
		term: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "raft_term",
			Help: "Current Raft term.",
		}),
		lastLogIndex: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "raft_last_log_index",
			Help: "Last log index.",
		}),
		commitIndex: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "raft_commit_index",
			Help: "Commit index.",
		}),
		appliedIndex: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "raft_applied_index",
			Help: "Applied index.",
		}),
		fsmPending: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "raft_fsm_pending",
			Help: "Number of pending FSM mutations.",
		}),
		numPeers: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "raft_num_peers",
			Help: "Number of peers in the cluster.",
		}),
		leaderChanges: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "raft_leader_changes_total",
			Help: "Total number of leader changes observed.",
		}),
		joinAttempts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "raft_join_attempts_total",
			Help: "Total number of join attempts.",
		}),
		joinFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "raft_join_failures_total",
			Help: "Total number of failed join attempts.",
		}),
		dnsFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "raft_dns_resolution_failures_total",
			Help: "Total number of DNS resolution failures.",
		}),
		dialRetries: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "raft_dial_retries_total",
			Help: "Total number of transport dial retries.",
		}),
		leadershipTransfer: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "raft_leadership_transfers_total",
			Help: "Total number of leadership transfers.",
		}),
		deadServers: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "raft_dead_servers_detected_total",
			Help: "Total number of dead servers detected by autopilot.",
		}),
		followerHeartbeat: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "raft_follower_heartbeat_age_ms",
			Help: "Milliseconds since the last heartbeat from each follower.",
		}, []string{"follower_id"}),
		appliedIndexDelta: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "raft_applied_index_delta",
			Help: "Difference between the leader and follower applied index.",
		}, []string{"follower_id"}),
		keyringTerm: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "raft_tls_keyring_term",
			Help: "Current in-band TLS keyring term.",
		}),
		keyringActiveAge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "raft_tls_keyring_active_key_age_seconds",
			Help: "Age of the active TLS keyring key in seconds.",
		}),
		keyringRotations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "raft_tls_keyring_rotations_total",
			Help: "Total number of TLS keyring rotations by status.",
		}, []string{"status"}),
	}
	m.state = registerCollector(reg, m.state)
	m.term = registerCollector(reg, m.term)
	m.lastLogIndex = registerCollector(reg, m.lastLogIndex)
	m.commitIndex = registerCollector(reg, m.commitIndex)
	m.appliedIndex = registerCollector(reg, m.appliedIndex)
	m.fsmPending = registerCollector(reg, m.fsmPending)
	m.numPeers = registerCollector(reg, m.numPeers)
	m.leaderChanges = registerCollector(reg, m.leaderChanges)
	m.joinAttempts = registerCollector(reg, m.joinAttempts)
	m.joinFailures = registerCollector(reg, m.joinFailures)
	m.dnsFailures = registerCollector(reg, m.dnsFailures)
	m.dialRetries = registerCollector(reg, m.dialRetries)
	m.leadershipTransfer = registerCollector(reg, m.leadershipTransfer)
	m.deadServers = registerCollector(reg, m.deadServers)
	m.followerHeartbeat = registerCollector(reg, m.followerHeartbeat)
	m.appliedIndexDelta = registerCollector(reg, m.appliedIndexDelta)
	m.keyringTerm = registerCollector(reg, m.keyringTerm)
	m.keyringActiveAge = registerCollector(reg, m.keyringActiveAge)
	m.keyringRotations = registerCollector(reg, m.keyringRotations)
	return m
}

func registerCollector[T prometheus.Collector](reg prometheus.Registerer, c T) T {
	if err := reg.Register(c); err != nil {
		var already prometheus.AlreadyRegisteredError
		if errors.As(err, &already) {
			if existing, ok := already.ExistingCollector.(T); ok {
				return existing
			}
		}
		panic(err)
	}
	return c
}

// UpdateFromRaftStats updates gauges from raft.Stats().
func (m *PrometheusMetrics) UpdateFromRaftStats(stats map[string]string) {
	if v, ok := stats["state"]; ok {
		switch v {
		case "Follower":
			m.state.Set(0)
		case "Candidate":
			m.state.Set(1)
		case "Leader":
			m.state.Set(2)
		}
	}
	setGauge := func(g prometheus.Gauge, key string) {
		if raw, ok := stats[key]; ok {
			if f, err := strconv.ParseFloat(raw, 64); err == nil {
				g.Set(f)
			}
		}
	}
	setGauge(m.term, "term")
	setGauge(m.lastLogIndex, "last_log_index")
	setGauge(m.commitIndex, "commit_index")
	setGauge(m.appliedIndex, "applied_index")
	setGauge(m.fsmPending, "fsm_pending")
	setGauge(m.numPeers, "num_peers")
}

func (m *PrometheusMetrics) IncLeaderChanges() { m.leaderChanges.Inc() }
func (m *PrometheusMetrics) ObserveFollowerHeartbeat(id string, v float64) {
	m.followerHeartbeat.WithLabelValues(id).Set(v)
}
func (m *PrometheusMetrics) ObserveAppliedIndexDelta(id string, v float64) {
	m.appliedIndexDelta.WithLabelValues(id).Set(v)
}
func (m *PrometheusMetrics) IncJoinAttempts()           { m.joinAttempts.Inc() }
func (m *PrometheusMetrics) IncJoinFailures()           { m.joinFailures.Inc() }
func (m *PrometheusMetrics) IncDNSResolutionFailures()  { m.dnsFailures.Inc() }
func (m *PrometheusMetrics) IncDialRetries()            { m.dialRetries.Inc() }
func (m *PrometheusMetrics) IncLeadershipTransfers()    { m.leadershipTransfer.Inc() }
func (m *PrometheusMetrics) IncDeadServersDetected()    { m.deadServers.Inc() }
func (m *PrometheusMetrics) SetKeyringTerm(term uint64) { m.keyringTerm.Set(float64(term)) }
func (m *PrometheusMetrics) SetKeyringActiveKeyAgeSeconds(v float64) {
	m.keyringActiveAge.Set(v)
}
func (m *PrometheusMetrics) IncKeyringRotations(status string) {
	m.keyringRotations.WithLabelValues(status).Inc()
}
