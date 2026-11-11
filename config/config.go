// Package config defines the configuration surface of the raft library,
// including defaults, Viper loading, validation, and adapters for the source
// projects.
package config

import "time"

// StorageBackendType selects the Raft log/stable storage backend.
type StorageBackendType string

const (
	// StorageBackendRaftBoltDB uses raft-boltdb/v2 (default).
	StorageBackendRaftBoltDB StorageBackendType = "raft-boltdb"
	// StorageBackendSharedBolt uses a single bbolt DB with logs, stable,
	// fsm_data, and _sys buckets.
	StorageBackendSharedBolt StorageBackendType = "shared-bolt"
	// StorageBackendInmem uses in-memory stores for testing.
	StorageBackendInmem StorageBackendType = "inmem"
)

// PKIMode selects how TLS keys are generated and used.
type PKIMode string

const (
	// PKIModeSharedCA uses a goca CA to sign per-node leaf certificates.
	PKIModeSharedCA PKIMode = "shared-ca"
	// PKIModeSelfSigned uses each keyring key directly as a self-signed
	// CA/leaf hybrid certificate (Vault-compatible).
	PKIModeSelfSigned PKIMode = "self-signed"
)

// Config is the complete raft library configuration.
type Config struct {
	Dir                      string          `mapstructure:"dir" yaml:"dir"`
	NodeID                   string          `mapstructure:"node_id" yaml:"node_id"`
	BindAddr                 string          `mapstructure:"bind_addr" yaml:"bind_addr"`
	AdvertiseAddr            string          `mapstructure:"advertise_addr" yaml:"advertise_addr"`
	AdvertiseResolveTimeout  time.Duration   `mapstructure:"advertise_resolve_timeout" yaml:"advertise_resolve_timeout"`
	ApplyTimeout             time.Duration   `mapstructure:"apply_timeout" yaml:"apply_timeout"`
	LeaderWaitTimeout        time.Duration   `mapstructure:"leader_wait_timeout" yaml:"leader_wait_timeout"`
	SnapshotThreshold        uint64          `mapstructure:"snapshot_threshold" yaml:"snapshot_threshold"`
	SnapshotInterval         time.Duration   `mapstructure:"snapshot_interval" yaml:"snapshot_interval"`
	SnapshotRetain           int             `mapstructure:"snapshot_retain" yaml:"snapshot_retain"`
	TrailingLogs             uint64          `mapstructure:"trailing_logs" yaml:"trailing_logs"`
	PerformanceMultiplier    float64         `mapstructure:"performance_multiplier" yaml:"performance_multiplier"`
	RaftLogCacheSize         int             `mapstructure:"raft_log_cache_size" yaml:"raft_log_cache_size"`
	MaxAppendEntries         int             `mapstructure:"max_append_entries" yaml:"max_append_entries"`
	BatchApplyCh             bool            `mapstructure:"batch_apply_ch" yaml:"batch_apply_ch"`
	MaxEntrySize             uint64          `mapstructure:"max_entry_size" yaml:"max_entry_size"`
	NoSnapshotRestoreOnStart bool            `mapstructure:"no_snapshot_restore_on_start" yaml:"no_snapshot_restore_on_start"`
	TerminationGracePeriod   time.Duration   `mapstructure:"termination_grace_period" yaml:"termination_grace_period"`
	RecoveryMode             bool            `mapstructure:"recovery_mode" yaml:"recovery_mode"`
	SingleNodeRecovery       bool            `mapstructure:"single_node_recovery" yaml:"single_node_recovery"`
	NonVoter                 bool            `mapstructure:"non_voter" yaml:"non_voter"`
	AllowInsecureMultiNode   bool            `mapstructure:"allow_insecure_multi_node" yaml:"allow_insecure_multi_node"`
	FollowerLastContactMax   time.Duration   `mapstructure:"follower_last_contact_max" yaml:"follower_last_contact_max"`
	Discovery                DiscoveryConfig `mapstructure:"discovery" yaml:"discovery"`
	Transport                TransportConfig `mapstructure:"transport" yaml:"transport"`
	TLS                      TLSConfig       `mapstructure:"tls" yaml:"tls"`
	Storage                  StorageConfig   `mapstructure:"storage" yaml:"storage"`
	Autopilot                AutopilotConfig `mapstructure:"autopilot" yaml:"autopilot"`
	Join                     JoinConfig      `mapstructure:"join" yaml:"join"`
}

// DiscoveryConfig controls peer discovery.
type DiscoveryConfig struct {
	Peers           []PeerConfig `mapstructure:"peers" yaml:"peers"`
	LegacyPeers     []string     `mapstructure:"legacy_peers" yaml:"legacy_peers"`
	Replicas        int          `mapstructure:"replicas" yaml:"replicas"`
	StatefulSetName string       `mapstructure:"statefulset_name" yaml:"statefulset_name"`
	HeadlessService string       `mapstructure:"headless_service" yaml:"headless_service"`
	Namespace       string       `mapstructure:"namespace" yaml:"namespace"`
	ClusterDomain   string       `mapstructure:"cluster_domain" yaml:"cluster_domain"`
	RaftPort        int          `mapstructure:"raft_port" yaml:"raft_port"`
}

// PeerConfig is one explicit peer entry.
type PeerConfig struct {
	ID       string `mapstructure:"id" yaml:"id"`
	Address  string `mapstructure:"address" yaml:"address"`
	NonVoter bool   `mapstructure:"non_voter" yaml:"non_voter"`
}

// TransportConfig controls the Raft network transport.
type TransportConfig struct {
	MaxPool           int           `mapstructure:"max_pool" yaml:"max_pool"`
	Timeout           time.Duration `mapstructure:"timeout" yaml:"timeout"`
	MaxDialRetries    int           `mapstructure:"max_dial_retries" yaml:"max_dial_retries"`
	DialRetryBase     time.Duration `mapstructure:"dial_retry_base" yaml:"dial_retry_base"`
	EchoMaxConcurrent int           `mapstructure:"echo_max_concurrent" yaml:"echo_max_concurrent"`
	EchoPeekTimeout   time.Duration `mapstructure:"echo_peek_timeout" yaml:"echo_peek_timeout"`
}

// TLSConfig controls mTLS and the in-band keyring.
type TLSConfig struct {
	Enabled                bool          `mapstructure:"enabled" yaml:"enabled"`
	Dir                    string        `mapstructure:"dir" yaml:"dir"`
	PKIMode                PKIMode       `mapstructure:"pki_mode" yaml:"pki_mode"`
	Validity               time.Duration `mapstructure:"validity" yaml:"validity"`
	CAValidity             time.Duration `mapstructure:"ca_validity" yaml:"ca_validity"`
	SafetyMargin           time.Duration `mapstructure:"safety_margin" yaml:"safety_margin"`
	Organization           string        `mapstructure:"organization" yaml:"organization"`
	CACertPath             string        `mapstructure:"ca_cert" yaml:"ca_cert"`
	CertPath               string        `mapstructure:"cert" yaml:"cert"`
	KeyPath                string        `mapstructure:"key" yaml:"key"`
	CASecret               string        `mapstructure:"ca_secret" yaml:"ca_secret"`
	CABootstrap            bool          `mapstructure:"ca_bootstrap" yaml:"ca_bootstrap"`
	AllowAutoCAMultiNode   bool          `mapstructure:"allow_auto_ca_multi_node" yaml:"allow_auto_ca_multi_node"`
	ClientAuth             bool          `mapstructure:"client_auth" yaml:"client_auth"`
	SecretPollTimeout      time.Duration `mapstructure:"secret_poll_timeout" yaml:"secret_poll_timeout"`
	ReloadPollInterval     time.Duration `mapstructure:"reload_poll_interval" yaml:"reload_poll_interval"`
	KeyringRotationEnabled bool          `mapstructure:"keyring_rotation_enabled" yaml:"keyring_rotation_enabled"`
	RotationPeriod         time.Duration `mapstructure:"rotation_period" yaml:"rotation_period"`
	RotationCheckInterval  time.Duration `mapstructure:"rotation_check_interval" yaml:"rotation_check_interval"`
	ExtraSANs              []string      `mapstructure:"extra_sans" yaml:"extra_sans"`
}

// StorageConfig controls the storage backend and at-rest encryption.
type StorageConfig struct {
	Backend         StorageBackendType `mapstructure:"backend" yaml:"backend"`
	BoltTimeout     time.Duration      `mapstructure:"bolt_timeout" yaml:"bolt_timeout"`
	NoFreelistSync  bool               `mapstructure:"no_freelist_sync" yaml:"no_freelist_sync"`
	InitialMmapSize int                `mapstructure:"initial_mmap_size" yaml:"initial_mmap_size"`
	AtRestKeyFile   string             `mapstructure:"at_rest_key_file" yaml:"at_rest_key_file"`
	AtRestKey       string             `mapstructure:"at_rest_key" yaml:"at_rest_key"`
	AtRestKeyInfo   string             `mapstructure:"at_rest_key_info" yaml:"at_rest_key_info"`
}

// AutopilotConfig controls dead-server cleanup and follower tracking.
type AutopilotConfig struct {
	Enabled                        bool          `mapstructure:"enabled" yaml:"enabled"`
	CleanupDeadServers             bool          `mapstructure:"cleanup_dead_servers" yaml:"cleanup_dead_servers"`
	DeadServerLastContactThreshold time.Duration `mapstructure:"dead_server_last_contact_threshold" yaml:"dead_server_last_contact_threshold"`
	MinQuorum                      int           `mapstructure:"min_quorum" yaml:"min_quorum"`
	StabilizationTime              time.Duration `mapstructure:"stabilization_time" yaml:"stabilization_time"`
	HeartbeatInterval              time.Duration `mapstructure:"heartbeat_interval" yaml:"heartbeat_interval"`
}

// JoinConfig controls the membership reconciliation loop.
type JoinConfig struct {
	Interval            time.Duration `mapstructure:"interval" yaml:"interval"`
	ReconcileTimeout    time.Duration `mapstructure:"reconcile_timeout" yaml:"reconcile_timeout"`
	RetryInterval       time.Duration `mapstructure:"retry_interval" yaml:"retry_interval"`
	MaxConcurrent       int           `mapstructure:"max_concurrent" yaml:"max_concurrent"`
	CheckPeerResolvable bool          `mapstructure:"check_peer_resolvable" yaml:"check_peer_resolvable"`
}
