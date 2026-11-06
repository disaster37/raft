package config

import (
	"time"

	"github.com/spf13/viper"
)

// DefaultConfig returns a Config populated with production defaults.
func DefaultConfig() Config {
	return Config{
		Dir:                      "/var/lib/raft",
		NodeID:                   "",
		BindAddr:                 ":8081",
		AdvertiseAddr:            "",
		AdvertiseResolveTimeout:  2 * time.Minute,
		ApplyTimeout:             5 * time.Second,
		LeaderWaitTimeout:        120 * time.Second,
		SnapshotThreshold:        1000,
		SnapshotInterval:         10 * time.Minute,
		SnapshotRetain:           2,
		TrailingLogs:             256,
		PerformanceMultiplier:    5.0,
		RaftLogCacheSize:         512,
		MaxAppendEntries:         64,
		BatchApplyCh:             true,
		MaxEntrySize:             1024 * 1024,
		NoSnapshotRestoreOnStart: false,
		TerminationGracePeriod:   60 * time.Second,
		RecoveryMode:             false,
		SingleNodeRecovery:       false,
		NonVoter:                 false,
		AllowInsecureMultiNode:   false,
		FollowerLastContactMax:   15 * time.Second,
		Discovery: DiscoveryConfig{
			Peers:           nil,
			LegacyPeers:     nil,
			Replicas:        1,
			StatefulSetName: "",
			HeadlessService: "",
			Namespace:       "",
			ClusterDomain:   "cluster.local",
			RaftPort:        8081,
		},
		Transport: TransportConfig{
			MaxPool:           1,
			Timeout:           10 * time.Second,
			MaxDialRetries:    4,
			DialRetryBase:     500 * time.Millisecond,
			EchoMaxConcurrent: 64,
			EchoPeekTimeout:   time.Second,
		},
		TLS: TLSConfig{
			Enabled:                false,
			Dir:                    "",
			PKIMode:                PKIModeSharedCA,
			Validity:               8760 * time.Hour,
			CAValidity:             30 * 365 * 24 * time.Hour,
			SafetyMargin:           7 * 24 * time.Hour,
			Organization:           "raft",
			CACertPath:             "",
			CertPath:               "",
			KeyPath:                "",
			CASecret:               "",
			CABootstrap:            false,
			AllowAutoCAMultiNode:   false,
			ClientAuth:             true,
			SecretPollTimeout:      120 * time.Second,
			ReloadPollInterval:     5 * time.Second,
			KeyringRotationEnabled: true,
			RotationPeriod:         24 * time.Hour,
			RotationCheckInterval:  30 * time.Second,
			ExtraSANs:              nil,
		},
		Storage: StorageConfig{
			Backend:         StorageBackendRaftBoltDB,
			BoltTimeout:     time.Second,
			NoFreelistSync:  true,
			InitialMmapSize: 100 * 1024 * 1024,
			AtRestKeyFile:   "",
		},
		Autopilot: AutopilotConfig{
			Enabled:                        true,
			CleanupDeadServers:             true,
			DeadServerLastContactThreshold: 24 * time.Hour,
			MinQuorum:                      2,
			StabilizationTime:              10 * time.Second,
			HeartbeatInterval:              time.Second,
		},
		Join: JoinConfig{
			Interval:            5 * time.Second,
			ReconcileTimeout:    10 * time.Second,
			RetryInterval:       2 * time.Second,
			MaxConcurrent:       20,
			CheckPeerResolvable: true,
		},
	}
}

// ApplyDefaults fills zero-valued fields with defaults. It is safe to call on
// a partially populated Config.
func ApplyDefaults(cfg *Config) {
	if cfg == nil {
		return
	}
	d := DefaultConfig()
	if cfg.Dir == "" {
		cfg.Dir = d.Dir
	}
	if cfg.BindAddr == "" {
		cfg.BindAddr = d.BindAddr
	}
	if cfg.AdvertiseResolveTimeout == 0 {
		cfg.AdvertiseResolveTimeout = d.AdvertiseResolveTimeout
	}
	if cfg.ApplyTimeout == 0 {
		cfg.ApplyTimeout = d.ApplyTimeout
	}
	if cfg.LeaderWaitTimeout == 0 {
		cfg.LeaderWaitTimeout = d.LeaderWaitTimeout
	}
	if cfg.SnapshotThreshold == 0 {
		cfg.SnapshotThreshold = d.SnapshotThreshold
	}
	if cfg.SnapshotInterval == 0 {
		cfg.SnapshotInterval = d.SnapshotInterval
	}
	if cfg.SnapshotRetain == 0 {
		cfg.SnapshotRetain = d.SnapshotRetain
	}
	if cfg.TrailingLogs == 0 {
		cfg.TrailingLogs = d.TrailingLogs
	}
	if cfg.PerformanceMultiplier == 0 {
		cfg.PerformanceMultiplier = d.PerformanceMultiplier
	}
	if cfg.RaftLogCacheSize == 0 {
		cfg.RaftLogCacheSize = d.RaftLogCacheSize
	}
	if cfg.MaxAppendEntries == 0 {
		cfg.MaxAppendEntries = d.MaxAppendEntries
	}
	if cfg.MaxEntrySize == 0 {
		cfg.MaxEntrySize = d.MaxEntrySize
	}
	if cfg.TerminationGracePeriod == 0 {
		cfg.TerminationGracePeriod = d.TerminationGracePeriod
	}
	if cfg.FollowerLastContactMax == 0 {
		cfg.FollowerLastContactMax = d.FollowerLastContactMax
	}

	if cfg.Discovery.Replicas == 0 {
		cfg.Discovery.Replicas = d.Discovery.Replicas
	}
	if cfg.Discovery.ClusterDomain == "" {
		cfg.Discovery.ClusterDomain = d.Discovery.ClusterDomain
	}
	if cfg.Discovery.RaftPort == 0 {
		cfg.Discovery.RaftPort = d.Discovery.RaftPort
	}

	if cfg.Transport.MaxPool == 0 {
		cfg.Transport.MaxPool = d.Transport.MaxPool
	}
	if cfg.Transport.Timeout == 0 {
		cfg.Transport.Timeout = d.Transport.Timeout
	}
	if cfg.Transport.MaxDialRetries == 0 {
		cfg.Transport.MaxDialRetries = d.Transport.MaxDialRetries
	}
	if cfg.Transport.DialRetryBase == 0 {
		cfg.Transport.DialRetryBase = d.Transport.DialRetryBase
	}
	if cfg.Transport.EchoMaxConcurrent == 0 {
		cfg.Transport.EchoMaxConcurrent = d.Transport.EchoMaxConcurrent
	}
	if cfg.Transport.EchoPeekTimeout == 0 {
		cfg.Transport.EchoPeekTimeout = d.Transport.EchoPeekTimeout
	}

	if cfg.TLS.PKIMode == "" {
		cfg.TLS.PKIMode = d.TLS.PKIMode
	}
	if cfg.TLS.Validity == 0 {
		cfg.TLS.Validity = d.TLS.Validity
	}
	if cfg.TLS.CAValidity == 0 {
		cfg.TLS.CAValidity = d.TLS.CAValidity
	}
	if cfg.TLS.SafetyMargin == 0 {
		cfg.TLS.SafetyMargin = d.TLS.SafetyMargin
	}
	if cfg.TLS.Organization == "" {
		cfg.TLS.Organization = d.TLS.Organization
	}
	if cfg.TLS.SecretPollTimeout == 0 {
		cfg.TLS.SecretPollTimeout = d.TLS.SecretPollTimeout
	}
	if cfg.TLS.ReloadPollInterval == 0 {
		cfg.TLS.ReloadPollInterval = d.TLS.ReloadPollInterval
	}
	if cfg.TLS.RotationPeriod == 0 {
		cfg.TLS.RotationPeriod = d.TLS.RotationPeriod
	}
	if cfg.TLS.RotationCheckInterval == 0 {
		cfg.TLS.RotationCheckInterval = d.TLS.RotationCheckInterval
	}

	if cfg.Storage.Backend == "" {
		cfg.Storage.Backend = d.Storage.Backend
	}
	if cfg.Storage.BoltTimeout == 0 {
		cfg.Storage.BoltTimeout = d.Storage.BoltTimeout
	}
	if cfg.Storage.InitialMmapSize == 0 {
		cfg.Storage.InitialMmapSize = d.Storage.InitialMmapSize
	}

	if cfg.Autopilot.DeadServerLastContactThreshold == 0 {
		cfg.Autopilot.DeadServerLastContactThreshold = d.Autopilot.DeadServerLastContactThreshold
	}
	if cfg.Autopilot.MinQuorum == 0 {
		cfg.Autopilot.MinQuorum = d.Autopilot.MinQuorum
	}
	if cfg.Autopilot.StabilizationTime == 0 {
		cfg.Autopilot.StabilizationTime = d.Autopilot.StabilizationTime
	}
	if cfg.Autopilot.HeartbeatInterval == 0 {
		cfg.Autopilot.HeartbeatInterval = d.Autopilot.HeartbeatInterval
	}

	if cfg.Join.Interval == 0 {
		cfg.Join.Interval = d.Join.Interval
	}
	if cfg.Join.ReconcileTimeout == 0 {
		cfg.Join.ReconcileTimeout = d.Join.ReconcileTimeout
	}
	if cfg.Join.RetryInterval == 0 {
		cfg.Join.RetryInterval = d.Join.RetryInterval
	}
	if cfg.Join.MaxConcurrent == 0 {
		cfg.Join.MaxConcurrent = d.Join.MaxConcurrent
	}
}

// RegisterViperDefaults registers every config key with v. When prefix is
// non-empty, keys are nested under it (for example "raft").
func RegisterViperDefaults(v *viper.Viper, prefix string) {
	if v == nil {
		return
	}
	d := DefaultConfig()
	key := func(k string) string {
		if prefix == "" {
			return k
		}
		return prefix + "." + k
	}
	v.SetDefault(key("dir"), d.Dir)
	v.SetDefault(key("node_id"), d.NodeID)
	v.SetDefault(key("bind_addr"), d.BindAddr)
	v.SetDefault(key("advertise_addr"), d.AdvertiseAddr)
	v.SetDefault(key("advertise_resolve_timeout"), d.AdvertiseResolveTimeout)
	v.SetDefault(key("apply_timeout"), d.ApplyTimeout)
	v.SetDefault(key("leader_wait_timeout"), d.LeaderWaitTimeout)
	v.SetDefault(key("snapshot_threshold"), d.SnapshotThreshold)
	v.SetDefault(key("snapshot_interval"), d.SnapshotInterval)
	v.SetDefault(key("snapshot_retain"), d.SnapshotRetain)
	v.SetDefault(key("trailing_logs"), d.TrailingLogs)
	v.SetDefault(key("performance_multiplier"), d.PerformanceMultiplier)
	v.SetDefault(key("raft_log_cache_size"), d.RaftLogCacheSize)
	v.SetDefault(key("max_append_entries"), d.MaxAppendEntries)
	v.SetDefault(key("batch_apply_ch"), d.BatchApplyCh)
	v.SetDefault(key("max_entry_size"), d.MaxEntrySize)
	v.SetDefault(key("no_snapshot_restore_on_start"), d.NoSnapshotRestoreOnStart)
	v.SetDefault(key("termination_grace_period"), d.TerminationGracePeriod)
	v.SetDefault(key("recovery_mode"), d.RecoveryMode)
	v.SetDefault(key("single_node_recovery"), d.SingleNodeRecovery)
	v.SetDefault(key("non_voter"), d.NonVoter)
	v.SetDefault(key("allow_insecure_multi_node"), d.AllowInsecureMultiNode)
	v.SetDefault(key("follower_last_contact_max"), d.FollowerLastContactMax)

	v.SetDefault(key("discovery.peers"), d.Discovery.Peers)
	v.SetDefault(key("discovery.legacy_peers"), d.Discovery.LegacyPeers)
	v.SetDefault(key("discovery.replicas"), d.Discovery.Replicas)
	v.SetDefault(key("discovery.statefulset_name"), d.Discovery.StatefulSetName)
	v.SetDefault(key("discovery.headless_service"), d.Discovery.HeadlessService)
	v.SetDefault(key("discovery.namespace"), d.Discovery.Namespace)
	v.SetDefault(key("discovery.cluster_domain"), d.Discovery.ClusterDomain)
	v.SetDefault(key("discovery.raft_port"), d.Discovery.RaftPort)

	v.SetDefault(key("transport.max_pool"), d.Transport.MaxPool)
	v.SetDefault(key("transport.timeout"), d.Transport.Timeout)
	v.SetDefault(key("transport.max_dial_retries"), d.Transport.MaxDialRetries)
	v.SetDefault(key("transport.dial_retry_base"), d.Transport.DialRetryBase)
	v.SetDefault(key("transport.echo_max_concurrent"), d.Transport.EchoMaxConcurrent)
	v.SetDefault(key("transport.echo_peek_timeout"), d.Transport.EchoPeekTimeout)

	v.SetDefault(key("tls.enabled"), d.TLS.Enabled)
	v.SetDefault(key("tls.dir"), d.TLS.Dir)
	v.SetDefault(key("tls.pki_mode"), d.TLS.PKIMode)
	v.SetDefault(key("tls.validity"), d.TLS.Validity)
	v.SetDefault(key("tls.ca_validity"), d.TLS.CAValidity)
	v.SetDefault(key("tls.safety_margin"), d.TLS.SafetyMargin)
	v.SetDefault(key("tls.organization"), d.TLS.Organization)
	v.SetDefault(key("tls.ca_cert"), d.TLS.CACertPath)
	v.SetDefault(key("tls.cert"), d.TLS.CertPath)
	v.SetDefault(key("tls.key"), d.TLS.KeyPath)
	v.SetDefault(key("tls.ca_secret"), d.TLS.CASecret)
	v.SetDefault(key("tls.ca_bootstrap"), d.TLS.CABootstrap)
	v.SetDefault(key("tls.allow_auto_ca_multi_node"), d.TLS.AllowAutoCAMultiNode)
	v.SetDefault(key("tls.client_auth"), d.TLS.ClientAuth)
	v.SetDefault(key("tls.secret_poll_timeout"), d.TLS.SecretPollTimeout)
	v.SetDefault(key("tls.reload_poll_interval"), d.TLS.ReloadPollInterval)
	v.SetDefault(key("tls.keyring_rotation_enabled"), d.TLS.KeyringRotationEnabled)
	v.SetDefault(key("tls.rotation_period"), d.TLS.RotationPeriod)
	v.SetDefault(key("tls.rotation_check_interval"), d.TLS.RotationCheckInterval)
	v.SetDefault(key("tls.extra_sans"), d.TLS.ExtraSANs)

	v.SetDefault(key("storage.backend"), d.Storage.Backend)
	v.SetDefault(key("storage.bolt_timeout"), d.Storage.BoltTimeout)
	v.SetDefault(key("storage.no_freelist_sync"), d.Storage.NoFreelistSync)
	v.SetDefault(key("storage.initial_mmap_size"), d.Storage.InitialMmapSize)
	v.SetDefault(key("storage.at_rest_key_file"), d.Storage.AtRestKeyFile)

	v.SetDefault(key("autopilot.enabled"), d.Autopilot.Enabled)
	v.SetDefault(key("autopilot.cleanup_dead_servers"), d.Autopilot.CleanupDeadServers)
	v.SetDefault(key("autopilot.dead_server_last_contact_threshold"), d.Autopilot.DeadServerLastContactThreshold)
	v.SetDefault(key("autopilot.min_quorum"), d.Autopilot.MinQuorum)
	v.SetDefault(key("autopilot.stabilization_time"), d.Autopilot.StabilizationTime)
	v.SetDefault(key("autopilot.heartbeat_interval"), d.Autopilot.HeartbeatInterval)

	v.SetDefault(key("join.interval"), d.Join.Interval)
	v.SetDefault(key("join.reconcile_timeout"), d.Join.ReconcileTimeout)
	v.SetDefault(key("join.retry_interval"), d.Join.RetryInterval)
	v.SetDefault(key("join.max_concurrent"), d.Join.MaxConcurrent)
	v.SetDefault(key("join.check_peer_resolvable"), d.Join.CheckPeerResolvable)
}
