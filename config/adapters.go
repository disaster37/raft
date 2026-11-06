package config

import "time"

// DaggerKubernetesConfig mirrors the Raft-relevant subset of the
// dagger-kubernetes supervisor configuration.
type DaggerKubernetesConfig struct {
	Dir                   string
	NodeID                string
	BindAddr              string
	AdvertiseAddr         string
	Peers                 []PeerConfig
	Replicas              int
	StatefulSetName       string
	HeadlessService       string
	Namespace             string
	ClusterDomain         string
	RaftPort              int
	ApplyTimeout          time.Duration
	LeaderWaitTimeout     time.Duration
	SnapshotThreshold     uint64
	SnapshotInterval      time.Duration
	TrailingLogs          uint64
	PerformanceMultiplier float64
	RaftLogCacheSize      int
	TransportMaxPool      int
	TLSEnabled            bool
	TLSDir                string
	TLSValidity           time.Duration
	TLSOrganization       string
	CACertPath            string
	CertPath              string
	KeyPath               string
	CASecret              string
	CABootstrap           bool
	ClientAuth            bool
	SecretPollTimeout     time.Duration
	AutopilotEnabled      bool
	CleanupDeadServers    bool
	MinQuorum             int
}

// FromDaggerKubernetes maps the dagger-kubernetes configuration shape to a
// Config. It selects raft-boltdb, shared-CA PKI, auto CA multi-node, and a
// transport pool of 1.
func FromDaggerKubernetes(in DaggerKubernetesConfig) Config {
	cfg := DefaultConfig()
	cfg.Dir = in.Dir
	cfg.NodeID = in.NodeID
	cfg.BindAddr = in.BindAddr
	cfg.AdvertiseAddr = in.AdvertiseAddr
	cfg.Discovery.Peers = in.Peers
	cfg.Discovery.Replicas = in.Replicas
	cfg.Discovery.StatefulSetName = in.StatefulSetName
	cfg.Discovery.HeadlessService = in.HeadlessService
	cfg.Discovery.Namespace = in.Namespace
	cfg.Discovery.ClusterDomain = in.ClusterDomain
	cfg.Discovery.RaftPort = in.RaftPort
	cfg.ApplyTimeout = in.ApplyTimeout
	cfg.LeaderWaitTimeout = in.LeaderWaitTimeout
	cfg.SnapshotThreshold = in.SnapshotThreshold
	cfg.SnapshotInterval = in.SnapshotInterval
	cfg.TrailingLogs = in.TrailingLogs
	cfg.PerformanceMultiplier = in.PerformanceMultiplier
	cfg.RaftLogCacheSize = in.RaftLogCacheSize
	cfg.Transport.MaxPool = in.TransportMaxPool
	cfg.Storage.Backend = StorageBackendRaftBoltDB
	cfg.TLS.Enabled = in.TLSEnabled
	cfg.TLS.Dir = in.TLSDir
	cfg.TLS.PKIMode = PKIModeSharedCA
	cfg.TLS.Validity = in.TLSValidity
	cfg.TLS.Organization = in.TLSOrganization
	cfg.TLS.CACertPath = in.CACertPath
	cfg.TLS.CertPath = in.CertPath
	cfg.TLS.KeyPath = in.KeyPath
	cfg.TLS.CASecret = in.CASecret
	cfg.TLS.CABootstrap = in.CABootstrap
	cfg.TLS.AllowAutoCAMultiNode = true
	cfg.TLS.ClientAuth = in.ClientAuth
	cfg.TLS.SecretPollTimeout = in.SecretPollTimeout
	cfg.Autopilot.Enabled = in.AutopilotEnabled
	cfg.Autopilot.CleanupDeadServers = in.CleanupDeadServers
	cfg.Autopilot.MinQuorum = in.MinQuorum
	ApplyDefaults(&cfg)
	return cfg
}

// GohookbridgeFlags mirrors the Raft-relevant subset of the gohookbridge
// command-line flags.
type GohookbridgeFlags struct {
	Dir                   string
	NodeID                string
	BindAddr              string
	AdvertiseAddr         string
	Peers                 []PeerConfig
	Replicas              int
	StatefulSetName       string
	HeadlessService       string
	Namespace             string
	ClusterDomain         string
	RaftPort              int
	ApplyTimeout          time.Duration
	LeaderWaitTimeout     time.Duration
	SnapshotThreshold     uint64
	SnapshotInterval      time.Duration
	TrailingLogs          uint64
	PerformanceMultiplier float64
	RaftLogCacheSize      int
	TransportMaxPool      int
	TLSEnabled            bool
	TLSDir                string
	TLSValidity           time.Duration
	TLSOrganization       string
	CACertPath            string
	CertPath              string
	KeyPath               string
	ClientAuth            bool
	AtRestKeyFile         string
	KeyringRotation       bool
	RotationPeriod        time.Duration
}

// FromGohookbridgeFlags maps the gohookbridge flag shape to a Config. It
// selects the shared single-file bbolt backend and keeps
// AllowAutoCAMultiNode=false (the F14 policy: multi-node requires manual
// certificates).
func FromGohookbridgeFlags(in GohookbridgeFlags) Config {
	cfg := DefaultConfig()
	cfg.Dir = in.Dir
	cfg.NodeID = in.NodeID
	cfg.BindAddr = in.BindAddr
	cfg.AdvertiseAddr = in.AdvertiseAddr
	cfg.Discovery.Peers = in.Peers
	cfg.Discovery.Replicas = in.Replicas
	cfg.Discovery.StatefulSetName = in.StatefulSetName
	cfg.Discovery.HeadlessService = in.HeadlessService
	cfg.Discovery.Namespace = in.Namespace
	cfg.Discovery.ClusterDomain = in.ClusterDomain
	cfg.Discovery.RaftPort = in.RaftPort
	cfg.ApplyTimeout = in.ApplyTimeout
	cfg.LeaderWaitTimeout = in.LeaderWaitTimeout
	cfg.SnapshotThreshold = in.SnapshotThreshold
	cfg.SnapshotInterval = in.SnapshotInterval
	cfg.TrailingLogs = in.TrailingLogs
	cfg.PerformanceMultiplier = in.PerformanceMultiplier
	cfg.RaftLogCacheSize = in.RaftLogCacheSize
	cfg.Transport.MaxPool = in.TransportMaxPool
	cfg.Storage.Backend = StorageBackendSharedBolt
	cfg.Storage.AtRestKeyFile = in.AtRestKeyFile
	cfg.TLS.Enabled = in.TLSEnabled
	cfg.TLS.Dir = in.TLSDir
	cfg.TLS.PKIMode = PKIModeSharedCA
	cfg.TLS.Validity = in.TLSValidity
	cfg.TLS.Organization = in.TLSOrganization
	cfg.TLS.CACertPath = in.CACertPath
	cfg.TLS.CertPath = in.CertPath
	cfg.TLS.KeyPath = in.KeyPath
	cfg.TLS.AllowAutoCAMultiNode = false
	cfg.TLS.ClientAuth = in.ClientAuth
	cfg.TLS.KeyringRotationEnabled = in.KeyringRotation
	cfg.TLS.RotationPeriod = in.RotationPeriod
	ApplyDefaults(&cfg)
	return cfg
}
