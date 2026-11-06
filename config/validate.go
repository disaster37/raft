package config

import (
	"fmt"
	"net"
	"strings"
)

// Validate enforces the configuration invariants. hasK8sClient reports
// whether a Kubernetes clientset is available for Secret-based CA bootstrap.
func Validate(cfg *Config, hasK8sClient bool) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if cfg.Discovery.Replicas < 1 {
		return fmt.Errorf("discovery.replicas must be >= 1, got %d", cfg.Discovery.Replicas)
	}
	if cfg.PerformanceMultiplier < 0 {
		return fmt.Errorf("performance_multiplier must be >= 0, got %f", cfg.PerformanceMultiplier)
	}
	switch cfg.Storage.Backend {
	case StorageBackendRaftBoltDB, StorageBackendSharedBolt, StorageBackendInmem:
	default:
		return fmt.Errorf("storage.backend %q is not supported", cfg.Storage.Backend)
	}
	if cfg.Storage.AtRestKey != "" && len(cfg.Storage.AtRestKey) < 16 {
		return fmt.Errorf("storage.at_rest_key must be at least 16 bytes, got %d", len(cfg.Storage.AtRestKey))
	}
	switch cfg.TLS.PKIMode {
	case PKIModeSharedCA, PKIModeSelfSigned:
	default:
		return fmt.Errorf("tls.pki_mode %q is not supported", cfg.TLS.PKIMode)
	}

	multiNode := isMultiNode(cfg)
	if multiNode {
		hasDNS := cfg.Discovery.StatefulSetName != "" && cfg.Discovery.HeadlessService != "" && cfg.Discovery.Namespace != ""
		hasExplicit := len(cfg.Discovery.Peers) > 1 || len(cfg.Discovery.LegacyPeers) > 1
		if !hasDNS && !hasExplicit {
			return fmt.Errorf("multi-node discovery requires statefulset_name, headless_service, and namespace, or explicit peers")
		}
		if !cfg.TLS.Enabled && !cfg.AllowInsecureMultiNode {
			return fmt.Errorf("multi-node clusters require tls.enabled=true unless allow_insecure_multi_node=true")
		}
		if cfg.TLS.Enabled && !cfg.AllowInsecureMultiNode && cfg.AdvertiseAddr != "" && isUnroutable(cfg.AdvertiseAddr) {
			return fmt.Errorf("multi-node advertise_addr %q is not routable", cfg.AdvertiseAddr)
		}
	}

	if cfg.TLS.Enabled {
		manual := cfg.TLS.CACertPath != "" || cfg.TLS.CertPath != "" || cfg.TLS.KeyPath != ""
		if manual && (cfg.TLS.CACertPath == "" || cfg.TLS.CertPath == "" || cfg.TLS.KeyPath == "") {
			return fmt.Errorf("tls.ca_cert, tls.cert, and tls.key must all be set together")
		}
		if multiNode && !manual {
			if !cfg.TLS.AllowAutoCAMultiNode {
				return fmt.Errorf("multi-node TLS requires manual ca_cert/cert/key files (allow_auto_ca_multi_node=false)")
			}
			if !hasK8sClient || cfg.TLS.CASecret == "" {
				return fmt.Errorf("multi-node auto CA requires a Kubernetes client and tls.ca_secret")
			}
		}
	}
	return nil
}

func isMultiNode(cfg *Config) bool {
	return cfg.Discovery.Replicas > 1 || len(cfg.Discovery.Peers) > 1 || len(cfg.Discovery.LegacyPeers) > 1
}

func isUnroutable(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	switch strings.ToLower(host) {
	case "", "127.0.0.1", "0.0.0.0", "::", "::1", "localhost":
		return true
	}
	return false
}
