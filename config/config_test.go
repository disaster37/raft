package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Discovery.Replicas != 1 {
		t.Fatalf("replicas = %d", cfg.Discovery.Replicas)
	}
	if cfg.Storage.Backend != StorageBackendRaftBoltDB {
		t.Fatalf("backend = %q", cfg.Storage.Backend)
	}
	if cfg.TLS.PKIMode != PKIModeSharedCA {
		t.Fatalf("pki mode = %q", cfg.TLS.PKIMode)
	}
	if cfg.PerformanceMultiplier != 5.0 {
		t.Fatalf("multiplier = %f", cfg.PerformanceMultiplier)
	}
	if cfg.Transport.EchoMaxConcurrent != 64 || cfg.Transport.EchoPeekTimeout != time.Second {
		t.Fatalf("transport echo defaults = %+v", cfg.Transport)
	}
}

func TestApplyDefaults(t *testing.T) {
	cfg := Config{}
	ApplyDefaults(&cfg)
	if cfg.Dir == "" || cfg.BindAddr == "" || cfg.ApplyTimeout == 0 {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
	ApplyDefaults(nil)
}

func TestParseExtendedDuration(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"7d", 7 * 24 * time.Hour, false},
		{"2w", 14 * 24 * time.Hour, false},
		{"1.5d", 36 * time.Hour, false},
		{"1.5d12h", 48 * time.Hour, false},
		{"1h30m", 90 * time.Minute, false},
		{"bad", 0, true},
		{"1x", 0, true},
		{"1d2x", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseExtendedDuration(tt.in)
		if (err != nil) != tt.wantErr {
			t.Fatalf("ParseExtendedDuration(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
		}
		if err == nil && got != tt.want {
			t.Fatalf("ParseExtendedDuration(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestDecodeSettingsDottedKeys(t *testing.T) {
	settings := map[string]any{
		"dir":           "/tmp/raft",
		"apply_timeout": "7d",
		"discovery": map[string]any{
			"replicas": 3,
			"peers": []any{
				map[string]any{"id": "a", "address": "a:1"},
			},
		},
	}
	var cfg Config
	if err := DecodeSettings(settings, &cfg); err != nil {
		t.Fatalf("DecodeSettings: %v", err)
	}
	if cfg.Dir != "/tmp/raft" {
		t.Fatalf("dir = %q", cfg.Dir)
	}
	if cfg.ApplyTimeout != 7*24*time.Hour {
		t.Fatalf("apply timeout = %v", cfg.ApplyTimeout)
	}
	if cfg.Discovery.Replicas != 3 || len(cfg.Discovery.Peers) != 1 {
		t.Fatalf("discovery = %+v", cfg.Discovery)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "dir: /tmp/raft-test\nnode_id: node-a\napply_timeout: 7d\ndiscovery:\n  replicas: 1\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFromFile(path, "RAFT_TEST")
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if cfg.Dir != "/tmp/raft-test" || cfg.NodeID != "node-a" {
		t.Fatalf("cfg = %+v", cfg)
	}
	if cfg.ApplyTimeout != 7*24*time.Hour {
		t.Fatalf("apply timeout = %v", cfg.ApplyTimeout)
	}
	if _, err := LoadFromFile(filepath.Join(dir, "missing.yaml"), "RAFT_TEST"); err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
}

func TestValidate(t *testing.T) {
	base := DefaultConfig()
	base.Discovery.Replicas = 1
	if err := Validate(&base, false); err != nil {
		t.Fatalf("single node should validate: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		k8s     bool
		wantErr bool
	}{
		{"nil", nil, false, true},
		{"replicas", func(c *Config) { c.Discovery.Replicas = 0 }, false, true},
		{"multi no discovery", func(c *Config) { c.Discovery.Replicas = 3 }, false, true},
		{"multi insecure", func(c *Config) {
			c.Discovery.Replicas = 3
			c.Discovery.StatefulSetName = "sts"
			c.Discovery.HeadlessService = "svc"
			c.Discovery.Namespace = "ns"
		}, false, true},
		{"multi tls manual partial", func(c *Config) {
			c.Discovery.Replicas = 3
			c.Discovery.StatefulSetName = "sts"
			c.Discovery.HeadlessService = "svc"
			c.Discovery.Namespace = "ns"
			c.TLS.Enabled = true
			c.TLS.CACertPath = "/ca"
		}, false, true},
		{"multi tls f14", func(c *Config) {
			c.Discovery.Replicas = 3
			c.Discovery.StatefulSetName = "sts"
			c.Discovery.HeadlessService = "svc"
			c.Discovery.Namespace = "ns"
			c.TLS.Enabled = true
		}, false, true},
		{"multi tls auto no k8s", func(c *Config) {
			c.Discovery.Replicas = 3
			c.Discovery.StatefulSetName = "sts"
			c.Discovery.HeadlessService = "svc"
			c.Discovery.Namespace = "ns"
			c.TLS.Enabled = true
			c.TLS.AllowAutoCAMultiNode = true
			c.TLS.CASecret = "ca"
		}, false, true},
		{"multi tls auto ok", func(c *Config) {
			c.Discovery.Replicas = 3
			c.Discovery.StatefulSetName = "sts"
			c.Discovery.HeadlessService = "svc"
			c.Discovery.Namespace = "ns"
			c.TLS.Enabled = true
			c.TLS.AllowAutoCAMultiNode = true
			c.TLS.CASecret = "ca"
		}, true, false},
		{"unroutable", func(c *Config) {
			c.Discovery.Replicas = 3
			c.Discovery.StatefulSetName = "sts"
			c.Discovery.HeadlessService = "svc"
			c.Discovery.Namespace = "ns"
			c.TLS.Enabled = true
			c.TLS.AllowAutoCAMultiNode = true
			c.TLS.CASecret = "ca"
			c.AdvertiseAddr = "127.0.0.1:8081"
		}, true, true},
		{"negative multiplier", func(c *Config) { c.PerformanceMultiplier = -1 }, false, true},
		{"bad backend", func(c *Config) { c.Storage.Backend = "bad" }, false, true},
		{"bad pki", func(c *Config) { c.TLS.PKIMode = "bad" }, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg *Config
			if tt.mutate != nil {
				c := DefaultConfig()
				tt.mutate(&c)
				cfg = &c
			}
			err := Validate(cfg, tt.k8s)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAdapters(t *testing.T) {
	dk := FromDaggerKubernetes(DaggerKubernetesConfig{
		Dir:                   "/tmp/dk",
		NodeID:                "n0",
		BindAddr:              "127.0.0.1:8081",
		Replicas:              3,
		StatefulSetName:       "sts",
		HeadlessService:       "svc",
		Namespace:             "ns",
		TLSEnabled:            true,
		CASecret:              "ca",
		AutopilotEnabled:      true,
		CleanupDeadServers:    true,
		MinQuorum:             2,
		PerformanceMultiplier: 5,
		TransportMaxPool:      1,
	})
	if dk.Storage.Backend != StorageBackendRaftBoltDB || !dk.TLS.AllowAutoCAMultiNode {
		t.Fatalf("dagger adapter = %+v", dk)
	}
	gh := FromGohookbridgeFlags(GohookbridgeFlags{
		Dir:             "/tmp/gh",
		NodeID:          "n0",
		BindAddr:        "127.0.0.1:6001",
		Replicas:        1,
		TLSEnabled:      true,
		KeyringRotation: true,
	})
	if gh.Storage.Backend != StorageBackendSharedBolt || gh.TLS.AllowAutoCAMultiNode {
		t.Fatalf("gohookbridge adapter = %+v", gh)
	}
}

func TestRegisterViperDefaultsAndEnv(t *testing.T) {
	v := viper.New()
	RegisterViperDefaults(v, "raft")
	if v.GetString("raft.dir") == "" {
		t.Fatal("default not registered")
	}
	RegisterViperDefaults(nil, "")
	t.Setenv("RAFT_TEST_DIR", "/tmp/env-dir")
	cfg, err := LoadFromFile("", "RAFT_TEST")
	if err != nil {
		t.Fatalf("LoadFromFile env: %v", err)
	}
	if cfg.Dir != "/tmp/env-dir" {
		t.Fatalf("dir = %q", cfg.Dir)
	}
}

func TestDecodeSettingsError(t *testing.T) {
	if err := DecodeSettings(map[string]any{"apply_timeout": "bad"}, &Config{}); err == nil {
		t.Fatal("expected duration error")
	}
}

func TestValidateManualTLS(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Discovery.Replicas = 3
	cfg.Discovery.StatefulSetName = "sts"
	cfg.Discovery.HeadlessService = "svc"
	cfg.Discovery.Namespace = "ns"
	cfg.TLS.Enabled = true
	cfg.TLS.CACertPath = "/ca"
	cfg.TLS.CertPath = "/cert"
	cfg.TLS.KeyPath = "/key"
	if err := Validate(&cfg, false); err != nil {
		t.Fatalf("manual TLS should validate: %v", err)
	}
	cfg.TLS.CertPath = ""
	if err := Validate(&cfg, false); err == nil {
		t.Fatal("expected all-or-nothing error")
	}
}

func TestApplyDefaultsPartial(t *testing.T) {
	cfg := Config{
		Discovery: DiscoveryConfig{Replicas: 2},
		TLS:       TLSConfig{Enabled: true},
		Storage:   StorageConfig{Backend: StorageBackendSharedBolt},
	}
	ApplyDefaults(&cfg)
	if cfg.Discovery.ClusterDomain == "" || cfg.TLS.PKIMode == "" || cfg.Storage.BoltTimeout == 0 {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
}
