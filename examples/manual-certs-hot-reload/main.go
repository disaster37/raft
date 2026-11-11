package main

import (
	"context"
	"log"
	"time"

	raft "github.com/disaster37/go-raft"
	"github.com/disaster37/go-raft/config"
)

func main() {
	cfg := config.DefaultConfig()
	cfg.Dir = "/var/lib/raft"
	cfg.NodeID = "node-0"
	cfg.BindAddr = "127.0.0.1:8081"
	cfg.AdvertiseAddr = "127.0.0.1:8081"
	cfg.TLS.Enabled = true
	cfg.TLS.CACertPath = "/etc/raft/tls/ca.crt"
	cfg.TLS.CertPath = "/etc/raft/tls/node.crt"
	cfg.TLS.KeyPath = "/etc/raft/tls/node.key"
	cfg.TLS.ReloadPollInterval = 5 * time.Second
	cfg.TLS.KeyringRotationEnabled = false

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := raft.NewNode(ctx, &cfg, raft.NodeOptions{})
	if err != nil {
		log.Fatal(err)
	}
	if err := n.Start(ctx); err != nil {
		log.Fatal(err)
	}
	defer n.Close()
	if err := n.WaitForLeader(ctx); err != nil {
		log.Fatal(err)
	}
	log.Printf("manual-cert node %s is ready; certificate files are hot-reloaded", n.NodeID())
}
