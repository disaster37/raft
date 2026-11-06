package main

import (
	"context"
	"log"
	"time"

	raft "github.com/disaster37/raft"
	"github.com/disaster37/raft/config"
)

func main() {
	cfg := config.DefaultConfig()
	cfg.Dir = "/var/lib/raft"
	cfg.NodeID = "node-0"
	cfg.BindAddr = "127.0.0.1:8081"
	cfg.AdvertiseAddr = "127.0.0.1:8081"
	cfg.TLS.Enabled = true
	cfg.TLS.PKIMode = config.PKIModeSharedCA
	cfg.TLS.KeyringRotationEnabled = true
	cfg.TLS.RotationPeriod = 24 * time.Hour
	cfg.TLS.RotationCheckInterval = time.Minute

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
	if kr := n.KeyringManager().CurrentKeyring(); kr != nil {
		log.Printf("keyring term=%d active=%s keys=%d", kr.Term, kr.ActiveKeyID, len(kr.Keys))
	}
}
