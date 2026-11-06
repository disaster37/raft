package main

import (
	"context"
	"fmt"
	"log"
	"time"

	raft "github.com/disaster37/raft"
	"github.com/disaster37/raft/config"
	"github.com/disaster37/raft/fsm"
)

func main() {
	cfg := config.DefaultConfig()
	cfg.Dir = "/tmp/raft-single-node"
	cfg.NodeID = "node-0"
	cfg.BindAddr = "127.0.0.1:8081"
	cfg.AdvertiseAddr = "127.0.0.1:8081"
	cfg.Autopilot.Enabled = false

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
	if _, err := n.ApplyCommand(ctx, fsm.KindSet, fsm.KVEntry{Bucket: "demo", Key: "hello", Value: []byte("world")}); err != nil {
		log.Fatal(err)
	}
	value, ok, err := n.KV().Get("demo", "hello")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("hello=%s found=%v\n", value, ok)
}
