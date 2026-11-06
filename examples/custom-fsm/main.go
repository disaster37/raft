package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	hraft "github.com/hashicorp/raft"

	raft "github.com/disaster37/raft"
	"github.com/disaster37/raft/config"
)

type counterFSM struct {
	mu    sync.Mutex
	value int
}

func (f *counterFSM) Apply(log *hraft.Log) interface{} {
	var delta int
	if err := json.Unmarshal(log.Data, &delta); err != nil {
		return err
	}
	f.mu.Lock()
	f.value += delta
	f.mu.Unlock()
	return nil
}

func (f *counterFSM) Snapshot() (hraft.FSMSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &counterSnapshot{value: f.value}, nil
}

func (f *counterFSM) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	var value int
	if err := json.NewDecoder(rc).Decode(&value); err != nil {
		return err
	}
	f.mu.Lock()
	f.value = value
	f.mu.Unlock()
	return nil
}

type counterSnapshot struct {
	value int
}

func (s *counterSnapshot) Persist(sink hraft.SnapshotSink) error {
	if err := json.NewEncoder(sink).Encode(s.value); err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}

func (s *counterSnapshot) Release() {}

func main() {
	fsm := &counterFSM{}
	cfg := config.DefaultConfig()
	cfg.Dir = "/tmp/raft-custom-fsm"
	cfg.NodeID = "node-0"
	cfg.BindAddr = "127.0.0.1:8081"
	cfg.AdvertiseAddr = "127.0.0.1:8081"
	cfg.Autopilot.Enabled = false

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := raft.NewNode(ctx, &cfg, raft.NodeOptions{FSM: fsm})
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
	if _, err := n.Apply(ctx, []byte("5")); err != nil {
		log.Fatal(err)
	}
	fsm.mu.Lock()
	defer fsm.mu.Unlock()
	fmt.Printf("counter=%d\n", fsm.value)
}
