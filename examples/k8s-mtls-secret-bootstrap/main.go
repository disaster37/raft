package main

import (
	"context"
	"log"
	"os"
	"time"

	raft "github.com/disaster37/raft"
	"github.com/disaster37/raft/config"
	"github.com/disaster37/raft/k8s"
)

func main() {
	clientset, err := k8s.NewClientset()
	if err != nil {
		log.Fatal(err)
	}
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	cfg := config.DefaultConfig()
	cfg.Dir = "/var/lib/raft"
	cfg.NodeID = os.Getenv("POD_NAME")
	cfg.BindAddr = ":8081"
	cfg.Discovery.Replicas = 3
	cfg.Discovery.StatefulSetName = "raft"
	cfg.Discovery.HeadlessService = "raft-headless"
	cfg.Discovery.Namespace = namespace
	cfg.TLS.Enabled = true
	cfg.TLS.CASecret = "raft-ca"
	cfg.TLS.AllowAutoCAMultiNode = true
	cfg.TLS.CABootstrap = os.Getenv("POD_NAME") == "raft-0"

	provider := k8s.NewSecretBootstrapProvider(k8s.SecretBootstrapConfig{
		Clientset:    clientset,
		Namespace:    namespace,
		SecretName:   cfg.TLS.CASecret,
		CABootstrap:  cfg.TLS.CABootstrap,
		CACommonName: "raft-ca",
		Organization: "raft",
		CAValidity:   10 * 365 * 24 * time.Hour,
		PollTimeout:  cfg.TLS.SecretPollTimeout,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	n, err := raft.NewNode(ctx, &cfg, raft.NodeOptions{BootstrapProvider: provider})
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
	log.Printf("raft node %s joined the cluster", n.NodeID())
}
