// Package raft is a production-grade layer on top of HashiCorp Raft that
// bundles storage, Kubernetes StatefulSet DNS discovery, dynamic mTLS, an
// in-band phased TLS keyring, autopilot, and HTTP helpers.
//
// The root package exposes a turnkey Node facade. Consumers that need finer
// control can compose the subpackages directly:
//
//   - config: configuration structs, defaults, loading, and validation
//   - discovery: peer resolvers for DNS, static, and single-node clusters
//   - transport: plaintext/TLS stream layers and hot-reloading TLS providers
//   - pki: goca-backed CA and leaf certificate issuance
//   - keyring: replicated TLS keyring and Vault-style phased rotation
//   - storage: raft-boltdb/v2 and shared single-file bbolt backends
//   - fsm: envelope FSM plus in-memory and Bolt-backed KV state machines
//   - autopilot: follower health tracking and dead-server cleanup
//   - k8s: Kubernetes Secret bootstrap, generation fencing, and replica reads
//   - observ: logging and Prometheus metrics adapters
//   - httpext: readiness/startup probes and leader-forwarding middleware
//   - testutil: listener reservation and test cluster helpers
//
// A minimal single-node node:
//
//	cfg := config.DefaultConfig()
//	cfg.Dir = "/var/lib/example"
//	cfg.NodeID = "node-0"
//	cfg.BindAddr = "127.0.0.1:8081"
//	cfg.AdvertiseAddr = "127.0.0.1:8081"
//
//	n, err := raft.NewNode(ctx, &cfg, raft.NodeOptions{})
//	if err != nil {
//		return err
//	}
//	if err := n.Start(ctx); err != nil {
//		return err
//	}
//	defer n.Close()
//	if err := n.WaitForLeader(ctx); err != nil {
//		return err
//	}
package raft
