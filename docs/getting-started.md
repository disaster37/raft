# Getting started

## 1. Single-node embedded store

```go
cfg := config.DefaultConfig()
cfg.Dir = "/var/lib/raft"
cfg.NodeID = "node-0"
cfg.BindAddr = "127.0.0.1:8081"
cfg.AdvertiseAddr = "127.0.0.1:8081"
cfg.Autopilot.Enabled = false

n, err := raft.NewNode(ctx, &cfg, raft.NodeOptions{})
if err != nil { return err }
if err := n.Start(ctx); err != nil { return err }
defer n.Close()
if err := n.WaitForLeader(ctx); err != nil { return err }
```

The default backend is `raft-boltdb/v2` with an in-memory log cache. The
default FSM is `fsm.MemoryKVFSM`; use `n.KV()` for reads and
`n.ApplyCommand`/`n.ApplyMulti` for writes.

## 2. Three-node static cluster with `goca` certificates

1. Generate a CA and one leaf per node with `pki.NewMintingCA` and
   `IssuePeerCertificate`. Include the node's DNS names and IP SANs.
2. Set `Discovery.Peers` to the explicit `id`/`address` list.
3. Set `TLS.Enabled=true` and the manual `CACertPath`, `CertPath`, and
   `KeyPath` for each node.
4. Start all nodes. Only the first peer in the sorted list bootstraps; the
   leader's join loop adds the rest.

```go
cfg.Discovery.Peers = []config.PeerConfig{
    {ID: "node-0", Address: "10.0.0.1:8081"},
    {ID: "node-1", Address: "10.0.0.2:8081"},
    {ID: "node-2", Address: "10.0.0.3:8081"},
}
cfg.Discovery.Replicas = 3
cfg.TLS.Enabled = true
cfg.TLS.CACertPath = "/etc/raft/tls/ca.crt"
cfg.TLS.CertPath = "/etc/raft/tls/node.crt"
cfg.TLS.KeyPath = "/etc/raft/tls/node.key"
```

## 3. Kubernetes StatefulSet with Secret bootstrap

```go
clientset, _ := k8s.NewClientset()
provider := k8s.NewSecretBootstrapProvider(k8s.SecretBootstrapConfig{
    Clientset:    clientset,
    Namespace:    "raft",
    SecretName:   "raft-ca",
    CABootstrap:  os.Getenv("POD_NAME") == "raft-0",
    CACommonName: "raft-ca",
    Organization: "raft",
    CAValidity:   10 * 365 * 24 * time.Hour,
})

cfg.Discovery.StatefulSetName = "raft"
cfg.Discovery.HeadlessService = "raft-headless"
cfg.Discovery.Namespace = "raft"
cfg.Discovery.Replicas = 3
cfg.TLS.Enabled = true
cfg.TLS.CASecret = "raft-ca"
cfg.TLS.AllowAutoCAMultiNode = true
cfg.TLS.KeyringRotationEnabled = true

n, err := raft.NewNode(ctx, &cfg, raft.NodeOptions{BootstrapProvider: provider})
```

Ordinal 0 creates the Secret; other pods poll until it appears. Once the
cluster is clean, the leader seeds the in-band keyring from the bootstrap CA
and the phased rotator takes over.

## 4. Custom FSM vs built-in KV

Pass `NodeOptions.FSM` to use your own `raft.FSM`. The library wraps it in
`fsm.EnvelopeFSM`, so system keyring/echo commands remain transparent. When a
custom FSM is supplied, `n.KV()` returns `nil`.

```go
n, err := raft.NewNode(ctx, &cfg, raft.NodeOptions{FSM: myFSM})
```

Use the built-in KV when you want transactional key/value storage without
writing an FSM:

```go
n.ApplyMulti(ctx, []fsm.KVEntry{
    {Bucket: "users", Key: "u1", Value: userJSON},
    {Bucket: "index", Key: "u1", Value: []byte("u1")},
})
```
