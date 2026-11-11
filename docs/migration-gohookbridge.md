# Migrating from `gohookbridge`

## Configuration

| `gohookbridge` | `github.com/disaster37/go-raft` |
|---|---|
| `RaftConfig` flags | `config.Config` |
| `raft.bind_addr` | `Config.BindAddr` |
| `raft.peers` | `Config.Discovery.Peers` |
| `raft.tls.*` | `Config.TLS.*` |
| `raft.at_rest_key_file` | `Config.Storage.AtRestKeyFile` |

Use `config.FromGohookbridgeFlags` to map the flag shape. It selects the
shared single-file bbolt backend and keeps `AllowAutoCAMultiNode=false`
(the F14 policy).

## Repository symbols

| Source | Library |
|---|---|
| `repository.NewRaftStore` | `raft.NewNode` |
| `repository.boltLogStore` / `boltStableStore` | `storage.SharedBoltStore` |
| `repository.FSM` | `fsm.BoltKVFSM` |
| `repository.CryptoKeeper` | `storage.AESGCMKeeper` |
| `repository.RaftPeer` | `discovery.Peer` |
| `repository.PeerResolver` | `discovery.PeerResolver` |
| `repository.newTLSStreamLayer` | `transport.NewTLSStreamLayer` |
| `pkg/tlsreload.Provider` | `transport.DynamicTLSProvider` + `transport.FileWatcher` |
| `server.raftGenerationStore` | `k8s.GenerationStore` |
| `handler.LeaderForwardMiddleware` | `httpext.LeaderForwardMiddleware` |

## Before / after

```go
// before
store, err := repository.NewRaftStore(cfg, logger)
// after
n, err := raft.NewNode(ctx, &cfg, raft.NodeOptions{
    BootstrapProvider: pki.NewFileBootstrapProvider(ca, cert, key),
})
```

## Behaviour notes

- `SharedBoltStore` uses the same `logs`, `stable`, `fsm_data`, and `_sys`
  buckets in `<dir>/<nodeID>.db`.
- `BoltKVFSM` implements atomic `set-multi` in one bbolt transaction.
- `AESGCMKeeper` keeps the same `EncryptedValue` envelope and lazy plaintext
  migration.
- The `tlsreload` static-CA bug is fixed: `DialTLSConfig` reads the current
  `RootCAs` on every dial and `GetConfigForClient` refreshes `ClientCAs`.
- `SingleNodeRecovery` is authorized by `k8s.StatefulSetReplicaReader` and
  fenced by `k8s.GenerationStore`.
