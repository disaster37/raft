# Migrating from `dagger-kubernetes`

## Configuration

| `dagger-kubernetes` | `github.com/disaster37/raft` |
|---|---|
| `domain.RaftConfig` | `config.Config` |
| `config.Load` | `config.LoadFromFile` + `config.Validate` |
| `raft.bind_addr` | `Config.BindAddr` |
| `raft.peers` | `Config.Discovery.Peers` |
| `raft.tls.*` | `Config.TLS.*` |
| `raft.autopilot.*` | `Config.Autopilot.*` |

Use `config.FromDaggerKubernetes` to map the existing shape in one call.

## Repository symbols

| Source | Library |
|---|---|
| `repository.NewRaftStore` | `raft.NewNode` + `Node.Start` |
| `RaftStore.WaitForLeader` | `Node.WaitForLeader` |
| `RaftStore.WaitForCleanState` | `Node.WaitForCleanState` |
| `RaftStore.Apply` | `Node.Apply` / `Node.ApplyCommand` |
| `RaftStore.ReconcileMembership` | `Node.ReconcileMembership` |
| `RaftStore.LeaveCluster` | `Node.LeaveCluster` |
| `RaftStore.IsRemoved` | `Node.IsRemoved` |
| `repository.PeerResolver` | `discovery.PeerResolver` |
| `repository.RaftPeer` | `discovery.Peer` |
| `repository.MintingCA` | `pki.MintingCA` |
| `repository.LoadOrBuildRaftTLS` | `pki.BootstrapProvider` + `Node.Start` |
| `repository.NewFSM` | `fsm.MemoryKVFSM` |
| `domain.SessionStateSink` | `fsm.SessionStateSink` |
| `observ.RaftMetrics` | `observ.PrometheusMetrics` |
| `handler.LeaderForwardMiddleware` | `httpext.LeaderForwardMiddleware` |

## Before / after

```go
// before
store, err := repository.NewRaftStore(cfg, logger)
if err != nil { return err }
if err := store.WaitForLeader(ctx); err != nil { return err }

// after
n, err := raft.NewNode(ctx, &cfg, raft.NodeOptions{Logger: observ.NewLogrusAdapter(logger)})
if err != nil { return err }
if err := n.Start(ctx); err != nil { return err }
if err := n.WaitForLeader(ctx); err != nil { return err }
```

The `SessionStateSink` is passed through `NodeOptions.SessionSink`; the
envelope FSM forwards session bucket mutations to it on every node.

## Behaviour notes

- The library uses the same single-voter bootstrap and `peerResolvable`
  guard, so split-brain and unreachable-peer stalls are avoided.
- `WaitForCleanState` uses the same commit/applied/fsm_pending/last_contact
  checks.
- The in-band keyring replaces the static CA pool; the bootstrap CA remains
  trusted until Term 3.
