# Migrating from `dagger-kubernetes`

## Configuration

| `dagger-kubernetes` | `github.com/disaster37/go-raft` |
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

## CloudWeGo Hertz integration

`httpext` stays framework-agnostic so `dagger-kubernetes` can keep Hertz out
of this module's `go.mod`. Hertz handlers can call the probe helpers directly
and use `Forwarder` for leader forwarding:

```go
fwd := httpext.NewForwarder(httpext.LeaderForwardConfig{
    LeaderInfo:  raftNode,
    TargetPort:  internalControlPort,
    Scheme:      "https",
    HeaderName:  "X-Dagger-Kubernetes-Leader-Forwarded",
    TLSProvider: raftNode.TLSProvider(),
})

func (s *Server) readyz(ctx context.Context, c *app.RequestContext) {
    code, body := httpext.ReadyzStatus(raftNode)
    c.SetStatusCode(code)
    c.SetBodyString(body)
}

func (s *Server) leaderForward() app.HandlerFunc {
    return func(ctx context.Context, c *app.RequestContext) {
        marker := string(c.Request.Header.Peek(fwd.HeaderName()))
        if !fwd.ShouldForward(string(c.Method()), string(c.Path()), marker) {
            c.Next(ctx)
            return
        }
        header := make(http.Header)
        c.Request.Header.VisitAll(func(k, v []byte) {
            header.Add(string(k), string(v))
        })
        resp, err := fwd.Forward(ctx, &httpext.ForwardRequest{
            Method:     string(c.Method()),
            RequestURI: string(c.Request.URI().RequestURI()),
            Header:     header,
            Body:       bytes.NewReader(c.Request.Body()),
        })
        if err != nil {
            c.SetStatusCode(http.StatusBadGateway)
            c.Abort()
            return
        }
        defer resp.Body.Close()
        for k, values := range resp.Header {
            for _, v := range values {
                c.Response.Header.Add(k, v)
            }
        }
        c.SetStatusCode(resp.StatusCode)
        c.SetBodyStream(resp.Body, -1)
        c.Abort()
    }
}
```

## At-rest encryption from a single secret

`dagger-kubernetes` can pass its existing `EncryptionKey` through
`config.DaggerKubernetesConfig.EncryptionKey`. `Node.Start` derives an
AES-256-GCM sealer with HKDF-SHA256 when `NodeOptions.Sealer` is nil:

```go
cfg := config.FromDaggerKubernetes(config.DaggerKubernetesConfig{
    // ...
    EncryptionKey: os.Getenv("DAGGER_KUBERNETES_ENCRYPTION_KEY"),
})
node, err := raft.NewNode(ctx, &cfg, raft.NodeOptions{})
```

Existing JSON key files keep working through `storage.LoadAESGCMKeeper`; raw
secrets and `storage.at_rest_key` are expanded with
`storage.DeriveAESGCMKeeper`.
