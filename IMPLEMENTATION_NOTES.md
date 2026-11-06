# Implementation notes

This file records deviations and environment-specific decisions made while
implementing the approved plan.

## Dependency versions

All versions pinned in the plan exist and were used unchanged:

- `github.com/disaster37/goca v1.0.7`
- `github.com/go-viper/mapstructure/v2 v2.5.0`
- `github.com/hashicorp/go-hclog v1.6.2`
- `github.com/hashicorp/raft v1.7.3`
- `github.com/hashicorp/raft-boltdb/v2 v2.3.1`
- `github.com/prometheus/client_golang v1.23.2`
- `github.com/sirupsen/logrus v1.9.4`
- `github.com/spf13/viper v1.21.0`
- `go.etcd.io/bbolt v1.4.3`
- `gopkg.in/yaml.v3 v3.0.1`
- `k8s.io/api`, `k8s.io/apimachinery`, `k8s.io/client-go v0.29.13`

## Dagger module

- The Dagger engine pinned in `dagger/dagger.json` is `v0.21.8`; the local
  CLI is `v0.21.10`. `dagger develop` and `format-check` succeed with the
  local Docker engine.
- The full `dagger call ... ci` could not complete in this environment
  because outbound HTTPS to `api.github.com` and `proxy.golang.org` times out
  during `govulncheck`/`golangci-lint` installation. The module preinstalls
  both tools into `/usr/local/bin` to avoid the upstream GitHub lookup, but
  the network remained unavailable. The local fallback suite (build, vet,
  race tests, golangci-lint, fuzz smoke, static example builds) passed.
- The Dagger `Coverage` function uses the plan's 90.0% threshold. The
  coverage total excludes `examples/` and `test/` packages (they contain no
  library statements); with that filter the library is at 90.4% overall and
  `config`/`discovery`/`keyring` are at 95.2%/96.0%/95.4%.

## Behavioural deviations

- `Node.LeaveCluster` removes the local server while it is still leader
  instead of transferring leadership first. `RemoveServer` is leader-only, so
  transferring first would leave the old leader unable to remove itself. The
  removal triggers a normal election among the remaining voters.
- `config.Validate` skips the loopback-advertise check when
  `allow_insecure_multi_node=true`, so loopback multi-node integration tests
  can run. Secure multi-node still rejects loopback advertise addresses.
- `goca` clamps CA validity to 10 years; `tls.ca_validity` values above that
  are clamped rather than rejected.
- The in-band keyring is seeded from the bootstrap CA by the rotator's `Seed`
  callback before any new key is generated. This avoids a race where a
  freshly generated key would be trusted by the leader before followers
  received it.
- Follower applied indexes are reported over a small echo protocol
  multiplexed on the Raft listener (`ECHO` magic + mTLS). This keeps the
  phased rotator's `MinFollowerAppliedIndex` accurate without an extra port.

## Review follow-ups

- `SharedBoltStore.Get` now returns the standard missing-key sentinel
  `raftboltdb.ErrKeyNotFound` instead of a bare `fmt.Errorf("not found")`.
  The pinned `hashicorp/raft` v1.7.3 does not define `ErrKeyNotFound`; the
  sentinel lives in `hashicorp/raft-boltdb/v2`, which is the backend this
  store mirrors. `GetUint64` propagates it, and `IsRemovedFlag` treats it as
  "flag not set" while returning other storage errors.
- `GenerationStore.BumpClusterGeneration` now performs a conflict-safe
  read-modify-write using the Secret's `ResourceVersion` and
  `retry.RetryOnConflict(retry.DefaultRetry, ...)`. Retries are bounded to
  the client-go default (5 attempts).
- `EnvelopeFSM.Apply` and `EnvelopeFSM.Restore` invoke the keyring callback
  before installing new FSM state. A callback error leaves the previous
  keyring/echo state intact.
- `muxListener` now bounds concurrent echo handlers with a semaphore and
  applies a configurable peek deadline to the four-byte echo magic. New
  transport keys: `transport.echo_max_concurrent` (default `64`) and
  `transport.echo_peek_timeout` (default `1s`). Excess echo connections are
  closed immediately; stalled peeks are closed after the deadline.
- `LeaderForwardMiddleware` builds one shared `http.Transport` per middleware
  instance instead of one per request. TLS dials use
  `DynamicTLSProvider.DialTLSConfig(serverName)` per connection so CA/leaf
  rotation is honored, and the transport sets dial, response-header,
  TLS-handshake, and idle-connection timeouts. Optional
  `LeaderForwardConfig` fields `DialTimeout`, `ResponseHeaderTimeout`, and
  `IdleConnTimeout` override the defaults.
- `Node.Start` now cleans up on failure: it stops the TLS file watcher,
  cancels the node context, waits for background goroutines, and closes any
  opened transport/backend. `FileWatcher.Done` exposes watcher termination
  for leak tests. A failed `Start` marks the node closed so a later `Start`
  returns `ErrAlreadyClosed`.
- Added `fsm/bench_test.go` with `BenchmarkEnvelopeApply` and
  `BenchmarkMemoryKVFSMApply` using 1 KiB values.

## Test environment

- Integration tests use `testutil.FreeListener(t)` and timed shutdown.
- The `k8s` in-cluster client test creates temporary service-account files
  under `/var/run/secrets/kubernetes.io/serviceaccount` and removes only the
  files it created.
