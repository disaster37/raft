# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Framework-agnostic `httpext.Forwarder`, `NewForwardHTTPClient`,
  `HopByHopHeaders`, `IsHopByHopHeader`, and `ReadyzStatus`/`StartupStatus`/
  `LivezStatus` helpers for CloudWeGo Hertz and `net/http` consumers.
- RFC 5869 HKDF-SHA256 at-rest key derivation (`DeriveAESGCMKey`,
  `DeriveAESGCMKeeper`, `LoadOrDeriveAESGCMKeeper`) and automatic sealer
  initialization in `Node.Start` from `storage.at_rest_key_file` /
  `storage.at_rest_key`.
- `observ.NewStdlibAdapter` for standard library `log.Logger` consumers.
- `config.PeerConfig.NonVoter` propagation through discovery.

### Fixed

- Manual TLS `FileWatcher` now updates the exact `DynamicTLSProvider` used by
  `Node`.
- Stream layers evict closed connections, cascade `CloseIdleConnections` to
  inner layers, and retry plaintext dials on `ECONNREFUSED`.
- `EnvelopeFSM.Restore` caps snapshot headers at 16 MiB.
- `BoltKVFSM.ListPrefix("", prefix)` no longer leaks named-bucket keys.
- `SharedBoltStore` applies the full tuned bbolt options.
- `Autopilot` reports real follower heartbeat age, updates Raft stats, and
  counts leader changes; `PrometheusMetrics` reuses existing collectors.
- `dagger/main.go` `Docs` returns the generated file and `Coverage` enforces
  per-package thresholds.

### Changed

- License updated to Apache-2.0.
- `PerformanceMultiplier` accepts values below `1.0` (floored at 5ms) so tests
  run quickly; `NewInmemNode` uses a unique temporary directory and cleans it
  up on `Close`.

## [0.1.0] - 2026-11-05

### Added

- Root `raft.Node` facade with lifecycle, readiness, membership, recovery,
  and keyring helpers.
- `config`, `discovery`, `transport`, `pki`, `keyring`, `storage`, `fsm`,
  `autopilot`, `k8s`, `observ`, `httpext`, and `testutil` packages.
- `raft-boltdb/v2` and shared single-file bbolt storage backends.
- Dynamic mTLS with leaf and CA hot reload.
- Vault-style in-band phased TLS keyring rotation with `goca`.
- Kubernetes Secret bootstrap, generation fencing, and StatefulSet replica
  authorization.
- In-memory and Bolt-backed transactional KV FSMs with atomic `set-multi`.
- AES-256-GCM at-rest encryption with key rotation.
- Dagger CI module, GitHub Actions workflows, examples, docs, and ADRs.
