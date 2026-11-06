# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
