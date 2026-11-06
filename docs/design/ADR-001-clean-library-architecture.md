# ADR-001: Clean library architecture

## Status
Accepted.

## Context
The Raft, storage, discovery, and TLS code was duplicated across
`dagger-kubernetes` and `gohookbridge`. Applications isolate code in
`internal/`, but a reusable library must expose cohesive public packages.

## Decision
Expose flat public packages (`config`, `discovery`, `transport`, `pki`,
`keyring`, `storage`, `fsm`, `autopilot`, `observ`, `k8s`, `httpext`,
`testutil`) and a root `raft.Node` facade. Keep only private helpers in
`internal/`. Kubernetes `client-go` is isolated to `k8s/`.

## Consequences
Consumers can use the turnkey facade or compose subpackages without pulling
unnecessary dependencies. The dependency direction is
`handler -> service -> domain <- repository`; `domain` is stdlib-only.
