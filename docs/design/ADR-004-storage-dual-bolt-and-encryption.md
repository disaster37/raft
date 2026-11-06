# ADR-004: Dual Bolt storage and at-rest encryption

## Status
Accepted.

## Context
`dagger-kubernetes` uses `raft-boltdb/v2` with an in-memory FSM;
`gohookbridge` persists FSM data in the same bbolt file as logs and stable
state.

## Decision
Support both backends behind `storage.Backend`:
`raft-boltdb/v2` with `raft.LogCache`, and a shared single-file bbolt store
with `logs`, `stable`, `fsm_data`, and `_sys` buckets. Provide
`storage.AESGCMKeeper` for AES-256-GCM at-rest encryption with key rotation
and lazy plaintext migration.

## Consequences
Consumers choose RAM-speed reads or disk-backed KV storage. Single-file
backups are atomic. `go-raftchunking` and `raft-wal` remain out of scope for
v1; callers can inject custom stores.
