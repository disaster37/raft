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

At-rest keys can be supplied as a multi-key JSON file (existing behaviour) or
derived from a single secret/passphrase with RFC 5869 HKDF-SHA256
(`storage.DeriveAESGCMKey`, `storage.DeriveAESGCMKeeper`,
`storage.LoadOrDeriveAESGCMKeeper`). The default domain-separation info is
`raft-at-rest-aes-256-gcm-v1`; secrets shorter than 16 bytes are rejected.
`Node.Start` automatically initializes the sealer from
`storage.at_rest_key_file` or `storage.at_rest_key` when no sealer is
injected.

## Consequences
Consumers choose RAM-speed reads or disk-backed KV storage. Single-file
backups are atomic. `go-raftchunking` and `raft-wal` remain out of scope for
v1; callers can inject custom stores.
