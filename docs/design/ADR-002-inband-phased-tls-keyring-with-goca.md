# ADR-002: In-band phased TLS keyring with goca

## Status
Accepted.

## Context
Overwriting a single trusted CA breaks peers that have not rotated yet.
Vault solves this with a two-phase in-band keyring.

## Decision
Replicate a `TLSKeyring` inside the Raft FSM via `fsm.EnvelopeFSM` system
commands. Rotation is two-phase: stage a new key (dual trust), wait for
`MinFollowerAppliedIndex >= keyring.AppliedIndex`, then promote and prune.
Keys are generated with `github.com/disaster37/goca` in either `shared-ca`
or `self-signed` mode. The keyring is capped at two keys.

## Consequences
Zero-downtime CA rotation, crash/leader-change recovery, and offline follower
safety. The envelope framing (`0xFF 'R' 'S' 'Y'`) prevents collisions with
user payloads; snapshots use the `RSN1` frame and remain backward compatible.
