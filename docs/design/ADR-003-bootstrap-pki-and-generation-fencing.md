# ADR-003: Bootstrap PKI and generation fencing

## Status
Accepted.

## Context
TLS material is needed before Raft exists, and stale PVCs can rejoin with an
old term after a recovery.

## Decision
Provide `pki.BootstrapProvider` implementations for Kubernetes Secrets,
manual PEM files, and local CAs. Ordinal 0 creates the Secret; followers poll.
The transport starts in dual-trust mode and migrates into the in-band keyring.
`k8s.GenerationStore` bumps a cluster generation on recovery; returning pods
with an older local generation wipe stale state before opening storage.

## Consequences
The chicken-and-egg bootstrap is solved without weakening mTLS. Stale PVCs
cannot form a split quorum.
