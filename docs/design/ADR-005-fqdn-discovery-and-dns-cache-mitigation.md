# ADR-005: FQDN discovery and DNS cache mitigation

## Status
Accepted.

## Context
Fresh clusters return NXDOMAIN during CoreDNS warmup, and restarted pods can
receive stale IPs from NodeLocal DNSCache/Cilium for up to 30 seconds.

## Decision
Default to fully-qualified peer names
(`<pod>.<headless>.<ns>.svc.<clusterDomain>`), keep DNS names in the Raft
configuration via `transport.HostAddr`, re-resolve on every dial in
`RetryingStreamLayer`, retry `ECONNREFUSED`, and use `MaxPool: 1`. Startup
resolution retries for two minutes.

## Consequences
Bootstrap survives DNS warmup and pod IP changes. The `peerResolvable` guard
prevents adding deleted StatefulSet pods to quorum.
