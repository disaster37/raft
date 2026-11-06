# Security policy

## Supported versions

| Version | Supported |
|---|---|
| `v0.1.x` | Yes |

## Reporting a vulnerability

Report vulnerabilities privately to the maintainers via GitHub Security
Advisories. Do not open a public issue for an unpatched vulnerability.

## Threat model and mitigations

| CWE | Risk | Mitigation |
|---|---|---|
| CWE-295 | Untrusted peer / wrong SAN | mTLS with `RequireAndVerifyClientCert`, SAN verification, dual-trust CA rotation. |
| CWE-311/319 | Cleartext data at rest/in transit | TLS 1.2+ for transport; AES-256-GCM `Sealer` for sensitive fields. |
| CWE-532 | Secrets in logs | Private keys and sealed values are never logged; log tests assert no `PRIVATE KEY`. |
| CWE-693 | Split-brain / election deadlock | Single-voter bootstrap, deterministic static peer sorting, `peerResolvable` guard. |
| CWE-732/922 | Permission leaks | Data dirs `0700`; keys, DB, node-id, snapshots `0600`/`0700`. |
| CWE-754 | Empty Secret crash | Empty CA Secrets are treated as unprovisioned and overwritten by the bootstrap node. |

## Operational guidance

- Restrict the CA Secret to the Raft ServiceAccount.
- Rotate the at-rest key file and keep old key IDs until re-sealing completes.
- Use `allow_insecure_multi_node` only in isolated tests.
- Monitor keyring term/age and follower applied-index lag.
