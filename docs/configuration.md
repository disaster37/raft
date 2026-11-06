# Configuration reference

All keys can be set in YAML or through environment variables. The default
environment prefix is `RAFT_`; `LoadFromFile(path, "DAGGER_KUBERNETES_RAFT")`
uses `DAGGER_KUBERNETES_RAFT_*`. Dots become underscores
(`tls.ca_secret` -> `RAFT_TLS_CA_SECRET`).

## Top-level

| Key | Type | Default | Validation / notes |
|---|---|---|---|
| `dir` | string | `/var/lib/raft` | Created `0700`. |
| `node_id` | string | `""` | Empty generates/persists `<dir>/node-id` (`0600`). |
| `bind_addr` | string | `:8081` | Raft listener. |
| `advertise_addr` | string | `""` | Empty derives from hostname/headless service. |
| `advertise_resolve_timeout` | duration | `2m` | Startup DNS warmup budget. |
| `apply_timeout` | duration | `5s` | Raft apply timeout. |
| `leader_wait_timeout` | duration | `120s` | Bootstrap/leader wait budget. |
| `snapshot_threshold` | uint64 | `1000` | Raft snapshot threshold. |
| `snapshot_interval` | duration | `10m` | Raft snapshot interval. |
| `snapshot_retain` | int | `2` | Snapshot files retained. |
| `trailing_logs` | uint64 | `256` | Logs kept after snapshot. |
| `performance_multiplier` | float64 | `5.0` | Scales election/heartbeat/lease; `>= 0`. |
| `raft_log_cache_size` | int | `512` | In-memory log cache entries. |
| `max_append_entries` | int | `64` | Raft batching. |
| `batch_apply_ch` | bool | `true` | Raft batch apply channel. |
| `max_entry_size` | uint64 | `1048576` | Rejects larger apply payloads. |
| `no_snapshot_restore_on_start` | bool | `false` | Disable snapshot restore on start. |
| `termination_grace_period` | duration | `60s` | Graceful shutdown budget. |
| `recovery_mode` | bool | `false` | Wipes local Raft state and bootstraps fresh. |
| `single_node_recovery` | bool | `false` | Uses `raft.RecoverCluster` to collapse quorum. |
| `non_voter` | bool | `false` | Join as a non-voter. |
| `allow_insecure_multi_node` | bool | `false` | Allows multi-node without TLS (tests only). |
| `follower_last_contact_max` | duration | `15s` | `IsCleanState` follower heartbeat threshold. |

## `discovery`

| Key | Type | Default | Notes |
|---|---|---|---|
| `peers` | list | `[]` | Explicit `{id,address}` peers. |
| `legacy_peers` | list | `[]` | `id=host:port` entries. |
| `replicas` | int | `1` | Must be `>= 1`. |
| `statefulset_name` | string | `""` | Required for DNS discovery. |
| `headless_service` | string | `""` | Required for DNS discovery. |
| `namespace` | string | `""` | Required for DNS discovery. |
| `cluster_domain` | string | `cluster.local` | Empty emits `.svc`-only names. |
| `raft_port` | int | `8081` | Port used in derived peer addresses. |

## `transport`

| Key | Type | Default | Notes |
|---|---|---|---|
| `max_pool` | int | `1` | Connections per peer. |
| `timeout` | duration | `10s` | Dial/RPC timeout. |
| `max_dial_retries` | int | `4` | Retries on `ECONNREFUSED`. |
| `dial_retry_base` | duration | `500ms` | Linear retry backoff base. |
| `echo_max_concurrent` | int | `64` | Max concurrent follower-echo handlers; excess connections are closed. |
| `echo_peek_timeout` | duration | `1s` | Max time to read the 4-byte echo magic before closing a slow connection. |

## `tls`

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Multi-node requires TLS unless insecure is allowed. |
| `dir` | string | `<dir>/tls` | TLS material directory (`0700`). |
| `pki_mode` | string | `shared-ca` | `shared-ca` or `self-signed`. |
| `validity` | duration | `8760h` | Leaf validity. |
| `ca_validity` | duration | `262800h` | CA validity (clamped to 10 years by `goca`). |
| `safety_margin` | duration | `168h` | Re-issue window before expiry. |
| `organization` | string | `raft` | Certificate organization. |
| `ca_cert` | string | `""` | Manual CA cert path. |
| `cert` | string | `""` | Manual leaf cert path. |
| `key` | string | `""` | Manual leaf key path. |
| `ca_secret` | string | `""` | Kubernetes Secret name for auto CA. |
| `ca_bootstrap` | bool | `false` | This pod creates the CA Secret. |
| `allow_auto_ca_multi_node` | bool | `false` | F14 policy toggle. |
| `client_auth` | bool | `true` | Require and verify client certs. |
| `secret_poll_timeout` | duration | `120s` | Follower Secret poll budget. |
| `reload_poll_interval` | duration | `5s` | Manual file watcher poll interval. |
| `keyring_rotation_enabled` | bool | `true` | Enable in-band phased rotation. |
| `rotation_period` | duration | `24h` | Time between rotations. |
| `rotation_check_interval` | duration | `30s` | Rotator tick. |
| `extra_sans` | list | `[]` | Extra DNS SANs for node leaves. |

Manual `ca_cert`, `cert`, and `key` must be set together. Multi-node without
manual certs requires `allow_auto_ca_multi_node=true`, a Kubernetes client,
and `ca_secret`.

## `storage`

| Key | Type | Default | Notes |
|---|---|---|---|
| `backend` | string | `raft-boltdb` | `raft-boltdb`, `shared-bolt`, or `inmem`. |
| `bolt_timeout` | duration | `1s` | bbolt open timeout. |
| `no_freelist_sync` | bool | `true` | bbolt freelist tuning. |
| `initial_mmap_size` | int | `104857600` | 100 MiB virtual mmap. |
| `at_rest_key_file` | string | `""` | AES-GCM key file for `Sealer`. |

## `autopilot`

| Key | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `true` | Enable autopilot. |
| `cleanup_dead_servers` | bool | `true` | Remove dead servers. |
| `dead_server_last_contact_threshold` | duration | `24h` | Dead threshold. |
| `min_quorum` | int | `2` | Never drop below this voter count. |
| `stabilization_time` | duration | `10s` | Wait between membership changes. |
| `heartbeat_interval` | duration | `1s` | Follower tracking tick. |

## `join`

| Key | Type | Default | Notes |
|---|---|---|---|
| `interval` | duration | `5s` | Leader reconcile tick. |
| `reconcile_timeout` | duration | `10s` | Membership operation timeout. |
| `retry_interval` | duration | `2s` | Retry interval. |
| `max_concurrent` | int | `20` | Max concurrent joins. |
| `check_peer_resolvable` | bool | `true` | Skip unresolvable peers (CWE-693). |
