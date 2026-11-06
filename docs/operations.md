# Operations

## Scaling up

Increase `spec.replicas` and the configured `discovery.replicas`. The leader's
join loop resolves the new peers and adds them. New pods start with no Raft
state and receive a snapshot/log replay from the leader.

## Scaling down

Decrease `spec.replicas` and `discovery.replicas`. The leader removes peers
that are no longer in the desired list. For a graceful pod shutdown, call
`Node.LeaveCluster` before the process exits.

## Single-node recovery

When a cluster loses quorum but the StatefulSet is scaled to one replica:

1. Set `single_node_recovery=true`.
2. Provide a `ReplicaCountAuthorizer` (for example
   `k8s.NewStatefulSetReplicaReader`). Recovery is authorized only when
   `spec.replicas == 1`.
3. On startup the node calls `raft.RecoverCluster` with a single-voter
   configuration, preserving the FSM state.

## Manual quorum recovery

If the configuration is lost entirely, set `recovery_mode=true` on the
bootstrap node. This wipes `raft.db`/`<nodeID>.db`, snapshots, and
`peers.json`, then bootstraps a fresh single-voter cluster. Other nodes must
be wiped and rejoined.

## Generation fencing

`k8s.GenerationStore` stores a cluster generation in the CA Secret. On
recovery the bootstrap node bumps it. Returning pods compare the cluster
generation with `<dir>/generation`; if the cluster is newer, they wipe stale
local state and rejoin as empty followers.

## At-rest key rotation

`storage.AESGCMKeeper` supports multiple key IDs. To rotate:

1. Add a new key to the key file and make it `primary`.
2. Keep the old key in `keys` so existing ciphertext still opens.
3. Restart or reload the keeper.
4. Re-seal values lazily; `OpenString` already accepts legacy plaintext.

## Monitoring

Key metrics:

- `raft_state`, `raft_term`, `raft_commit_index`, `raft_applied_index`
- `raft_fsm_pending`, `raft_num_peers`
- `raft_follower_heartbeat_age_ms`, `raft_applied_index_delta`
- `raft_tls_keyring_term`, `raft_tls_keyring_active_key_age_seconds`
- `raft_tls_keyring_rotations_total{status}`
- `raft_dead_servers_detected_total`, `raft_dial_retries_total`

Alert on:

- no leader for more than 2× election timeout
- `raft_fsm_pending > 0` for more than 1 minute
- keyring term stuck at 2 with a growing active-key age
- follower heartbeat age above the dead-server threshold
