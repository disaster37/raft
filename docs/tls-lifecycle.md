# TLS lifecycle

## PKI modes

### `shared-ca` (default)

A `goca` root CA signs per-node leaf certificates. The keyring stores the CA
certificate and (sealed) CA private key. Each node mints or reuses its own
leaf under the active CA and trusts every CA currently in the keyring.

### `self-signed` (Vault-compatible)

Each keyring key is a self-signed `goca` CA/leaf hybrid certificate with the
cluster SANs. All nodes use the same active key for dialing and accept every
key in the keyring.

## Bootstrap before Raft

1. **Manual files**: `FileBootstrapProvider` loads `ca.crt`, `node.crt`, and
   `node.key`. A `FileWatcher` hot-reloads replacements.
2. **Kubernetes Secret**: ordinal 0 creates the Secret with `ca.crt`/`ca.key`;
   followers poll until it appears. An existing empty Secret is overwritten.
3. **Local CA**: single-node deployments generate `<dir>/tls/ca.crt` and
   `ca.key` (`0600`).

The transport starts in dual-trust mode: `RootCAs` and `ClientCAs` are the
union of the bootstrap CA and the keyring CAs. The bootstrap CA is dropped
after the first full in-band rotation (Term 3).

## Phased rotation

1. **Stage (Phase 1)**: the leader generates a new key, appends it
   (`len(Keys)==2`), increments `Term`, and applies the keyring. All nodes
   trust both keys but keep dialing with `ActiveKeyID`.
2. **Commit index**: the leader writes the staged keyring's `AppliedIndex`.
3. **Wait**: `CheckCommitted` waits until
   `MinFollowerAppliedIndex >= keyring.AppliedIndex`.
4. **Activate (Phase 2)**: the leader promotes the new key, prunes the old
   one, increments `Term`, and applies. `DynamicTLSProvider` swaps the active
   leaf and closes idle pooled connections.

### Failure handling

- **Crash between Phase 1 writes**: the next tick sees
  `len(Keys)==2 && Keys[1].AppliedIndex==0` and completes the index write.
- **Lagging/offline follower**: activation blocks while
  `MinFollowerAppliedIndex` is below the staged index. The keyring is capped
  at two keys so the offline follower still trusts the old key on reconnect.
- **Leader change**: the new leader reads the keyring from the FSM and
  resumes Phase 1 or Phase 2.

## Hot reload

`DynamicTLSProvider` stores immutable state behind `atomic.Pointer`:

- `GetCertificate` returns the active leaf (or an SNI match).
- `GetClientCertificate` returns the active leaf (or an acceptable-CA match).
- `GetConfigForClient` returns a per-connection server config with the
  current `ClientCAs`, so CA rotations apply to new handshakes.
- `DialTLSConfig(serverName)` builds a fresh client config with the current
  `RootCAs` on every dial.

## Runbooks

### Emergency manual rotation

1. Generate a new CA and leaves with `goca`.
2. Write the new files atomically.
3. The `FileWatcher` reloads them within `reload_poll_interval`.
4. Verify `/readyz` and peer connectivity before removing the old CA.

### Recover a stuck rotation

1. Check `raft_tls_keyring_term` and `raft_tls_keyring_active_key_age_seconds`.
2. Inspect follower applied indexes via autopilot metrics.
3. If a follower is permanently gone, let autopilot remove it after
   `dead_server_last_contact_threshold`; activation then proceeds.
