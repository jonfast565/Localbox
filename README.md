# Localbox

Localbox is a peer-to-peer file replication engine for small networks. Each node watches local “shares”, discovers peers via UDP, and exchanges encrypted batches of changes over TCP. Batches now carry file metadata **and** the full file contents; receivers reconstruct remote copies using atomic, fsynced writes under a configurable `remote_share_root`.

## Highlights

- **End-to-end security:** TLS 1.3 + mutual authentication by default, optional plaintext fallback, signed bootstrap invites, fingerprint pinning, and on-disk TLS material rotation with live reloads.
- **Real file replication:** Create/modify/delete events stream file bytes in 128 KiB chunks with hash verification, atomic writes, and fsyncs before rename to remote share paths.
- **Autonomous discovery:** Nodes broadcast discovery packets, auto-provision remote share directories, and backfill historical change logs when peers connect.
- **Operational tooling:** `localbox init`, `validate`, `bootstrap invite/accept/join`, TLS bundle helpers, and `localbox monitor` for queue-depth/peer-health alerts.
- **Observability-first:** Structured logging to console + file, queue/backoff metrics, and per-peer progress tracking in SQLite.

## Requirements

- Rust stable (Edition 2021).
- UDP broadcast reachability on the discovery port (default `5001`) plus TCP access to the peer listen ports (default TLS `5000`, plaintext `5002`).
- Ability to create TLS materials under `certs/` (or custom paths) and persist a SQLite database file.

## Getting Started

1. **Build the workspace:**
   ```bash
   cargo build
   ```

2. **Generate a starter config:**
   ```bash
   cargo run -p localbox-core -- init --force
   # edit config.toml to add your shares, ports, TLS paths, etc.
   ```

3. **Ensure TLS materials exist (per node):**
   ```bash
   cargo run -p localbox-core -- tls ensure
   cargo run -p localbox-core -- tls fingerprint    # inspect fingerprints for pinning
   ```

4. **Bootstrap peers with signed invites (optional but recommended):**
   ```bash
   # On node A
   cargo run -p localbox-core -- bootstrap invite --peer workstation-b --out invites/workstation-b.json

   # On node B
   cargo run -p localbox-core -- bootstrap join \
     --incoming invites/workstation-b.json \
     --peer workstation-a \
     --out invites/workstation-a.json
   ```
   Copy the response invite back to node A to finish the round trip, ensuring both sides import each other’s CA and fingerprint data.

5. **Run two nodes (example on one host):**
   ```bash
   # Terminal 1
   cargo run -p localbox-core -- run \
     --instance-id node-a \
     --listen-port 5000 \
     --plain-listen-port 5002 \
     --discovery-port 5001 \
     --remote-share-root remote-a \
     --db-path node-a.db \
     --log-path node-a.log \
     --share docs=/tmp/docs-a,recursive=true

   # Terminal 2
   cargo run -p localbox-core -- run \
     --instance-id node-b \
     --listen-port 6000 \
     --plain-listen-port 6002 \
     --discovery-port 6001 \
     --remote-share-root remote-b \
     --db-path node-b.db \
     --log-path node-b.log \
     --share docs=/tmp/docs-b,recursive=true
   ```

6. **Monitor / inspect:**
   ```bash
   cargo run -p localbox-core -- monitor --queue-threshold 50 --stale-peer-seconds 120
   cargo run -p localbox-core -- status --json
   ```

## Sync & Peering Semantics

- **Ownership:** A share is owned by the node that watches it. Peers replicate it read-only under `<remote_share_root>/<peer_pc>/<peer_instance>/<share_name>`.
- **Batching:** Filesystem events become `FileChange`s and are aggregated (default 2 s window) before enqueueing to the outbound queue. Each batch receives a UUID and per-change sequence numbers.
- **File transfer:** For each create/modify, the sender reads the current file, hashes it, and streams bytes in 128 KiB chunks immediately after the metadata batch. Receivers stage bytes per file, enforce chunk ordering, fsync to a temp file, then rename atomically.
- **Deletes:** Deletions drop pending buffers, remove any on-disk file (best effort), and persist a tombstone.
- **Durability:** All metadata lives in SQLite (`sync.db`). Remote writes use atomic rename + directory fsync to avoid torn files.
- **Discovery:** Nodes broadcast `DISCOVER` and respond with `HERE` messages, forming outbound connections based on TLS preference. Plaintext is supported for legacy testing but flagged and recorded in the DB.

## Application States

Set `app_state` in `config.toml` (or `--app-state` on the CLI) to control what a node is allowed to do:

- `mirror_only` – Hosts remote shares only. No local shares are advertised or watched, so the node only mirrors peers.
- `host_only` – Watches and shares local folders with others but refuses to host remote shares.
- `mirrorhost` – Default dual-role behavior: watch local shares *and* host remote shares.
- `zombie` – Neither shares nor hosts. Useful for plumbing/tests when you just need the process up but idle.

Nodes advertise their capability to peers so that hosts don't waste time pushing shares to mirror-disabled or zombie nodes.

## Monitoring & Operations

- `localbox monitor` surfaces queue depth, number of dequeuable batches, and peer staleness. It can emit JSON or exit on alert.
- `localbox status` prints DB snapshots (peers, shares, progress) to quickly debug backpressure.
- Logs go to stdout and `--log-path` with non-blocking writers. Use `RUST_LOG=debug` for verbose tracing.
- TLS materials reload automatically when cert/key/CA files change.

## Security & Performance Review

- **Transport security:** TLS 1.3 with client cert auth is on by default. Fingerprint pinning (`tls_peer_fingerprints`) stops MITM even if a trusted CA is compromised. Plaintext mode still exists but is opt-in and stamped in the DB (`last_insecure_seen`).
- **Bootstrap integrity:** Signed invite bundles carry CA + leaf fingerprints. Accepting an invite both verifies the signature and updates `config.toml`, reducing manual trust-store mistakes.
- **Disk safety:** All remote writes go through temp files + fsync + atomic rename. Deletes clear staged buffers to prevent resurrecting stale data.
- **Chunking backpressure:** File data currently buffers in memory until EOF for each file. For very large files consider lowering `max_file_size_bytes` per share or extending the engine with streaming-to-disk staging.
- **DoS considerations:** Discovery listens on UDP broadcast; untrusted networks could spam HELLO/Batch traffic. Restrict the discovery subnet and use firewall rules when running outside a trusted LAN.
- **Performance knobs:** Watcher aggregation can be tuned via `--aggregation-window-ms`. Batch senders have exponential backoff capped at 5 min. Keep an eye on `localbox monitor` for queue explosions.

## Repository Layout

- `core/` – `localbox-core` package (CLI + engine, binary `localbox`).
- `db/` – `localbox-db` (SQLite access layer and persistence helpers).
- `models/` – `localbox-models` (config/wire/change-log structs).
- `peering/` – `localbox-peering` (discovery, TLS/plain connections, batching, chunk streaming).
- `protocol/` – `localbox-protocol` (Protobuf schema + framing helpers).
- `tls/` – `localbox-tls` (runtime TLS, invite workflow, trust-store utilities).
- `utilities/` – `localbox-utilities` (filesystem/network abstractions, hashing, logging).

## Development & Testing

- Run targeted tests while iterating to avoid long workspace builds:
  ```bash
  cargo test -p protocol
  cargo test -p peering
  ```
- For a full validation, run `cargo test` from the workspace root (on slower hardware this may exceed CI/CLI timeouts—rerun locally if needed).
- `cargo fmt` and `cargo clippy --workspace --all-targets` keep the style and lints consistent.

## License

MIT. See [`LICENSE`](LICENSE) for full text.
