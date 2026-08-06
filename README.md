# Localbox

Localbox is a peer-to-peer file replication engine for small networks (and optional WAN meshes). Each node is both a client and a server: it discovers peers via LAN UDP broadcast and/or a private BEP5 DHT (irontide), dials over TCP/TLS or TLS-over-uTP, and exchanges encrypted batches of file metadata and contents. Transfers are **manual by default**; opt into auto sync and/or auto pull per share (or per peer). Peers can also chat (DM or share-scoped threads) with a persistent inbox.

## Highlights

- **End-to-end security:** TLS 1.3 + mutual authentication by default, certificates bound to peer identity, optional plaintext fallback, fingerprint pinning, and on-disk TLS material rotation with live reloads.
- **Two ways to establish trust:** a shared network CA with token-based enrollment (`localbox ca` / `localbox enroll`) so a new machine joins by pasting one string, or the original per-node signed bootstrap invites.
- **On-demand transfers:** `push` / `pull` / `request` / `reply` over the wire (`TransferRequest` / `TransferReply`) plus optional `sync=auto` / `pull=auto` policies. Every outbound transfer is a `TransferIntent` (Snapshot from the file index, or SyncCatchup from the share journal).
- **Interactive shell:** `localbox run --interactive` (ephemeral engine + REPL) or `localbox shell` attached to a running daemon’s control plane (Unix socket or Windows named pipe). Use `intents` / `intent show` to inspect the outbox.
- **Chat + inbox:** Peer DMs and share-scoped threads, with dead CLI (`localbox chat …`) or live REPL; optional file attachments trigger a push into a share.
- **Desktop GUI:** `localbox-gui` (iced) talks to the same control socket for status, transfers, and chat.
- **Operational tooling:** `localbox init`, `validate`, `bootstrap invite/accept/join`, TLS helpers, and `localbox monitor` for queue-depth/peer-health alerts.
- **WAN peering:** private BEP5 DHT + uTP (via [irontide](https://crates.io/crates/irontide-dht)) with `[[bootstrap_peers]]` — no public Mainline routers. Session trust remains mTLS enrollment.

## Requirements

- Rust stable (Edition 2021).
- UDP broadcast reachability on the discovery port (default `5001`) plus TCP access to the peer listen ports (default TLS `5000`, plaintext `5002`).
- For WAN: UDP reachability for DHT (`dht_port`, default `5003`) and uTP (`utp_port`, default `5004`) to at least one bootstrap peer; do not list public BitTorrent DHT routers.
- Ability to create TLS materials under `certs/` (or custom paths) and persist a SQLite database file.

## Getting Started

1. **Build the workspace:**
   ```bash
   cargo build
   ```

2. **Generate a starter config:**
   ```bash
   cargo run -p localbox-core -- init --force
   # edit config.toml for ports/TLS (shares are optional at startup; add later via CLI/REPL/GUI)
   ```

3. **Set up trust.** Pick one of the two models below — the shared network CA is
   the recommended one for anything past a couple of machines.

4. **Bootstrap peers with signed invites (the original, per-node-CA model):**
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

6. **Run daemon (control socket on by default) or ephemeral interactive host:**
   ```bash
   # Daemon
   cargo run -p localbox-core -- run --instance-id node-a ... --share docs=/tmp/docs-a

   # Attach shell in another terminal
   cargo run -p localbox-core -- shell --socket localbox.sock

   # Or one-process ephemeral host + REPL
   cargo run -p localbox-core -- run --interactive --instance-id node-a ... --share docs=/tmp/docs-a
   ```

7. **Add shares dynamically** (daemon running; also via REPL `share add` or the GUI Status tab). The DB is the live share registry; `config.toml` is updated for restarts:
   ```bash
   cargo run -p localbox-core -- share add --name docs --path /tmp/docs
   cargo run -p localbox-core -- share list
   ```

8. **Manual transfers / chat (daemon must be running, or use the REPL):**
   ```bash
   cargo run -p localbox-core -- push --share docs --peer workstation-b
   cargo run -p localbox-core -- pull --share docs --peer workstation-b
   cargo run -p localbox-core -- reply --id <request-id> accept
   cargo run -p localbox-core -- chat send --peer workstation-b --message "ready when you are"
   cargo run -p localbox-core -- chat inbox
   ```

9. **Monitor / inspect:**
   ```bash
   cargo run -p localbox-core -- monitor --queue-threshold 50 --stale-peer-seconds 120
   cargo run -p localbox-core -- status --json
   ```

## Trust Models

### Shared network CA (recommended)

With signed invites, trust is O(n²): every pair of nodes exchanges bundles and
pins each other, so adding the sixth machine to a five-node network means five
round trips and edits on every existing node. The alternative is one root CA for
the whole network. Every node trusts that root, and each node holds one
certificate signed by it — so adding a machine costs one signature and changes no
other node's config.

Create the root once, on whichever machine will issue certificates:

```bash
localbox ca init --dir ca --name my-network-ca
# prints the root fingerprint; pin it on every node
```

The root's **private key** only ever needs to exist on that machine. Its
certificate is public — distribute it freely.

**Enrolling a machine (nothing to copy but one string).** On the CA machine:

```bash
localbox ca serve --dir ca --listen 0.0.0.0:5010     # leave running
localbox ca token --name workstation-b --ttl-secs 600
```

`ca token` prints a single-use, time-limited token. Paste it on the new machine:

```bash
localbox enroll --server ca-host:5010 --token lbx1.… --pin
```

That machine generates its own key locally (never transmitted), proves it holds
the token, receives a certificate issued for its own hostname, and pins the root.
The token name must match the target machine's hostname — peers identify each
other by hostname, and `enroll` refuses a mismatch rather than installing a
certificate that would be rejected later.

**Offline signing.** If the CA machine is not reachable, skip the server:

```bash
# on the new machine
localbox ca request --name workstation-b --csr-out b.csr.pem --key-out b.key.pem
# move only the CSR to the CA machine
localbox ca sign --dir ca --csr b.csr.pem --name workstation-b --out b.chain.pem
# back on the new machine
localbox ca install --chain b.chain.pem --key b.key.pem --pin
```

The CA always issues for the name **it** was told, ignoring whatever the CSR asks
for, so a request cannot choose its own identity.

**Operational notes.** There is no CRL. Prefer short leaf lifetimes (default
`365d`, `--lifetime` to change; accepts `d`/`h`/`m`/`s`, e.g. `24h` or `30m`)
and re-enroll, and use `localbox peer quarantine` to block a hostname
immediately without waiting for expiry. Compromise of the root key compromises
the network, so keep it on one administrative machine rather than on every node.

### Peer identity

A peer's certificate must be issued for the name that peer claims in its
handshake. Trusting a CA only establishes that a peer belongs to the network, not
*which* member it is; without this binding, any node holding a valid certificate
could announce itself under another node's `pc_name` and receive that node's
shares. This is enforced on connections in both directions.

Per-peer pinning (`tls_peer_fingerprints`) remains available and is now optional
belt-and-braces rather than the primary mechanism. Pinning the root
(`tls_pinned_ca_fingerprints`, set for you by `--pin`) is the recommended posture:
it means a certificate that merely lands in the trust store cannot quietly become
an accepted issuer.

### Insecure: one certificate shared by every node

If you would rather not hold a certificate per machine, a whole network can share
a single one:

```bash
localbox ca provision-shared --dir ca --out-dir shared
# copy the bundle to each node, then on each:
localbox ca install --chain shared.chain.pem --key shared.key.pem --pin
# and in config.toml:
tls_insecure_shared_cert = true
```

This is genuinely less secure, and the flag is named accordingly. Traffic is
still encrypted and an untrusted CA is still refused, but peers can no longer tell
each other apart, and anyone who obtains the bundle can act as any node. Nodes
must opt in explicitly — without the flag they reject each other, because the
shared certificate names nobody in particular. Connections accepted this way are
stamped insecure in the DB (`last_insecure_seen`), the same way plaintext ones
are, and are visible in `localbox status`.

## Sync & Peering Semantics

- **Ownership:** A share is owned by the node that watches it. Peers replicate it under `<remote_share_root>/<peer_pc>/<peer_instance>/<share_name>` when transfers run.
- **Share journal vs outbox:** Local FS events update the file index (`files`) and append to the **share journal** (`share_journal` — local history only). Outbound work is always a **TransferIntent** that materializes into `outbound_queue`. Continuous sync uses `SyncCatchup` from journal ranges; manual push/chat/reply use `SnapshotPush` / `PullFulfill` **Snapshot** intents from the index. `peer_progress` advances **only** for `SyncCatchup`.
- **Manual by default:** Journal writes always happen, but SyncCatchup intents are created only when `sync = "auto"` (or a matching `[[peer_policies]]`). Discovery bootstrap/catch-up is similarly gated. Set `pull = "auto"` to send `TransferRequest`s on connect. `sync` gates *journal sync only* — `localbox push` works on demand regardless. (`push` is accepted as a deprecated alias for `sync`.)
- **Intent completion:** `Acked` means the peer confirmed via `BatchAck` and is reached only by `SyncCatchup`. Everything else — `SnapshotPush`, `PullFulfill`, an accepted `PullRequest` — terminates as `Sent`, meaning the batches reached the transport with no confirmation expected. Both are terminal, so `is_active()` alone decides what still counts as in-flight work.
- **Request/reply:** `pull`/`request` sends `TransferRequest`; the peer auto-fulfills only when `request_handling = "auto"`, otherwise pending until `reply accept|decline`. Fulfillment is a `PullFulfill` intent.
- **Conflict policy:** Per share (overridable per `[[peer_policies]]`) via `conflict = "last_write_wins" | "keep_both" | "owner_wins"` (default `last_write_wins`). LWW uses version then mtime/hash (including deletes). `keep_both` writes conflicting inbound bytes beside the original as `{stem} (conflict from {peer}){ext}`. `owner_wins` rejects inbound overwrites on shares this node owns and always applies when mirroring.
- **Selective sync:** Optional `sync_allow` glob allowlist plus `ignore_patterns` (deny). Applied on local watch and inbound apply; peer policies may override both.
- **Per-peer ACLs:** `allow_push` / `allow_pull` / `allow_request` on `[[peer_policies]]` (default true). False is a hard deny for auto and manual paths.
- **Batching / framing (wire v4):** Materialized intents become `BatchManifest` batches; `FileChunk` carries `batch_id` + `protocol_version`; `BatchAck` may include `batch_id` so the sender resolves the DB-local intent. Intent ids never go on the wire. Chunk payloads stream from disk on send and stage to a temp file on receive (hash-verified, then atomic rename).
- **Seq namespaces:** Every `share_journal.seq` is allocated **locally**; a peer's position is kept separately as `origin_peer_id`/`origin_seq`, with a partial unique index over the pair acting as the replay gate. `BatchManifest.basis` (`journal` / `snapshot`) tells the receiver whether `FileChange.seq` holds real positions, and `journal_from_seq`/`journal_to_seq` declare the range so a filtered-out change cannot pin the watermark. `BatchAck.upto_seq` is always in the **sender's** namespace, and 0 for a snapshot batch. Outbound watermarks (`last_seq_sent`/`last_seq_acked`, our journal) are separate from the inbound one (`last_seq_recv`, theirs) — `TransferRequest.since_seq` comes from the latter.
- **Chat:** Peer DM thread ids are deterministic (`min(local,remote)`); share threads key off share name. Messages persist in SQLite (`chat_threads` / `chat_messages`).
- **Discovery:** Nodes broadcast `DISCOVER` and respond with `HERE`. Protocol version is 4; there is no version negotiation, so all peers must be upgraded together.
- **Control plane:** Daemon listens on `control_socket` for newline-delimited JSON (`shell`, dead CLI, `localbox-gui`). Default `localbox.sock` on Unix, `\\.\pipe\localbox` on Windows. List intents with `intents` / `intent show --id …`. Transfer byte progress is exposed via `transfer_progress` (and enriched on `intents` / `intent_show`).

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
- `localbox peer list|quarantine|unquarantine` marks a hostname untrusted immediately (config + DB); connections to/from quarantined peers are refused.
- Logs go to stdout and `--log-path` with non-blocking writers. Use `RUST_LOG=debug` for verbose tracing.
- TLS materials reload automatically when cert/key/CA files change.

## Security & Performance Review

- **Transport security:** TLS 1.3 with client cert auth is on by default. Fingerprint pinning (`tls_peer_fingerprints`) stops MITM even if a trusted CA is compromised. Plaintext mode still exists but is opt-in and stamped in the DB (`last_insecure_seen`).
- **Peer identity:** A peer's certificate must be issued for the `pc_name` it claims, checked on both inbound and outbound connections. CA trust alone would only prove network membership, not which member. Relaxed only by the explicit `tls_insecure_shared_cert` opt-in, which stamps such peers insecure.
- **Bootstrap integrity:** Signed invite bundles carry CA + leaf fingerprints. Accepting an invite both verifies the signature and updates `config.toml`, reducing manual trust-store mistakes.
- **Enrollment:** Tokens are single-use and time-limited, and are proven by an HMAC over the CSR rather than sent in the clear, so an observer cannot reuse one. The CA issues for the name the token authorizes, never the name the CSR requests. The enrolling node installs the result only if the root matches the fingerprint carried in its token, so an interceptor cannot substitute its own CA. Private keys are generated locally and written owner-only.
- **Disk safety:** Inbound file payloads stream into a staging temp file, are hash-checked, then atomically renamed into place (fsync where the real filesystem supports it). Deletes clear pending staging. Failed hash checks discard staging and never leave a partial final file.
- **Quarantine (no CRL yet):** Leaf expiry remains the long-term decommission path. For immediate removal use `localbox peer quarantine <name>` (also `quarantined_peers` in config.toml); the node refuses dial/accept for that peer until unquarantined.
- **DoS considerations:** Discovery listens on UDP broadcast; untrusted networks could spam HELLO/Batch traffic. Restrict the discovery subnet and use firewall rules when running outside a trusted LAN.
- **Performance knobs:** Watcher aggregation can be tuned via `--aggregation-window-ms`. Batch senders have exponential backoff capped at 5 min. Keep an eye on `localbox monitor` for queue explosions.

## GUI

The `localbox-gui` crate is an iced desktop UI for the same control-plane IPC as the CLI. On launch it **attaches** if a daemon is already listening on the control socket; otherwise it **spawns** `localbox-core run` as a child and stops that child when the GUI exits (an already-running daemon is left alone).

```bash
# Attach or spawn (default socket: localbox.sock / \\.\pipe\localbox)
cargo run -p localbox-gui

# Use a config.toml (passed to a spawned runtime; also sets control_socket if --socket is default)
cargo run -p localbox-gui -- --config config.toml

# Client-only: never spawn
cargo run -p localbox-gui -- --no-runtime --socket localbox.sock
```

Binary resolution for a spawned runtime: `--core PATH`, then `$LOCALBOX_CORE`, then a `localbox-core` sibling of the GUI binary, then `PATH`. The Transfers tab lists pending requests and active TransferIntents with byte/batch progress bars. The Status tab shows quarantined peers (manage quarantine via CLI/control plane).

## Repository Layout

- `core/` – `localbox-core` package (CLI + engine, binary `localbox`).
- `db/` – `localbox-db` (SQLite access layer and persistence helpers).
- `models/` – `localbox-models` (config/wire/JournalEntry/TransferIntent structs).
- `peering/` – `localbox-peering` (discovery, TLS/plain connections, batching, chunk streaming).
- `protocol/` – `localbox-protocol` (Protobuf schema + framing helpers).
- `tls/` – `localbox-tls` (runtime TLS, invite workflow, trust-store utilities).
- `utilities/` – `localbox-utilities` (filesystem/network abstractions, hashing, logging).
- `gui/` – `localbox-gui` (iced desktop control-plane UI).

## Development & Testing

- Run targeted tests while iterating to avoid long workspace builds:
  ```bash
  cargo test -p protocol
  cargo test -p peering
  ```
- For a full validation, run `cargo test` from the workspace root (on slower hardware this may exceed CI/CLI timeouts—rerun locally if needed).
- `cargo fmt` and `cargo clippy --workspace --all-targets` keep the style and lints consistent.

## WAN / private DHT

Same-LAN peers keep using UDP `DISCOVER`/`HERE` and TCP/TLS. For one peer on the LAN and one off-LAN, configure a **private** BEP5 mesh (irontide) that only uses your bootstrap nodes:

```toml
enable_dht = true
dht_port = 5003
utp_port = 5004

[[bootstrap_peers]]
addr = "bootstrap.example.com:5003"          # DHT UDP
session_addr = "bootstrap.example.com:5000"  # optional TCP/TLS dial hint
pc_name = "home-server"
```

At least one node (or a tiny third host) must be UDP-reachable for DHT bootstrap. Peers announce under an infohash derived from `pc_name`, publish a BEP44 endpoint record (TLS/plain/uTP ports + reflexive candidates when known), and dial with TCP on LAN or TLS-over-uTP on WAN. Enrollment / mTLS still gates trust — DHT visibility alone is not enough.

## License

GPL-3.0-or-later (required for the irontide BEP5/uTP stack). See [`LICENSE`](LICENSE) for full text.
