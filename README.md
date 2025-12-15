# Localbox

Localbox is an experimental peer-to-peer file sharing/sync engine for a local network. Each node:

- Watches one or more local "shares" for filesystem changes
- Discovers peers over UDP broadcast
- Exchanges change batches over TCP using mutual TLS (mTLS)
- Persists state (shares, peers, change log, progress) in a local SQLite database
- Materializes remote peers' shares under a configurable `remote_share_root`

This repo is a Rust workspace; the main binary is `localbox` (in `core/`).

## Status

Prototype / work in progress. Expect breaking changes and rough edges.

## Requirements

- Rust stable (edition 2021)
- Network connectivity between peers:
  - UDP broadcast on the discovery port (default `5001`)
  - TCP on the listen port (default `5000`)
  - Allow through OS/firewall rules as needed

## Quickstart

### Build

```bash
cargo build
```

### Run a node

You must configure at least one share, either via `--share` flags or a `config.toml`.

```bash
cargo run -p localbox -- \
  --instance-id node-a \
  --share docs=C:/path/to/docs,recursive=true
```

### Run two nodes on the same machine (example)

When running multiple instances on one host, use different ports, DB paths, and output folders.

Node A:

```bash
cargo run -p localbox -- \
  --instance-id node-a \
  --listen-port 5000 \
  --discovery-port 5001 \
  --db-path node-a.db \
  --log-path node-a.log \
  --remote-share-root remote-a \
  --share docs=C:/tmp/docs,recursive=true
```

Node B:

```bash
cargo run -p localbox -- \
  --instance-id node-b \
  --listen-port 6000 \
  --discovery-port 6001 \
  --db-path node-b.db \
  --log-path node-b.log \
  --remote-share-root remote-b \
  --share docs=C:/tmp/docs-b,recursive=true
```

## Configuration (CLI)

Run `cargo run -p localbox -- --help` for the full list. Common flags:

- `--instance-id`: stable identifier for the node instance
- `--listen-port`: TCP port for peer connections
- `--discovery-port`: UDP broadcast port for peer discovery
- `--aggregation-window-ms`: time window for batching file changes
- `--db-path`: SQLite DB file (state + change log)
- `--log-path`: log output file (also logs to console)
- `--remote-share-root`: base directory for remote peer shares
- `--share NAME=PATH[,recursive=true|false]`: add a watched share (repeatable)
- `--config PATH`: load settings from a TOML config file (defaults to `./config.toml` if it exists)

## Configuration (config.toml)

Generate a template:

```bash
cargo run -p localbox -- init
```

Validate your config (and any CLI overrides):

```bash
cargo run -p localbox -- validate
```

Logging level is controlled via `RUST_LOG` (defaults to `info`), for example:

```bash
# bash/zsh
export RUST_LOG=debug

# PowerShell
$env:RUST_LOG="debug"
```

## Remote share layout

Remote shares are created under:

`<remote_share_root>/<peer_pc_name>/<peer_instance_id>/<share_name>`

Where `<share_name>` is sanitized into a safe relative path (see `utilities::disk_utilities::relative_share_path`).

## Sync semantics (current guarantees)

Localbox currently replicates *change logs and file metadata*, not file contents. Concretely:

- **Ownership / direction:** a share is owned by the node that watches it. Other nodes register it as a *remote share* and do not watch or mutate it. This is effectively **one-way replication per share** (owner → peers).
- **What propagates:** create/modify/delete events for file paths with metadata (`size`, `mtime`, `hash`). Remote nodes persist these events and metadata in `sync.db` and create the remote-share directory layout, but **do not download/write file bytes yet**.
- **Delivery model:** changes are sent in batches and may be delivered more than once. Batches are deduplicated by `batch_id`. Per-share ordering is tracked by a monotonically increasing `seq` assigned by the share owner.
- **Conflict resolution:** if multiple non-delete updates for the same path arrive, Localbox prefers higher `version`, then higher `mtime`, and finally applies when hashes differ (ties). (`version` is currently always `1` for filesystem events.)
- **Deletions:** deletes are treated as tombstones. A delete only “wins” if it is not a replay (i.e., it has a `seq` newer than what the receiver has already processed for that share).
- **Renames:** renames are represented as **two events**: `Delete(old_path)` + `Modify(new_path)`. This is not atomic and may be observed as two independent operations.

## TLS notes

Localbox uses TLS 1.3 with mutual authentication and expects three PEM files:

- `--tls-cert-path` (leaf certificate)
- `--tls-key-path` (PKCS#8 private key)
- `--tls-ca-cert-path` (CA bundle used to authenticate peers)

If these files are missing or invalid, Localbox generates a new local CA + leaf cert and attempts to write them to the configured paths. The running daemon automatically reloads TLS materials when any of the files change, so you can rotate certificates without restarting.

For multiple machines to connect, each node must trust the other nodes' CA certificates (for example, by distributing CA certs and concatenating them into the `--tls-ca-cert-path` bundle on every node).

### Trust store workflow (two machines)

On **each** machine, decide where you keep `config.toml` and set the TLS paths (defaults are under `certs/`).

1. Generate or ensure TLS materials exist:
   - `localbox tls ensure`
2. Export the local CA certificate from machine A:
   - `localbox tls export-ca --out pc-a.ca.pem`
3. Copy `pc-a.ca.pem` to machine B via a secure channel (USB, SCP, etc).
4. Import it into machine B's trust store:
   - `localbox tls import-ca --in pc-a.ca.pem`
5. Repeat in the other direction (export from B, import into A).
6. Verify what each machine trusts:
   - `localbox tls list`
   - Optional: `localbox tls fingerprint --file pc-a.ca.pem`

### Rotation (recommended overlap)

Rotate on a machine (new CA + new leaf cert):

- `localbox tls rotate --backup --export-ca pc-a.ca.new.pem`

Then distribute/import `pc-a.ca.new.pem` to all peers **before** expecting them to trust the rotated machine. Keep the old CA in peers' trust stores until you're confident no one still uses it.

### Provisioning bundles

To provision a new peer (or refresh secrets) and share fingerprints/config snippets with others, run:

```
localbox tls provision --out ./tls-bundle
```

This copies the current leaf cert, key, CA bundle, fingerprints, and a `[tls_peer_fingerprints]` snippet into the provided directory. Distribute the CA bundle + snippet to other peers so they can trust and pin this node.

### Signed bootstrap invites

To make onboarding safer and less error-prone, you can generate a signed invite bundle on the source machine:

```
localbox bootstrap invite --peer workstation-b --out invites/workstation-b.json
```

Transfer the JSON bundle via a trusted channel. On the receiving machine run:

```
localbox bootstrap accept --file invites/workstation-b.json
```

This verifies the signature, imports the CA certs, and appends the peer's fingerprint to `tls_peer_fingerprints` inside your `config.toml` (respecting `--config` if provided).

### Optional pinning

There are two levels of pinning:

- Restrict trust to a specific set of CA fingerprints with `tls_pinned_ca_fingerprints` (SHA-256 hex; spaces/colons ignored).
- Pin individual peer leaf certificates via `tls_peer_fingerprints`:

```toml
[tls_peer_fingerprints]
"workstation-1" = [
  "AA:BB:CC:...",
]
```

Connection attempts fail if the presented certificate fingerprint is not in the configured list for that peer.

## Monitoring & alerting

Use the built-in monitor to keep an eye on queue depth and peer freshness:

```
localbox monitor --queue-threshold 50 --stale-peer-seconds 120 --exit-on-alert
```

It polls the database, prints human-readable or JSON snapshots (`--json`), and emits alerts (optionally exiting non-zero) when thresholds are exceeded.

## Workspace layout

- `core/`: main engine and `localbox` binary
- `models/`: shared data types (config, shares, wire-level models)
- `db/`: SQLite persistence and change log
- `peering/`: discovery, TLS connections, batch exchange
- `protocol/`: protobuf-based protocol helpers (`wire.proto`)
- `utilities/`: filesystem/network abstractions, hashing, logging

## Development

```bash
cargo test
```

## License

MIT - see `LICENSE`.
