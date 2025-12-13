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

Localbox uses mTLS for peer connections and expects three PEM files:

- `--tls-cert-path` (leaf certificate)
- `--tls-key-path` (PKCS#8 private key)
- `--tls-ca-cert-path` (CA bundle used to authenticate peers)

If these files are missing or invalid, Localbox generates an ephemeral CA + leaf cert, and attempts to write them to the configured paths.

For multiple machines to connect, each node must trust the other nodes' CA certificates (for example, by distributing CA certs and concatenating them into the `--tls-ca-cert-path` bundle on every node).

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
