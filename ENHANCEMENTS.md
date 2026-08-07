# Localbox — Enhancement Backlog

A review of the workspace as of `f4755d7`. Each item cites the code it came from so it can
be verified before being scheduled. Items are grouped by area and ordered roughly by
value-per-effort within each group.

Nothing here is a criticism of the design — the invariants around seq namespaces, intent
lifecycle, and staging-then-rename are unusually well thought through. These are the gaps
that remain.

---

## 1. Correctness & data integrity

### 1.1 Concurrent inbound pushes of the same path collide

`PendingFiles` is a single process-wide map (`localbox-peering/src/lib.rs:234`) keyed by
`(ShareId, String)` (`localbox-peering/src/lib.rs:133`) — the peer is not part of the key.
Every connection handler clones the same `Arc`.

If two peers push the same `rel_path` in the same share at overlapping times, the second
peer's `offset == 0` chunk hits the "out-of-order" branch in
`handle_file_chunk_message` (`localbox-peering/src/connection.rs:1352-1377`), which
truncates the staging file and resets the hasher — discarding the first peer's progress.
The two streams then interleave into one staging file. The final hash check catches the
corruption (so nothing wrong lands on disk), but both transfers are wasted and the two
peers can livelock re-restarting each other.

**Fix:** include `peer_id` in the `PendingFiles` key and in the staging filename. This is a
small, contained change and removes a whole class of multi-peer flakiness.

### 1.2 Foreign keys are declared but never enforced

The schema uses `REFERENCES … ON DELETE CASCADE` on `peer_shares`, `files`,
`share_journal`, `peer_progress`, `share_progress`, and `chat_messages`
(`localbox-db/src/lib.rs:157-290`), but no `PRAGMA foreign_keys = ON` is ever issued —
`init_schema` (`localbox-db/src/lib.rs:125`) sets no pragmas at all. SQLite defaults FKs
off per connection, so every cascade is inert. The code already knows this in one place
(`localbox-db/src/lib.rs:2023`: *"SQLite foreign keys are off unless PRAGMA is set"*) and
hand-deletes there, but the other paths silently orphan rows.

**Fix:** enable `PRAGMA foreign_keys = ON` at connection open. Do it behind a one-off
cleanup migration that deletes existing orphans first, otherwise the pragma will start
rejecting writes against already-inconsistent databases.

### 1.3 Startup drift detection is shallow and add-only

`seed_journal_from_index` (`localbox-core/src/engine.rs:1236`) reconciles the DB against
disk on startup, but:

- It calls `fs.read_dir(&share.root_path)` once, and `read_dir` is **not** recursive
  (`localbox-utilities/src/filesystem.rs:69`). For a `recursive = true` share, anything
  added below the top level while the daemon was down is never noticed.
- It only handles *new* paths — `if share.index.contains_key(&rel_path) { continue; }`
  (`localbox-core/src/engine.rs:1304`). Files **modified** or **deleted** while the daemon
  was down are never journaled, so peers stay permanently stale for those paths.

**Fix:** replace the single `read_dir` with a recursive walk, and compare
`(size, mtime)` against the index to emit `Modify` for drifted files and `Delete` for
index entries with no file on disk. A `localbox rescan --share <name>` command falls out of
the same code and is worth exposing.

### 1.4 Outbound queue retries forever with no dead-letter

`dequeue_due` selects `WHERE status != 'sent'` (`localbox-db/src/lib.rs:1260`) with no
attempts ceiling, and backoff caps at 300s (`localbox-peering/src/lib.rs:656`). A batch for
a peer that has been decommissioned, or one that fails deterministically (missing share,
permanently unreadable file), is retried every five minutes forever. The `attempts` column
is incremented (`localbox-db/src/lib.rs:1307`) but never read for a decision.

**Fix:** add a `max_attempts` config knob; on exhaustion move the row to a `failed`
terminal status, mark the owning intent `Failed` with `last_error`, and surface the count
in `localbox monitor` and `status`.

### 1.5 `max_file_size_bytes` is not enforced on inbound

The limit is applied on local watch and index seeding, but a grep across the receive path
shows no reference in `localbox-peering/src` at all — the only hits are config plumbing
(`localbox-core/src/config.rs`, `localbox-core/src/service.rs:561`). A peer can therefore
push a file of any size into a share whose config caps it.

**Fix:** check `expected_size` against the share's limit in `prepare_pending_file`
(`localbox-peering/src/connection.rs:1255`) and reject the manifest entry before staging.

---

## 2. Performance & scalability

### 2.1 Blocking SQLite behind one global async mutex

The database is a single `Arc<tokio::Mutex<Db>>` (`localbox-core/src/engine.rs:113`) wrapping
one `rusqlite::Connection` (`localbox-db/src/lib.rs:16`), and callers do synchronous queries
while holding it on runtime worker threads — e.g. `db.lock().await.set_peer_shares(…)`
(`localbox-peering/src/discovery.rs:459`), and dozens of similar sites in `discovery.rs`,
`lib.rs`, and `connection.rs`. Two consequences:

- Every DB call blocks a tokio worker for the duration of the query.
- All peers, all shares, discovery, chunk handling, and the control plane serialize on one
  lock. With N peers this is the throughput ceiling.

Note the `unsafe impl Send/Sync for Db` at `localbox-db/src/lib.rs:100-101` — the mutex is
load-bearing for soundness, so this needs care rather than a quick swap.

**Fix (incremental):** enable WAL first (§2.2), then move to a small connection pool with
readers separate from the single writer, and route calls through `spawn_blocking`.
`DbFactory` (`localbox-db/src/lib.rs:79`) already exists and is the natural seam.

### 2.2 No SQLite pragmas: WAL, busy_timeout, synchronous

`PRAGMA` appears only for `user_version` and `table_info`. That means rollback-journal mode
(readers block writers), no busy timeout (any contention is an immediate `SQLITE_BUSY`
error rather than a wait), and default `synchronous=FULL` (an fsync per transaction, on the
hot journal-append path).

**Fix:** at open — `journal_mode = WAL`, `busy_timeout = 5000`, `synchronous = NORMAL`.
Cheap, and a prerequisite for §2.1.

### 2.3 Missing indexes on hot query paths

The only index in the schema is `idx_share_journal_origin` (`localbox-db/src/lib.rs:529`),
plus whatever the `UNIQUE` constraints provide. Queries that currently full-scan:

| Query | Site | Suggested index |
|---|---|---|
| `outbound_queue WHERE status != 'sent' AND next_attempt_at <= ?` | `lib.rs:1260`, `lib.rs:1830` | `(status, next_attempt_at)` |
| `transfer_intents` filtered by status | `lib.rs:2310` | `(status, updated_at)` |
| `chat_messages` by thread, newest-first | `lib.rs:2015-2029` | `(thread_id, created_at)` |
| `batches WHERE created_at < ?` | `lib.rs:913` | `(created_at)` |

These are cheap to add in a migration and matter most on the queue polling loop, which runs
continuously.

### 2.4 No delta transfer, no compression

`send_file_chunks` (`localbox-peering/src/lib.rs:697`) streams the whole file in 128 KiB
chunks (`FILE_CHUNK_SIZE`, `localbox-peering/src/lib.rs:679`) on every change, with no
block-level diffing and no compression on the wire. A one-byte edit to a 2 GB file resends
2 GB.

**Fix:** two independent wins, either worth doing alone —
- Per-chunk content hashes in the manifest so the receiver can `BatchAck` the blocks it
  already holds (rsync-style, but without the rolling-checksum complexity since both sides
  keep an index).
- Opportunistic compression on chunk payloads with a per-file "already compressed" skip
  based on extension or a cheap entropy probe.

### 2.5 Interrupted transfers restart from zero

The receiver only ever accepts `offset == state.expected_offset`, and any mismatch is
handled by truncating and restarting (`localbox-peering/src/connection.rs:1352-1377`).
There is no persistence of staging progress, so a connection drop mid-file means the whole
file is resent.

**Fix:** persist `(peer_id, share_id, path, bytes_staged, partial_hash_state)` and let the
sender resume from a receiver-declared offset. Pairs naturally with §2.4.

### 2.6 Unbounded table growth

`cleanup_old_batches` (`localbox-db/src/lib.rs:907`) prunes only `batches` and *sent*
`outbound_queue` rows older than 7 days (`localbox-core/src/engine.rs:1077`). Never pruned:

- `share_journal` — one row per change, forever. This is the biggest one; a busy share
  grows without bound and `max_journal_seq` scans get slower.
- `chat_messages` / `chat_threads`.
- `files` rows for deleted paths (tombstones are permanent).

**Fix:** journal compaction — once `MIN(last_seq_acked)` across all peers for a share
passes a seq, entries below it are only needed for history, so collapse them to one entry
per path or drop them behind a retention window. Add configurable retention for chat and
tombstones.

### 2.7 GUI polls on a 2s timer instead of consuming the event stream

`app.rs:1121-1122` subscribes to `time::every(Duration::from_secs(2))` for both
`SyncSystemTheme` and `Tick`, unconditionally, on every tab. Meanwhile the control plane
already supports `ControlRequest::Subscribe` (`localbox-core/src/service.rs:465`) with a
`broadcast::Sender<ControlEvent>` behind it.

**Fix:** consume the event stream for peer/transfer/chat updates and drop the timer to a
slow keepalive. Also gate the log tail on `Tab::Logs` being active.

---

## 3. Security hardening

### 3.1 Control socket has no access control

`run_unix_server` (`localbox-core/src/control.rs:83`) binds the Unix socket and never
adjusts its mode — no `set_permissions` call exists anywhere in `localbox-core/src` or
`localbox-tls/src`. The default is umask-derived, typically world-connectable. Anything
that can connect gets `ConfigSet`, `ShareAdd` with an arbitrary path, `Shutdown`, full chat
history, and peer quarantine control (`localbox-core/src/service.rs:215-465`).

On a single-user laptop this is academic. On a shared or server host it is a local
privilege boundary that does not exist.

**Fix:** `chmod 0600` the socket immediately after bind (and place it in a `0700` parent
directory), then verify peer credentials via `SO_PEERCRED` / `getpeereid`. On Windows, set
an equivalent named-pipe DACL.

### 3.2 TLS private keys are written without explicit modes

No `PermissionsExt` / `set_permissions` usage appears in `localbox-tls/src` or
`localbox-utilities/src`, so generated keys land at whatever umask allows. The README
states keys are "written owner-only" — that claim is not backed by code in this tree.

**Fix:** write key material through a helper that sets `0600` before the first write, and
add a test asserting the mode.

### 3.3 Revocation is still expiry-plus-quarantine

Acknowledged in the README, restating here because it is the largest remaining gap in the
CA story: a leaked leaf certificate is only stoppable by quarantining it on **every** node
individually, or by waiting out a lifetime that defaults to 365 days.

**Fix, in ascending order of effort:** ship a much shorter default lifetime with an
auto-renew path in `enroll`; then a signed revocation list distributed over the existing
peer channel and checked at handshake; then short-lived certs with a renewal daemon.

### 3.4 Discovery has no rate limiting

Noted in the README's DoS section. `DISCOVER` / `HERE` handling
(`localbox-peering/src/discovery.rs`) has no per-source throttle, so an unfriendly host on
the LAN can drive unbounded DB writes through `upsert_peer_with_meta`
(`localbox-peering/src/discovery.rs:668`) — which, per §2.1, holds the global DB lock.

**Fix:** per-source-IP token bucket in front of discovery handling, and a cap on distinct
unknown peers admitted per interval.

---

## 4. Protocol & compatibility

### 4.1 No version negotiation — the whole mesh must upgrade in lockstep

The parser rejects anything above `WIRE_PROTOCOL_VERSION`
(`localbox-protocol/src/parse.rs:174,186`) and every message carries a version field, but
nothing negotiates. The README states this plainly: *"there is no version negotiation, so
all peers must be upgraded together."* For a tool whose whole point is heterogeneous
machines on a home or office network, this is the sharpest operational edge.

**Fix:** have `Hello` carry `min_supported` / `max_supported`, pick
`min(local_max, remote_max)` for the session, and gate new fields on the negotiated
version. Even supporting N and N-1 removes the flag-day requirement.

### 4.2 Sender hashes after transmitting, not before

`send_file_chunks` streams every chunk and only then compares the computed digest against
`meta.hash` (`localbox-peering/src/lib.rs:828-829`). A file modified between indexing and
sending is transmitted in full before the mismatch is noticed. Safe, but wasteful.

**Fix:** stat-and-compare `(size, mtime)` against the index before opening the file, and
abort early with a re-index rather than a full send.

---

## 5. Feature gaps

### 5.1 Shares can be added but never removed

`ShareCliCommand` has only `List` and `Add` (`localbox-core/src/config.rs:133-155`), and
`ControlRequest` correspondingly has `ShareList` / `ShareAdd` with no removal
(`localbox-core/src/service.rs:432-464`). Removing a share means hand-editing `config.toml`,
restarting, and leaving orphaned DB rows behind (which §1.2 guarantees are never cascaded).

**Fix:** `share remove --name <n> [--purge]` across CLI, control plane, REPL, and the GUI
Status tab — stopping the watcher, removing DB rows, and optionally deleting the mirrored
copy.

### 5.2 No peer removal

`PeerCliCommand` offers `List` / `Quarantine` / `Unquarantine`
(`localbox-core/src/config.rs:163-176`) but no `forget`. A peer that is gone for good stays
in `peers`, in `peer_progress`, and in `status` output permanently.

**Fix:** `localbox peer forget <name>` that removes the peer and its progress rows.

### 5.3 No bandwidth limiting

`AppConfig` (`localbox-models/src/config.rs:43-112`) has no rate-limit knob, and the chunk
loop sends as fast as the socket accepts. Saturating a home uplink is the most common
complaint against every tool in this category.

**Fix:** per-node and per-peer byte-rate caps applied in the chunk send loop, with an
optional schedule (e.g. unthrottled overnight).

### 5.4 No file versioning or delete protection

Conflict policy covers concurrent writes (`keep_both` etc.), but a propagated delete is
final and an overwrite discards the previous content. There is no "staging area" or trash.

**Fix:** an opt-in per-share `versioning = "trash" | "simple" | "staggered"` that moves the
superseded copy under `.localbox-versions/` before applying inbound changes.

### 5.5 No free-space check before staging

Inbound files stage to a temp file with no capacity check
(`prepare_pending_file`, `localbox-peering/src/connection.rs:1255`); a large push can fill
the disk and the failure surfaces as a mid-write I/O error
(`localbox-peering/src/connection.rs:1377-1387`).

**Fix:** check available space against the manifest's declared total before accepting, and
decline the batch with a clear reason.

### 5.6 GUI has no tray presence or desktop integration

`localbox-gui` is a plain window; closing it stops the child daemon it spawned
(`localbox-gui/src/runtime.rs`). There is no tray icon, no autostart, and no packaging
target — `notify-rust` is a dependency, so notifications exist, but nothing else.

**Fix:** tray icon with sync status and quick actions, minimize-to-tray, autostart, and
platform packaging (`.app` bundle, MSI, `.deb`). Also worth having: a file-manager context
menu for "share this folder".

---

## 6. Operability

### 6.1 Metrics are pull-only over a separate DB connection

`run_monitor` (`localbox-core/src/monitoring.rs:36`) opens its **own** `Db` handle against
the same file and polls in a `thread::sleep` loop. Under rollback-journal mode (§2.2) this
contends with the daemon's writer.

**Fix:** expose the same snapshot over the control plane (the daemon already has the data),
and add an optional Prometheus `/metrics` listener. Cheap once `MetricsSnapshot` exists.

### 6.2 Metrics coverage is thin

`MetricsSnapshot` (`localbox-core/src/monitoring.rs:9`) carries queue depth, due-now,
journal count, and peer staleness. Missing: bytes transferred in/out, transfer throughput,
per-intent success/failure counts, conflict-resolution counts, hash-mismatch counts,
connection churn. The `TransferProgressRegistry` already tracks byte-level data that never
reaches the snapshot.

### 6.3 No structured audit trail

Security-relevant events — quarantine, insecure connection accepted, identity check
failure, hash mismatch, enrollment — go to `tracing` at varying levels and are then only
recoverable by grepping the log.

**Fix:** an `audit_log` table with structured events, queryable via `localbox audit`
(the subcommand already exists — `localbox-core/src/config.rs:71`).

### 6.4 Logs tab reads the file rather than streaming

The GUI tails `log_path` via `ControlRequest::Logs { limit }`
(`localbox-core/src/service.rs:464`) on the 2s tick. With `Subscribe` already in place,
log lines could be pushed.

---

## 7. Testing & developer experience

### 7.1 No CI

There is no `.github/` directory. Everything — `cargo test`, `fmt`, `clippy` — is manual,
which the README's "on slower hardware this may exceed CI/CLI timeouts" note suggests is
already a pain point.

**Fix:** a workflow running `fmt --check`, `clippy --workspace --all-targets -D warnings`,
and `cargo test --workspace` on Linux/macOS/Windows, plus `cargo-deny` for the GPL
dependency surface.

### 7.2 GUI is untested

`localbox-gui/` has no `tests/` directory, and `app.rs` is 2,810 lines mixing state,
update logic, and view construction. The pure parts (state transitions, `Message` handling,
peer/share list derivation) are testable if split from the `view` functions.

**Fix:** extract state transitions into a testable module; split `app.rs` by tab.

### 7.3 Coverage gaps in the areas most likely to break

Well covered: protocol parsing, virtual peers, journal-vs-push, TLS pinning, migrations,
chat inbox. Thin or absent:

- Crash/restart recovery — kill mid-transfer, verify no partial file and correct resume.
- Concurrent multi-peer writes to the same path (§1.1 has no test).
- Large-file paths (>2 GB, offset arithmetic).
- Clock skew between peers, given LWW leans on `mtime`.
- Filesystem edge cases: symlinks, hardlinks, case-insensitive collisions on macOS/Windows,
  paths near the OS length limit, non-UTF-8 names (`to_string_lossy` at
  `localbox-core/src/engine.rs:1286` is silently lossy).

### 7.4 Test residue is committed

`tmp/test-write.txt`, `tmp/rename-test/b.txt`, and three PEM files under
`tmp/localbox-tls-482366c5-…/` are tracked in git. `.gitignore` covers `certs/`, `sync.db`,
and `sync.log` but not `tmp/`.

**Fix:** `git rm -r --cached tmp/` and add `tmp/` to `.gitignore`. Confirm the tracked PEMs
are throwaway test material before this lands anywhere public.

### 7.5 Repo layout does not match the README

The README's "Repository Layout" section lists `core/`, `db/`, `models/`, `peering/`,
`protocol/`, `tls/`, `utilities/`, `gui/`. The actual directories are `localbox-core/`,
`localbox-db/`, and so on. Likewise, "Development & Testing" suggests `cargo test -p
protocol` and `-p peering`, but the package names are `localbox-protocol` and
`localbox-peering` — those commands fail as written.

---

## Suggested sequencing

**First — small, contained, high value**
§2.2 pragmas · §2.3 indexes · §1.1 pending-files key · §3.1 socket permissions ·
§7.5 README fixes · §7.4 tmp cleanup · §7.1 CI

**Second — needs a migration or a design decision**
§1.2 foreign keys · §1.3 recursive rescan · §1.4 dead-letter · §1.5 inbound size limit ·
§5.1 share removal · §5.2 peer removal · §3.2 key permissions

**Third — larger investments**
§2.1 DB concurrency · §2.6 journal compaction · §4.1 version negotiation ·
§2.4 delta/compression · §2.5 resume · §5.3 bandwidth limits · §5.4 versioning

**Fourth — product surface**
§5.6 GUI/desktop integration · §2.7 event-driven GUI · §6.1–6.4 observability
