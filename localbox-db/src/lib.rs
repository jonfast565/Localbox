#![allow(dead_code)]

use models::{
    AppConfig, ChangeKind, ChatMessageRecord, FileChange, FileMeta, IntentBasis, IntentKind,
    IntentOrigin, IntentStatus, JournalEntry, ShareConfig, ShareContext, ShareId, ThreadKind,
    ThreadSummary, TransferIntent, TransferRequest,
};
use rusqlite::{params, types::Type, Connection, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

const DB_SCHEMA_VERSION: i32 = 9;

pub struct Db {
    conn: Connection,
}

/// Where a journal entry came from. Determines whether it carries a foreign
/// seq that must be kept out of the local `share_journal.seq` namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalOrigin {
    /// Authored on this node by a filesystem event or index seed.
    Local,
    /// Replicated from `peer_id`. `origin_seq` is that peer's journal position,
    /// or 0 for snapshot-derived changes (a manual push), which have none.
    Peer { peer_id: i64, origin_seq: i64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRow {
    pub id: i64,
    pub pc_name: String,
    pub instance_id: String,
    pub last_ip: String,
    pub last_port: i64,
    pub last_tls_port: i64,
    pub last_plain_port: i64,
    pub last_seen: i64,
    pub state: String,
    pub prefer_tls: bool,
    pub last_insecure_seen: i64,
    pub quarantined: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareRow {
    pub id: i64,
    pub share_name: String,
    pub pc_name: String,
    pub root_path: String,
    pub recursive: bool,
}

#[derive(Debug, Clone)]
pub struct PeerProgressRow {
    pub peer_id: i64,
    pub peer_pc_name: String,
    pub peer_instance_id: String,
    pub share_row_id: i64,
    pub share_name: String,
    pub share_pc_name: String,
    /// Outbound: positions in *our* journal shipped to / confirmed by this peer.
    pub last_seq_sent: i64,
    pub last_seq_acked: i64,
    /// Inbound: how far of *their* journal we have taken in. Different namespace.
    pub last_seq_recv: i64,
}

pub trait DbFactory: Send + Sync {
    fn create(&self) -> Result<Db>;
}

pub struct DiskDbFactory {
    pub path: PathBuf,
}

impl DbFactory for DiskDbFactory {
    fn create(&self) -> Result<Db> {
        Db::open(&self.path)
    }
}

pub struct MemoryDbFactory;

impl DbFactory for MemoryDbFactory {
    fn create(&self) -> Result<Db> {
        Db::open_in_memory()
    }
}

// rusqlite::Connection is !Send by default. We guard access through our own
// synchronization and only use it from controlled contexts, so mark as Send/Sync.
unsafe impl Send for Db {}
unsafe impl Sync for Db {}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Db { conn };
        db.init_schema()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Db { conn };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS peers (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                pc_name      TEXT NOT NULL,
                instance_id  TEXT NOT NULL,
                last_ip      TEXT NOT NULL,
                last_port    INTEGER NOT NULL,
                last_tls_port INTEGER NOT NULL,
                last_plain_port INTEGER NOT NULL,
                last_seen    INTEGER NOT NULL,
                state        TEXT NOT NULL,
                prefer_tls   INTEGER NOT NULL DEFAULT 1,
                last_insecure_seen INTEGER NOT NULL DEFAULT 0,
                quarantined  INTEGER NOT NULL DEFAULT 0,
                UNIQUE (pc_name, instance_id)
            );

            CREATE TABLE IF NOT EXISTS shares (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                share_name   TEXT NOT NULL,
                pc_name      TEXT NOT NULL,
                share_id     BLOB NOT NULL,
                root_path    TEXT NOT NULL,
                recursive    INTEGER NOT NULL,
                UNIQUE (share_name, pc_name)
            );

            CREATE TABLE IF NOT EXISTS peer_shares (
                peer_id      INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
                share_name   TEXT NOT NULL,
                PRIMARY KEY (peer_id, share_name)
            );

            CREATE TABLE IF NOT EXISTS files (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                share_id     INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
                rel_path     TEXT NOT NULL,
                size         INTEGER NOT NULL,
                mtime        INTEGER NOT NULL,
                hash         BLOB NOT NULL,
                version      INTEGER NOT NULL,
                deleted      INTEGER NOT NULL,
                UNIQUE (share_id, rel_path)
            );

            CREATE TABLE IF NOT EXISTS batches (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_id        INTEGER NOT NULL REFERENCES peers(id),
                share_id       INTEGER NOT NULL REFERENCES shares(id),
                batch_uuid     TEXT NOT NULL,
                direction      TEXT NOT NULL,
                created_at     INTEGER NOT NULL,
                change_count   INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS transfer_intents (
                id            TEXT PRIMARY KEY,
                kind          TEXT NOT NULL,
                origin        TEXT NOT NULL,
                status        TEXT NOT NULL,
                share_name    TEXT NOT NULL,
                share_id      BLOB NOT NULL,
                peer_id       INTEGER REFERENCES peers(id),
                basis_json    TEXT NOT NULL,
                request_id    TEXT,
                last_error    TEXT,
                created_at    INTEGER NOT NULL,
                updated_at    INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS outbound_queue (
                batch_uuid      TEXT PRIMARY KEY,
                share_id        BLOB NOT NULL,
                payload         BLOB NOT NULL,
                created_at      INTEGER NOT NULL,
                attempts        INTEGER NOT NULL DEFAULT 0,
                status          TEXT NOT NULL DEFAULT 'pending',
                last_error      TEXT,
                next_attempt_at INTEGER NOT NULL,
                peer_id         INTEGER REFERENCES peers(id),
                intent_id       TEXT REFERENCES transfer_intents(id)
            );

            CREATE TABLE IF NOT EXISTS inbound_batches (
                batch_uuid TEXT PRIMARY KEY,
                received_at INTEGER NOT NULL
            );

            -- `seq` is ALWAYS locally allocated (invariant I1). A seq that arrived
            -- from a peer lives in `origin_seq`, never here: the two are different
            -- numbering namespaces and mixing them corrupts every watermark.
            CREATE TABLE IF NOT EXISTS share_journal (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                share_id       INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
                seq            INTEGER NOT NULL,
                path           TEXT NOT NULL,
                kind           TEXT NOT NULL,
                size           INTEGER,
                mtime          INTEGER,
                hash           BLOB,
                version        INTEGER,
                deleted        INTEGER NOT NULL,
                created_at     INTEGER NOT NULL,
                -- NULL = authored locally. Set = replicated from this peer.
                origin_peer_id INTEGER REFERENCES peers(id) ON DELETE SET NULL,
                -- The originating node's journal seq. 0 = snapshot-derived
                -- (a manual push), which has no position in any journal.
                origin_seq     INTEGER NOT NULL DEFAULT 0,
                UNIQUE (share_id, seq)
            );

            -- NOTE: the replay-gate index (idx_share_journal_origin) is created by
            -- the v7 migration, not here. This batch runs before migrations, so on
            -- an upgraded DB the origin columns do not exist yet at this point.

            -- last_seq_sent/last_seq_acked are OUTBOUND: positions in *our* journal
            -- that we have shipped to / had confirmed by this peer.
            -- last_seq_recv is INBOUND: how far of *their* journal we have taken in.
            -- The two are different namespaces; never assign one from the other.
            CREATE TABLE IF NOT EXISTS peer_progress (
                peer_id        INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
                share_id       INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
                last_seq_sent  INTEGER NOT NULL DEFAULT 0,
                last_seq_acked INTEGER NOT NULL DEFAULT 0,
                last_seq_recv  INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (peer_id, share_id)
            );

            -- Denormalized MAX(share_journal.seq) cache. Local namespace only;
            -- not a replay gate (see idx_share_journal_origin for that).
            CREATE TABLE IF NOT EXISTS share_progress (
                share_id       INTEGER NOT NULL UNIQUE REFERENCES shares(id) ON DELETE CASCADE,
                last_seq_applied INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS chat_threads (
                id            TEXT PRIMARY KEY,
                kind          TEXT NOT NULL,
                peer_key      TEXT,
                share_name    TEXT,
                title         TEXT NOT NULL,
                updated_at    INTEGER NOT NULL,
                unread_count  INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS chat_messages (
                id                 TEXT PRIMARY KEY,
                thread_id          TEXT NOT NULL REFERENCES chat_threads(id) ON DELETE CASCADE,
                from_peer          TEXT NOT NULL,
                body               TEXT NOT NULL,
                attachment_share   TEXT,
                attachment_path    TEXT,
                created_at         INTEGER NOT NULL,
                direction          TEXT NOT NULL,
                status             TEXT NOT NULL DEFAULT 'sent'
            );

            CREATE TABLE IF NOT EXISTS transfer_requests (
                request_id     TEXT PRIMARY KEY,
                peer_id        INTEGER REFERENCES peers(id) ON DELETE SET NULL,
                share_name     TEXT NOT NULL,
                share_id       BLOB,
                paths_json     TEXT NOT NULL DEFAULT '[]',
                since_seq      INTEGER NOT NULL DEFAULT 0,
                from_pc        TEXT NOT NULL,
                from_instance  TEXT NOT NULL,
                direction      TEXT NOT NULL,
                status         TEXT NOT NULL DEFAULT 'pending',
                reason         TEXT,
                created_at     INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key        TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
        "#,
        )?;
        self.apply_schema_migrations()?;
        Ok(())
    }

    fn apply_schema_migrations(&self) -> Result<()> {
        let current: i32 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;

        if current > DB_SCHEMA_VERSION {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_MISMATCH),
                Some(format!(
                    "db schema version {} is newer than this binary supports (max {})",
                    current, DB_SCHEMA_VERSION
                )),
            ));
        }

        let mut stmt = self.conn.prepare("PRAGMA table_info(peers)")?;
        let mut rows = stmt.query([])?;
        let mut has_last_tls_port = false;
        let mut has_last_plain_port = false;
        let mut has_last_http_port = false;
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            match name.as_str() {
                "last_tls_port" => has_last_tls_port = true,
                "last_plain_port" => has_last_plain_port = true,
                "last_http_port" => has_last_http_port = true,
                _ => {}
            }
        }

        if current < 2 && !has_last_tls_port {
            self.conn.execute_batch(
                r#"
                ALTER TABLE peers ADD COLUMN last_tls_port INTEGER NOT NULL DEFAULT 0;
                ALTER TABLE peers ADD COLUMN last_plain_port INTEGER NOT NULL DEFAULT 0;
                ALTER TABLE peers ADD COLUMN prefer_tls INTEGER NOT NULL DEFAULT 1;
                ALTER TABLE peers ADD COLUMN last_insecure_seen INTEGER NOT NULL DEFAULT 0;
                "#,
            )?;
            has_last_plain_port = true;
        }

        if current < 3 && !has_last_plain_port {
            self.conn.execute(
                "ALTER TABLE peers ADD COLUMN last_plain_port INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
            if has_last_http_port {
                self.conn
                    .execute("UPDATE peers SET last_plain_port = last_http_port", [])?;
            }
        }

        if current < 4 {
            self.conn.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS chat_threads (
                    id            TEXT PRIMARY KEY,
                    kind          TEXT NOT NULL,
                    peer_key      TEXT,
                    share_name    TEXT,
                    title         TEXT NOT NULL,
                    updated_at    INTEGER NOT NULL,
                    unread_count  INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id                 TEXT PRIMARY KEY,
                    thread_id          TEXT NOT NULL REFERENCES chat_threads(id) ON DELETE CASCADE,
                    from_peer          TEXT NOT NULL,
                    body               TEXT NOT NULL,
                    attachment_share   TEXT,
                    attachment_path    TEXT,
                    created_at         INTEGER NOT NULL,
                    direction          TEXT NOT NULL,
                    status             TEXT NOT NULL DEFAULT 'sent'
                );
                CREATE TABLE IF NOT EXISTS transfer_requests (
                    request_id     TEXT PRIMARY KEY,
                    peer_id        INTEGER REFERENCES peers(id) ON DELETE SET NULL,
                    share_name     TEXT NOT NULL,
                    share_id       BLOB,
                    paths_json     TEXT NOT NULL DEFAULT '[]',
                    since_seq      INTEGER NOT NULL DEFAULT 0,
                    from_pc        TEXT NOT NULL,
                    from_instance  TEXT NOT NULL,
                    direction      TEXT NOT NULL,
                    status         TEXT NOT NULL DEFAULT 'pending',
                    reason         TEXT,
                    created_at     INTEGER NOT NULL
                );
                "#,
            )?;
        }

        if current < 5 {
            self.conn.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS transfer_intents (
                    id            TEXT PRIMARY KEY,
                    kind          TEXT NOT NULL,
                    origin        TEXT NOT NULL,
                    status        TEXT NOT NULL,
                    share_name    TEXT NOT NULL,
                    share_id      BLOB NOT NULL,
                    peer_id       INTEGER REFERENCES peers(id),
                    basis_json    TEXT NOT NULL,
                    request_id    TEXT,
                    last_error    TEXT,
                    created_at    INTEGER NOT NULL,
                    updated_at    INTEGER NOT NULL
                );
                "#,
            )?;
            let mut stmt = self.conn.prepare("PRAGMA table_info(outbound_queue)")?;
            let mut rows = stmt.query([])?;
            let mut has_intent_id = false;
            while let Some(row) = rows.next()? {
                let name: String = row.get(1)?;
                if name == "intent_id" {
                    has_intent_id = true;
                    break;
                }
            }
            drop(rows);
            drop(stmt);
            if !has_intent_id {
                self.conn.execute(
                    "ALTER TABLE outbound_queue ADD COLUMN intent_id TEXT REFERENCES transfer_intents(id)",
                    [],
                )?;
            }
        }

        if current < 6 {
            // Rename ShareJournal table (was change_log). CREATE IF NOT EXISTS may already
            // have made an empty share_journal alongside the legacy table.
            let has_old: bool = self
                .conn
                .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='change_log'")?
                .exists([])?;
            let has_new: bool = self
                .conn
                .prepare(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='share_journal'",
                )?
                .exists([])?;
            if has_old && has_new {
                self.conn.execute_batch(
                    r#"
                    INSERT OR IGNORE INTO share_journal
                      (id, share_id, seq, path, kind, size, mtime, hash, version, deleted, created_at)
                    SELECT id, share_id, seq, path, kind, size, mtime, hash, version, deleted, created_at
                    FROM change_log;
                    DROP TABLE change_log;
                    "#,
                )?;
            } else if has_old && !has_new {
                self.conn
                    .execute("ALTER TABLE change_log RENAME TO share_journal", [])?;
            } else if !has_new {
                self.conn.execute_batch(
                    r#"
                    CREATE TABLE IF NOT EXISTS share_journal (
                        id            INTEGER PRIMARY KEY AUTOINCREMENT,
                        share_id      INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
                        seq           INTEGER NOT NULL,
                        path          TEXT NOT NULL,
                        kind          TEXT NOT NULL,
                        size          INTEGER,
                        mtime         INTEGER,
                        hash          BLOB,
                        version       INTEGER,
                        deleted       INTEGER NOT NULL,
                        created_at    INTEGER NOT NULL,
                        UNIQUE (share_id, seq)
                    );
                    "#,
                )?;
            }
        }

        if current < 7 {
            // Separate the two seq namespaces that previously shared
            // `share_journal.seq` and `peer_progress.last_seq_acked`.
            //
            // Safe because a share row is either owner-authored or a mirror
            // replica, never both: batches are only ever produced for
            // locally-owned shares (ShareId is derived from the local pc_name),
            // mirrors are registered under the remote pc_name, and `shares` is
            // UNIQUE (share_name, pc_name). So a legacy `last_seq_acked` had
            // exactly one meaning per row -- but we cannot tell which from the
            // value alone, so we discard rather than guess (see below).
            if !self.has_column("share_journal", "origin_peer_id")? {
                self.conn.execute(
                    "ALTER TABLE share_journal ADD COLUMN origin_peer_id INTEGER REFERENCES peers(id) ON DELETE SET NULL",
                    [],
                )?;
            }
            if !self.has_column("share_journal", "origin_seq")? {
                self.conn.execute(
                    "ALTER TABLE share_journal ADD COLUMN origin_seq INTEGER NOT NULL DEFAULT 0",
                    [],
                )?;
            }
            if !self.has_column("peer_progress", "last_seq_recv")? {
                self.conn.execute(
                    "ALTER TABLE peer_progress ADD COLUMN last_seq_recv INTEGER NOT NULL DEFAULT 0",
                    [],
                )?;
            }
            self.conn.execute_batch(
                r#"
                CREATE UNIQUE INDEX IF NOT EXISTS idx_share_journal_origin
                    ON share_journal (share_id, origin_peer_id, origin_seq)
                    WHERE origin_peer_id IS NOT NULL AND origin_seq > 0;

                UPDATE transfer_intents SET kind   = 'snapshot_push' WHERE kind   = 'push';
                UPDATE transfer_intents SET origin = 'auto_sync'     WHERE origin = 'auto_push';

                -- Pre-release: existing watermarks may already be contaminated by
                -- the namespace collision, and there is no way to tell a good value
                -- from a bad one. Reset and re-catch-up; that is idempotent because
                -- `should_apply` rejects changes at or below the current version.
                UPDATE peer_progress
                   SET last_seq_sent = 0, last_seq_acked = 0, last_seq_recv = 0;

                -- Queued payloads were serialized under the old semantics.
                DELETE FROM outbound_queue;
                "#,
            )?;
        }

        if current < 8 {
            if !self.has_column("peers", "quarantined")? {
                self.conn.execute(
                    "ALTER TABLE peers ADD COLUMN quarantined INTEGER NOT NULL DEFAULT 0",
                    [],
                )?;
            }
        }

        if current < 9 {
            self.conn.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS settings (
                    key        TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                "#,
            )?;
        }

        self.conn
            .execute_batch(&format!("PRAGMA user_version = {DB_SCHEMA_VERSION};"))?;

        Ok(())
    }

    fn has_column(&self, table: &str, column: &str) -> Result<bool> {
        let mut stmt = self.conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            if name == column {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Sparse config overrides: key → JSON text.
    pub fn list_settings(&self) -> Result<HashMap<String, String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value_json FROM settings ORDER BY key")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = HashMap::new();
        for row in rows {
            let (k, v) = row?;
            out.insert(k, v);
        }
        Ok(out)
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT value_json FROM settings WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    pub fn set_setting(&self, key: &str, value_json: &str, updated_at: i64) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO settings (key, value_json, updated_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(key) DO UPDATE SET
                value_json = excluded.value_json,
                updated_at = excluded.updated_at
            "#,
            params![key, value_json, updated_at],
        )?;
        Ok(())
    }

    pub fn delete_setting(&self, key: &str) -> Result<bool> {
        let n = self
            .conn
            .execute("DELETE FROM settings WHERE key = ?1", params![key])?;
        Ok(n > 0)
    }

    pub fn schema_version(&self) -> Result<i32> {
        self.conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
    }

    /// Ensure shares from config exist; return loaded ShareContexts (indexes loaded).
    pub fn load_shares(&self, cfg: &AppConfig) -> Result<Vec<ShareContext>> {
        if !cfg.app_state.can_share() {
            return Ok(Vec::new());
        }
        let mut contexts = Vec::new();
        for sc in &cfg.shares {
            let share_id = ShareId::new(&sc.name, &cfg.pc_name);
            let id = self.upsert_share(&cfg.pc_name, sc, &share_id)?;
            let index = self.load_file_index(id)?;
            contexts.push(ShareContext {
                id,
                share_name: sc.name.clone(),
                pc_name: cfg.pc_name.clone(),
                share_id,
                root_path: sc.root_path.clone(),
                recursive: sc.recursive,
                ignore_patterns: sc.ignore_patterns.clone(),
                sync_allow: sc.sync_allow.clone(),
                conflict: sc.conflict,
                max_file_size_bytes: sc.max_file_size_bytes,
                index,
            });
        }
        Ok(contexts)
    }

    pub fn upsert_share(&self, pc_name: &str, sc: &ShareConfig, share_id: &ShareId) -> Result<i64> {
        self.conn.execute(
            r#"
            INSERT INTO shares (share_name, pc_name, share_id, root_path, recursive)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(share_name, pc_name) DO UPDATE SET
                share_id = excluded.share_id,
                root_path = excluded.root_path,
                recursive = excluded.recursive
            "#,
            params![
                sc.name,
                pc_name,
                &share_id.0[..],
                sc.root_path.to_string_lossy(),
                sc.recursive as i64
            ],
        )?;

        let mut stmt = self
            .conn
            .prepare("SELECT id FROM shares WHERE share_name=?1 AND pc_name=?2")?;
        let id: i64 = stmt.query_row(params![sc.name, pc_name], |row| row.get(0))?;
        Ok(id)
    }

    fn load_file_index(&self, share_row_id: i64) -> Result<HashMap<String, FileMeta>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT rel_path, size, mtime, hash, version, deleted
            FROM files
            WHERE share_id = ?1
            "#,
        )?;
        let mut map = HashMap::new();
        let rows = stmt.query_map(params![share_row_id], |row| {
            let path: String = row.get(0)?;
            let size: i64 = row.get(1)?;
            let mtime: i64 = row.get(2)?;
            let hash: Vec<u8> = row.get(3)?;
            let version: i64 = row.get(4)?;
            let deleted: i64 = row.get(5)?;
            Ok((
                path,
                FileMeta {
                    path: String::new(), // filled later
                    size: size as u64,
                    mtime,
                    hash: {
                        let mut arr = [0u8; 32];
                        let len = hash.len().min(32);
                        arr[..len].copy_from_slice(&hash[..len]);
                        arr
                    },
                    version,
                    deleted: deleted != 0,
                },
            ))
        })?;

        for row in rows {
            let (path, mut meta) = row?;
            meta.path = path.clone();
            map.insert(path, meta);
        }
        Ok(map)
    }

    pub fn get_file_meta(&self, share_row_id: i64, rel_path: &str) -> Result<Option<FileMeta>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT size, mtime, hash, version, deleted
            FROM files
            WHERE share_id = ?1 AND rel_path = ?2
            "#,
        )?;
        let res = stmt.query_row(params![share_row_id, rel_path], |row| {
            let size: i64 = row.get(0)?;
            let mtime: i64 = row.get(1)?;
            let hash: Vec<u8> = row.get(2)?;
            let version: i64 = row.get(3)?;
            let deleted: i64 = row.get(4)?;
            let mut arr = [0u8; 32];
            let len = hash.len().min(32);
            arr[..len].copy_from_slice(&hash[..len]);
            Ok(FileMeta {
                path: rel_path.to_string(),
                size: size as u64,
                mtime,
                hash: arr,
                version,
                deleted: deleted != 0,
            })
        });
        match res {
            Ok(meta) => Ok(Some(meta)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn list_file_metas(&self, share_row_id: i64) -> Result<Vec<FileMeta>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT rel_path, size, mtime, hash, version, deleted
            FROM files
            WHERE share_id = ?1
            "#,
        )?;
        let rows = stmt.query_map(params![share_row_id], |row| {
            let path: String = row.get(0)?;
            let size: i64 = row.get(1)?;
            let mtime: i64 = row.get(2)?;
            let hash: Vec<u8> = row.get(3)?;
            let version: i64 = row.get(4)?;
            let deleted: i64 = row.get(5)?;
            Ok(FileMeta {
                path,
                size: size as u64,
                mtime,
                hash: {
                    let mut arr = [0u8; 32];
                    let len = hash.len().min(32);
                    arr[..len].copy_from_slice(&hash[..len]);
                    arr
                },
                version,
                deleted: deleted != 0,
            })
        })?;
        let mut metas = Vec::new();
        for row in rows {
            metas.push(row?);
        }
        Ok(metas)
    }

    pub fn upsert_file_meta(&self, share_row_id: i64, meta: &FileMeta) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO files (share_id, rel_path, size, mtime, hash, version, deleted)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(share_id, rel_path) DO UPDATE SET
                size = excluded.size,
                mtime = excluded.mtime,
                hash = excluded.hash,
                version = excluded.version,
                deleted = excluded.deleted
            "#,
            params![
                share_row_id,
                meta.path,
                meta.size as i64,
                meta.mtime,
                &meta.hash[..],
                meta.version,
                meta.deleted as i64,
            ],
        )?;
        Ok(())
    }

    pub fn insert_batch(
        &self,
        peer_id: i64,
        share_row_id: i64,
        batch_uuid: &str,
        direction: &str,
        created_at: i64,
        change_count: usize,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO batches (peer_id, share_id, batch_uuid, direction, created_at, change_count)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                peer_id,
                share_row_id,
                batch_uuid,
                direction,
                created_at,
                change_count as i64
            ],
        )?;
        Ok(())
    }

    /// Clean up old batches to stop the tables growing forever.
    /// max_age_secs: delete rows older than now - max_age_secs.
    ///
    /// Covers both the `batches` audit log and delivered `outbound_queue` rows.
    /// The latter matters: `outbound_queue_depth` only counts `status != 'sent'`,
    /// so without this sweep the table grows without bound (each row holding a
    /// full serialized manifest) while both the queue-depth guard and
    /// `localbox monitor` keep reporting healthy.
    pub fn cleanup_old_batches(&self, max_age_secs: i64) -> Result<usize> {
        use time::OffsetDateTime;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let cutoff = now - max_age_secs;
        let mut rows = self
            .conn
            .execute("DELETE FROM batches WHERE created_at < ?1", params![cutoff])?;
        rows += self.conn.execute(
            "DELETE FROM outbound_queue WHERE status = 'sent' AND created_at < ?1",
            params![cutoff],
        )?;
        Ok(rows)
    }

    /* Peer helpers */

    pub fn upsert_peer(
        &self,
        pc_name: &str,
        instance_id: &str,
        addr: SocketAddr,
        now_ts: i64,
        state: &str,
        tls_port: u16,
        plain_port: u16,
        prefer_tls: bool,
    ) -> Result<i64> {
        self.conn.execute(
            r#"
            INSERT INTO peers (pc_name, instance_id, last_ip, last_port, last_tls_port, last_plain_port, last_seen, state, prefer_tls)
            VALUES (?1, ?2, ?3, ?4, ?7, ?8, ?5, ?6, ?9)
            ON CONFLICT(pc_name, instance_id) DO UPDATE SET
                last_ip = excluded.last_ip,
                last_port = excluded.last_port,
                last_tls_port = excluded.last_tls_port,
                last_plain_port = excluded.last_plain_port,
                last_seen = excluded.last_seen,
                state = excluded.state,
                prefer_tls = excluded.prefer_tls
            "#,
            params![
                pc_name,
                instance_id,
                addr.ip().to_string(),
                addr.port() as i64,
                now_ts,
                state,
                tls_port as i64,
                plain_port as i64,
                prefer_tls as i64,
            ],
        )?;

        let mut stmt = self
            .conn
            .prepare("SELECT id FROM peers WHERE pc_name=?1 AND instance_id=?2")?;
        let id: i64 = stmt.query_row(params![pc_name, instance_id], |row| row.get(0))?;
        Ok(id)
    }

    pub fn mark_peer_insecure(&self, peer_id: i64, when_ts: i64) -> Result<()> {
        self.conn.execute(
            r#"
            UPDATE peers
            SET last_insecure_seen = MAX(last_insecure_seen, ?2)
            WHERE id = ?1
            "#,
            params![peer_id, when_ts],
        )?;
        Ok(())
    }

    /// Set the quarantined flag for a peer. Returns `false` if the peer is not found.
    pub fn set_peer_quarantined(&self, peer_key: &str, quarantined: bool) -> Result<bool> {
        let Some(peer) = self.find_peer_by_key(peer_key)? else {
            return Ok(false);
        };
        self.conn.execute(
            "UPDATE peers SET quarantined = ?2 WHERE id = ?1",
            params![peer.id, quarantined as i64],
        )?;
        Ok(true)
    }

    pub fn is_peer_quarantined(&self, peer_key: &str) -> Result<bool> {
        Ok(self
            .find_peer_by_key(peer_key)?
            .map(|p| p.quarantined)
            .unwrap_or(false))
    }

    pub fn set_peer_shares(&self, peer_id: i64, shares: &[String]) -> Result<()> {
        // Use autocommit; for the small number of rows here this keeps the signature non-mutable.
        self.conn
            .execute("DELETE FROM peer_shares WHERE peer_id=?1", params![peer_id])?;
        for s in shares {
            self.conn.execute(
                "INSERT INTO peer_shares (peer_id, share_name) VALUES (?1, ?2)",
                params![peer_id, s],
            )?;
        }
        Ok(())
    }

    pub fn get_share_row_id_by_share_id(&self, share_id: &ShareId) -> Result<i64> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM shares WHERE share_id = ?1")?;
        let id: i64 = stmt.query_row(params![&share_id.0[..]], |row| row.get(0))?;
        Ok(id)
    }

    pub fn get_share_row(&self, share_row_id: i64) -> Result<ShareRow> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, share_name, pc_name, root_path, recursive
            FROM shares
            WHERE id = ?1
            "#,
        )?;
        stmt.query_row(params![share_row_id], |row| {
            Ok(ShareRow {
                id: row.get(0)?,
                share_name: row.get(1)?,
                pc_name: row.get(2)?,
                root_path: row.get(3)?,
                recursive: {
                    let v: i64 = row.get(4)?;
                    v != 0
                },
            })
        })
    }

    pub fn list_peer_ids_for_share_name(&self, share_name: &str) -> Result<Vec<i64>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT p.id
            FROM peers p
            JOIN peer_shares ps ON ps.peer_id = p.id
            WHERE ps.share_name = ?1
            "#,
        )?;
        let rows = stmt.query_map(params![share_name], |row| row.get(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /* Outbound queue */

    pub fn enqueue_outbound_batch(
        &self,
        manifest: &models::BatchManifest,
        peer_id: Option<i64>,
        intent_id: Option<&str>,
    ) -> Result<()> {
        let payload = serde_json::to_vec(manifest).expect("serialize manifest");
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        self.conn.execute(
            r#"
            INSERT OR IGNORE INTO outbound_queue
              (batch_uuid, share_id, payload, created_at, attempts, status, last_error, next_attempt_at, peer_id, intent_id)
            VALUES (?1, ?2, ?3, ?4, 0, 'pending', NULL, ?4, ?5, ?6)
            "#,
            params![
                manifest.batch_id,
                &manifest.share_id.0[..],
                payload,
                now,
                peer_id,
                intent_id
            ],
        )?;
        Ok(())
    }

    pub fn dequeue_due_outbound(
        &self,
        limit: usize,
        now_ts: i64,
    ) -> Result<Vec<OutboundQueueItem>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT batch_uuid, payload, attempts, peer_id, intent_id
            FROM outbound_queue
            WHERE status != 'sent' AND next_attempt_at <= ?1
            ORDER BY created_at ASC
            LIMIT ?2
            "#,
        )?;
        let rows = stmt.query_map(params![now_ts, limit as i64], |row| {
            let batch_id: String = row.get(0)?;
            let payload: Vec<u8> = row.get(1)?;
            let attempts: i64 = row.get(2)?;
            let peer_id: Option<i64> = row.get(3)?;
            let intent_id: Option<String> = row.get(4)?;
            let manifest: models::BatchManifest =
                serde_json::from_slice(&payload).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        payload.len(),
                        Type::Blob,
                        Box::new(e),
                    )
                })?;
            Ok(OutboundQueueItem {
                batch_id,
                manifest,
                attempts,
                peer_id,
                intent_id,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn mark_outbound_sent(&self, batch_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE outbound_queue SET status='sent', last_error=NULL, next_attempt_at=0 WHERE batch_uuid=?1",
            params![batch_id],
        )?;
        Ok(())
    }

    pub fn mark_outbound_failed(&self, batch_id: &str, err: &str, backoff_secs: i64) -> Result<()> {
        let next_attempt = time::OffsetDateTime::now_utc().unix_timestamp() + backoff_secs;
        self.conn.execute(
            r#"
            UPDATE outbound_queue
            SET attempts = attempts + 1,
                status = 'pending',
                last_error = ?2,
                next_attempt_at = ?3
            WHERE batch_uuid = ?1
            "#,
            params![batch_id, err, next_attempt],
        )?;
        Ok(())
    }

    /* Inbound tracking */

    pub fn record_inbound_batch(&self, batch_id: &str) -> Result<bool> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let rows = self.conn.execute(
            r#"
            INSERT OR IGNORE INTO inbound_batches (batch_uuid, received_at)
            VALUES (?1, ?2)
            "#,
            params![batch_id, now],
        )?;
        Ok(rows > 0)
    }

    /* Share journal + progress watermarks */

    pub fn next_journal_seq(&self, share_row_id: i64) -> Result<i64> {
        let mut stmt = self
            .conn
            .prepare("SELECT COALESCE(MAX(seq), 0) + 1 FROM share_journal WHERE share_id = ?1")?;
        let next: i64 = stmt.query_row(params![share_row_id], |row| row.get(0))?;
        Ok(next)
    }

    /// Append one entry to a share's journal.
    ///
    /// The returned seq is **always locally allocated** (invariant I1) —
    /// `change.seq` is deliberately ignored. When the entry came from a peer,
    /// pass its journal position as [`JournalOrigin::Peer::origin_seq`] so it is
    /// recorded in the peer's namespace instead of being conflated with ours.
    ///
    /// Returns `Ok(None)` when this peer entry has already been journaled, which
    /// is a normal no-op rather than an error. Callers must distinguish that from
    /// `Err`, which means the append genuinely failed.
    pub fn append_journal_entry(
        &self,
        share_row_id: i64,
        change: &FileChange,
        created_at: i64,
        origin: JournalOrigin,
    ) -> Result<Option<i64>> {
        let seq = self.next_journal_seq(share_row_id)?;
        let (origin_peer_id, origin_seq) = match origin {
            JournalOrigin::Local => (None, 0),
            JournalOrigin::Peer {
                peer_id,
                origin_seq,
            } => (Some(peer_id), origin_seq.max(0)),
        };

        let (size, mtime, hash, version, deleted) = match &change.meta {
            Some(meta) => (
                Some(meta.size as i64),
                Some(meta.mtime),
                Some(meta.hash.to_vec()),
                Some(meta.version),
                meta.deleted,
            ),
            None => (None, None, None, None, true),
        };

        // DO NOTHING (not IGNORE) so a genuine failure still surfaces as Err,
        // while a re-delivered peer entry collapses into a reported no-op.
        let inserted = self.conn.execute(
            r#"
            INSERT INTO share_journal
              (share_id, seq, path, kind, size, mtime, hash, version, deleted,
               created_at, origin_peer_id, origin_seq)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            ON CONFLICT DO NOTHING
            "#,
            params![
                share_row_id,
                seq,
                change.path,
                format!("{:?}", change.kind),
                size,
                mtime,
                hash,
                version,
                deleted as i64,
                created_at,
                origin_peer_id,
                origin_seq
            ],
        )?;
        if inserted == 0 {
            return Ok(None);
        }

        // MAX, not assignment: a late lower-seq append must never rewind the cache.
        self.conn.execute(
            r#"
            INSERT INTO share_progress (share_id, last_seq_applied)
            VALUES (?1, ?2)
            ON CONFLICT(share_id) DO UPDATE SET
                last_seq_applied = MAX(share_progress.last_seq_applied, excluded.last_seq_applied)
            "#,
            params![share_row_id, seq],
        )?;
        Ok(Some(seq))
    }

    pub fn journal_high_water(&self, share_row_id: i64) -> Result<i64> {
        let mut stmt = self
            .conn
            .prepare("SELECT last_seq_applied FROM share_progress WHERE share_id=?1")?;
        match stmt.query_row(params![share_row_id], |row| row.get(0)) {
            Ok(seq) => Ok(seq),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// Read a share's journal in local-seq order. `from_seq_exclusive` is
    /// exclusive, so pass a watermark directly.
    ///
    /// `change.share_id` is left zeroed — the row stores a share *row id*, not
    /// the 16-byte ShareId. Callers that put these on the wire must set it.
    pub fn list_journal_since(
        &self,
        share_row_id: i64,
        from_seq_exclusive: i64,
        limit: usize,
    ) -> Result<Vec<JournalEntry>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT seq, path, kind, size, mtime, hash, version, deleted,
                   origin_peer_id, origin_seq
            FROM share_journal
            WHERE share_id = ?1 AND seq > ?2
            ORDER BY seq ASC
            LIMIT ?3
            "#,
        )?;
        let rows = stmt.query_map(
            params![share_row_id, from_seq_exclusive, limit as i64],
            |row| {
                let seq: i64 = row.get(0)?;
                let path: String = row.get(1)?;
                let kind: String = row.get(2)?;
                let size: Option<i64> = row.get(3)?;
                let mtime: Option<i64> = row.get(4)?;
                let hash: Option<Vec<u8>> = row.get(5)?;
                let version: Option<i64> = row.get(6)?;
                let deleted: i64 = row.get(7)?;
                let origin_peer_id: Option<i64> = row.get(8)?;
                let origin_seq: i64 = row.get(9)?;
                let ck = match kind.as_str() {
                    "Create" => ChangeKind::Create,
                    "Modify" => ChangeKind::Modify,
                    "Delete" => ChangeKind::Delete,
                    _ => ChangeKind::Modify,
                };
                let meta = if deleted != 0 {
                    None
                } else {
                    let mut h = [0u8; 32];
                    if let Some(hash_bytes) = hash {
                        let len = hash_bytes.len().min(32);
                        h[..len].copy_from_slice(&hash_bytes[..len]);
                    }
                    Some(FileMeta {
                        path: path.clone(),
                        size: size.unwrap_or_default() as u64,
                        mtime: mtime.unwrap_or_default(),
                        hash: h,
                        version: version.unwrap_or_default(),
                        deleted: false,
                    })
                };
                Ok(JournalEntry {
                    origin_peer_id,
                    origin_seq,
                    change: FileChange {
                        seq,
                        share_id: ShareId([0u8; 16]),
                        path,
                        kind: ck,
                        meta,
                    },
                })
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn get_peer_progress(&self, peer_id: i64, share_row_id: i64) -> Result<(i64, i64)> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT last_seq_sent, last_seq_acked
            FROM peer_progress
            WHERE peer_id = ?1 AND share_id = ?2
            "#,
        )?;
        let res = stmt.query_row(params![peer_id, share_row_id], |row| {
            let sent: i64 = row.get(0)?;
            let ack: i64 = row.get(1)?;
            Ok((sent, ack))
        });
        match res {
            Ok(v) => Ok(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok((0, 0)),
            Err(e) => Err(e),
        }
    }

    /// Assigns outbound watermarks outright. Admin/test setup only —
    /// use `bump_*` on hot paths so watermarks stay monotonic.
    pub fn set_peer_progress(
        &self,
        peer_id: i64,
        share_row_id: i64,
        last_sent: i64,
        last_acked: i64,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO peer_progress (peer_id, share_id, last_seq_sent, last_seq_acked)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(peer_id, share_id) DO UPDATE SET
                last_seq_sent = excluded.last_seq_sent,
                last_seq_acked = excluded.last_seq_acked
            "#,
            params![peer_id, share_row_id, last_sent, last_acked],
        )?;
        Ok(())
    }

    pub fn bump_last_seq_sent(&self, peer_id: i64, share_row_id: i64, new_sent: i64) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO peer_progress (peer_id, share_id, last_seq_sent, last_seq_acked)
            VALUES (?1, ?2, ?3, 0)
            ON CONFLICT(peer_id, share_id) DO UPDATE SET
                last_seq_sent = MAX(peer_progress.last_seq_sent, excluded.last_seq_sent)
            "#,
            params![peer_id, share_row_id, new_sent],
        )?;
        Ok(())
    }

    /// Outbound watermark: how far of *our* journal this peer has confirmed.
    /// MAX-based — a stale or malformed ack must never rewind sync, because
    /// `from_seq` for the next SyncCatchup is read straight off this value.
    pub fn bump_last_seq_acked(
        &self,
        peer_id: i64,
        share_row_id: i64,
        new_acked: i64,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO peer_progress (peer_id, share_id, last_seq_sent, last_seq_acked)
            VALUES (?1, ?2, ?3, ?3)
            ON CONFLICT(peer_id, share_id) DO UPDATE SET
                last_seq_acked = MAX(peer_progress.last_seq_acked, excluded.last_seq_acked),
                last_seq_sent = MAX(peer_progress.last_seq_sent, excluded.last_seq_sent)
            "#,
            params![peer_id, share_row_id, new_acked],
        )?;
        Ok(())
    }

    /// Inbound watermark: how far of *this peer's* journal we have taken in.
    /// This is the value that belongs in `TransferRequest.since_seq` — never
    /// `last_seq_acked`, which lives in our own namespace.
    pub fn inbound_watermark(&self, peer_id: i64, share_row_id: i64) -> Result<i64> {
        let mut stmt = self.conn.prepare(
            "SELECT last_seq_recv FROM peer_progress WHERE peer_id = ?1 AND share_id = ?2",
        )?;
        match stmt.query_row(params![peer_id, share_row_id], |row| row.get(0)) {
            Ok(v) => Ok(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// Advance the inbound watermark. Only journal-derived (SyncCatchup) traffic
    /// may call this: snapshot pushes carry no journal position (invariant I6).
    pub fn bump_inbound_watermark(
        &self,
        peer_id: i64,
        share_row_id: i64,
        new_recv: i64,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO peer_progress (peer_id, share_id, last_seq_sent, last_seq_acked, last_seq_recv)
            VALUES (?1, ?2, 0, 0, ?3)
            ON CONFLICT(peer_id, share_id) DO UPDATE SET
                last_seq_recv = MAX(peer_progress.last_seq_recv, excluded.last_seq_recv)
            "#,
            params![peer_id, share_row_id, new_recv],
        )?;
        Ok(())
    }

    /* Status/observability helpers */

    pub fn list_peers(&self) -> Result<Vec<PeerRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, pc_name, instance_id, last_ip, last_port, last_tls_port, last_plain_port,
                   last_seen, state, prefer_tls, last_insecure_seen, quarantined
            FROM peers
            ORDER BY last_seen DESC
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PeerRow {
                id: row.get(0)?,
                pc_name: row.get(1)?,
                instance_id: row.get(2)?,
                last_ip: row.get(3)?,
                last_port: row.get(4)?,
                last_tls_port: row.get(5)?,
                last_plain_port: row.get(6)?,
                last_seen: row.get(7)?,
                state: row.get(8)?,
                prefer_tls: {
                    let v: i64 = row.get(9)?;
                    v != 0
                },
                last_insecure_seen: row.get(10)?,
                quarantined: {
                    let v: i64 = row.get(11)?;
                    v != 0
                },
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn list_shares_table(&self) -> Result<Vec<ShareRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, share_name, pc_name, root_path, recursive
            FROM shares
            ORDER BY pc_name ASC, share_name ASC
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(ShareRow {
                id: row.get(0)?,
                share_name: row.get(1)?,
                pc_name: row.get(2)?,
                root_path: row.get(3)?,
                recursive: {
                    let v: i64 = row.get(4)?;
                    v != 0
                },
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Local shares owned by this PC (the runtime share registry).
    pub fn list_shares_for_pc(&self, pc_name: &str) -> Result<Vec<ShareRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, share_name, pc_name, root_path, recursive
            FROM shares
            WHERE pc_name = ?1
            ORDER BY share_name ASC
            "#,
        )?;
        let rows = stmt.query_map(params![pc_name], |row| {
            Ok(ShareRow {
                id: row.get(0)?,
                share_name: row.get(1)?,
                pc_name: row.get(2)?,
                root_path: row.get(3)?,
                recursive: {
                    let v: i64 = row.get(4)?;
                    v != 0
                },
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn get_share_by_share_id(&self, share_id: &ShareId) -> Result<Option<ShareRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, share_name, pc_name, root_path, recursive
            FROM shares
            WHERE share_id = ?1
            "#,
        )?;
        let mut rows = stmt.query_map(params![&share_id.0[..]], |row| {
            Ok(ShareRow {
                id: row.get(0)?,
                share_name: row.get(1)?,
                pc_name: row.get(2)?,
                root_path: row.get(3)?,
                recursive: {
                    let v: i64 = row.get(4)?;
                    v != 0
                },
            })
        })?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    pub fn get_share_by_name(&self, pc_name: &str, share_name: &str) -> Result<Option<ShareRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, share_name, pc_name, root_path, recursive
            FROM shares
            WHERE pc_name = ?1 AND share_name = ?2
            "#,
        )?;
        let mut rows = stmt.query_map(params![pc_name, share_name], |row| {
            Ok(ShareRow {
                id: row.get(0)?,
                share_name: row.get(1)?,
                pc_name: row.get(2)?,
                root_path: row.get(3)?,
                recursive: {
                    let v: i64 = row.get(4)?;
                    v != 0
                },
            })
        })?;
        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    pub fn list_peer_progress_table(&self) -> Result<Vec<PeerProgressRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                p.id,
                p.pc_name,
                p.instance_id,
                s.id,
                s.share_name,
                s.pc_name,
                pp.last_seq_sent,
                pp.last_seq_acked,
                pp.last_seq_recv
            FROM peer_progress pp
            JOIN peers p ON p.id = pp.peer_id
            JOIN shares s ON s.id = pp.share_id
            ORDER BY p.pc_name ASC, p.instance_id ASC, s.pc_name ASC, s.share_name ASC
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PeerProgressRow {
                peer_id: row.get(0)?,
                peer_pc_name: row.get(1)?,
                peer_instance_id: row.get(2)?,
                share_row_id: row.get(3)?,
                share_name: row.get(4)?,
                share_pc_name: row.get(5)?,
                last_seq_sent: row.get(6)?,
                last_seq_acked: row.get(7)?,
                last_seq_recv: row.get(8)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn outbound_queue_depth(&self) -> Result<i64> {
        let mut stmt = self
            .conn
            .prepare("SELECT COUNT(*) FROM outbound_queue WHERE status != 'sent'")?;
        let n: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(n)
    }

    pub fn outbound_queue_due_now(&self, now_ts: i64) -> Result<i64> {
        let mut stmt = self.conn.prepare(
            "SELECT COUNT(*) FROM outbound_queue WHERE status != 'sent' AND next_attempt_at <= ?1",
        )?;
        let n: i64 = stmt.query_row(params![now_ts], |row| row.get(0))?;
        Ok(n)
    }

    /// Whether a share's journal already carries any entry for `path`.
    /// Used to keep startup seeding idempotent across restarts.
    pub fn journal_has_path(&self, share_row_id: i64, path: &str) -> Result<bool> {
        self.conn
            .prepare("SELECT 1 FROM share_journal WHERE share_id = ?1 AND path = ?2 LIMIT 1")?
            .exists(params![share_row_id, path])
    }

    /// Total journal entries across all shares.
    pub fn journal_entry_count(&self) -> Result<i64> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM share_journal")?;
        let n: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(n)
    }

    pub fn find_peer_by_key(&self, peer_key: &str) -> Result<Option<PeerRow>> {
        let (pc, inst) = match peer_key.split_once('@') {
            Some((pc, inst)) => (pc.to_string(), Some(inst.to_string())),
            None => (peer_key.to_string(), None),
        };
        let peers = self.list_peers()?;
        Ok(peers.into_iter().find(|p| {
            if let Some(inst) = &inst {
                p.pc_name == pc && p.instance_id == *inst
            } else {
                p.pc_name == pc
            }
        }))
    }

    pub fn ensure_chat_thread(
        &self,
        id: &str,
        kind: ThreadKind,
        peer_key: Option<&str>,
        share_name: Option<&str>,
        title: &str,
        updated_at: i64,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO chat_threads (id, kind, peer_key, share_name, title, updated_at, unread_count)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)
            ON CONFLICT(id) DO UPDATE SET
                title = excluded.title,
                updated_at = MAX(chat_threads.updated_at, excluded.updated_at)
            "#,
            params![
                id,
                kind.as_str(),
                peer_key,
                share_name,
                title,
                updated_at
            ],
        )?;
        Ok(())
    }

    pub fn insert_chat_message(&self, msg: &ChatMessageRecord, bump_unread: bool) -> Result<()> {
        self.conn.execute(
            r#"
            INSERT OR IGNORE INTO chat_messages
              (id, thread_id, from_peer, body, attachment_share, attachment_path, created_at, direction, status)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                msg.id,
                msg.thread_id,
                msg.from_peer,
                msg.body,
                msg.attachment_share,
                msg.attachment_path,
                msg.created_at,
                msg.direction,
                msg.status
            ],
        )?;
        self.conn.execute(
            "UPDATE chat_threads SET updated_at = MAX(updated_at, ?2) WHERE id = ?1",
            params![msg.thread_id, msg.created_at],
        )?;
        if bump_unread {
            self.conn.execute(
                "UPDATE chat_threads SET unread_count = unread_count + 1 WHERE id = ?1",
                params![msg.thread_id],
            )?;
        }
        Ok(())
    }

    pub fn list_inbox(&self) -> Result<Vec<ThreadSummary>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, kind, peer_key, share_name, title, updated_at, unread_count
            FROM chat_threads
            ORDER BY updated_at DESC
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            let kind_s: String = row.get(1)?;
            Ok(ThreadSummary {
                id: row.get(0)?,
                kind: ThreadKind::parse(&kind_s).unwrap_or(ThreadKind::Peer),
                peer_key: row.get(2)?,
                share_name: row.get(3)?,
                title: row.get(4)?,
                updated_at: row.get(5)?,
                unread_count: row.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn list_thread_messages(
        &self,
        thread_id: &str,
        limit: usize,
    ) -> Result<Vec<ChatMessageRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, thread_id, from_peer, body, attachment_share, attachment_path,
                   created_at, direction, status
            FROM chat_messages
            WHERE thread_id = ?1
            ORDER BY created_at ASC
            LIMIT ?2
            "#,
        )?;
        let rows = stmt.query_map(params![thread_id, limit as i64], |row| {
            Ok(ChatMessageRecord {
                id: row.get(0)?,
                thread_id: row.get(1)?,
                from_peer: row.get(2)?,
                body: row.get(3)?,
                attachment_share: row.get(4)?,
                attachment_path: row.get(5)?,
                created_at: row.get(6)?,
                direction: row.get(7)?,
                status: row.get(8)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn mark_thread_read(&self, thread_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE chat_threads SET unread_count = 0 WHERE id = ?1",
            params![thread_id],
        )?;
        Ok(())
    }

    pub fn insert_transfer_request(
        &self,
        req: &TransferRequest,
        peer_id: Option<i64>,
        direction: &str,
        status: &str,
    ) -> Result<()> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let paths_json = serde_json::to_string(&req.paths).unwrap_or_else(|_| "[]".into());
        let share_id = req.share_id.0.to_vec();
        let since = req.since_seq;
        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO transfer_requests
              (request_id, peer_id, share_name, share_id, paths_json, since_seq,
               from_pc, from_instance, direction, status, reason, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, ?11)
            "#,
            params![
                req.request_id,
                peer_id,
                req.share_name,
                share_id,
                paths_json,
                since,
                req.from_pc,
                req.from_instance,
                direction,
                status,
                now
            ],
        )?;
        Ok(())
    }

    pub fn list_pending_transfer_requests(&self) -> Result<Vec<PendingTransferRequest>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT request_id, peer_id, share_name, share_id, paths_json, since_seq,
                   from_pc, from_instance, direction, status, reason, created_at
            FROM transfer_requests
            WHERE status = 'pending' AND direction = 'in'
            ORDER BY created_at ASC
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            let share_id_blob: Option<Vec<u8>> = row.get(3)?;
            let paths_json: String = row.get(4)?;
            let paths: Vec<String> = serde_json::from_str(&paths_json).unwrap_or_default();
            let share_id = share_id_blob.and_then(|b| {
                if b.len() == 16 {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(&b);
                    Some(ShareId(arr))
                } else {
                    None
                }
            });
            Ok(PendingTransferRequest {
                request_id: row.get(0)?,
                peer_id: row.get(1)?,
                share_name: row.get(2)?,
                share_id,
                paths,
                since_seq: row.get(5)?,
                from_pc: row.get(6)?,
                from_instance: row.get(7)?,
                direction: row.get(8)?,
                status: row.get(9)?,
                reason: row.get(10)?,
                created_at: row.get(11)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn get_transfer_request(&self, request_id: &str) -> Result<Option<PendingTransferRequest>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT request_id, peer_id, share_name, share_id, paths_json, since_seq,
                   from_pc, from_instance, direction, status, reason, created_at
            FROM transfer_requests
            WHERE request_id = ?1
            "#,
        )?;
        let mut rows = stmt.query(params![request_id])?;
        if let Some(row) = rows.next()? {
            let share_id_blob: Option<Vec<u8>> = row.get(3)?;
            let paths_json: String = row.get(4)?;
            let paths: Vec<String> = serde_json::from_str(&paths_json).unwrap_or_default();
            let share_id = share_id_blob.and_then(|b| {
                if b.len() == 16 {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(&b);
                    Some(ShareId(arr))
                } else {
                    None
                }
            });
            Ok(Some(PendingTransferRequest {
                request_id: row.get(0)?,
                peer_id: row.get(1)?,
                share_name: row.get(2)?,
                share_id,
                paths,
                since_seq: row.get(5)?,
                from_pc: row.get(6)?,
                from_instance: row.get(7)?,
                direction: row.get(8)?,
                status: row.get(9)?,
                reason: row.get(10)?,
                created_at: row.get(11)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn update_transfer_request_status(
        &self,
        request_id: &str,
        status: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE transfer_requests SET status = ?2, reason = ?3 WHERE request_id = ?1",
            params![request_id, status, reason],
        )?;
        Ok(())
    }

    pub fn delete_transfer_request(&self, request_id: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM transfer_requests WHERE request_id = ?1",
            params![request_id],
        )?;
        Ok(())
    }

    /* Transfer intents */

    fn row_to_transfer_intent(row: &rusqlite::Row<'_>) -> Result<TransferIntent> {
        let share_id_blob: Vec<u8> = row.get(5)?;
        let mut arr = [0u8; 16];
        let len = share_id_blob.len().min(16);
        arr[..len].copy_from_slice(&share_id_blob[..len]);
        let basis_json: String = row.get(7)?;
        let basis: IntentBasis = serde_json::from_str(&basis_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(basis_json.len(), Type::Text, Box::new(e))
        })?;
        let kind_s: String = row.get(1)?;
        let origin_s: String = row.get(2)?;
        let status_s: String = row.get(3)?;
        Ok(TransferIntent {
            id: row.get(0)?,
            kind: IntentKind::parse(&kind_s).unwrap_or(IntentKind::SnapshotPush),
            origin: IntentOrigin::parse(&origin_s).unwrap_or(IntentOrigin::User),
            status: IntentStatus::parse(&status_s).unwrap_or(IntentStatus::Pending),
            share_name: row.get(4)?,
            share_id: ShareId(arr),
            peer_id: row.get(6)?,
            basis,
            request_id: row.get(8)?,
            last_error: row.get(9)?,
            created_at: row.get(10)?,
            updated_at: row.get(11)?,
        })
    }

    pub fn insert_transfer_intent(&self, intent: &TransferIntent) -> Result<()> {
        let basis_json = serde_json::to_string(&intent.basis).expect("serialize basis");
        self.conn.execute(
            r#"
            INSERT INTO transfer_intents
              (id, kind, origin, status, share_name, share_id, peer_id, basis_json,
               request_id, last_error, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
            params![
                intent.id,
                intent.kind.as_str(),
                intent.origin.as_str(),
                intent.status.as_str(),
                intent.share_name,
                &intent.share_id.0[..],
                intent.peer_id,
                basis_json,
                intent.request_id,
                intent.last_error,
                intent.created_at,
                intent.updated_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_transfer_intent(&self, id: &str) -> Result<Option<TransferIntent>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, kind, origin, status, share_name, share_id, peer_id, basis_json,
                   request_id, last_error, created_at, updated_at
            FROM transfer_intents
            WHERE id = ?1
            "#,
        )?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(Self::row_to_transfer_intent(row)?))
        } else {
            Ok(None)
        }
    }

    pub fn update_transfer_intent_status(
        &self,
        id: &str,
        status: IntentStatus,
        last_error: Option<&str>,
    ) -> Result<()> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        self.conn.execute(
            r#"
            UPDATE transfer_intents
            SET status = ?2, last_error = ?3, updated_at = ?4
            WHERE id = ?1
            "#,
            params![id, status.as_str(), last_error, now],
        )?;
        Ok(())
    }

    /// Look up the intent raised for a `TransferRequest`, so the eventual
    /// `TransferReply` can complete it instead of leaving it active forever.
    pub fn get_transfer_intent_by_request_id(
        &self,
        request_id: &str,
    ) -> Result<Option<TransferIntent>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, kind, origin, status, share_name, share_id, peer_id, basis_json,
                   request_id, last_error, created_at, updated_at
            FROM transfer_intents
            WHERE request_id = ?1
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )?;
        match stmt.query_row(params![request_id], Self::row_to_transfer_intent) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn list_transfer_intents(
        &self,
        statuses: Option<&[IntentStatus]>,
        limit: usize,
    ) -> Result<Vec<TransferIntent>> {
        let mut sql = String::from(
            r#"
            SELECT id, kind, origin, status, share_name, share_id, peer_id, basis_json,
                   request_id, last_error, created_at, updated_at
            FROM transfer_intents
            "#,
        );
        let status_params: Vec<String> = statuses
            .filter(|s| !s.is_empty())
            .map(|s| s.iter().map(|st| st.as_str().to_string()).collect())
            .unwrap_or_default();
        if !status_params.is_empty() {
            let placeholders: Vec<String> = (1..=status_params.len())
                .map(|i| format!("?{i}"))
                .collect();
            sql.push_str(" WHERE status IN (");
            sql.push_str(&placeholders.join(","));
            sql.push(')');
        }
        sql.push_str(&format!(
            " ORDER BY created_at DESC LIMIT {}",
            limit.max(1)
        ));

        let mut stmt = self.conn.prepare(&sql)?;
        let mut out = Vec::new();
        if status_params.is_empty() {
            let rows = stmt.query_map([], |row| Self::row_to_transfer_intent(row))?;
            for row in rows {
                out.push(row?);
            }
        } else {
            let refs: Vec<&dyn rusqlite::types::ToSql> = status_params
                .iter()
                .map(|s| s as &dyn rusqlite::types::ToSql)
                .collect();
            let rows = stmt.query_map(refs.as_slice(), |row| Self::row_to_transfer_intent(row))?;
            for row in rows {
                out.push(row?);
            }
        }
        Ok(out)
    }

    pub fn get_outbound_intent_id(&self, batch_uuid: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT intent_id FROM outbound_queue WHERE batch_uuid = ?1")?;
        match stmt.query_row(params![batch_uuid], |row| row.get::<_, Option<String>>(0)) {
            Ok(v) => Ok(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Pending (not yet sent) outbound batches for an intent.
    pub fn count_pending_batches_for_intent(&self, intent_id: &str) -> Result<i64> {
        let mut stmt = self.conn.prepare(
            "SELECT COUNT(*) FROM outbound_queue WHERE intent_id = ?1 AND status != 'sent'",
        )?;
        stmt.query_row(params![intent_id], |row| row.get(0))
    }

    /// All outbound batches for an intent (any status).

    pub fn max_journal_seq(&self, share_row_id: i64) -> Result<i64> {
        let mut stmt = self
            .conn
            .prepare("SELECT COALESCE(MAX(seq), 0) FROM share_journal WHERE share_id = ?1")?;
        stmt.query_row(params![share_row_id], |row| row.get(0))
    }

    /// Create a TransferIntent and enqueue outbound batches (Snapshot or JournalRange).
    /// Returns (intent_id, batch_ids). Does not bump peer_progress.
    pub fn create_and_materialize_intent(
        &self,
        kind: IntentKind,
        origin: IntentOrigin,
        share_name: &str,
        share_id: ShareId,
        peer_id: Option<i64>,
        basis: IntentBasis,
        request_id: Option<&str>,
        from_node: &str,
    ) -> Result<(String, Vec<String>)> {
        const MAX_CHANGES_PER_BATCH: usize = 256;
        const MAX_OUTBOUND_QUEUE_DEPTH: i64 = 50_000;

        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let intent_id = uuid::Uuid::new_v4().to_string();
        let intent = TransferIntent {
            id: intent_id.clone(),
            kind,
            origin,
            status: IntentStatus::Pending,
            share_name: share_name.to_string(),
            share_id,
            peer_id,
            basis: basis.clone(),
            request_id: request_id.map(|s| s.to_string()),
            last_error: None,
            created_at: now,
            updated_at: now,
        };
        self.insert_transfer_intent(&intent)?;

        let share_row_id = self.get_share_row_id_by_share_id(&share_id)?;
        let changes = match &basis {
            IntentBasis::Snapshot { paths } => {
                self.snapshot_changes(share_row_id, share_id, paths)?
            }
            IntentBasis::JournalRange { from_seq, to_seq } => {
                let mut all = Vec::new();
                let mut start = *from_seq;
                while start < *to_seq {
                    let chunk =
                        self.list_journal_since(share_row_id, start, MAX_CHANGES_PER_BATCH)?;
                    if chunk.is_empty() {
                        break;
                    }
                    let mut advanced = false;
                    for entry in chunk {
                        let mut ch = entry.change;
                        if ch.seq > *to_seq {
                            break;
                        }
                        // The journal stores a share row id, not the wire ShareId.
                        ch.share_id = share_id;
                        start = ch.seq;
                        all.push(ch);
                        advanced = true;
                    }
                    if !advanced {
                        break;
                    }
                }
                all
            }
        };

        if changes.is_empty() {
            self.update_transfer_intent_status(
                &intent_id,
                IntentStatus::Failed,
                Some("no changes to materialize"),
            )?;
            return Ok((intent_id, Vec::new()));
        }

        let depth = self.outbound_queue_depth().unwrap_or(0);
        if depth >= MAX_OUTBOUND_QUEUE_DEPTH {
            self.update_transfer_intent_status(
                &intent_id,
                IntentStatus::Failed,
                Some("outbound queue full"),
            )?;
            return Ok((intent_id, Vec::new()));
        }

        let mut batch_ids = Vec::new();
        for chunk in changes.chunks(MAX_CHANGES_PER_BATCH) {
            let batch_id = uuid::Uuid::new_v4().to_string();
            // Tell the receiver how to read these seqs. A chunk covers from the
            // range start up to its own last seq, so a partial send still lets
            // the receiver advance to exactly what it received.
            let (basis, from_seq, to_seq) = match &basis {
                IntentBasis::Snapshot { .. } => (models::BatchBasis::Snapshot, 0, 0),
                IntentBasis::JournalRange { from_seq, .. } => {
                    let chunk_to = chunk.last().map(|c| c.seq).unwrap_or(0);
                    (models::BatchBasis::Journal, *from_seq, chunk_to)
                }
            };
            let manifest = models::BatchManifest {
                protocol_version: models::WIRE_PROTOCOL_VERSION,
                batch_id: batch_id.clone(),
                share_id,
                from_node: from_node.to_string(),
                created_at: now,
                basis,
                journal_from_seq: from_seq,
                journal_to_seq: to_seq,
                changes: chunk.to_vec(),
            };
            self.enqueue_outbound_batch(&manifest, peer_id, Some(&intent_id))?;
            batch_ids.push(batch_id);
        }

        self.update_transfer_intent_status(&intent_id, IntentStatus::Materialized, None)?;
        Ok((intent_id, batch_ids))
    }

    fn snapshot_changes(
        &self,
        share_row_id: i64,
        share_id: ShareId,
        paths: &[String],
    ) -> Result<Vec<FileChange>> {
        let metas = if paths.is_empty() {
            self.list_file_metas(share_row_id)?
        } else {
            let mut out = Vec::new();
            for p in paths {
                if let Some(m) = self.get_file_meta(share_row_id, p)? {
                    out.push(m);
                }
            }
            out
        };
        let mut changes = Vec::with_capacity(metas.len());
        for meta in metas {
            let kind = if meta.deleted {
                ChangeKind::Delete
            } else if meta.version <= 1 {
                ChangeKind::Create
            } else {
                ChangeKind::Modify
            };
            let meta_opt = if meta.deleted {
                None
            } else {
                Some(meta.clone())
            };
            changes.push(FileChange {
                seq: 0,
                share_id,
                path: meta.path,
                kind,
                meta: meta_opt,
            });
        }
        Ok(changes)
    }

    /// After a batch is successfully sent: mark intent InFlight; bump last_seq_sent only for SyncCatchup.
    pub fn on_outbound_batch_sent(
        &self,
        batch_id: &str,
        peer_id: i64,
        share_id: &ShareId,
        max_seq: i64,
    ) -> Result<()> {
        self.mark_outbound_sent(batch_id)?;
        let intent_id = self.get_outbound_intent_id(batch_id)?;
        let Some(intent_id) = intent_id else {
            // No intent to attribute this batch to, so we cannot tell whether
            // max_seq is a journal position or a snapshot's placeholder 0.
            // Leave the watermark alone rather than guess.
            return Ok(());
        };
        if let Some(intent) = self.get_transfer_intent(&intent_id)? {
            if intent.kind.awaits_ack() && max_seq > 0 {
                if let Ok(share_row_id) = self.get_share_row_id_by_share_id(share_id) {
                    let _ = self.bump_last_seq_sent(peer_id, share_row_id, max_seq);
                }
            }
            let pending = self.count_pending_batches_for_intent(&intent_id)?;
            if pending == 0 && !intent.kind.awaits_ack() {
                // SnapshotPush / PullFulfill: nothing will confirm these, so
                // `Sent` is their terminal state. Reporting them as `Acked`
                // would claim a confirmation the peer never gave.
                self.update_transfer_intent_status(&intent_id, IntentStatus::Sent, None)?;
            } else {
                self.update_transfer_intent_status(&intent_id, IntentStatus::InFlight, None)?;
            }
        }
        Ok(())
    }

    /// On BatchAck: bump last_seq_acked only for SyncCatchup; mark intents Acked when drained.
    pub fn on_batch_ack(
        &self,
        peer_id: i64,
        share_id: &ShareId,
        upto_seq: i64,
        batch_id: Option<&str>,
    ) -> Result<()> {
        let mut intent_ids = Vec::new();
        if let Some(bid) = batch_id {
            if let Some(id) = self.get_outbound_intent_id(bid)? {
                intent_ids.push(id);
            }
        }
        if intent_ids.is_empty() {
            // No batch_id on the ack: fall back to sent batches for this peer+share.
            // Restricted to sync_catchup because only that kind owns a seq range —
            // resolving to a snapshot push here would bump our watermark with a
            // number from the receiver's namespace.
            let mut stmt = self.conn.prepare(
                r#"
                SELECT DISTINCT oq.intent_id
                FROM outbound_queue oq
                JOIN transfer_intents ti ON ti.id = oq.intent_id
                WHERE oq.peer_id = ?1 AND oq.share_id = ?2
                  AND oq.intent_id IS NOT NULL AND oq.status = 'sent'
                  AND ti.kind = 'sync_catchup'
                "#,
            )?;
            let rows = stmt.query_map(params![peer_id, &share_id.0[..]], |row| {
                row.get::<_, String>(0)
            })?;
            for row in rows {
                intent_ids.push(row?);
            }
        }

        if intent_ids.is_empty() {
            // Nothing resolvable. Do NOT bump: an unattributed upto_seq cannot be
            // trusted to be in our namespace, and bump_last_seq_acked is one-way.
            return Ok(());
        }

        let mut bumped = false;
        for id in &intent_ids {
            if let Some(intent) = self.get_transfer_intent(id)? {
                if intent.kind.awaits_ack() && !bumped {
                    // Clamp to the range this intent actually covers. A peer can
                    // only ever confirm what we sent; anything beyond that would
                    // push from_seq past our own journal and stall sync forever.
                    let covered = match &intent.basis {
                        IntentBasis::JournalRange { to_seq, .. } => upto_seq.min(*to_seq),
                        IntentBasis::Snapshot { .. } => 0,
                    };
                    if covered > 0 {
                        if let Ok(share_row_id) = self.get_share_row_id_by_share_id(share_id) {
                            let _ = self.bump_last_seq_acked(peer_id, share_row_id, covered);
                            bumped = true;
                        }
                    }
                }
                // Only a kind that actually waits for confirmation may reach
                // Acked. A stray ack naming a Sent snapshot intent is a no-op.
                let pending = self.count_pending_batches_for_intent(id)?;
                if pending == 0
                    && intent.kind.awaits_ack()
                    && matches!(
                        intent.status,
                        IntentStatus::Materialized | IntentStatus::InFlight
                    )
                {
                    self.update_transfer_intent_status(id, IntentStatus::Acked, None)?;
                }
            }
        }
        Ok(())
    }


    pub fn update_chat_message_status(&self, message_id: &str, status: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE chat_messages SET status = ?2 WHERE id = ?1",
            params![message_id, status],
        )?;
        Ok(())
    }

    pub fn get_peer(&self, peer_id: i64) -> Result<Option<PeerRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, pc_name, instance_id, last_ip, last_port, last_tls_port, last_plain_port,
                   last_seen, state, prefer_tls, last_insecure_seen, quarantined
            FROM peers
            WHERE id = ?1
            "#,
        )?;
        let mut rows = stmt.query(params![peer_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(PeerRow {
                id: row.get(0)?,
                pc_name: row.get(1)?,
                instance_id: row.get(2)?,
                last_ip: row.get(3)?,
                last_port: row.get(4)?,
                last_tls_port: row.get(5)?,
                last_plain_port: row.get(6)?,
                last_seen: row.get(7)?,
                state: row.get(8)?,
                prefer_tls: {
                    let v: i64 = row.get(9)?;
                    v != 0
                },
                last_insecure_seen: row.get(10)?,
                quarantined: {
                    let v: i64 = row.get(11)?;
                    v != 0
                },
            }))
        } else {
            Ok(None)
        }
    }

    // Aliases matching the control-plane / docs naming.

    pub fn ensure_thread(
        &self,
        id: &str,
        kind: ThreadKind,
        peer_key: Option<&str>,
        share_name: Option<&str>,
        title: &str,
        updated_at: i64,
    ) -> Result<()> {
        self.ensure_chat_thread(id, kind, peer_key, share_name, title, updated_at)
    }

    pub fn insert_message(&self, msg: &ChatMessageRecord, bump_unread: bool) -> Result<()> {
        self.insert_chat_message(msg, bump_unread)
    }

    pub fn list_messages(&self, thread_id: &str, limit: usize) -> Result<Vec<ChatMessageRecord>> {
        self.list_thread_messages(thread_id, limit)
    }

    pub fn insert_pending_request(
        &self,
        req: &TransferRequest,
        peer_id: Option<i64>,
        direction: &str,
        status: &str,
    ) -> Result<()> {
        self.insert_transfer_request(req, peer_id, direction, status)
    }

    pub fn list_pending_requests(&self) -> Result<Vec<PendingTransferRequest>> {
        self.list_pending_transfer_requests()
    }

    pub fn get_pending_request(&self, request_id: &str) -> Result<Option<PendingTransferRequest>> {
        self.get_transfer_request(request_id)
    }

    pub fn update_pending_request_status(
        &self,
        request_id: &str,
        status: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        self.update_transfer_request_status(request_id, status, reason)
    }

    pub fn delete_pending_request(&self, request_id: &str) -> Result<()> {
        self.delete_transfer_request(request_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTransferRequest {
    pub request_id: String,
    pub peer_id: Option<i64>,
    pub share_name: String,
    pub share_id: Option<ShareId>,
    pub paths: Vec<String>,
    pub since_seq: i64,
    pub from_pc: String,
    pub from_instance: String,
    pub direction: String,
    pub status: String,
    pub reason: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundQueueItem {
    pub batch_id: String,
    pub manifest: models::BatchManifest,
    pub attempts: i64,
    pub peer_id: Option<i64>,
    pub intent_id: Option<String>,
}
