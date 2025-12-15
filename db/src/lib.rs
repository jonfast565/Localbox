#![allow(dead_code)]

use models::{AppConfig, ChangeKind, FileChange, FileMeta, ShareConfig, ShareContext, ShareId};
use rusqlite::{params, types::Type, Connection, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

const DB_SCHEMA_VERSION: i32 = 3;

pub struct Db {
    conn: Connection,
}

#[derive(Debug, Clone)]
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
}

#[derive(Debug, Clone)]
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
    pub last_seq_sent: i64,
    pub last_seq_acked: i64,
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

            CREATE TABLE IF NOT EXISTS outbound_queue (
                batch_uuid      TEXT PRIMARY KEY,
                share_id        BLOB NOT NULL,
                payload         BLOB NOT NULL,
                created_at      INTEGER NOT NULL,
                attempts        INTEGER NOT NULL DEFAULT 0,
                status          TEXT NOT NULL DEFAULT 'pending',
                last_error      TEXT,
                next_attempt_at INTEGER NOT NULL,
                peer_id         INTEGER REFERENCES peers(id)
            );

            CREATE TABLE IF NOT EXISTS inbound_batches (
                batch_uuid TEXT PRIMARY KEY,
                received_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS change_log (
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

            CREATE TABLE IF NOT EXISTS peer_progress (
                peer_id        INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
                share_id       INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
                last_seq_sent  INTEGER NOT NULL DEFAULT 0,
                last_seq_acked INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (peer_id, share_id)
            );

            CREATE TABLE IF NOT EXISTS share_progress (
                share_id       INTEGER NOT NULL UNIQUE REFERENCES shares(id) ON DELETE CASCADE,
                last_seq_applied INTEGER NOT NULL DEFAULT 0
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

        self.conn
            .execute_batch(&format!("PRAGMA user_version = {DB_SCHEMA_VERSION};"))?;

        Ok(())
    }

    pub fn schema_version(&self) -> Result<i32> {
        self.conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
    }

    /// Ensure shares from config exist; return loaded ShareContexts (indexes loaded).
    pub fn load_shares(&self, cfg: &AppConfig) -> Result<Vec<ShareContext>> {
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

    /// Clean up old batches to stop the table growing forever.
    /// max_age_secs: delete batches older than now - max_age_secs.
    pub fn cleanup_old_batches(&self, max_age_secs: i64) -> Result<usize> {
        use time::OffsetDateTime;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let cutoff = now - max_age_secs;
        let rows = self
            .conn
            .execute("DELETE FROM batches WHERE created_at < ?1", params![cutoff])?;
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
    ) -> Result<()> {
        let payload = serde_json::to_vec(manifest).expect("serialize manifest");
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        self.conn.execute(
            r#"
            INSERT OR IGNORE INTO outbound_queue
              (batch_uuid, share_id, payload, created_at, attempts, status, last_error, next_attempt_at, peer_id)
            VALUES (?1, ?2, ?3, ?4, 0, 'pending', NULL, ?4, ?5)
            "#,
            params![manifest.batch_id, &manifest.share_id.0[..], payload, now, peer_id],
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
            SELECT batch_uuid, payload, attempts, peer_id
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

    /* Change log + progress */

    pub fn next_change_seq(&self, share_row_id: i64) -> Result<i64> {
        let mut stmt = self
            .conn
            .prepare("SELECT COALESCE(MAX(seq), 0) + 1 FROM change_log WHERE share_id = ?1")?;
        let next: i64 = stmt.query_row(params![share_row_id], |row| row.get(0))?;
        Ok(next)
    }

    pub fn append_change_log(
        &self,
        share_row_id: i64,
        change: &FileChange,
        created_at: i64,
    ) -> Result<i64> {
        let seq = if change.seq > 0 {
            change.seq
        } else {
            self.next_change_seq(share_row_id)?
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

        self.conn.execute(
            r#"
            INSERT INTO change_log
              (share_id, seq, path, kind, size, mtime, hash, version, deleted, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
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
                created_at
            ],
        )?;
        self.conn.execute(
            r#"
            INSERT INTO share_progress (share_id, last_seq_applied)
            VALUES (?1, ?2)
            ON CONFLICT(share_id) DO UPDATE SET last_seq_applied=excluded.last_seq_applied
            "#,
            params![share_row_id, seq],
        )?;
        Ok(seq)
    }

    pub fn get_last_applied_seq(&self, share_row_id: i64) -> Result<i64> {
        let mut stmt = self
            .conn
            .prepare("SELECT last_seq_applied FROM share_progress WHERE share_id=?1")?;
        match stmt.query_row(params![share_row_id], |row| row.get(0)) {
            Ok(seq) => Ok(seq),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
            Err(e) => Err(e),
        }
    }

    pub fn list_changes_since(
        &self,
        share_row_id: i64,
        from_seq_exclusive: i64,
        limit: usize,
    ) -> Result<Vec<FileChange>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT seq, path, kind, size, mtime, hash, version, deleted
            FROM change_log
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
                Ok(FileChange {
                    seq,
                    share_id: ShareId([0u8; 16]), // caller should overwrite
                    path,
                    kind: ck,
                    meta,
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
                last_seq_sent = excluded.last_seq_sent
            "#,
            params![peer_id, share_row_id, new_sent],
        )?;
        Ok(())
    }

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
                last_seq_acked = excluded.last_seq_acked,
                last_seq_sent = MAX(peer_progress.last_seq_sent, excluded.last_seq_sent)
            "#,
            params![peer_id, share_row_id, new_acked],
        )?;
        Ok(())
    }

    /* Status/observability helpers */

    pub fn list_peers(&self) -> Result<Vec<PeerRow>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, pc_name, instance_id, last_ip, last_port, last_tls_port, last_plain_port, last_seen, state, prefer_tls, last_insecure_seen
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
                pp.last_seq_acked
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

    pub fn change_log_total(&self) -> Result<i64> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM change_log")?;
        let n: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(n)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundQueueItem {
    pub batch_id: String,
    pub manifest: models::BatchManifest,
    pub attempts: i64,
    pub peer_id: Option<i64>,
}
