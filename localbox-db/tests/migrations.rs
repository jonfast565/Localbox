use localbox_db as db;
use db::Db;
use rusqlite::Connection;
use utilities::test_temp_path;

#[test]
fn db_sets_user_version_and_is_backward_openable() {
    let path = test_temp_path("localbox-mig-v0").with_extension("db");

    // Simulate an "older" DB file: user_version=0 and only a subset of tables.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            PRAGMA user_version = 0;
            CREATE TABLE IF NOT EXISTS peers (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                pc_name      TEXT NOT NULL,
                instance_id  TEXT NOT NULL,
                last_ip      TEXT NOT NULL,
                last_port    INTEGER NOT NULL,
                last_seen    INTEGER NOT NULL,
                state        TEXT NOT NULL,
                UNIQUE (pc_name, instance_id)
            );
            "#,
        )
        .unwrap();
    }

    let db = Db::open(&path).unwrap();
    assert_eq!(db.schema_version().unwrap(), 7);
    // Should have created the full schema.
    assert!(db.list_shares_table().unwrap().is_empty());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn db_migrates_http_port_column_to_plain_port() {
    let path = test_temp_path("localbox-mig-http").with_extension("db");
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            PRAGMA user_version = 2;
            CREATE TABLE IF NOT EXISTS peers (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                pc_name      TEXT NOT NULL,
                instance_id  TEXT NOT NULL,
                last_ip      TEXT NOT NULL,
                last_port    INTEGER NOT NULL,
                last_tls_port INTEGER NOT NULL DEFAULT 0,
                last_http_port INTEGER NOT NULL DEFAULT 0,
                last_seen    INTEGER NOT NULL,
                state        TEXT NOT NULL,
                prefer_tls   INTEGER NOT NULL DEFAULT 1,
                last_insecure_seen INTEGER NOT NULL DEFAULT 0,
                UNIQUE (pc_name, instance_id)
            );
            INSERT INTO peers (pc_name, instance_id, last_ip, last_port, last_tls_port, last_http_port, last_seen, state, prefer_tls, last_insecure_seen)
            VALUES ('pc-old', 'inst', '127.0.0.1', 4000, 8443, 8080, 123, 'known', 1, 0);
            "#,
        )
        .unwrap();
    }

    let db = Db::open(&path).unwrap();
    assert_eq!(db.schema_version().unwrap(), 7);
    drop(db);

    let conn = Connection::open(&path).unwrap();
    let plain_port: i64 = conn
        .query_row(
            "SELECT last_plain_port FROM peers WHERE pc_name='pc-old'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(plain_port, 8080);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn db_migrates_v4_to_current_adds_intents_and_share_journal() {
    let path = test_temp_path("localbox-mig-v4").with_extension("db");
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            PRAGMA user_version = 4;
            CREATE TABLE IF NOT EXISTS peers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pc_name TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                last_ip TEXT NOT NULL,
                last_port INTEGER NOT NULL,
                last_tls_port INTEGER NOT NULL DEFAULT 0,
                last_plain_port INTEGER NOT NULL DEFAULT 0,
                last_seen INTEGER NOT NULL,
                state TEXT NOT NULL,
                prefer_tls INTEGER NOT NULL DEFAULT 1,
                last_insecure_seen INTEGER NOT NULL DEFAULT 0,
                UNIQUE (pc_name, instance_id)
            );
            CREATE TABLE IF NOT EXISTS shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                share_name TEXT NOT NULL,
                pc_name TEXT NOT NULL,
                share_id BLOB NOT NULL,
                root_path TEXT NOT NULL,
                recursive INTEGER NOT NULL,
                UNIQUE (share_name, pc_name)
            );
            CREATE TABLE IF NOT EXISTS outbound_queue (
                batch_uuid TEXT PRIMARY KEY,
                share_id BLOB NOT NULL,
                payload BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending',
                last_error TEXT,
                next_attempt_at INTEGER NOT NULL,
                peer_id INTEGER REFERENCES peers(id)
            );
            CREATE TABLE IF NOT EXISTS change_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                share_id INTEGER NOT NULL,
                seq INTEGER NOT NULL,
                path TEXT NOT NULL,
                kind TEXT NOT NULL,
                size INTEGER,
                mtime INTEGER,
                hash BLOB,
                version INTEGER,
                deleted INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE (share_id, seq)
            );
            "#,
        )
        .unwrap();
    }

    let db = Db::open(&path).unwrap();
    assert_eq!(db.schema_version().unwrap(), 7);
    drop(db);

    let conn = Connection::open(&path).unwrap();
    let has_intents: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='transfer_intents'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(has_intents, 1);
    let has_journal: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='share_journal'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(has_journal, 1);
    let has_old: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='change_log'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(has_old, 0);
    let mut stmt = conn.prepare("PRAGMA table_info(outbound_queue)").unwrap();
    let cols: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert!(cols.iter().any(|c| c == "intent_id"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn db_migrates_v6_to_v7_separates_seq_namespaces() {
    let path = test_temp_path("localbox-mig-v6").with_extension("db");
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            PRAGMA user_version = 6;
            CREATE TABLE IF NOT EXISTS peers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pc_name TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                last_ip TEXT NOT NULL,
                last_port INTEGER NOT NULL,
                last_tls_port INTEGER NOT NULL DEFAULT 0,
                last_plain_port INTEGER NOT NULL DEFAULT 0,
                last_seen INTEGER NOT NULL,
                state TEXT NOT NULL,
                prefer_tls INTEGER NOT NULL DEFAULT 1,
                last_insecure_seen INTEGER NOT NULL DEFAULT 0,
                UNIQUE (pc_name, instance_id)
            );
            CREATE TABLE IF NOT EXISTS shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                share_name TEXT NOT NULL,
                pc_name TEXT NOT NULL,
                share_id BLOB NOT NULL,
                root_path TEXT NOT NULL,
                recursive INTEGER NOT NULL,
                UNIQUE (share_name, pc_name)
            );
            CREATE TABLE IF NOT EXISTS share_journal (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                share_id INTEGER NOT NULL,
                seq INTEGER NOT NULL,
                path TEXT NOT NULL,
                kind TEXT NOT NULL,
                size INTEGER,
                mtime INTEGER,
                hash BLOB,
                version INTEGER,
                deleted INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                UNIQUE (share_id, seq)
            );
            CREATE TABLE IF NOT EXISTS peer_progress (
                peer_id INTEGER NOT NULL,
                share_id INTEGER NOT NULL,
                last_seq_sent INTEGER NOT NULL DEFAULT 0,
                last_seq_acked INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (peer_id, share_id)
            );
            CREATE TABLE IF NOT EXISTS transfer_intents (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                origin TEXT NOT NULL,
                status TEXT NOT NULL,
                share_name TEXT NOT NULL,
                share_id BLOB NOT NULL,
                peer_id INTEGER,
                basis_json TEXT NOT NULL,
                request_id TEXT,
                last_error TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            INSERT INTO share_journal
              (share_id, seq, path, kind, size, mtime, hash, version, deleted, created_at)
            VALUES (1, 4, 'legacy.txt', 'Modify', 1, 0, X'00', 4, 0, 0);
            INSERT INTO peer_progress (peer_id, share_id, last_seq_sent, last_seq_acked)
            VALUES (1, 1, 9, 9);
            INSERT INTO transfer_intents
              (id, kind, origin, status, share_name, share_id, peer_id, basis_json,
               request_id, last_error, created_at, updated_at)
            VALUES ('i1', 'push', 'auto_push', 'acked', 's', X'00', 1, '{}', NULL, NULL, 0, 0);
            "#,
        )
        .unwrap();
    }

    let db = Db::open(&path).unwrap();
    assert_eq!(db.schema_version().unwrap(), 7);
    drop(db);

    let conn = Connection::open(&path).unwrap();

    // New columns exist, and pre-existing journal rows read as locally authored.
    let (origin_peer, origin_seq): (Option<i64>, i64) = conn
        .query_row(
            "SELECT origin_peer_id, origin_seq FROM share_journal WHERE path='legacy.txt'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(origin_peer, None);
    assert_eq!(origin_seq, 0);

    // Contaminated watermarks are discarded rather than guessed at, so the
    // node re-catches-up once instead of silently skipping history.
    let (sent, acked, recv): (i64, i64, i64) = conn
        .query_row(
            "SELECT last_seq_sent, last_seq_acked, last_seq_recv FROM peer_progress",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((sent, acked, recv), (0, 0, 0));

    // Intent vocabulary is migrated in place.
    let (kind, origin): (String, String) = conn
        .query_row(
            "SELECT kind, origin FROM transfer_intents WHERE id='i1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(kind, "snapshot_push");
    assert_eq!(origin, "auto_sync");

    // The replay gate is in place.
    let has_index: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_share_journal_origin'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(has_index, 1);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn legacy_intent_spellings_still_parse() {
    assert_eq!(
        models::IntentKind::parse("push"),
        Some(models::IntentKind::SnapshotPush)
    );
    assert_eq!(
        models::IntentOrigin::parse("auto_push"),
        Some(models::IntentOrigin::AutoSync)
    );
}
