use std::path::PathBuf;

use localbox_db as db;
use db::Db;
use rusqlite::Connection;
use uuid::Uuid;

#[test]
fn db_sets_user_version_and_is_backward_openable() {
    let path: PathBuf = std::env::temp_dir().join(format!("localbox-mig-{}.db", Uuid::new_v4()));

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
    assert_eq!(db.schema_version().unwrap(), 3);
    // Should have created the full schema.
    assert!(db.list_shares_table().unwrap().is_empty());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn db_migrates_http_port_column_to_plain_port() {
    let path: PathBuf = std::env::temp_dir().join(format!("localbox-mig-{}.db", Uuid::new_v4()));
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
    assert_eq!(db.schema_version().unwrap(), 3);
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
