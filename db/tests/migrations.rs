use std::path::PathBuf;

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
    assert_eq!(db.schema_version().unwrap(), 1);
    // Should have created the full schema.
    assert!(db.list_shares_table().unwrap().is_empty());

    let _ = std::fs::remove_file(&path);
}

