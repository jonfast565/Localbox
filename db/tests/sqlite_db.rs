use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use db::Db;
use models::{AppConfig, BatchManifest, ChangeKind, FileChange, FileMeta, ShareConfig, ShareId};

fn test_config(pc_name: &str, share_name: &str) -> AppConfig {
    AppConfig {
        pc_name: pc_name.to_string(),
        instance_id: "inst".to_string(),
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        discovery_port: 0,
        aggregation_window_ms: 100,
        db_path: PathBuf::new(),
        log_path: PathBuf::new(),
        tls_cert_path: PathBuf::new(),
        tls_key_path: PathBuf::new(),
        tls_ca_cert_path: PathBuf::new(),
        remote_share_root: PathBuf::from("remote"),
        shares: vec![ShareConfig {
            name: share_name.to_string(),
            root_path: PathBuf::from("/share"),
            recursive: true,
        }],
    }
}

#[test]
fn load_shares_creates_contexts_with_stable_ids() {
    let db = Db::open_in_memory().unwrap();
    let cfg = test_config("pc-one", "shareA");
    let shares = db.load_shares(&cfg).unwrap();
    assert_eq!(shares.len(), 1);

    let sc = &shares[0];
    assert_eq!(sc.share_name, "shareA");
    assert_eq!(sc.pc_name, "pc-one");
    assert_eq!(sc.share_id, ShareId::new("shareA", "pc-one"));
    assert_eq!(sc.root_path.to_string_lossy(), "/share");
    assert!(sc.recursive);
}

#[test]
fn inbound_batches_are_deduplicated() {
    let db = Db::open_in_memory().unwrap();
    assert!(db.record_inbound_batch("b1").unwrap());
    assert!(!db.record_inbound_batch("b1").unwrap());
}

#[test]
fn outbound_queue_round_trip_and_mark_sent() {
    let db = Db::open_in_memory().unwrap();
    let cfg = test_config("pc-one", "shareA");
    let shares = db.load_shares(&cfg).unwrap();

    let share_id = shares[0].share_id;
    let manifest = BatchManifest {
        batch_id: "batch-1".to_string(),
        share_id,
        from_node: "pc-one".to_string(),
        created_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        changes: vec![FileChange {
            seq: 0,
            share_id,
            path: "a.txt".to_string(),
            kind: ChangeKind::Modify,
            meta: Some(FileMeta {
                path: "a.txt".to_string(),
                size: 1,
                mtime: time::OffsetDateTime::now_utc().unix_timestamp(),
                hash: [7u8; 32],
                version: 1,
                deleted: false,
            }),
        }],
    };

    db.enqueue_outbound_batch(&manifest, None).unwrap();

    let now = time::OffsetDateTime::now_utc().unix_timestamp() + 1;
    let due = db.dequeue_due_outbound(10, now).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].batch_id, "batch-1");
    assert_eq!(due[0].manifest.share_id, share_id);
    assert_eq!(due[0].manifest.changes.len(), 1);

    db.mark_outbound_sent("batch-1").unwrap();
    let due2 = db.dequeue_due_outbound(10, now).unwrap();
    assert!(due2.is_empty());
}

#[test]
fn change_log_append_and_list() {
    let db = Db::open_in_memory().unwrap();
    let cfg = test_config("pc-one", "shareA");
    let shares = db.load_shares(&cfg).unwrap();
    let share_row_id = shares[0].id;
    let share_id = shares[0].share_id;

    let created_at = time::OffsetDateTime::now_utc().unix_timestamp();
    let change = FileChange {
        seq: 0,
        share_id,
        path: "a.txt".to_string(),
        kind: ChangeKind::Create,
        meta: Some(FileMeta {
            path: "a.txt".to_string(),
            size: 2,
            mtime: created_at,
            hash: [1u8; 32],
            version: 1,
            deleted: false,
        }),
    };

    let seq = db.append_change_log(share_row_id, &change, created_at).unwrap();
    assert_eq!(seq, 1);

    let changes = db.list_changes_since(share_row_id, 0, 10).unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].seq, 1);
    assert_eq!(changes[0].path, "a.txt");
    assert_eq!(changes[0].kind, ChangeKind::Create);
    assert!(changes[0].meta.is_some());
}

