use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use db::Db;
use models::{
    AppConfig, ApplicationState, BatchManifest, ChangeKind, FileChange, FileMeta, ShareConfig,
    ShareId,
};

fn test_config(pc_name: &str, share_name: &str) -> AppConfig {
    AppConfig {
        pc_name: pc_name.to_string(),
        instance_id: "inst".to_string(),
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        plain_listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        use_tls_for_peers: true,
        discovery_port: 0,
        aggregation_window_ms: 100,
        db_path: PathBuf::new(),
        log_path: PathBuf::new(),
        tls_cert_path: PathBuf::new(),
        tls_key_path: PathBuf::new(),
        tls_ca_cert_path: PathBuf::new(),
        tls_pinned_ca_fingerprints: Vec::new(),
        tls_peer_fingerprints: std::collections::HashMap::new(),
        remote_share_root: PathBuf::from("remote"),
        shares: vec![ShareConfig {
            name: share_name.to_string(),
            root_path: PathBuf::from("/share"),
            recursive: true,
            ignore_patterns: Vec::new(),
            max_file_size_bytes: None,
        }],
        app_state: ApplicationState::MirrorHost,
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
fn load_shares_skips_when_state_disables_sharing() {
    let db = Db::open_in_memory().unwrap();
    let mut cfg = test_config("pc-one", "shareA");
    cfg.app_state = ApplicationState::MirrorOnly;
    let shares = db.load_shares(&cfg).unwrap();
    assert!(shares.is_empty());
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
        protocol_version: models::WIRE_PROTOCOL_VERSION,
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
fn status_helpers_report_queue_depth_and_peers() {
    let db = Db::open_in_memory().unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    assert_eq!(db.outbound_queue_depth().unwrap(), 0);
    assert_eq!(db.outbound_queue_due_now(now).unwrap(), 0);
    assert_eq!(db.change_log_total().unwrap(), 0);
    assert!(db.list_peers().unwrap().is_empty());

    let peer_id = db
        .upsert_peer(
            "pc-one",
            "inst-one",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000),
            now,
            "connected",
            5000,
            0,
            true,
        )
        .unwrap();
    let peers = db.list_peers().unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].id, peer_id);

    let cfg = test_config("pc-two", "shareA");
    let shares = db.load_shares(&cfg).unwrap();
    assert!(!shares.is_empty());
    assert!(!db.list_shares_table().unwrap().is_empty());

    let share_row_id = shares[0].id;
    db.set_peer_progress(peer_id, share_row_id, 10, 9).unwrap();
    let progress = db.list_peer_progress_table().unwrap();
    assert_eq!(progress.len(), 1);
    assert_eq!(progress[0].last_seq_sent, 10);
    assert_eq!(progress[0].last_seq_acked, 9);

    let manifest = BatchManifest {
        protocol_version: models::WIRE_PROTOCOL_VERSION,
        batch_id: "batch-status-1".to_string(),
        share_id: shares[0].share_id,
        from_node: "pc-two".to_string(),
        created_at: now,
        changes: vec![FileChange {
            seq: 0,
            share_id: shares[0].share_id,
            path: "x.txt".to_string(),
            kind: ChangeKind::Modify,
            meta: Some(FileMeta {
                path: "x.txt".to_string(),
                size: 1,
                mtime: now,
                hash: [1u8; 32],
                version: 1,
                deleted: false,
            }),
        }],
    };
    db.enqueue_outbound_batch(&manifest, Some(peer_id)).unwrap();
    assert_eq!(db.outbound_queue_depth().unwrap(), 1);
    assert_eq!(db.outbound_queue_due_now(now).unwrap(), 1);
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

    let seq = db
        .append_change_log(share_row_id, &change, created_at)
        .unwrap();
    assert_eq!(seq, 1);

    let changes = db.list_changes_since(share_row_id, 0, 10).unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].seq, 1);
    assert_eq!(changes[0].path, "a.txt");
    assert_eq!(changes[0].kind, ChangeKind::Create);
    assert!(changes[0].meta.is_some());
}
