use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use localbox_db as db;
use db::Db;
use models::{
    peer_thread_id, AppConfig, ApplicationState, BatchManifest, ChangeKind, ChatMessageRecord,
    FileChange, FileMeta, ShareConfig, ShareId, ThreadKind, TransferRequest,
    WIRE_PROTOCOL_VERSION,
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
            tls_insecure_shared_cert: false,
        remote_share_root: PathBuf::from("remote"),
        shares: vec![ShareConfig {
            name: share_name.to_string(),
            root_path: PathBuf::from("/share"),
            recursive: true,
            ignore_patterns: Vec::new(),
            max_file_size_bytes: None,
            push: Default::default(),
            pull: Default::default(),
            request_handling: None,
        }],
        app_state: ApplicationState::MirrorHost,
        request_handling: Default::default(),
        peer_policies: Vec::new(),
        control_socket: std::path::PathBuf::from("localbox.sock"),
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

    db.enqueue_outbound_batch(&manifest, None, None).unwrap();

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
    db.enqueue_outbound_batch(&manifest, Some(peer_id), None).unwrap();
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

#[test]
fn schema_version_is_six() {
    let db = Db::open_in_memory().unwrap();
    assert_eq!(db.schema_version().unwrap(), 6);
}

#[test]
fn migrates_v4_to_v6_renames_share_journal() {
    use rusqlite::Connection;

    let dir = std::env::temp_dir().join(format!(
        "localbox-mig-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("migrate.db");
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            r#"
            PRAGMA user_version = 4;
            CREATE TABLE peers (
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
            CREATE TABLE shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                share_name TEXT NOT NULL,
                pc_name TEXT NOT NULL,
                share_id BLOB NOT NULL,
                root_path TEXT NOT NULL,
                recursive INTEGER NOT NULL,
                UNIQUE (share_name, pc_name)
            );
            CREATE TABLE change_log (
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
            CREATE TABLE outbound_queue (
                batch_uuid TEXT PRIMARY KEY,
                share_id BLOB NOT NULL,
                payload BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending',
                last_error TEXT,
                next_attempt_at INTEGER NOT NULL,
                peer_id INTEGER
            );
            CREATE TABLE chat_threads (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                peer_key TEXT,
                share_name TEXT,
                title TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                unread_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE chat_messages (
                id TEXT PRIMARY KEY,
                thread_id TEXT NOT NULL,
                from_peer TEXT NOT NULL,
                body TEXT NOT NULL,
                attachment_share TEXT,
                attachment_path TEXT,
                created_at INTEGER NOT NULL,
                direction TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'sent'
            );
            CREATE TABLE transfer_requests (
                request_id TEXT PRIMARY KEY,
                peer_id INTEGER,
                share_name TEXT NOT NULL,
                share_id BLOB,
                paths_json TEXT NOT NULL DEFAULT '[]',
                since_seq INTEGER NOT NULL DEFAULT 0,
                from_pc TEXT NOT NULL,
                from_instance TEXT NOT NULL,
                direction TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                reason TEXT,
                created_at INTEGER NOT NULL
            );
            "#,
        )
        .unwrap();
        conn.execute(
            "INSERT INTO shares (share_name, pc_name, share_id, root_path, recursive) VALUES ('s','pc', X'00000000000000000000000000000001', '/tmp', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO change_log (share_id, seq, path, kind, deleted, created_at) VALUES (1, 1, 'a.txt', 'Create', 0, 1)",
            [],
        )
        .unwrap();
    }
    let db = Db::open(&path).unwrap();
    assert_eq!(db.schema_version().unwrap(), 6);
    assert_eq!(db.share_journal_total().unwrap(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn chat_threads_and_messages_round_trip() {
    let db = Db::open_in_memory().unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let tid = peer_thread_id("a@1", "b@2");
    db.ensure_thread(&tid, ThreadKind::Peer, Some("b@2"), None, "b@2", now)
        .unwrap();
    let msg = ChatMessageRecord {
        id: "m1".into(),
        thread_id: tid.clone(),
        from_peer: "a@1".into(),
        body: "hello".into(),
        attachment_share: None,
        attachment_path: None,
        created_at: now,
        direction: "in".into(),
        status: "received".into(),
    };
    db.insert_message(&msg, true).unwrap();
    let inbox = db.list_inbox().unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].unread_count, 1);
    let messages = db.list_messages(&tid, 10).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].body, "hello");
    db.mark_thread_read(&tid).unwrap();
    assert_eq!(db.list_inbox().unwrap()[0].unread_count, 0);
    db.update_chat_message_status("m1", "acked").unwrap();
    assert_eq!(db.list_messages(&tid, 10).unwrap()[0].status, "acked");
}

#[test]
fn pending_transfer_requests_crud() {
    let db = Db::open_in_memory().unwrap();
    let req = TransferRequest {
        protocol_version: WIRE_PROTOCOL_VERSION,
        request_id: "r1".into(),
        share_id: ShareId::new("docs", "pc-a"),
        share_name: "docs".into(),
        since_seq: 3,
        paths: vec!["a.txt".into()],
        from_pc: "pc-b".into(),
        from_instance: "i1".into(),
    };
    db.insert_pending_request(&req, None, "in", "pending")
        .unwrap();
    let pending = db.list_pending_requests().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].request_id, "r1");
    assert_eq!(pending[0].since_seq, 3);
    db.update_pending_request_status("r1", "accepted", None)
        .unwrap();
    assert!(db.list_pending_requests().unwrap().is_empty());
    let got = db.get_pending_request("r1").unwrap().unwrap();
    assert_eq!(got.status, "accepted");
    db.delete_pending_request("r1").unwrap();
    assert!(db.get_pending_request("r1").unwrap().is_none());
}

#[test]
fn snapshot_push_does_not_change_peer_progress() {
    use models::{IntentBasis, IntentKind, IntentOrigin};

    let db = Db::open_in_memory().unwrap();
    let cfg = test_config("pc-one", "shareA");
    let shares = db.load_shares(&cfg).unwrap();
    let share = &shares[0];
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let peer_id = db
        .upsert_peer(
            "pc-two",
            "inst-two",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000),
            now,
            "connected",
            5000,
            0,
            true,
        )
        .unwrap();

    let meta = FileMeta {
        path: "only.txt".into(),
        size: 4,
        mtime: now,
        hash: [9u8; 32],
        version: 1,
        deleted: false,
    };
    db.upsert_file_meta(share.id, &meta).unwrap();

    let (intent_id, batch_ids) = db
        .create_and_materialize_intent(
            IntentKind::Push,
            IntentOrigin::User,
            &share.share_name,
            share.share_id,
            Some(peer_id),
            IntentBasis::Snapshot {
                paths: vec!["only.txt".into()],
            },
            None,
            "pc-one",
        )
        .unwrap();
    assert!(!batch_ids.is_empty());
    assert_eq!(db.get_peer_progress(peer_id, share.id).unwrap(), (0, 0));

    db.on_outbound_batch_sent(&batch_ids[0], peer_id, &share.share_id, 0)
        .unwrap();
    assert_eq!(db.get_peer_progress(peer_id, share.id).unwrap(), (0, 0));
    db.on_batch_ack(peer_id, &share.share_id, 99, Some(&batch_ids[0]))
        .unwrap();
    assert_eq!(db.get_peer_progress(peer_id, share.id).unwrap(), (0, 0));

    let intent = db.get_transfer_intent(&intent_id).unwrap().unwrap();
    assert_eq!(intent.kind, IntentKind::Push);
}

#[test]
fn sync_catchup_advances_watermarks_on_ack() {
    use models::{IntentBasis, IntentKind, IntentOrigin, IntentStatus};

    let db = Db::open_in_memory().unwrap();
    let cfg = test_config("pc-one", "shareA");
    let shares = db.load_shares(&cfg).unwrap();
    let share = &shares[0];
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let peer_id = db
        .upsert_peer(
            "pc-two",
            "inst-two",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000),
            now,
            "connected",
            5000,
            0,
            true,
        )
        .unwrap();

    let mut change = FileChange {
        seq: 0,
        share_id: share.share_id,
        path: "a.txt".into(),
        kind: ChangeKind::Create,
        meta: Some(FileMeta {
            path: "a.txt".into(),
            size: 1,
            mtime: now,
            hash: [1u8; 32],
            version: 1,
            deleted: false,
        }),
    };
    let seq = db.append_change_log(share.id, &change, now).unwrap();
    change.seq = seq;

    let (_intent_id, batch_ids) = db
        .create_and_materialize_intent(
            IntentKind::SyncCatchup,
            IntentOrigin::AutoPush,
            &share.share_name,
            share.share_id,
            Some(peer_id),
            IntentBasis::JournalRange {
                from_seq: 0,
                to_seq: seq,
            },
            None,
            "pc-one",
        )
        .unwrap();
    assert!(!batch_ids.is_empty());

    db.on_outbound_batch_sent(&batch_ids[0], peer_id, &share.share_id, seq)
        .unwrap();
    assert_eq!(db.get_peer_progress(peer_id, share.id).unwrap().0, seq);

    db.on_batch_ack(peer_id, &share.share_id, seq, Some(&batch_ids[0]))
        .unwrap();
    assert_eq!(db.get_peer_progress(peer_id, share.id).unwrap().1, seq);

    let intent = db.get_transfer_intent(&_intent_id).unwrap().unwrap();
    assert_eq!(intent.status, IntentStatus::Acked);
}

#[test]
fn manual_path_snapshot_uses_index_not_full_journal() {
    use models::{IntentBasis, IntentKind, IntentOrigin};

    let db = Db::open_in_memory().unwrap();
    let cfg = test_config("pc-one", "shareA");
    let shares = db.load_shares(&cfg).unwrap();
    let share = &shares[0];
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    // Journal has an old path that is no longer in the index.
    let old = FileChange {
        seq: 0,
        share_id: share.share_id,
        path: "gone.txt".into(),
        kind: ChangeKind::Create,
        meta: Some(FileMeta {
            path: "gone.txt".into(),
            size: 1,
            mtime: now,
            hash: [2u8; 32],
            version: 1,
            deleted: false,
        }),
    };
    let _ = db.append_change_log(share.id, &old, now).unwrap();

    db.upsert_file_meta(
        share.id,
        &FileMeta {
            path: "keep.txt".into(),
            size: 2,
            mtime: now,
            hash: [3u8; 32],
            version: 2,
            deleted: false,
        },
    )
    .unwrap();

    let (_intent_id, batch_ids) = db
        .create_and_materialize_intent(
            IntentKind::Push,
            IntentOrigin::User,
            &share.share_name,
            share.share_id,
            None,
            IntentBasis::Snapshot {
                paths: vec!["keep.txt".into()],
            },
            None,
            "pc-one",
        )
        .unwrap();
    assert_eq!(batch_ids.len(), 1);
    let due = db
        .dequeue_due_outbound(10, now + 1)
        .unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].manifest.changes.len(), 1);
    assert_eq!(due[0].manifest.changes[0].path, "keep.txt");
    assert_eq!(due[0].manifest.changes[0].seq, 0);
}
