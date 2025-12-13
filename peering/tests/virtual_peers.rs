use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use db::Db;
use models::{AppConfig, ChangeKind, FileChange, FileMeta, ShareConfig};
use peering::PeerManager;
use rcgen;
use time::OffsetDateTime;
use tokio::sync::{mpsc, Mutex};
use utilities::{FileSystem, Net, VirtualFileSystem, VirtualNet};
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "current_thread")]
async fn virtual_peers_exchange_changes() {
    let net: Arc<dyn Net> = Arc::new(VirtualNet::default());
    let fs1: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());
    let fs2: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());

    let tls_paths1 = TlsPaths::new("cert1.pem", "key1.pem", "ca.pem");
    let tls_paths2 = TlsPaths::new("cert2.pem", "key2.pem", "ca.pem");
    let tls_material = generate_shared_tls(&["pc-one", "pc-two", "localhost"]);
    write_shared_tls(fs1.as_ref(), &tls_paths1, &tls_material);
    write_shared_tls(fs2.as_ref(), &tls_paths2, &tls_material);

    let cfg1 = test_config("pc-one", "inst-one", 6001, 7001, "shareA", &tls_paths1);
    let cfg2 = test_config("pc-two", "inst-two", 6002, 7001, "shareA", &tls_paths2);

    let db1 = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
    let db2 = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));

    let shares1 = db1.lock().await.load_shares(&cfg1).unwrap();
    let shares2 = db2.lock().await.load_shares(&cfg2).unwrap();

    let (net_tx1, net_rx1) = mpsc::channel(16);
    let (net_tx2, net_rx2) = mpsc::channel(16);

    let pm1 = PeerManager::new(
        cfg1.clone(),
        db1.clone(),
        net_tx1.clone(),
        shares1.clone(),
        fs1.clone(),
        net.clone(),
    )
    .unwrap();
    let tok1 = CancellationToken::new();
    let tok1_runner = tok1.clone();
    let pm2 = PeerManager::new(
        cfg2.clone(),
        db2.clone(),
        net_tx2.clone(),
        shares2.clone(),
        fs2.clone(),
        net.clone(),
    )
    .unwrap();
    let tok2 = CancellationToken::new();
    let tok2_runner = tok2.clone();

    let t1 = tokio::spawn(async move { pm1.run(net_rx1, tok1_runner).await.unwrap() });
    let t2 = tokio::spawn(async move { pm2.run(net_rx2, tok2_runner).await.unwrap() });

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Node1 sends a modify.
    enqueue_sample_batch(
        &db1,
        &shares1[0].share_id,
        "a.txt",
        ChangeKind::Modify,
        net_tx1.clone(),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Node2 sends a delete.
    enqueue_sample_batch(
        &db2,
        &shares2[0].share_id,
        "old.txt",
        ChangeKind::Delete,
        net_tx2.clone(),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Wait for remote share rows to materialize.
    let share_row2 = wait_for_share(&db2, &shares1[0].share_id).await;
    let changes_on_2 = db2
        .lock()
        .await
        .list_changes_since(share_row2, 0, 10)
        .unwrap();
    assert!(
        changes_on_2.iter().any(|c| c.path == "a.txt"),
        "peer2 should have received a.txt"
    );

    // Verify db1 received delete.
    let share_row1 = wait_for_share(&db1, &shares2[0].share_id).await;
    let changes_on_1 = db1
        .lock()
        .await
        .list_changes_since(share_row1, 0, 10)
        .unwrap();
    assert!(
        changes_on_1.iter().any(|c| c.path == "old.txt" && c.kind == ChangeKind::Delete),
        "peer1 should have received delete for old.txt"
    );

    drop(net_tx1);
    drop(net_tx2);
    tok1.cancel();
    tok2.cancel();
    let _ = t1.await;
    let _ = t2.await;
}

#[tokio::test(flavor = "current_thread")]
async fn replayed_change_does_not_clobber_file_meta() {
    let net: Arc<dyn Net> = Arc::new(VirtualNet::default());
    let fs1: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());
    let fs2: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());

    let tls_paths1 = TlsPaths::new("cert1.pem", "key1.pem", "ca.pem");
    let tls_paths2 = TlsPaths::new("cert2.pem", "key2.pem", "ca.pem");
    let tls_material = generate_shared_tls(&["pc-one", "pc-two", "localhost"]);
    write_shared_tls(fs1.as_ref(), &tls_paths1, &tls_material);
    write_shared_tls(fs2.as_ref(), &tls_paths2, &tls_material);

    let cfg1 = test_config("pc-one", "inst-one", 6101, 7101, "shareA", &tls_paths1);
    let cfg2 = test_config("pc-two", "inst-two", 6102, 7101, "shareA", &tls_paths2);

    let db1 = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
    let db2 = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));

    let shares1 = db1.lock().await.load_shares(&cfg1).unwrap();
    let shares2 = db2.lock().await.load_shares(&cfg2).unwrap();

    let (net_tx1, net_rx1) = mpsc::channel(16);
    let (net_tx2, net_rx2) = mpsc::channel(16);

    let pm1 = PeerManager::new(
        cfg1.clone(),
        db1.clone(),
        net_tx1.clone(),
        shares1.clone(),
        fs1.clone(),
        net.clone(),
    )
    .unwrap();
    let tok1 = CancellationToken::new();
    let tok1_runner = tok1.clone();
    let pm2 = PeerManager::new(
        cfg2.clone(),
        db2.clone(),
        net_tx2.clone(),
        shares2.clone(),
        fs2.clone(),
        net.clone(),
    )
    .unwrap();
    let tok2 = CancellationToken::new();
    let tok2_runner = tok2.clone();

    let t1 = tokio::spawn(async move { pm1.run(net_rx1, tok1_runner).await.unwrap() });
    let t2 = tokio::spawn(async move { pm2.run(net_rx2, tok2_runner).await.unwrap() });

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send seq=2 modify then seq=1 delete for the same path. The delete is a replay and must not
    // overwrite the file metadata on the receiver.
    enqueue_batch_with_seq(
        &db1,
        &shares1[0].share_id,
        "a.txt",
        ChangeKind::Modify,
        2,
        [2u8; 32],
        200,
        net_tx1.clone(),
    )
    .await;

    let share_row2 = wait_for_share(&db2, &shares1[0].share_id).await;
    wait_for_file_meta(&db2, share_row2, "a.txt").await;

    enqueue_batch_with_seq(
        &db1,
        &shares1[0].share_id,
        "a.txt",
        ChangeKind::Delete,
        1,
        [0u8; 32],
        100,
        net_tx1.clone(),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(500)).await;
    let meta = db2
        .lock()
        .await
        .get_file_meta(share_row2, "a.txt")
        .unwrap()
        .unwrap();
    assert!(!meta.deleted, "replayed delete must not mark file deleted");
    assert_eq!(meta.hash, [2u8; 32]);

    drop(net_tx1);
    drop(net_tx2);
    tok1.cancel();
    tok2.cancel();
    let _ = t1.await;
    let _ = t2.await;
}

fn test_config(
    pc_name: &str,
    instance_id: &str,
    listen_port: u16,
    discovery_port: u16,
    share_name: &str,
    tls: &TlsPaths,
) -> AppConfig {
    AppConfig {
        pc_name: pc_name.to_string(),
        instance_id: instance_id.to_string(),
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port),
        discovery_port,
        aggregation_window_ms: 100,
        db_path: PathBuf::from(""),
        log_path: PathBuf::from(""),
        tls_cert_path: tls.cert.clone(),
        tls_key_path: tls.key.clone(),
        tls_ca_cert_path: tls.ca.clone(),
        remote_share_root: PathBuf::from("remote"),
        shares: vec![ShareConfig {
            name: share_name.to_string(),
            root_path: PathBuf::from("/virtual"),
            recursive: true,
        }],
    }
}

async fn enqueue_sample_batch(
    db: &Arc<Mutex<Db>>,
    share_id: &models::ShareId,
    path: &str,
    kind: ChangeKind,
    net_tx: mpsc::Sender<String>,
) {
    let change = FileChange {
        seq: 0,
        share_id: *share_id,
        path: path.to_string(),
        kind: kind.clone(),
        meta: match kind {
            ChangeKind::Delete => None,
            _ => Some(FileMeta {
                path: path.to_string(),
                size: 1,
                mtime: OffsetDateTime::now_utc().unix_timestamp(),
                hash: [1u8; 32],
                version: 1,
                deleted: false,
            }),
        },
    };
    let manifest = models::BatchManifest {
        batch_id: format!("batch-{}", path),
        share_id: *share_id,
        from_node: "local".to_string(),
        created_at: OffsetDateTime::now_utc().unix_timestamp(),
        changes: vec![change],
    };
    let db_guard = db.lock().await;
    db_guard
        .enqueue_outbound_batch(&manifest, None)
        .unwrap();
    let _ = net_tx.try_send(manifest.batch_id);
}

async fn enqueue_batch_with_seq(
    db: &Arc<Mutex<Db>>,
    share_id: &models::ShareId,
    path: &str,
    kind: ChangeKind,
    seq: i64,
    hash: [u8; 32],
    mtime: i64,
    net_tx: mpsc::Sender<String>,
) {
    let change = FileChange {
        seq,
        share_id: *share_id,
        path: path.to_string(),
        kind: kind.clone(),
        meta: match kind {
            ChangeKind::Delete => None,
            _ => Some(FileMeta {
                path: path.to_string(),
                size: 1,
                mtime,
                hash,
                version: 1,
                deleted: false,
            }),
        },
    };
    let manifest = models::BatchManifest {
        batch_id: format!("batch-{}-{}", path, seq),
        share_id: *share_id,
        from_node: "local".to_string(),
        created_at: OffsetDateTime::now_utc().unix_timestamp(),
        changes: vec![change],
    };
    let db_guard = db.lock().await;
    db_guard
        .enqueue_outbound_batch(&manifest, None)
        .unwrap();
    let _ = net_tx.try_send(manifest.batch_id);
}

async fn wait_for_share(db: &Arc<Mutex<Db>>, share_id: &models::ShareId) -> i64 {
    for _ in 0..20 {
        if let Ok(id) = db.lock().await.get_share_row_id_by_share_id(share_id) {
            return id;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("share {:?} not registered in time", share_id.0);
}

async fn wait_for_file_meta(db: &Arc<Mutex<Db>>, share_row_id: i64, path: &str) {
    for _ in 0..20 {
        if let Ok(Some(_)) = db.lock().await.get_file_meta(share_row_id, path) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("file meta for {} not present in time", path);
}

#[derive(Clone)]
struct TlsPaths {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
}

impl TlsPaths {
    fn new(cert: &str, key: &str, ca: &str) -> Self {
        Self {
            cert: PathBuf::from(cert),
            key: PathBuf::from(key),
            ca: PathBuf::from(ca),
        }
    }
}

struct TlsMaterial {
    ca_pem: String,
    cert_pem: String,
    key_pem: String,
}

fn generate_shared_tls(names: &[&str]) -> TlsMaterial {
    let cert = rcgen::generate_simple_self_signed(
        names.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    )
    .unwrap();
    let ca_pem = cert.serialize_pem().unwrap();
    let cert_pem = ca_pem.clone();
    let key_pem = cert.serialize_private_key_pem();
    TlsMaterial {
        ca_pem,
        cert_pem,
        key_pem,
    }
}

fn write_shared_tls(fs: &dyn FileSystem, paths: &TlsPaths, mat: &TlsMaterial) {
    let _ = fs.write(&paths.cert, mat.cert_pem.as_bytes());
    let _ = fs.write(&paths.key, mat.key_pem.as_bytes());
    let _ = fs.write(&paths.ca, mat.ca_pem.as_bytes());
}
