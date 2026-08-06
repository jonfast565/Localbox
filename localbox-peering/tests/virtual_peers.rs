use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use db::Db;
use models::{
    AppConfig, ApplicationState, ChangeKind, ConflictPolicy, FileChange, FileMeta, ShareConfig,
    ShareContext,
};
use localbox_peering as peering;
use peering::PeerManager;
use rcgen;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use utilities::{
    disk_utilities::build_remote_share_root, FileSystem, Net, VirtualFileSystem, VirtualNet,
};

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
    let modify_bytes = b"hello-peer";
    enqueue_sample_batch(
        &db1,
        &shares1[0],
        fs1.clone(),
        "a.txt",
        ChangeKind::Modify,
        Some(modify_bytes),
        net_tx1.clone(),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Node2 sends a delete.
    enqueue_sample_batch(
        &db2,
        &shares2[0],
        fs2.clone(),
        "old.txt",
        ChangeKind::Delete,
        None,
        net_tx2.clone(),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Wait for remote share rows to materialize.
    let share_row2 = wait_for_share(&db2, &shares1[0].share_id).await;
    let changes_on_2 = db2
        .lock()
        .await
        .list_journal_since(share_row2, 0, 10)
        .unwrap();
    assert!(
        changes_on_2.iter().any(|c| c.change.path == "a.txt"),
        "peer2 should have received a.txt"
    );
    let remote_root = build_remote_share_root(
        &cfg2.remote_share_root,
        &cfg1.pc_name,
        &cfg1.instance_id,
        &shares1[0].share_name,
    );
    let mirrored_bytes = fs2.read(&remote_root.join("a.txt")).unwrap();
    assert_eq!(mirrored_bytes.as_slice(), modify_bytes);

    // Verify db1 received delete.
    let share_row1 = wait_for_share(&db1, &shares2[0].share_id).await;
    let changes_on_1 = db1
        .lock()
        .await
        .list_journal_since(share_row1, 0, 10)
        .unwrap();
    assert!(
        changes_on_1
            .iter()
            .any(|c| c.change.path == "old.txt" && c.change.kind == ChangeKind::Delete),
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

    // Build two entries in node1's journal for the same path: a delete at seq 1,
    // then a modify at seq 2. Ship the modify first, then re-ship the older
    // delete -- which discovery genuinely does when a bootstrap intent (from_seq 0)
    // races a catch-up. The delete is a replay and must not clobber the file.
    let replay_bytes = b"seq-two";
    let delete_seq = journal_change(
        &db1,
        &shares1[0],
        fs1.clone(),
        "a.txt",
        ChangeKind::Delete,
        None,
    )
    .await;
    let modify_seq = journal_change(
        &db1,
        &shares1[0],
        fs1.clone(),
        "a.txt",
        ChangeKind::Modify,
        Some(replay_bytes),
    )
    .await;
    assert_eq!((delete_seq, modify_seq), (1, 2));

    send_journal_range(&db1, &shares1[0], delete_seq, modify_seq, net_tx1.clone()).await;

    let share_row2 = wait_for_share(&db2, &shares1[0].share_id).await;
    wait_for_file_meta(&db2, share_row2, "a.txt").await;

    send_journal_range(&db1, &shares1[0], 0, delete_seq, net_tx1.clone()).await;

    tokio::time::sleep(Duration::from_millis(500)).await;
    let meta = db2
        .lock()
        .await
        .get_file_meta(share_row2, "a.txt")
        .unwrap()
        .unwrap();
    assert!(!meta.deleted, "replayed delete must not mark file deleted");
    assert_eq!(meta.hash, hash_bytes(replay_bytes));

    drop(net_tx1);
    drop(net_tx2);
    tok1.cancel();
    tok2.cancel();
    let _ = t1.await;
    let _ = t2.await;
}

#[tokio::test(flavor = "current_thread")]
async fn large_files_stream_correctly() {
    let net: Arc<dyn Net> = Arc::new(VirtualNet::default());
    let fs1: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());
    let fs2: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());

    let tls_paths1 = TlsPaths::new("cert1.pem", "key1.pem", "ca.pem");
    let tls_paths2 = TlsPaths::new("cert2.pem", "key2.pem", "ca.pem");
    let tls_material = generate_shared_tls(&["pc-one", "pc-two", "localhost"]);
    write_shared_tls(fs1.as_ref(), &tls_paths1, &tls_material);
    write_shared_tls(fs2.as_ref(), &tls_paths2, &tls_material);

    let cfg1 = test_config("pc-one", "inst-one", 6201, 7201, "shareA", &tls_paths1);
    let cfg2 = test_config("pc-two", "inst-two", 6202, 7201, "shareA", &tls_paths2);

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

    let large_bytes = vec![0xAB; 512 * 1024 + 1337];
    enqueue_sample_batch(
        &db1,
        &shares1[0],
        fs1.clone(),
        "big.bin",
        ChangeKind::Modify,
        Some(&large_bytes),
        net_tx1.clone(),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(1000)).await;

    let remote_root = build_remote_share_root(
        &cfg2.remote_share_root,
        &cfg1.pc_name,
        &cfg1.instance_id,
        &shares1[0].share_name,
    );
    let mirrored_bytes = wait_for_remote_file(&fs2, &remote_root, "big.bin").await;
    assert_eq!(mirrored_bytes, large_bytes);

    drop(net_tx1);
    drop(net_tx2);
    tok1.cancel();
    tok2.cancel();
    let _ = t1.await;
    let _ = t2.await;
}

#[tokio::test(flavor = "current_thread")]
async fn deletes_remove_remote_files() {
    let net: Arc<dyn Net> = Arc::new(VirtualNet::default());
    let fs1: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());
    let fs2: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());

    let tls_paths1 = TlsPaths::new("cert1.pem", "key1.pem", "ca.pem");
    let tls_paths2 = TlsPaths::new("cert2.pem", "key2.pem", "ca.pem");
    let tls_material = generate_shared_tls(&["pc-one", "pc-two", "localhost"]);
    write_shared_tls(fs1.as_ref(), &tls_paths1, &tls_material);
    write_shared_tls(fs2.as_ref(), &tls_paths2, &tls_material);

    let cfg1 = test_config("pc-one", "inst-one", 6301, 7301, "shareA", &tls_paths1);
    let cfg2 = test_config("pc-two", "inst-two", 6302, 7301, "shareA", &tls_paths2);

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

    enqueue_sample_batch(
        &db1,
        &shares1[0],
        fs1.clone(),
        "transient.txt",
        ChangeKind::Modify,
        Some(b"temporary"),
        net_tx1.clone(),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let remote_root = build_remote_share_root(
        &cfg2.remote_share_root,
        &cfg1.pc_name,
        &cfg1.instance_id,
        &shares1[0].share_name,
    );
    let _ = wait_for_remote_file(&fs2, &remote_root, "transient.txt").await;

    enqueue_sample_batch(
        &db1,
        &shares1[0],
        fs1.clone(),
        "transient.txt",
        ChangeKind::Delete,
        None,
        net_tx1.clone(),
    )
    .await;

    wait_for_remote_file_removed(&fs2, &remote_root, "transient.txt").await;

    drop(net_tx1);
    drop(net_tx2);
    tok1.cancel();
    tok2.cancel();
    let _ = t1.await;
    let _ = t2.await;
}

#[tokio::test(flavor = "current_thread")]
async fn mirror_only_nodes_host_remote_shares() {
    let net: Arc<dyn Net> = Arc::new(VirtualNet::default());
    let fs_host: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());
    let fs_mirror: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());

    let tls_host = TlsPaths::new("cert-host.pem", "key-host.pem", "ca.pem");
    let tls_mirror = TlsPaths::new("cert-mirror.pem", "key-mirror.pem", "ca.pem");
    let tls_material = generate_shared_tls(&["pc-host", "pc-mirror", "localhost"]);
    write_shared_tls(fs_host.as_ref(), &tls_host, &tls_material);
    write_shared_tls(fs_mirror.as_ref(), &tls_mirror, &tls_material);

    let cfg_host = test_config_with_state(
        "pc-host",
        "inst-host",
        6401,
        7401,
        "shareA",
        &tls_host,
        ApplicationState::HostOnly,
    );
    let cfg_mirror = test_config_with_state(
        "pc-mirror",
        "inst-mirror",
        6402,
        7401,
        "shareA",
        &tls_mirror,
        ApplicationState::MirrorOnly,
    );

    let db_host = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
    let db_mirror = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));

    let shares_host = db_host.lock().await.load_shares(&cfg_host).unwrap();
    let shares_mirror = db_mirror.lock().await.load_shares(&cfg_mirror).unwrap();
    assert!(
        shares_mirror.is_empty(),
        "mirror-only nodes should not load local shares"
    );

    let (net_tx_host, net_rx_host) = mpsc::channel(16);
    let (net_tx_mirror, net_rx_mirror) = mpsc::channel(16);

    let pm_host = PeerManager::new(
        cfg_host.clone(),
        db_host.clone(),
        net_tx_host.clone(),
        shares_host.clone(),
        fs_host.clone(),
        net.clone(),
    )
    .unwrap();
    let pm_mirror = PeerManager::new(
        cfg_mirror.clone(),
        db_mirror.clone(),
        net_tx_mirror.clone(),
        shares_mirror.clone(),
        fs_mirror.clone(),
        net.clone(),
    )
    .unwrap();

    let tok_host = CancellationToken::new();
    let tok_mirror = CancellationToken::new();
    let t_host = tokio::spawn({
        let tok = tok_host.clone();
        async move { pm_host.run(net_rx_host, tok).await.unwrap() }
    });
    let t_mirror = tokio::spawn({
        let tok = tok_mirror.clone();
        async move { pm_mirror.run(net_rx_mirror, tok).await.unwrap() }
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    enqueue_sample_batch(
        &db_host,
        &shares_host[0],
        fs_host.clone(),
        "mirror.txt",
        ChangeKind::Modify,
        Some(b"mirrored"),
        net_tx_host.clone(),
    )
    .await;

    let remote_root = build_remote_share_root(
        &cfg_mirror.remote_share_root,
        &cfg_host.pc_name,
        &cfg_host.instance_id,
        &shares_host[0].share_name,
    );
    let mirrored_bytes = wait_for_remote_file(&fs_mirror, &remote_root, "mirror.txt").await;
    assert_eq!(mirrored_bytes, b"mirrored".to_vec());

    drop(net_tx_host);
    drop(net_tx_mirror);
    tok_host.cancel();
    tok_mirror.cancel();
    let _ = t_host.await;
    let _ = t_mirror.await;
}

#[tokio::test(flavor = "current_thread")]
async fn host_only_peers_do_not_host_remote_shares() {
    let net: Arc<dyn Net> = Arc::new(VirtualNet::default());
    let fs1: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());
    let fs2: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());

    let tls_paths1 = TlsPaths::new("cert-ho1.pem", "key-ho1.pem", "ca.pem");
    let tls_paths2 = TlsPaths::new("cert-ho2.pem", "key-ho2.pem", "ca.pem");
    let tls_material = generate_shared_tls(&["pc-one", "pc-two", "localhost"]);
    write_shared_tls(fs1.as_ref(), &tls_paths1, &tls_material);
    write_shared_tls(fs2.as_ref(), &tls_paths2, &tls_material);

    let cfg1 = test_config_with_state(
        "pc-one",
        "inst-one",
        6501,
        7501,
        "shareA",
        &tls_paths1,
        ApplicationState::HostOnly,
    );
    let cfg2 = test_config_with_state(
        "pc-two",
        "inst-two",
        6502,
        7501,
        "shareA",
        &tls_paths2,
        ApplicationState::HostOnly,
    );

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
    let pm2 = PeerManager::new(
        cfg2.clone(),
        db2.clone(),
        net_tx2.clone(),
        shares2.clone(),
        fs2.clone(),
        net.clone(),
    )
    .unwrap();

    let tok1 = CancellationToken::new();
    let tok2 = CancellationToken::new();
    let t1 = tokio::spawn({
        let tok = tok1.clone();
        async move { pm1.run(net_rx1, tok).await.unwrap() }
    });
    let t2 = tokio::spawn({
        let tok = tok2.clone();
        async move { pm2.run(net_rx2, tok).await.unwrap() }
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    enqueue_sample_batch(
        &db1,
        &shares1[0],
        fs1.clone(),
        "blocked.txt",
        ChangeKind::Modify,
        Some(b"blocked"),
        net_tx1.clone(),
    )
    .await;

    let remote_root = build_remote_share_root(
        &cfg2.remote_share_root,
        &cfg1.pc_name,
        &cfg1.instance_id,
        &shares1[0].share_name,
    );
    assert_remote_file_never_materializes(&fs2, &remote_root, "blocked.txt").await;
    assert_share_never_registered(&db2, &shares1[0].share_id).await;

    drop(net_tx1);
    drop(net_tx2);
    tok1.cancel();
    tok2.cancel();
    let _ = t1.await;
    let _ = t2.await;
}

#[tokio::test(flavor = "current_thread")]
async fn zombie_nodes_never_host_remote_shares() {
    let net: Arc<dyn Net> = Arc::new(VirtualNet::default());
    let fs1: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());
    let fs2: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());

    let tls_paths1 = TlsPaths::new("cert-z1.pem", "key-z1.pem", "ca.pem");
    let tls_paths2 = TlsPaths::new("cert-z2.pem", "key-z2.pem", "ca.pem");
    let tls_material = generate_shared_tls(&["pc-one", "pc-two", "localhost"]);
    write_shared_tls(fs1.as_ref(), &tls_paths1, &tls_material);
    write_shared_tls(fs2.as_ref(), &tls_paths2, &tls_material);

    let cfg1 = test_config("pc-one", "inst-one", 6601, 7601, "shareA", &tls_paths1);
    let cfg2 = test_config_with_state(
        "pc-two",
        "inst-two",
        6602,
        7601,
        "shareA",
        &tls_paths2,
        ApplicationState::Zombie,
    );

    let db1 = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
    let db2 = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));

    let shares1 = db1.lock().await.load_shares(&cfg1).unwrap();
    let shares2 = db2.lock().await.load_shares(&cfg2).unwrap();
    assert!(
        shares2.is_empty(),
        "zombie nodes must not start share watchers"
    );

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
    let pm2 = PeerManager::new(
        cfg2.clone(),
        db2.clone(),
        net_tx2.clone(),
        shares2.clone(),
        fs2.clone(),
        net.clone(),
    )
    .unwrap();

    let tok1 = CancellationToken::new();
    let tok2 = CancellationToken::new();
    let t1 = tokio::spawn({
        let tok = tok1.clone();
        async move { pm1.run(net_rx1, tok).await.unwrap() }
    });
    let t2 = tokio::spawn({
        let tok = tok2.clone();
        async move { pm2.run(net_rx2, tok).await.unwrap() }
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    enqueue_sample_batch(
        &db1,
        &shares1[0],
        fs1.clone(),
        "zombie.txt",
        ChangeKind::Modify,
        Some(b"zombie"),
        net_tx1.clone(),
    )
    .await;

    let remote_root = build_remote_share_root(
        &cfg2.remote_share_root,
        &cfg1.pc_name,
        &cfg1.instance_id,
        &shares1[0].share_name,
    );
    assert_remote_file_never_materializes(&fs2, &remote_root, "zombie.txt").await;
    assert_share_never_registered(&db2, &shares1[0].share_id).await;

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
    test_config_with_state(
        pc_name,
        instance_id,
        listen_port,
        discovery_port,
        share_name,
        tls,
        ApplicationState::MirrorHost,
    )
}

fn test_config_with_state(
    pc_name: &str,
    instance_id: &str,
    listen_port: u16,
    discovery_port: u16,
    share_name: &str,
    tls: &TlsPaths,
    app_state: ApplicationState,
) -> AppConfig {
    AppConfig {
        pc_name: pc_name.to_string(),
        instance_id: instance_id.to_string(),
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port),
        plain_listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port + 1000),
        use_tls_for_peers: true,
        discovery_port,
        dht_port: 5003,
        utp_port: 5004,
        enable_dht: false,
        bootstrap_peers: Vec::new(),
        aggregation_window_ms: 100,
        db_path: PathBuf::from(""),
        log_path: PathBuf::from(""),
        tls_cert_path: tls.cert.clone(),
        tls_key_path: tls.key.clone(),
        tls_ca_cert_path: tls.ca.clone(),
        tls_pinned_ca_fingerprints: Vec::new(),
        tls_peer_fingerprints: std::collections::HashMap::new(),
            tls_insecure_shared_cert: false,
        remote_share_root: PathBuf::from("remote"),
        shares: vec![ShareConfig {
            name: share_name.to_string(),
            root_path: PathBuf::from("/virtual"),
            recursive: true,
            ignore_patterns: Vec::new(),
            sync_allow: Vec::new(),
            max_file_size_bytes: None,
            sync: Default::default(),
            pull: Default::default(),
            request_handling: None,
            conflict: ConflictPolicy::LastWriteWins,
        }],
        app_state,
        request_handling: Default::default(),
        peer_policies: Vec::new(),
        quarantined_peers: Vec::new(),
        control_socket: std::path::PathBuf::from("localbox.sock"),
    }
}

/// Build the sender-side index entry a change of `kind` would have produced.
/// `version` mirrors what `snapshot_changes` needs to round-trip `kind`: it maps
/// `version <= 1` to `Create` and anything higher to `Modify`.
fn stage_index_entry(
    share: &ShareContext,
    fs: &dyn FileSystem,
    path: &str,
    kind: &ChangeKind,
    contents: Option<&[u8]>,
    version: i64,
) -> FileMeta {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if matches!(kind, ChangeKind::Delete) {
        return FileMeta {
            path: path.to_string(),
            size: 0,
            mtime: now,
            hash: [0u8; 32],
            version,
            deleted: true,
        };
    }
    let data = contents.unwrap_or(b"default");
    write_share_file(fs, share, path, data);
    FileMeta {
        path: path.to_string(),
        size: data.len() as u64,
        mtime: now,
        hash: hash_bytes(data),
        version,
        deleted: false,
    }
}

/// Manual push: stage the file in the index, then materialize a real
/// `Push`/`Snapshot` intent. Deliberately goes through
/// `create_and_materialize_intent` rather than hand-building a manifest, so the
/// tests exercise the intent path the daemon actually uses.
async fn enqueue_sample_batch(
    db: &Arc<Mutex<Db>>,
    share: &ShareContext,
    fs: Arc<dyn FileSystem>,
    path: &str,
    kind: ChangeKind,
    contents: Option<&[u8]>,
    net_tx: mpsc::Sender<String>,
) {
    // Modify must survive the snapshot round-trip as Modify, not Create.
    let version = if matches!(kind, ChangeKind::Modify) { 2 } else { 1 };
    let meta = stage_index_entry(share, fs.as_ref(), path, &kind, contents, version);

    let batch_ids = {
        let db_guard = db.lock().await;
        db_guard.upsert_file_meta(share.id, &meta).unwrap();
        let (_intent_id, batch_ids) = db_guard
            .create_and_materialize_intent(
                models::IntentKind::SnapshotPush,
                models::IntentOrigin::User,
                &share.share_name,
                share.share_id,
                None,
                models::IntentBasis::Snapshot {
                    paths: vec![path.to_string()],
                },
                None,
                "local",
            )
            .unwrap();
        batch_ids
    };
    for batch_id in batch_ids {
        let _ = net_tx.try_send(batch_id);
    }
}

/// Append a change to the owning node's share journal without sending anything.
/// Returns the seq the journal actually assigned — seqs are locally allocated,
/// so callers must take the value rather than dictate it.
async fn journal_change(
    db: &Arc<Mutex<Db>>,
    share: &ShareContext,
    fs: Arc<dyn FileSystem>,
    path: &str,
    kind: ChangeKind,
    contents: Option<&[u8]>,
) -> i64 {
    let meta = stage_index_entry(share, fs.as_ref(), path, &kind, contents, 1);
    let change = FileChange {
        seq: 0,
        share_id: share.share_id,
        path: path.to_string(),
        kind: kind.clone(),
        meta: if matches!(kind, ChangeKind::Delete) {
            None
        } else {
            Some(meta.clone())
        },
    };

    let db_guard = db.lock().await;
    if !matches!(kind, ChangeKind::Delete) {
        db_guard.upsert_file_meta(share.id, &meta).unwrap();
    }
    db_guard
        .append_journal_entry(
            share.id,
            &change,
            OffsetDateTime::now_utc().unix_timestamp(),
            db::JournalOrigin::Local,
        )
        .unwrap()
        .expect("journal append must insert")
}

/// Materialize a real `SyncCatchup`/`JournalRange` intent over an existing range
/// of the owning node's journal. `from_seq` is exclusive, `to_seq` inclusive.
async fn send_journal_range(
    db: &Arc<Mutex<Db>>,
    share: &ShareContext,
    from_seq: i64,
    to_seq: i64,
    net_tx: mpsc::Sender<String>,
) {
    let batch_ids = {
        let db_guard = db.lock().await;
        let (_intent_id, batch_ids) = db_guard
            .create_and_materialize_intent(
                models::IntentKind::SyncCatchup,
                models::IntentOrigin::AutoSync,
                &share.share_name,
                share.share_id,
                None,
                models::IntentBasis::JournalRange { from_seq, to_seq },
                None,
                "local",
            )
            .unwrap();
        batch_ids
    };
    for batch_id in batch_ids {
        let _ = net_tx.try_send(batch_id);
    }
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

fn write_share_file(fs: &dyn FileSystem, share: &ShareContext, rel: &str, data: &[u8]) {
    let full_path = share.root_path.join(rel);
    if let Some(parent) = full_path.parent() {
        let _ = fs.create_dir_all(parent);
    }
    let _ = fs.write(&full_path, data);
}

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

async fn wait_for_remote_file(fs: &Arc<dyn FileSystem>, root: &Path, rel: &str) -> Vec<u8> {
    let target = root.join(rel);
    for _ in 0..50 {
        match fs.read(&target) {
            Ok(bytes) => return bytes,
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
    panic!("remote file {} never materialized", target.display());
}

async fn wait_for_remote_file_removed(fs: &Arc<dyn FileSystem>, root: &Path, rel: &str) {
    let target = root.join(rel);
    for _ in 0..50 {
        match fs.metadata(&target) {
            Ok(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
    panic!("remote file {} was never removed", target.display());
}

async fn assert_remote_file_never_materializes(fs: &Arc<dyn FileSystem>, root: &Path, rel: &str) {
    let target = root.join(rel);
    for _ in 0..30 {
        if fs.metadata(&target).is_ok() {
            panic!("remote file {} unexpectedly materialized", target.display());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn assert_share_never_registered(db: &Arc<Mutex<Db>>, share_id: &models::ShareId) {
    for _ in 0..10 {
        if db
            .lock()
            .await
            .get_share_row_id_by_share_id(share_id)
            .is_ok()
        {
            panic!("share {:?} unexpectedly registered", share_id.0);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
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
    let cert =
        rcgen::generate_simple_self_signed(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
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
