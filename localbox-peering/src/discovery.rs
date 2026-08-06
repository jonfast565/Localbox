use models::{AppConfig, ShareContext};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use utilities::{Net, UdpSocketLike};

use crate::connection::connect_to_peer;
use crate::{DbHandle, PendingFiles, SharedWriters};
use protocol::{parse_discovery_message, DiscoveryMessage};
use std::collections::HashSet;
use tls::ManagedTls;

pub fn spawn_discovery(
    cfg: AppConfig,
    db: DbHandle,
    shares: Arc<Vec<ShareContext>>,
    tls: Arc<ManagedTls>,
    connections: SharedWriters,
    net_tx: tokio::sync::mpsc::Sender<String>,
    fs: Arc<dyn utilities::FileSystem>,
    net: Arc<dyn Net>,
    pending_files: PendingFiles,
    token: CancellationToken,
) -> JoinHandle<()> {
    let share_names: Vec<String> = shares.iter().map(|s| s.share_name.clone()).collect();
    let share_lookup = shares;
    let net_tx = Arc::new(net_tx);
    tokio::spawn(discovery_loop(
        cfg,
        db,
        share_names,
        share_lookup,
        tls,
        connections,
        net_tx,
        fs,
        net,
        pending_files,
        token,
    ))
}

async fn discovery_loop(
    cfg: AppConfig,
    db: DbHandle,
    share_names: Vec<String>,
    share_lookup: Arc<Vec<ShareContext>>,
    tls: Arc<ManagedTls>,
    connections: SharedWriters,
    net_tx: Arc<tokio::sync::mpsc::Sender<String>>,
    fs: Arc<dyn utilities::FileSystem>,
    net: Arc<dyn Net>,
    pending_files: PendingFiles,
    token: CancellationToken,
) {
    let addr: SocketAddr = format!("0.0.0.0:{}", cfg.discovery_port)
        .parse()
        .expect("valid discovery addr");
    let socket = match net.bind_udp(addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to bind UDP discovery socket: {e}");
            return;
        }
    };
    info!("Discovery listening on {}", addr);

    if let Err(e) = socket.set_broadcast(true) {
        warn!("Failed to set SO_BROADCAST: {e}");
    }

    let socket_send = Arc::clone(&socket);
    let _broadcaster = tokio::spawn(discovery_broadcast_loop(
        cfg.clone(),
        share_names.clone(),
        socket_send,
        token.clone(),
    ));

    let mut buf = [0u8; 2048];

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            res = socket.recv_from(&mut buf) => {
                match res {
                    Ok((n, src)) => {
                        let msg = String::from_utf8_lossy(&buf[..n]);
                        handle_discovery_message(
                            &cfg,
                            &db,
                            &share_names,
                            &share_lookup,
                            msg.as_ref(),
                            src,
                            &socket,
                            tls.clone(),
                            connections.clone(),
                            net_tx.clone(),
                            fs.clone(),
                            net.clone(),
                            pending_files.clone(),
                            token.clone(),
                        )
                        .await;
                    }
                    Err(e) => {
                        error!("UDP recv error: {e}");
                        break;
                    }
                }
            }
        }
    }
}

async fn discovery_broadcast_loop(
    cfg: AppConfig,
    share_names: Vec<String>,
    socket: Arc<dyn UdpSocketLike>,
    token: CancellationToken,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            _ = interval.tick() => {}
        }
        let msg = format!(
            "DISCOVER v1 pc_name={} instance_id={} tls_port={} plain_port={} use_tls={} accepts_remote={} shares={}",
            cfg.pc_name,
            cfg.instance_id,
            cfg.listen_addr.port(),
            cfg.plain_listen_addr.port(),
            cfg.use_tls_for_peers,
            cfg.app_state.can_host_remote(),
            share_names.join(","),
        );
        let broadcast_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            cfg.discovery_port,
        );
        if let Err(e) = socket.send_to(msg.as_bytes(), &broadcast_addr).await {
            warn!("Failed to send DISCOVER: {e}");
        }
    }
}

async fn handle_discovery_message(
    cfg: &AppConfig,
    db: &DbHandle,
    share_names: &[String],
    share_lookup: &Arc<Vec<ShareContext>>,
    msg: &str,
    src: SocketAddr,
    socket: &Arc<dyn UdpSocketLike>,
    tls: Arc<ManagedTls>,
    connections: SharedWriters,
    net_tx: Arc<tokio::sync::mpsc::Sender<String>>,
    fs: Arc<dyn utilities::FileSystem>,
    net: Arc<dyn Net>,
    pending_files: PendingFiles,
    token: CancellationToken,
) {
    let parsed = match parse_discovery_message(msg) {
        Some(p) => p,
        None => {
            warn!("Unknown discovery message from {src}: {msg}");
            return;
        }
    };

    match parsed {
        DiscoveryMessage::Discover {
            pc_name,
            instance_id,
            tls_port,
            plain_port,
            use_tls_for_peers,
            shares,
            accepts_remote_shares,
        } => {
            handle_discover(
                cfg,
                db,
                share_names,
                share_lookup,
                &pc_name,
                &instance_id,
                tls_port,
                plain_port,
                use_tls_for_peers,
                shares,
                accepts_remote_shares,
                src,
                socket,
                tls.clone(),
                connections,
                net_tx,
                fs.clone(),
                net.clone(),
                pending_files.clone(),
                token.clone(),
            )
            .await;
        }
        DiscoveryMessage::Here {
            pc_name,
            instance_id,
            tls_port,
            plain_port,
            use_tls_for_peers,
            shares,
            accepts_remote_shares,
        } => {
            handle_here(
                cfg,
                db,
                share_names,
                share_lookup,
                &pc_name,
                &instance_id,
                tls_port,
                plain_port,
                use_tls_for_peers,
                shares,
                accepts_remote_shares,
                src,
                tls.clone(),
                connections,
                net_tx,
                fs.clone(),
                net.clone(),
                pending_files.clone(),
                token.clone(),
            )
            .await;
        }
    }
}

async fn handle_discover(
    cfg: &AppConfig,
    db: &DbHandle,
    share_names: &[String],
    share_lookup: &Arc<Vec<ShareContext>>,
    pc_name: &str,
    instance_id: &str,
    tls_port: u16,
    plain_port: u16,
    prefer_tls: bool,
    shares: Vec<String>,
    accepts_remote_shares: bool,
    src: SocketAddr,
    socket: &Arc<dyn UdpSocketLike>,
    tls: Arc<ManagedTls>,
    connections: SharedWriters,
    net_tx: Arc<tokio::sync::mpsc::Sender<String>>,
    fs: Arc<dyn utilities::FileSystem>,
    net: Arc<dyn Net>,
    pending_files: PendingFiles,
    token: CancellationToken,
) {
    if is_self_peer(cfg, pc_name, instance_id) {
        return;
    }

    let peer_ip = if src.ip().is_unspecified() {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        src.ip()
    };
    let peer_tls_addr = SocketAddr::new(peer_ip, tls_port);
    let peer_plain_addr = SocketAddr::new(peer_ip, plain_port);
    let peer_addr = if cfg.use_tls_for_peers && tls_port != 0 {
        peer_tls_addr
    } else if !cfg.use_tls_for_peers && plain_port != 0 {
        peer_plain_addr
    } else if tls_port != 0 {
        peer_tls_addr
    } else {
        peer_plain_addr
    };
    let Some(peer_id) = upsert_peer_with_state(
        db,
        pc_name,
        instance_id,
        peer_tls_addr,
        peer_plain_addr,
        prefer_tls,
        "discovered",
    )
    .await
    else {
        return;
    };

    info!(
        "Discovered peer {} (instance={}) at {}",
        pc_name, instance_id, peer_addr
    );

    if accepts_remote_shares {
        maybe_enqueue_auto_sync(
            cfg,
            db,
            share_lookup,
            &shares,
            peer_id,
            pc_name,
            instance_id,
            net_tx.clone(),
        )
        .await;
    } else {
        info!(
            "Peer {} (instance={}) is not accepting remote shares; skipping outbound sync",
            pc_name, instance_id
        );
    }

    let reply = format!(
        "HERE v1 pc_name={} instance_id={} tls_port={} plain_port={} use_tls={} accepts_remote={} shares={}",
        cfg.pc_name,
        cfg.instance_id,
        cfg.listen_addr.port(),
        cfg.plain_listen_addr.port(),
        cfg.use_tls_for_peers,
        cfg.app_state.can_host_remote(),
        share_names.join(","),
    );
    if let Err(e) = socket.send_to(reply.as_bytes(), &src).await {
        warn!("Failed to send HERE to {src}: {e}");
    }

    spawn_connect_task(
        peer_tls_addr,
        peer_plain_addr,
        pc_name,
        cfg,
        db,
        share_names,
        connections,
        tls.clone(),
        fs,
        net.clone(),
        pending_files,
        token,
    );
}

async fn handle_here(
    cfg: &AppConfig,
    db: &DbHandle,
    share_names: &[String],
    share_lookup: &Arc<Vec<ShareContext>>,
    pc_name: &str,
    instance_id: &str,
    tls_port: u16,
    plain_port: u16,
    prefer_tls: bool,
    shares: Vec<String>,
    accepts_remote_shares: bool,
    src: SocketAddr,
    tls: Arc<ManagedTls>,
    connections: SharedWriters,
    net_tx: Arc<tokio::sync::mpsc::Sender<String>>,
    fs: Arc<dyn utilities::FileSystem>,
    net: Arc<dyn Net>,
    pending_files: PendingFiles,
    token: CancellationToken,
) {
    if is_self_peer(cfg, pc_name, instance_id) {
        return;
    }

    let peer_ip = if src.ip().is_unspecified() {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        src.ip()
    };
    let peer_tls_addr = SocketAddr::new(peer_ip, tls_port);
    let peer_plain_addr = SocketAddr::new(peer_ip, plain_port);
    let peer_addr = if cfg.use_tls_for_peers && tls_port != 0 {
        peer_tls_addr
    } else if !cfg.use_tls_for_peers && plain_port != 0 {
        peer_plain_addr
    } else if tls_port != 0 {
        peer_tls_addr
    } else {
        peer_plain_addr
    };
    let Some(peer_id) = upsert_peer_with_state(
        db,
        pc_name,
        instance_id,
        peer_tls_addr,
        peer_plain_addr,
        prefer_tls,
        "discovered",
    )
    .await
    else {
        return;
    };

    let set_res = { db.lock().await.set_peer_shares(peer_id, &shares) };
    if let Err(e) = set_res {
        error!("DB set_peer_shares error: {e}");
    } else {
        info!(
            "HERE from peer {} (instance={}) at {} shares={:?}",
            pc_name, instance_id, peer_addr, shares
        );
        if accepts_remote_shares {
            maybe_enqueue_auto_sync(
                cfg,
                db,
                share_lookup,
                &shares,
                peer_id,
                pc_name,
                instance_id,
                net_tx.clone(),
            )
            .await;
        } else {
            info!(
                "Peer {} (instance={}) is not accepting remote shares; skipping outbound sync",
                pc_name, instance_id
            );
        }
    }

    spawn_connect_task(
        peer_tls_addr,
        peer_plain_addr,
        pc_name,
        cfg,
        db,
        share_names,
        connections,
        tls.clone(),
        fs,
        net.clone(),
        pending_files,
        token,
    );
}

fn spawn_connect_task(
    peer_tls_addr: SocketAddr,
    peer_plain_addr: SocketAddr,
    pc_name: &str,
    cfg: &AppConfig,
    db: &DbHandle,
    share_names: &[String],
    connections: SharedWriters,
    tls: Arc<ManagedTls>,
    fs: Arc<dyn utilities::FileSystem>,
    net: Arc<dyn Net>,
    pending_files: PendingFiles,
    token: CancellationToken,
) {
    let cfg_clone = cfg.clone();
    let db = Arc::clone(db);
    let share_names = share_names.to_vec();
    let connections = connections.clone();
    let pc_name_connect = pc_name.to_string();
    tokio::spawn(run_connect_task(
        peer_tls_addr,
        peer_plain_addr,
        pc_name_connect,
        cfg_clone,
        db,
        share_names,
        connections,
        tls,
        fs,
        net,
        pending_files,
        token,
    ));
}

async fn run_connect_task(
    peer_tls_addr: SocketAddr,
    peer_plain_addr: SocketAddr,
    pc_name: String,
    cfg: AppConfig,
    db: DbHandle,
    share_names: Vec<String>,
    connections: SharedWriters,
    tls: Arc<ManagedTls>,
    fs: Arc<dyn utilities::FileSystem>,
    net: Arc<dyn Net>,
    pending_files: PendingFiles,
    token: CancellationToken,
) {
    tokio::select! {
        _ = token.cancelled() => {}
        res = async {
            let connector = tls.connector().await;
            connect_to_peer(
                peer_tls_addr,
                peer_plain_addr,
                &pc_name,
                &cfg,
                &db,
                &share_names,
                connections,
                pending_files.clone(),
                connector,
                fs,
                net,
            ).await
        } => {
            if let Err(e) = res {
                warn!("Connect to peer {} failed: {e}", pc_name);
            }
        }
    }
}

async fn upsert_peer_with_state(
    db: &DbHandle,
    pc_name: &str,
    instance_id: &str,
    tls_addr: SocketAddr,
    plain_addr: SocketAddr,
    prefer_tls: bool,
    state: &str,
) -> Option<i64> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let chosen_addr = if tls_addr.port() != 0 {
        tls_addr
    } else {
        plain_addr
    };
    let res = {
        db.lock().await.upsert_peer(
            pc_name,
            instance_id,
            chosen_addr,
            now,
            state,
            tls_addr.port(),
            plain_addr.port(),
            prefer_tls,
        )
    };
    match res {
        Ok(id) => Some(id),
        Err(e) => {
            error!("DB upsert_peer error: {e}");
            None
        }
    }
}

fn is_self_peer(cfg: &AppConfig, pc_name: &str, _instance_id: &str) -> bool {
    // Treat any peer reporting the same PC name as self to avoid two local
    // instances chatting with each other.
    pc_name == cfg.pc_name
}

async fn maybe_enqueue_auto_sync(
    cfg: &AppConfig,
    db: &DbHandle,
    share_lookup: &Arc<Vec<ShareContext>>,
    remote_shares: &[String],
    peer_id: i64,
    peer_pc: &str,
    peer_instance: &str,
    net_tx: Arc<tokio::sync::mpsc::Sender<String>>,
) {
    let peer_key = format!("{peer_pc}@{peer_instance}");
    let auto_shares: Vec<ShareContext> = share_lookup
        .iter()
        .filter(|s| cfg.resolve_sync_mode(&s.share_name, Some(&peer_key)).is_auto())
        .cloned()
        .collect();
    if auto_shares.is_empty() {
        info!(
            peer = %peer_key,
            "Skipping discovery bootstrap/catch-up; no shares with push=auto"
        );
        return;
    }
    let filtered = Arc::new(auto_shares);
    enqueue_bootstrap_if_needed(
        db,
        &filtered,
        remote_shares,
        peer_id,
        &cfg.pc_name,
        peer_pc,
        net_tx.clone(),
    )
    .await;
    enqueue_catchup_if_needed(
        db,
        &filtered,
        remote_shares,
        peer_id,
        &cfg.pc_name,
        net_tx,
    )
    .await;
}

async fn enqueue_catchup_if_needed(
    db: &DbHandle,
    share_lookup: &Arc<Vec<ShareContext>>,
    remote_shares: &[String],
    peer_id: i64,
    local_name: &str,
    net_tx: Arc<tokio::sync::mpsc::Sender<String>>,
) {
    let remote: HashSet<&str> = remote_shares.iter().map(|s| s.as_str()).collect();
    for share in share_lookup.iter() {
        if !remote.contains(share.share_name.as_str()) {
            continue;
        }
        let share_row_id = share.id;
        let (_last_sent, last_acked) =
            match db.lock().await.get_peer_progress(peer_id, share_row_id) {
                Ok(p) => p,
                Err(e) => {
                    warn!(
                        "Failed to read progress for peer {} share {}: {e}",
                        peer_id, share.share_name
                    );
                    continue;
                }
            };
        let max_seq = match db.lock().await.max_journal_seq(share_row_id) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "Failed to read share journal for {}: {e}",
                    share.share_name
                );
                continue;
            }
        };
        if max_seq <= last_acked {
            continue;
        }
        match db.lock().await.create_and_materialize_intent(
            models::IntentKind::SyncCatchup,
            models::IntentOrigin::AutoSync,
            &share.share_name,
            share.share_id,
            Some(peer_id),
            models::IntentBasis::JournalRange {
                from_seq: last_acked,
                to_seq: max_seq,
            },
            None,
            local_name,
        ) {
            Ok((intent_id, batch_ids)) => {
                for bid in &batch_ids {
                    let _ = net_tx.try_send(bid.clone());
                }
                info!(
                    intent_id = %intent_id,
                    peer_id = peer_id,
                    share_name = %share.share_name,
                    from_seq = last_acked,
                    to_seq = max_seq,
                    batches = batch_ids.len(),
                    "Queued SyncCatchup catch-up intent"
                );
            }
            Err(e) => warn!(
                peer_id = peer_id,
                share_name = %share.share_name,
                error = %e,
                "Failed to enqueue SyncCatchup catch-up intent"
            ),
        }
    }
}

async fn enqueue_bootstrap_if_needed(
    db: &DbHandle,
    share_lookup: &Arc<Vec<ShareContext>>,
    remote_shares: &[String],
    peer_id: i64,
    local_name: &str,
    remote_name: &str,
    net_tx: Arc<tokio::sync::mpsc::Sender<String>>,
) {
    let remote: HashSet<&str> = remote_shares.iter().map(|s| s.as_str()).collect();
    for share in share_lookup.iter() {
        if remote.contains(share.share_name.as_str()) {
            continue;
        }

        let max_seq = match db.lock().await.max_journal_seq(share.id) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "Failed to load share journal for bootstrap of share {}: {e}",
                    share.share_name
                );
                continue;
            }
        };
        if max_seq <= 0 {
            continue;
        }

        match db.lock().await.create_and_materialize_intent(
            models::IntentKind::SyncCatchup,
            models::IntentOrigin::AutoSync,
            &share.share_name,
            share.share_id,
            Some(peer_id),
            models::IntentBasis::JournalRange {
                from_seq: 0,
                to_seq: max_seq,
            },
            None,
            local_name,
        ) {
            Ok((intent_id, batch_ids)) => {
                for bid in &batch_ids {
                    let _ = net_tx.try_send(bid.clone());
                }
                info!(
                    intent_id = %intent_id,
                    peer_id = peer_id,
                    share_name = %share.share_name,
                    remote_pc_name = %remote_name,
                    batches = batch_ids.len(),
                    "Queued SyncCatchup bootstrap intent"
                );
            }
            Err(e) => warn!(
                peer_id = peer_id,
                share_name = %share.share_name,
                error = %e,
                "Failed to enqueue SyncCatchup bootstrap intent"
            ),
        }
    }
}
