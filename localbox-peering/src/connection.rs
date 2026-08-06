use anyhow::{bail, Context, Result};
use db::JournalOrigin;
use models::{
    AppConfig, ChangeKind, ChatAck, ChatMessage, ChatMessageRecord, ConflictPolicy, FileChange,
    FileChunk, FileMeta, HelloMessage, ShareConfig, ShareId, ThreadKind, TransferMode,
    TransferProgressRegistry, TransferReply, TransferReplyStatus, TransferRequest, WireMessage,
};
use uuid::Uuid;
use irontide_utp::UtpSocket;
use rustls::ServerName;
use std::collections::HashSet;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::io::{split, AsyncRead, AsyncWrite};
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::Instrument;
use tracing::{debug, error, info, warn};
use utilities::disk_utilities::build_remote_share_root;
use sha2::{Digest, Sha256};
use std::io::Write;
use utilities::{staging_tmp_path, DynStream, FileSystem, Net};

use crate::writer::{recv_framed_message, send_framed_message, PeerWriter};
use crate::{DbHandle, InboundFileState, PendingFiles, SharedWriters};
use tls::{fingerprint_from_certificates, normalize_fingerprint, verify_peer_cert_name};

pub async fn handle_tls_connection(
    stream: DynStream,
    cfg: &AppConfig,
    db: &DbHandle,
    share_names: &[String],
    addr: SocketAddr,
    connections: SharedWriters,
    pending_files: PendingFiles,
    tls_acceptor: TlsAcceptor,
    fs: Arc<dyn FileSystem>,
    _net: Arc<dyn Net>,
    progress: Arc<TransferProgressRegistry>,
) -> Result<()> {
    let tls_stream = tls_acceptor.accept(stream).await?;
    let mut tls_stream = tls_stream;
    let peer_certs: Option<Vec<_>> = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .map(|chain| chain.to_vec());
    let peer_fp = fingerprint_from_certificates(peer_certs.as_deref());
    let (remote, resolved_peer_id) =
        perform_handshake(&mut tls_stream, cfg, db, share_names, addr, fs.clone()).await?;
    refuse_if_quarantined(cfg, db, &remote).await?;
    check_peer_identity(
        cfg,
        db,
        resolved_peer_id,
        &remote.pc_name,
        peer_certs.as_deref(),
    )
    .await?;
    ensure_peer_fingerprint(cfg, &remote.pc_name, peer_fp.as_deref())?;
    if let Some(fp) = peer_fp {
        info!(
            peer = %remote.pc_name,
            fingerprint = %fp,
            "Verified inbound TLS peer certificate"
        );
    }

    let (reader, writer) = split(tls_stream);
    {
        let mut guard = connections.lock().await;
        guard.push((
            resolved_peer_id,
            Arc::new(AsyncMutex::new(PeerWriter::Server(writer))),
        ));
    }

    maybe_auto_pull(cfg, db, &connections, resolved_peer_id, &remote).await;

    let _reader_task = spawn_incoming_reader(
        reader,
        cfg.clone(),
        db.clone(),
        remote,
        resolved_peer_id,
        connections.clone(),
        pending_files,
        fs,
        progress,
    );
    Ok(())
}

pub async fn handle_plain_connection(
    mut stream: DynStream,
    cfg: &AppConfig,
    db: &DbHandle,
    share_names: &[String],
    addr: SocketAddr,
    connections: SharedWriters,
    pending_files: PendingFiles,
    fs: Arc<dyn FileSystem>,
    _net: Arc<dyn Net>,
    progress: Arc<TransferProgressRegistry>,
) -> Result<()> {
    warn!("Inbound plaintext peer connection from {addr}");
    let (remote, resolved_peer_id) =
        perform_handshake(&mut stream, cfg, db, share_names, addr, fs.clone()).await?;
    refuse_if_quarantined(cfg, db, &remote).await?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    db.lock().await.mark_peer_insecure(resolved_peer_id, now)?;

    let (reader, writer) = split(stream);
    {
        let mut guard = connections.lock().await;
        guard.push((
            resolved_peer_id,
            Arc::new(AsyncMutex::new(PeerWriter::Plain(writer))),
        ));
    }

    maybe_auto_pull(cfg, db, &connections, resolved_peer_id, &remote).await;

    let _reader_task = spawn_incoming_reader(
        reader,
        cfg.clone(),
        db.clone(),
        remote,
        resolved_peer_id,
        connections.clone(),
        pending_files,
        fs,
        progress,
    );
    Ok(())
}

fn is_likely_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

pub async fn connect_to_peer(
    peer_tls_addr: SocketAddr,
    peer_plain_addr: SocketAddr,
    peer_utp_addr: Option<SocketAddr>,
    server_name: &str,
    cfg: &AppConfig,
    db: &DbHandle,
    share_names: &[String],
    connections: SharedWriters,
    pending_files: PendingFiles,
    connector: TlsConnector,
    fs: Arc<dyn FileSystem>,
    net: Arc<dyn Net>,
    utp: Option<UtpSocket>,
    progress: Arc<TransferProgressRegistry>,
) -> Result<()> {
    let use_tls = if cfg.use_tls_for_peers && peer_tls_addr.port() != 0 {
        true
    } else if !cfg.use_tls_for_peers && peer_plain_addr.port() != 0 {
        false
    } else {
        peer_plain_addr.port() == 0
    };

    let target_addr = if use_tls {
        peer_tls_addr
    } else if peer_plain_addr.port() != 0 {
        peer_plain_addr
    } else {
        peer_tls_addr
    };

    let prefer_utp = peer_utp_addr
        .map(|a| !is_likely_lan(a.ip()))
        .unwrap_or(false)
        && utp.is_some()
        && use_tls;

    if prefer_utp {
        if let (Some(utp_sock), Some(utp_addr)) = (utp.as_ref(), peer_utp_addr) {
            match connect_tls_over_utp(
                utp_sock,
                utp_addr,
                server_name,
                cfg,
                db,
                share_names,
                connections.clone(),
                pending_files.clone(),
                connector.clone(),
                fs.clone(),
                Arc::clone(&progress),
            )
            .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(
                        "uTP dial to {} failed ({e:#}); falling back to TCP",
                        utp_addr
                    );
                }
            }
        }
    }

    if !use_tls {
        warn!(
            "Connecting to peer {} at {} without TLS",
            server_name, target_addr
        );
    }

    let tcp = match net.connect_tcp(target_addr).await {
        Ok(s) => s,
        Err(e) => {
            // Coordinated dial: try uTP when TCP fails (typical WAN / NAT case).
            if use_tls {
                if let (Some(utp_sock), Some(utp_addr)) = (utp.as_ref(), peer_utp_addr) {
                    return connect_tls_over_utp(
                        utp_sock,
                        utp_addr,
                        server_name,
                        cfg,
                        db,
                        share_names,
                        connections,
                        pending_files,
                        connector,
                        fs,
                        progress,
                    )
                    .await
                    .with_context(|| format!("TCP to {target_addr} failed ({e}); uTP also failed"));
                }
            }
            return Err(e.into());
        }
    };
    if use_tls {
        let name = ServerName::try_from(server_name)
            .or_else(|_| ServerName::try_from(target_addr.ip().to_string().as_str()))
            .context("server name for TLS")?;
        let mut tls_stream = connector.connect(name, tcp).await?;
        let peer_certs: Option<Vec<_>> = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .map(|chain| chain.to_vec());
        let peer_fp = fingerprint_from_certificates(peer_certs.as_deref());
        let (remote, peer_id) = perform_handshake(
            &mut tls_stream,
            cfg,
            db,
            share_names,
            target_addr,
            fs.clone(),
        )
        .await?;
        refuse_if_quarantined(cfg, db, &remote).await?;
        // rustls validated the certificate against the address we dialed; this
        // re-checks it against the name the peer claimed in its Hello, which may
        // differ (we can dial by IP) and is what the rest of the engine keys off.
        check_peer_identity(cfg, db, peer_id, &remote.pc_name, peer_certs.as_deref()).await?;
        ensure_peer_fingerprint(cfg, &remote.pc_name, peer_fp.as_deref())?;
        if let Some(fp) = peer_fp {
            info!(
                peer = %remote.pc_name,
                fingerprint = %fp,
                "Verified outbound TLS peer certificate"
            );
        }

        let (reader, writer) = split(tls_stream);
        {
            let mut guard = connections.lock().await;
            guard.push((
                peer_id,
                Arc::new(AsyncMutex::new(PeerWriter::Client(writer))),
            ));
        }
        maybe_auto_pull(cfg, db, &connections, peer_id, &remote).await;
        let _reader_task = spawn_incoming_reader(
            reader,
            cfg.clone(),
            db.clone(),
            remote,
            peer_id,
            connections.clone(),
            pending_files,
            fs,
            progress,
        );
        info!("Established outbound TLS to {}", target_addr);
    } else {
        let mut plain_stream = tcp;
        let (remote, peer_id) = perform_handshake(
            &mut plain_stream,
            cfg,
            db,
            share_names,
            target_addr,
            fs.clone(),
        )
        .await?;
        refuse_if_quarantined(cfg, db, &remote).await?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        db.lock().await.mark_peer_insecure(peer_id, now)?;
        let (reader, writer) = split(plain_stream);
        {
            let mut guard = connections.lock().await;
            guard.push((
                peer_id,
                Arc::new(AsyncMutex::new(PeerWriter::Plain(writer))),
            ));
        }
        maybe_auto_pull(cfg, db, &connections, peer_id, &remote).await;
        let _reader_task = spawn_incoming_reader(
            reader,
            cfg.clone(),
            db.clone(),
            remote,
            peer_id,
            connections.clone(),
            pending_files,
            fs,
            progress,
        );
        info!("Established outbound plaintext to {}", target_addr);
    }
    Ok(())
}

async fn connect_tls_over_utp(
    utp: &UtpSocket,
    utp_addr: SocketAddr,
    server_name: &str,
    cfg: &AppConfig,
    db: &DbHandle,
    share_names: &[String],
    connections: SharedWriters,
    pending_files: PendingFiles,
    connector: TlsConnector,
    fs: Arc<dyn FileSystem>,
    progress: Arc<TransferProgressRegistry>,
) -> Result<()> {
    let stream = utp.connect(utp_addr).await.map_err(|e| anyhow::anyhow!("{e}"))?;
    let stream: DynStream = Box::new(stream);
    let name = ServerName::try_from(server_name)
        .or_else(|_| ServerName::try_from(utp_addr.ip().to_string().as_str()))
        .context("server name for TLS")?;
    let mut tls_stream = connector.connect(name, stream).await?;
    let peer_certs: Option<Vec<_>> = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .map(|chain| chain.to_vec());
    let peer_fp = fingerprint_from_certificates(peer_certs.as_deref());
    let (remote, peer_id) = perform_handshake(
        &mut tls_stream,
        cfg,
        db,
        share_names,
        utp_addr,
        fs.clone(),
    )
    .await?;
    refuse_if_quarantined(cfg, db, &remote).await?;
    check_peer_identity(cfg, db, peer_id, &remote.pc_name, peer_certs.as_deref()).await?;
    ensure_peer_fingerprint(cfg, &remote.pc_name, peer_fp.as_deref())?;
    let (reader, writer) = split(tls_stream);
    {
        let mut guard = connections.lock().await;
        guard.push((
            peer_id,
            Arc::new(AsyncMutex::new(PeerWriter::Client(writer))),
        ));
    }
    maybe_auto_pull(cfg, db, &connections, peer_id, &remote).await;
    let _reader_task = spawn_incoming_reader(
        reader,
        cfg.clone(),
        db.clone(),
        remote,
        peer_id,
        connections,
        pending_files,
        fs,
        progress,
    );
    info!("Established outbound TLS-over-uTP to {}", utp_addr);
    Ok(())
}

async fn perform_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &AppConfig,
    db: &DbHandle,
    share_names: &[String],
    addr: SocketAddr,
    fs: Arc<dyn FileSystem>,
) -> Result<(HelloMessage, i64)> {
    let hello = HelloMessage {
        protocol_version: models::WIRE_PROTOCOL_VERSION,
        pc_name: cfg.pc_name.clone(),
        instance_id: cfg.instance_id.clone(),
        listen_port: cfg.listen_addr.port(),
        plain_port: cfg.plain_listen_addr.port(),
        use_tls_for_peers: cfg.use_tls_for_peers,
        utp_port: cfg.utp_port,
        shares: share_names.to_vec(),
        accepts_remote_shares: cfg.app_state.can_host_remote(),
    };
    let msg = WireMessage::Hello(hello);
    send_framed_message(stream, &msg).await?;

    match recv_framed_message(stream).await? {
        Some(WireMessage::Hello(remote)) => {
            info!(
                "Handshake with peer {} (instance={}) at {} shares={:?} tls_pref={}",
                remote.pc_name, remote.instance_id, addr, remote.shares, remote.use_tls_for_peers
            );
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let peer_addr = SocketAddr::new(
                addr.ip(),
                if addr.port() != 0 {
                    addr.port()
                } else {
                    remote.listen_port
                },
            );
            let peer_id = db.lock().await.upsert_peer(
                &remote.pc_name,
                &remote.instance_id,
                peer_addr,
                now,
                "connected",
                remote.listen_port,
                remote.plain_port,
                remote.use_tls_for_peers,
            )?;
            db.lock().await.set_peer_shares(peer_id, &remote.shares)?;
            ensure_remote_shares(cfg, db, &remote, fs.as_ref()).await;
            Ok((remote, peer_id))
        }
        Some(other) => {
            bail!(
                "Unexpected message during handshake from {addr}: {:?}",
                other
            );
        }
        None => {
            bail!("Peer at {addr} closed during handshake");
        }
    }
}

fn spawn_incoming_reader<R>(
    reader: R,
    cfg: AppConfig,
    db: DbHandle,
    remote: HelloMessage,
    peer_id: i64,
    connections: SharedWriters,
    pending_files: PendingFiles,
    fs: Arc<dyn FileSystem>,
    progress: Arc<TransferProgressRegistry>,
) -> tokio::task::JoinHandle<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(incoming_reader_loop(
        reader,
        cfg,
        db,
        remote,
        peer_id,
        connections,
        pending_files,
        fs,
        progress,
    ))
}

async fn incoming_reader_loop<R>(
    mut reader: R,
    cfg: AppConfig,
    db: DbHandle,
    remote: HelloMessage,
    peer_id: i64,
    connections: SharedWriters,
    pending_files: PendingFiles,
    fs: Arc<dyn FileSystem>,
    progress: Arc<TransferProgressRegistry>,
) where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    loop {
        match recv_framed_message(&mut reader).await {
            Ok(Some(WireMessage::Hello(h))) => {
                info!("Unexpected Hello from {}: {:?}", h.pc_name, h);
            }
            Ok(Some(WireMessage::Batch(b))) => {
                handle_batch_message(
                    &cfg,
                    &db,
                    &connections,
                    &pending_files,
                    Arc::clone(&fs),
                    peer_id,
                    &remote,
                    b,
                )
                .await;
            }
            Ok(Some(WireMessage::BatchAck(ack))) => {
                let db_guard = db.lock().await;
                let _ = db_guard.on_batch_ack(
                    peer_id,
                    &ack.share_id,
                    ack.upto_seq,
                    ack.batch_id.as_deref(),
                );
                info!(
                    "Received ack for share {:?} upto seq {} batch {:?} from {}",
                    ack.share_id.0, ack.upto_seq, ack.batch_id, remote.pc_name
                );
            }
            Ok(Some(WireMessage::FileChunk(chunk))) => {
                handle_file_chunk_message(
                    chunk,
                    &pending_files,
                    Arc::clone(&fs),
                    Arc::clone(&progress),
                )
                .await;
            }
            Ok(Some(WireMessage::TransferRequest(req))) => {
                handle_transfer_request(&cfg, &db, &connections, peer_id, req).await;
            }
            Ok(Some(WireMessage::TransferReply(reply))) => {
                handle_transfer_reply(&db, reply).await;
            }
            Ok(Some(WireMessage::TransferPushOffer(offer))) => {
                handle_transfer_push_offer(&cfg, &db, &connections, peer_id, offer).await;
            }
            Ok(Some(WireMessage::ChatMessage(msg))) => {
                handle_chat_message(&cfg, &db, &connections, peer_id, msg).await;
            }
            Ok(Some(WireMessage::ChatAck(ack))) => {
                handle_chat_ack(&db, &ack.message_id).await;
            }
            Ok(None) => {
                info!("Peer {} disconnected", remote.pc_name);
                break;
            }
            Err(e) => {
                error!("Read error from {}: {e}", remote.pc_name);
                break;
            }
        }
    }
}

async fn maybe_auto_pull(
    cfg: &AppConfig,
    db: &DbHandle,
    connections: &SharedWriters,
    peer_id: i64,
    remote: &HelloMessage,
) {
    let peer_key = format!("{}@{}", remote.pc_name, remote.instance_id);
    for share_name in &remote.shares {
        if !cfg.resolve_allow_request(share_name, &peer_key) {
            continue;
        }
        if !cfg.resolve_pull_mode(share_name, Some(&peer_key)).is_auto() {
            continue;
        }
        let share_id = ShareId::new(share_name, &remote.pc_name);
        // How far of *their* journal we already hold — the peer's namespace.
        let since_seq = {
            let db = db.lock().await;
            match db.get_share_row_id_by_share_id(&share_id) {
                Ok(row_id) => db.inbound_watermark(peer_id, row_id).unwrap_or(0),
                Err(_) => 0,
            }
        };
        let req = TransferRequest {
            protocol_version: models::WIRE_PROTOCOL_VERSION,
            request_id: Uuid::new_v4().to_string(),
            share_name: share_name.clone(),
            share_id,
            paths: Vec::new(),
            since_seq,
            from_pc: cfg.pc_name.clone(),
            from_instance: cfg.instance_id.clone(),
        };
        let _ = db
            .lock()
            .await
            .insert_transfer_request(&req, Some(peer_id), "out", "pending");
        let msg = WireMessage::TransferRequest(req);
        let _ = send_wire_to_peer(connections, peer_id, &msg).await;
        info!(share = %share_name, peer = %peer_key, "Auto-pull TransferRequest sent");
    }
}

async fn send_wire_to_peer(
    connections: &SharedWriters,
    peer_id: i64,
    msg: &WireMessage,
) -> Result<()> {
    let writer = {
        let guard = connections.lock().await;
        guard
            .iter()
            .find(|(pid, _)| *pid == peer_id)
            .map(|(_, w)| Arc::clone(w))
    };
    let Some(writer) = writer else {
        bail!("peer {peer_id} not connected");
    };
    let mut g = writer.lock().await;
    g.send(msg).await?;
    Ok(())
}

async fn handle_transfer_request(
    cfg: &AppConfig,
    db: &DbHandle,
    connections: &SharedWriters,
    peer_id: i64,
    req: TransferRequest,
) {
    let peer_key = format!("{}@{}", req.from_pc, req.from_instance);
    if !cfg.resolve_allow_pull(&req.share_name, &peer_key) {
        info!(
            request_id = %req.request_id,
            share = %req.share_name,
            from = %peer_key,
            "Inbound transfer request refused by allow_pull ACL"
        );
        let reply = TransferReply {
            protocol_version: models::WIRE_PROTOCOL_VERSION,
            request_id: req.request_id.clone(),
            status: TransferReplyStatus::Decline,
            reason: Some("allow_pull=false".into()),
        };
        let _ = db
            .lock()
            .await
            .insert_transfer_request(&req, Some(peer_id), "in", "declined");
        let _ = send_wire_to_peer(connections, peer_id, &WireMessage::TransferReply(reply)).await;
        return;
    }
    let _ = db
        .lock()
        .await
        .insert_transfer_request(&req, Some(peer_id), "in", "pending");
    let handling = cfg.resolve_request_handling(&req.share_name, Some(&peer_key));
    if handling == TransferMode::Auto {
        if let Err(e) = fulfill_transfer_request(cfg, db, connections, peer_id, &req).await {
            warn!(error = %e, "Auto-fulfill transfer request failed");
            let reply = TransferReply {
                protocol_version: models::WIRE_PROTOCOL_VERSION,
                request_id: req.request_id.clone(),
                status: TransferReplyStatus::Decline,
                reason: Some(e.to_string()),
            };
            let _ = db.lock().await.update_transfer_request_status(
                &req.request_id,
                "declined",
                Some(&e.to_string()),
            );
            let _ = send_wire_to_peer(connections, peer_id, &WireMessage::TransferReply(reply))
                .await;
        } else {
            let reply = TransferReply {
                protocol_version: models::WIRE_PROTOCOL_VERSION,
                request_id: req.request_id.clone(),
                status: TransferReplyStatus::Accept,
                reason: None,
            };
            let _ = db
                .lock()
                .await
                .update_transfer_request_status(&req.request_id, "accepted", None);
            let _ = send_wire_to_peer(connections, peer_id, &WireMessage::TransferReply(reply))
                .await;
        }
    } else {
        info!(
            request_id = %req.request_id,
            share = %req.share_name,
            from = %peer_key,
            "Inbound transfer request queued for manual reply"
        );
    }
}

pub async fn fulfill_transfer_request(
    cfg: &AppConfig,
    db: &DbHandle,
    connections: &SharedWriters,
    peer_id: i64,
    req: &TransferRequest,
) -> Result<()> {
    let peer_key = format!("{}@{}", req.from_pc, req.from_instance);
    if !cfg.resolve_allow_pull(&req.share_name, &peer_key) {
        bail!("allow_pull=false for peer {peer_key}");
    }
    let shares = db.lock().await.list_shares_table()?;
    let share_row = shares
        .into_iter()
        .find(|s| s.share_name == req.share_name && s.pc_name == cfg.pc_name)
        .context("local share not found for transfer request")?;
    let share_id = ShareId::new(&req.share_name, &cfg.pc_name);
    let basis = if !req.paths.is_empty() {
        models::IntentBasis::Snapshot {
            paths: req.paths.clone(),
        }
    } else {
        let max_seq = db.lock().await.max_journal_seq(share_row.id).unwrap_or(0);
        models::IntentBasis::JournalRange {
            from_seq: req.since_seq,
            to_seq: max_seq,
        }
    };
    let origin = if cfg
        .resolve_sync_mode(&req.share_name, None)
        .is_auto()
    {
        models::IntentOrigin::AutoPull
    } else {
        models::IntentOrigin::Reply
    };
    let (_intent_id, batch_ids) = db.lock().await.create_and_materialize_intent(
        models::IntentKind::PullFulfill,
        origin,
        &req.share_name,
        share_id,
        Some(peer_id),
        basis,
        Some(&req.request_id),
        &cfg.pc_name,
    )?;
    // Wake path is via outbox; best-effort notify if a batch was queued.
    let _ = connections;
    let _ = batch_ids;
    Ok(())
}

async fn handle_transfer_reply(db: &DbHandle, reply: TransferReply) {
    let status = match reply.status {
        TransferReplyStatus::Accept => "accepted",
        TransferReplyStatus::Decline => "declined",
    };
    let _ = db.lock().await.update_transfer_request_status(
        &reply.request_id,
        status,
        reply.reason.as_deref(),
    );

    // Close out the PullRequest intent. Without this it stays InFlight forever
    // and every `pull` permanently inflates the active-intent count.
    {
        let guard = db.lock().await;
        match guard.get_transfer_intent_by_request_id(&reply.request_id) {
            Ok(Some(intent)) if intent.status.is_active() => {
                // On accept, our side of the exchange is done: what follows is a
                // separate PullFulfill intent raised by the peer.
                let (next, err) = match reply.status {
                    TransferReplyStatus::Accept => (models::IntentStatus::Sent, None),
                    TransferReplyStatus::Decline => {
                        (models::IntentStatus::Declined, reply.reason.as_deref())
                    }
                };
                if let Err(e) = guard.update_transfer_intent_status(&intent.id, next, err) {
                    warn!(intent_id = %intent.id, error = %e, "Failed to close pull request intent");
                }
            }
            Ok(_) => {}
            Err(e) => warn!(
                request_id = %reply.request_id,
                error = %e,
                "Failed to look up intent for transfer reply"
            ),
        }
    }

    info!(
        request_id = %reply.request_id,
        status = status,
        "Transfer reply received"
    );
}

async fn handle_transfer_push_offer(
    cfg: &AppConfig,
    db: &DbHandle,
    connections: &SharedWriters,
    peer_id: i64,
    offer: models::TransferPushOffer,
) {
    let peer_key = format!("{}@{}", offer.from_pc, offer.from_instance);
    let as_req = TransferRequest {
        protocol_version: offer.protocol_version,
        request_id: offer.offer_id.clone(),
        share_id: offer.share_id,
        share_name: offer.share_name.clone(),
        since_seq: 0,
        paths: offer.paths.clone(),
        from_pc: offer.from_pc.clone(),
        from_instance: offer.from_instance.clone(),
    };
    let _ = db
        .lock()
        .await
        .insert_transfer_request(&as_req, Some(peer_id), "in", "pending");
    if cfg.resolve_pull_mode(&offer.share_name, Some(&peer_key)).is_auto() {
        let reply = TransferReply {
            protocol_version: models::WIRE_PROTOCOL_VERSION,
            request_id: offer.offer_id.clone(),
            status: TransferReplyStatus::Accept,
            reason: None,
        };
        let _ = db
            .lock()
            .await
            .update_transfer_request_status(&offer.offer_id, "accepted", None);
        let _ = send_wire_to_peer(connections, peer_id, &WireMessage::TransferReply(reply)).await;
        info!(
            offer_id = %offer.offer_id,
            share = %offer.share_name,
            peer = %peer_key,
            "Auto-accepted TransferPushOffer (pull=auto)"
        );
    } else {
        info!(
            offer_id = %offer.offer_id,
            share = %offer.share_name,
            peer = %peer_key,
            "Stored TransferPushOffer for manual pull"
        );
    }
}

async fn handle_chat_ack(db: &DbHandle, message_id: &str) {
    let _ = db
        .lock()
        .await
        .update_chat_message_status(message_id, "acked");
    info!(message_id = %message_id, "Chat ack received");
}

async fn handle_chat_message(
    _cfg: &AppConfig,
    db: &DbHandle,
    connections: &SharedWriters,
    peer_id: i64,
    msg: ChatMessage,
) {
    let kind = msg.thread_kind;
    let title = match kind {
        ThreadKind::Peer => msg
            .peer_key
            .clone()
            .unwrap_or_else(|| format!("{}@{}", msg.from_pc, msg.from_instance)),
        ThreadKind::Share => msg
            .share_name
            .clone()
            .unwrap_or_else(|| "share".to_string()),
    };
    {
        let db = db.lock().await;
        let _ = db.ensure_chat_thread(
            &msg.thread_id,
            kind,
            msg.peer_key.as_deref(),
            msg.share_name.as_deref(),
            &title,
            msg.created_at,
        );
        let record = ChatMessageRecord {
            id: msg.message_id.clone(),
            thread_id: msg.thread_id.clone(),
            from_peer: format!("{}@{}", msg.from_pc, msg.from_instance),
            body: msg.body.clone(),
            attachment_share: msg.attachment.as_ref().map(|a| a.share_name.clone()),
            attachment_path: msg.attachment.as_ref().map(|a| a.path.clone()),
            created_at: msg.created_at,
            direction: "in".into(),
            status: "received".into(),
        };
        let _ = db.insert_chat_message(&record, true);
    }
    let ack = ChatAck {
        protocol_version: models::WIRE_PROTOCOL_VERSION,
        message_id: msg.message_id.clone(),
    };
    let _ = send_wire_to_peer(connections, peer_id, &WireMessage::ChatAck(ack)).await;
    info!(
        thread = %msg.thread_id,
        from = %msg.from_pc,
        "Chat message received"
    );
}

async fn handle_batch_message(
    cfg: &AppConfig,
    db: &DbHandle,
    connections: &SharedWriters,
    pending_files: &PendingFiles,
    fs: Arc<dyn FileSystem>,
    peer_id: i64,
    remote: &HelloMessage,
    batch: models::BatchManifest,
) {
    let span = tracing::info_span!(
        "handle_batch",
        batch_id = %batch.batch_id,
        peer_id = peer_id,
        share_id = ?batch.share_id.0
    );
    async move {
        let peer_key = format!("{}@{}", remote.pc_name, remote.instance_id);

        let is_new = db
            .lock()
            .await
            .record_inbound_batch(&batch.batch_id)
            .unwrap_or(false);
        if !is_new {
            info!(from_node = %batch.from_node, "Duplicate batch ignored");
            return;
        }

        info!(from_node = %batch.from_node, change_count = batch.changes.len(), "Received batch");

        let share_row_id = match db
            .lock()
            .await
            .get_share_row_id_by_share_id(&batch.share_id)
        {
            Ok(id) => id,
            Err(e) => {
                info!(
                    "Unknown share {:?} for inbound batch {}: {e}",
                    batch.share_id.0, batch.batch_id
                );
                return;
            }
        };
        let share_row = match db.lock().await.get_share_row(share_row_id) {
            Ok(row) => row,
            Err(e) => {
                warn!(
                    share_id = ?batch.share_id.0,
                    error = %e,
                    "Failed to load share row"
                );
                return;
            }
        };
        let share_root = PathBuf::from(share_row.root_path.clone());
        let share_name = share_row.share_name.clone();
        let we_own_share = share_row.pc_name == cfg.pc_name;

        if !cfg.resolve_allow_push(&share_name, &peer_key) {
            warn!(
                peer = %peer_key,
                share = %share_name,
                "Rejecting inbound batch: allow_push=false"
            );
            // Still ack so the sender does not retry forever.
            send_batch_ack(
                connections,
                peer_id,
                &batch.share_id,
                0,
                Some(batch.batch_id.clone()),
            )
            .await;
            return;
        }

        let conflict = cfg.resolve_conflict_policy(&share_name, Some(&peer_key));
        let sync_allow = cfg.resolve_sync_allow(&share_name, Some(&peer_key));
        let ignore = cfg.resolve_ignore_patterns(&share_name, Some(&peer_key));

        // The basis decides how to read `change.seq` and whether any watermark
        // may move. A journal batch carries real positions in the sender's
        // namespace; a snapshot batch carries none at all.
        let is_journal = batch.basis == models::BatchBasis::Journal;

        // Tracked in the SENDER's namespace so the ack we send back is a number
        // the sender can interpret (invariant I4).
        let mut max_origin_seq = 0;
        for mut change in batch.changes.clone() {
            // Only journal batches can be replays; a snapshot has no position to
            // compare, and gating it on a seq would drop legitimate pushes.
            if is_journal && is_replay(db, peer_id, share_row_id, change.seq).await {
                max_origin_seq = max_origin_seq.max(change.seq);
                continue;
            }

            if !utilities::ignore::is_path_allowed(&change.path, &sync_allow, &ignore) {
                max_origin_seq = max_origin_seq.max(change.seq);
                continue;
            }

            let existing = db
                .lock()
                .await
                .get_file_meta(share_row_id, &change.path)
                .ok()
                .flatten();

            let decision = decide_apply(
                conflict,
                we_own_share,
                &change,
                existing.as_ref(),
                &batch.from_node,
            );
            let disk_rel_path = match &decision {
                ApplyDecision::Skip => {
                    max_origin_seq = max_origin_seq.max(change.seq);
                    continue;
                }
                ApplyDecision::Apply => change.path.clone(),
                ApplyDecision::KeepBoth(alt) => alt.clone(),
            };

            change.meta = resolve_change_meta(&change, existing.clone());
            if let Some(meta) = &change.meta {
                let mut meta = meta.clone();
                meta.path = disk_rel_path.clone();
                // `version` is the conflict-resolution key in `should_apply`, so
                // it may only ever be raised from the sender's journal position.
                // For a snapshot the sender's index version already travels in
                // the meta; overwriting it with a local number would shadow
                // genuine later updates.
                if is_journal && (meta.version <= 0 || change.seq > meta.version) {
                    meta.version = change.seq.max(1);
                } else if meta.version <= 0 {
                    meta.version = 1;
                }
                let _ = db.lock().await.upsert_file_meta(share_row_id, &meta);
                change.meta = Some(meta);
            }
            let expected_hash = change.meta.as_ref().map(|m| m.hash);
            let expected_size = change.meta.as_ref().map(|m| m.size);
            let wire_path = change.path.clone();

            match change.kind {
                ChangeKind::Delete => {
                    drop_existing_pending(pending_files, change.share_id, &wire_path, fs.as_ref())
                        .await;
                    apply_delete_to_disk(&share_root, &disk_rel_path, fs.as_ref()).await;
                }
                _ => {
                    prepare_pending_file(
                        pending_files,
                        change.share_id,
                        &wire_path,
                        &disk_rel_path,
                        &share_root,
                        fs.as_ref(),
                        expected_hash,
                        expected_size,
                    )
                    .await;
                }
            }

            append_inbound_change(db, peer_id, share_row_id, &change, batch.created_at).await;
            max_origin_seq = max_origin_seq.max(change.seq);
        }

        // Advance to the whole declared range, not just the changes we applied.
        // Changes filtered out by should_apply_change are still *covered* by this
        // range; without crediting them the watermark pins and the sender
        // re-sends the same range forever.
        let covered = if is_journal {
            batch.journal_to_seq.max(max_origin_seq)
        } else {
            0
        };
        if covered > 0 {
            let _ = db
                .lock()
                .await
                .bump_inbound_watermark(peer_id, share_row_id, covered);
        }

        // Always ack so the sender can resolve the intent via batch_id. upto_seq
        // is in the sender's namespace and is 0 for a snapshot batch, which the
        // sender treats as "no watermark to advance".
        send_batch_ack(
            connections,
            peer_id,
            &batch.share_id,
            covered,
            Some(batch.batch_id.clone()),
        )
        .await;
    }
    .instrument(span)
    .await;
}

async fn prepare_pending_file(
    pending_files: &PendingFiles,
    share_id: ShareId,
    wire_path: &str,
    disk_rel_path: &str,
    share_root: &Path,
    fs: &dyn FileSystem,
    expected_hash: Option<[u8; 32]>,
    expected_size: Option<u64>,
) {
    let target = share_root.join(disk_rel_path);
    if let Some(parent) = target.parent() {
        if let Err(e) = fs.create_dir_all(parent) {
            warn!(
                path = %target.display(),
                error = %e,
                "Failed to create parent directory for inbound file"
            );
            return;
        }
    }
    let staging_path = staging_tmp_path(&target);
    let writer = match fs.open_write_trunc(&staging_path) {
        Ok(w) => w,
        Err(e) => {
            warn!(
                path = %staging_path.display(),
                error = %e,
                "Failed to open staging file for inbound receive"
            );
            return;
        }
    };
    // Keyed by wire path so FileChunk messages still match.
    {
        let mut guard = pending_files.lock().await;
        if let Some(prev) = guard.remove(&(share_id, wire_path.to_string())) {
            drop(prev.writer);
            let _ = fs.remove_file(&prev.staging_path);
        }
        guard.insert(
            (share_id, wire_path.to_string()),
            InboundFileState {
                target_path: target,
                staging_path,
                writer: Some(writer),
                hasher: Sha256::new(),
                expected_offset: 0,
                expected_hash,
                expected_size,
            },
        );
    }
}

async fn drop_existing_pending(
    pending_files: &PendingFiles,
    share_id: ShareId,
    rel_path: &str,
    fs: &dyn FileSystem,
) {
    let mut guard = pending_files.lock().await;
    if let Some(prev) = guard.remove(&(share_id, rel_path.to_string())) {
        drop(prev.writer);
        let _ = fs.remove_file(&prev.staging_path);
    }
}

async fn apply_delete_to_disk(share_root: &Path, rel_path: &str, fs: &dyn FileSystem) {
    let target = share_root.join(rel_path);
    match fs.remove_file(&target) {
        Ok(_) => info!(path = %target.display(), "Deleted inbound file"),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => warn!(
            path = %target.display(),
            error = %e,
            "Failed to delete inbound file"
        ),
    }
}

async fn handle_file_chunk_message(
    chunk: FileChunk,
    pending_files: &PendingFiles,
    fs: Arc<dyn FileSystem>,
    progress: Arc<TransferProgressRegistry>,
) {
    let key = (chunk.share_id, chunk.path.clone());
    let mut completed: Option<(PathBuf, PathBuf, [u8; 32], Option<[u8; 32]>)> = None;
    {
        let mut guard = pending_files.lock().await;
        if let Some(state) = guard.get_mut(&key) {
            if chunk.offset != state.expected_offset {
                warn!(
                    share_id = ?chunk.share_id.0,
                    path = %chunk.path,
                    expected = state.expected_offset,
                    got = chunk.offset,
                    "Out-of-order file chunk"
                );
                if chunk.offset != 0 {
                    return;
                }
                // Restart staging from offset 0.
                drop(state.writer.take());
                let _ = fs.remove_file(&state.staging_path);
                match fs.open_write_trunc(&state.staging_path) {
                    Ok(w) => state.writer = Some(w),
                    Err(e) => {
                        error!(
                            path = %state.staging_path.display(),
                            error = %e,
                            "Failed to reopen staging file after restart"
                        );
                        guard.remove(&key);
                        return;
                    }
                }
                state.hasher = Sha256::new();
                state.expected_offset = 0;
            }
            if let Some(w) = state.writer.as_mut() {
                if let Err(e) = w.write_all(&chunk.data) {
                    error!(
                        path = %state.staging_path.display(),
                        error = %e,
                        "Failed to write inbound chunk to staging"
                    );
                    drop(state.writer.take());
                    let staging = state.staging_path.clone();
                    guard.remove(&key);
                    drop(guard);
                    let _ = fs.remove_file(&staging);
                    return;
                }
            }
            state.hasher.update(&chunk.data);
            state.expected_offset = chunk.offset + chunk.data.len() as u64;
            progress.note_inbound_file(
                Some(&chunk.batch_id),
                &chunk.path,
                state.expected_offset,
                state.expected_size,
                chunk.eof,
            );
            if chunk.eof {
                if let Some(mut w) = state.writer.take() {
                    if let Err(e) = w.sync_all() {
                        error!(
                            path = %state.staging_path.display(),
                            error = %e,
                            "Failed to sync staging file"
                        );
                        let staging = state.staging_path.clone();
                        guard.remove(&key);
                        drop(guard);
                        let _ = fs.remove_file(&staging);
                        return;
                    }
                }
                let target = state.target_path.clone();
                let staging = state.staging_path.clone();
                let incoming_hash = {
                    let hasher = std::mem::replace(&mut state.hasher, Sha256::new());
                    let digest = hasher.finalize();
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&digest);
                    out
                };
                let expected_hash = state.expected_hash;
                guard.remove(&key);
                completed = Some((target, staging, incoming_hash, expected_hash));
            }
        } else {
            warn!(
                share_id = ?chunk.share_id.0,
                path = %chunk.path,
                "Received file chunk with no pending file entry"
            );
        }
    }

    if let Some((target, staging, incoming_hash, expected_hash)) = completed {
        if let Some(expected) = expected_hash {
            if incoming_hash != expected {
                error!(
                    path = %target.display(),
                    share_id = ?chunk.share_id.0,
                    expected = ?expected,
                    got = ?incoming_hash,
                    "Inbound file hash mismatch; discarding staging file"
                );
                let _ = fs.remove_file(&staging);
                return;
            }
        }

        let _ = fs.remove_file(&target);
        if let Err(e) = fs.rename(&staging, &target) {
            error!(
                path = %target.display(),
                staging = %staging.display(),
                error = %e,
                "Failed to finalize inbound file from staging"
            );
            let _ = fs.remove_file(&staging);
            return;
        }
        if let Some(expected) = expected_hash {
            match utilities::compute_file_hash(fs.as_ref(), &target) {
                Ok(on_disk) if on_disk != expected => {
                    error!(
                        path = %target.display(),
                        expected = ?expected,
                        got = ?on_disk,
                        "Post-write hash verification failed; removing corrupted file"
                    );
                    let _ = fs.remove_file(&target);
                    return;
                }
                Ok(_) => {}
                Err(e) => {
                    warn!(
                        path = %target.display(),
                        error = %e,
                        "Failed to verify hash on disk after write"
                    );
                    return;
                }
            }
        }
        info!(path = %target.display(), "Wrote inbound file");
    }
}

async fn send_batch_ack(
    connections: &SharedWriters,
    target_peer_id: i64,
    share_id: &models::ShareId,
    upto_seq: i64,
    batch_id: Option<String>,
) {
    let writers: Vec<_> = {
        let guard = connections.lock().await;
        guard
            .iter()
            .filter(|(pid, _)| *pid == target_peer_id)
            .map(|(_, w)| Arc::clone(w))
            .collect()
    };

    let msg = WireMessage::BatchAck(models::BatchAck {
        protocol_version: models::WIRE_PROTOCOL_VERSION,
        share_id: *share_id,
        upto_seq,
        batch_id,
    });

    for writer_arc in writers {
        if let Err(e) = writer_arc.lock().await.send(&msg).await {
            error!(
                "Failed to send BatchAck to peer {} for share {:?}: {e}",
                target_peer_id, share_id.0
            );
        }
    }
}

#[derive(Debug, Clone)]
enum ApplyDecision {
    Apply,
    Skip,
    KeepBoth(String),
}

fn conflict_sibling_path(rel_path: &str, from_peer: &str) -> String {
    let path = Path::new(rel_path);
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let name = format!("{stem} (conflict from {from_peer}){ext}");
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            format!("{}/{name}", parent.to_string_lossy())
        }
        _ => name,
    }
}

fn decide_apply(
    policy: ConflictPolicy,
    we_own_share: bool,
    change: &FileChange,
    existing: Option<&FileMeta>,
    from_peer: &str,
) -> ApplyDecision {
    match policy {
        ConflictPolicy::OwnerWins => {
            if we_own_share {
                // Owner keeps local truth: only fill missing paths.
                if existing.is_none() && !matches!(change.kind, ChangeKind::Delete) {
                    ApplyDecision::Apply
                } else {
                    ApplyDecision::Skip
                }
            } else {
                // Mirror of someone else's share: always take owner data.
                ApplyDecision::Apply
            }
        }
        ConflictPolicy::KeepBoth => {
            match change.kind {
                ChangeKind::Delete => {
                    // Do not delete local data on conflict; only delete when LWW would.
                    if lww_should_apply_change(change, existing) {
                        ApplyDecision::Apply
                    } else {
                        ApplyDecision::Skip
                    }
                }
                _ => {
                    let Some(incoming) = change.meta.as_ref() else {
                        return ApplyDecision::Skip;
                    };
                    match existing {
                        None => ApplyDecision::Apply,
                        Some(cur) if cur.hash == incoming.hash && !cur.deleted => {
                            ApplyDecision::Skip
                        }
                        Some(_) => ApplyDecision::KeepBoth(conflict_sibling_path(
                            &change.path,
                            from_peer,
                        )),
                    }
                }
            }
        }
        ConflictPolicy::LastWriteWins => {
            if lww_should_apply_change(change, existing) {
                ApplyDecision::Apply
            } else {
                ApplyDecision::Skip
            }
        }
    }
}

fn lww_should_apply_change(change: &FileChange, existing: Option<&FileMeta>) -> bool {
    match change.kind {
        ChangeKind::Delete => match existing {
            None => true,
            Some(cur) => {
                // Prefer delete meta version when present; otherwise treat as apply.
                change
                    .meta
                    .as_ref()
                    .map(|m| should_apply_lww(m, Some(cur)))
                    .unwrap_or(true)
            }
        },
        _ => change
            .meta
            .as_ref()
            .map(|m| should_apply_lww(m, existing))
            .unwrap_or(false),
    }
}

fn resolve_change_meta(change: &FileChange, existing: Option<FileMeta>) -> Option<FileMeta> {
    match change.kind {
        ChangeKind::Delete => {
            let mut meta = existing.unwrap_or(FileMeta {
                path: change.path.clone(),
                size: 0,
                mtime: OffsetDateTime::now_utc().unix_timestamp(),
                hash: [0u8; 32],
                version: 1,
                deleted: true,
            });
            meta.deleted = true;
            Some(meta)
        }
        _ => change.meta.clone().map(|mut m| {
            m.deleted = false;
            m
        }),
    }
}

/// True when this peer's journal entry is at or below what we have already taken
/// in from them. Compares within the *peer's* namespace via the inbound
/// watermark — never against our own journal seqs, which are a different
/// numbering space, and never against a counter that local activity can move.
async fn is_replay(db: &DbHandle, peer_id: i64, share_row_id: i64, seq: i64) -> bool {
    if seq <= 0 {
        // Snapshot-derived (manual push): carries no journal position, so there
        // is nothing to compare and nothing to suppress.
        return false;
    }
    match db.lock().await.inbound_watermark(peer_id, share_row_id) {
        Ok(recv) => seq <= recv,
        Err(_) => false,
    }
}

/// Journal an inbound change under the originating peer's namespace.
///
/// Does not touch watermarks: the caller credits the batch's whole declared
/// range once, which also covers changes that were filtered out locally.
///
/// Returns the locally allocated seq, or `None` when the entry was already
/// journaled (a benign duplicate) or the append failed.
async fn append_inbound_change(
    db: &DbHandle,
    peer_id: i64,
    share_row_id: i64,
    change: &FileChange,
    created_at: i64,
) -> Option<i64> {
    let origin = JournalOrigin::Peer {
        peer_id,
        origin_seq: change.seq.max(0),
    };
    let local_seq = match db
        .lock()
        .await
        .append_journal_entry(share_row_id, change, created_at, origin)
    {
        Ok(Some(seq)) => seq,
        Ok(None) => {
            debug!(
                path = %change.path,
                origin_seq = change.seq,
                "Journal entry already present; skipping duplicate"
            );
            return None;
        }
        Err(e) => {
            error!(
                path = %change.path,
                origin_seq = change.seq,
                error = %e,
                "Failed to append inbound change to journal"
            );
            return None;
        }
    };
    Some(local_seq)
}

fn should_apply_lww(incoming: &FileMeta, existing: Option<&FileMeta>) -> bool {
    match existing {
        None => true,
        Some(cur) => {
            if incoming.version > cur.version {
                return true;
            }
            if incoming.version < cur.version {
                return false;
            }
            // Tie-break on mtime, then hash difference
            if incoming.mtime > cur.mtime {
                return true;
            }
            if incoming.mtime < cur.mtime {
                return false;
            }
            incoming.hash != cur.hash
        }
    }
}

async fn ensure_remote_shares(
    cfg: &AppConfig,
    db: &DbHandle,
    remote: &HelloMessage,
    fs: &dyn FileSystem,
) {
    if !cfg.app_state.can_host_remote() {
        return;
    }
    if remote.pc_name == cfg.pc_name {
        return;
    }

    for share_name in &remote.shares {
        let share_root = build_remote_share_root(
            &cfg.remote_share_root,
            &remote.pc_name,
            &remote.instance_id,
            share_name,
        );
        if let Err(e) = fs.create_dir_all(&share_root) {
            warn!(
                "Failed to create root for remote share {} from {}: {e}",
                share_name, remote.pc_name
            );
            continue;
        }

        let share_cfg = ShareConfig::new(share_name.clone(), share_root, true);
        let share_id = ShareId::new(share_name, &remote.pc_name);
        if let Err(e) = db
            .lock()
            .await
            .upsert_share(&remote.pc_name, &share_cfg, &share_id)
        {
            warn!(
                "Failed to register remote share {} from {}: {e}",
                share_name, remote.pc_name
            );
        }
    }
}

/// Confirm the peer's certificate was issued for the name it claims.
///
/// Trusting a CA establishes that a peer belongs to the network, not which member
/// it is; without this a node holding any valid certificate could announce itself
/// under another node's name. When `tls_insecure_shared_cert` is set the network
/// has deliberately given up per-node identity, so the failure is downgraded to a
/// warning and the peer is stamped insecure the same way a plaintext one is.
async fn check_peer_identity(
    cfg: &AppConfig,
    db: &DbHandle,
    peer_id: i64,
    peer_name: &str,
    certs: Option<&[rustls::Certificate]>,
) -> Result<()> {
    match verify_peer_cert_name(certs, peer_name) {
        Ok(()) => Ok(()),
        Err(e) if cfg.tls_insecure_shared_cert => {
            warn!(
                peer = %peer_name,
                error = %e,
                "Accepting peer without certificate identity (tls_insecure_shared_cert is enabled)"
            );
            let now = OffsetDateTime::now_utc().unix_timestamp();
            db.lock().await.mark_peer_insecure(peer_id, now)?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

async fn refuse_if_quarantined(cfg: &AppConfig, db: &DbHandle, remote: &HelloMessage) -> Result<()> {
    let key = format!("{}@{}", remote.pc_name, remote.instance_id);
    if cfg.is_peer_quarantined(&key) || cfg.is_peer_quarantined(&remote.pc_name) {
        bail!("peer {key} is quarantined (config)");
    }
    let locked = db.lock().await;
    if locked.is_peer_quarantined(&key)? || locked.is_peer_quarantined(&remote.pc_name)? {
        bail!("peer {key} is quarantined (db)");
    }
    Ok(())
}

fn ensure_peer_fingerprint(
    cfg: &AppConfig,
    peer_name: &str,
    fingerprint: Option<&str>,
) -> Result<()> {
    if cfg.tls_peer_fingerprints.is_empty() {
        return Ok(());
    }
    let Some(expected) = cfg.tls_peer_fingerprints.get(peer_name) else {
        return Ok(());
    };

    let Some(actual) = fingerprint else {
        bail!(
            "TLS peer {} did not provide a certificate for fingerprint pinning",
            peer_name
        );
    };

    let normalized_actual = normalize_fingerprint(actual);
    let allowed: HashSet<String> = expected
        .iter()
        .map(|fp| normalize_fingerprint(fp))
        .collect();
    if !allowed.contains(&normalized_actual) {
        bail!(
            "TLS certificate fingerprint mismatch for peer {} (got {}, expected one of {:?})",
            peer_name,
            actual,
            expected
        );
    }
    Ok(())
}

#[cfg(test)]
mod conflict_tests {
    use super::*;
    use models::ShareId;

    fn meta(path: &str, version: i64, hash_byte: u8) -> FileMeta {
        FileMeta {
            path: path.into(),
            size: 1,
            mtime: 10,
            hash: [hash_byte; 32],
            version,
            deleted: false,
        }
    }

    fn change(kind: ChangeKind, path: &str, version: i64, hash_byte: u8) -> FileChange {
        FileChange {
            seq: version,
            share_id: ShareId::new("s", "pc"),
            path: path.into(),
            kind,
            meta: Some(meta(path, version, hash_byte)),
        }
    }

    #[test]
    fn lww_prefers_higher_version() {
        let incoming = change(ChangeKind::Modify, "a.txt", 2, 1);
        let existing = meta("a.txt", 1, 2);
        assert!(matches!(
            decide_apply(
                ConflictPolicy::LastWriteWins,
                true,
                &incoming,
                Some(&existing),
                "bob"
            ),
            ApplyDecision::Apply
        ));
        let older = change(ChangeKind::Modify, "a.txt", 1, 1);
        let newer = meta("a.txt", 2, 2);
        assert!(matches!(
            decide_apply(
                ConflictPolicy::LastWriteWins,
                true,
                &older,
                Some(&newer),
                "bob"
            ),
            ApplyDecision::Skip
        ));
    }

    #[test]
    fn lww_delete_respects_version() {
        let mut del = change(ChangeKind::Delete, "a.txt", 1, 0);
        del.kind = ChangeKind::Delete;
        let existing = meta("a.txt", 5, 1);
        assert!(matches!(
            decide_apply(
                ConflictPolicy::LastWriteWins,
                true,
                &del,
                Some(&existing),
                "bob"
            ),
            ApplyDecision::Skip
        ));
    }

    #[test]
    fn owner_wins_blocks_inbound_on_owned_share() {
        let incoming = change(ChangeKind::Modify, "a.txt", 9, 1);
        let existing = meta("a.txt", 1, 2);
        assert!(matches!(
            decide_apply(
                ConflictPolicy::OwnerWins,
                true,
                &incoming,
                Some(&existing),
                "bob"
            ),
            ApplyDecision::Skip
        ));
        assert!(matches!(
            decide_apply(
                ConflictPolicy::OwnerWins,
                false,
                &incoming,
                Some(&existing),
                "bob"
            ),
            ApplyDecision::Apply
        ));
    }

    #[test]
    fn keep_both_writes_sibling() {
        let incoming = change(ChangeKind::Modify, "dir/a.txt", 1, 1);
        let existing = meta("dir/a.txt", 1, 2);
        match decide_apply(
            ConflictPolicy::KeepBoth,
            true,
            &incoming,
            Some(&existing),
            "bob",
        ) {
            ApplyDecision::KeepBoth(p) => {
                assert_eq!(p, "dir/a (conflict from bob).txt");
            }
            other => panic!("expected KeepBoth, got {other:?}"),
        }
    }
}
