use anyhow::{bail, Context, Result};
use models::{
    AppConfig, ChangeKind, FileChange, FileChunk, FileMeta, HelloMessage, ShareConfig, ShareId,
    WireMessage,
};
use rustls::ServerName;
use std::collections::HashSet;
use std::io::ErrorKind;
use std::mem;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::io::{split, AsyncRead, AsyncWrite};
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::Instrument;
use tracing::{error, info, warn};
use utilities::disk_utilities::build_remote_share_root;
use utilities::{write_atomic, DynStream, FileSystem, Net};

use crate::writer::{recv_framed_message, send_framed_message, PeerWriter};
use crate::{DbHandle, InboundFileState, PendingFiles, SharedWriters};
use tls::{fingerprint_from_certificates, normalize_fingerprint};

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
) -> Result<()> {
    let tls_stream = tls_acceptor.accept(stream).await?;
    let mut tls_stream = tls_stream;
    let peer_fp = fingerprint_from_certificates(tls_stream.get_ref().1.peer_certificates());
    let (remote, resolved_peer_id) =
        perform_handshake(&mut tls_stream, cfg, db, share_names, addr, fs.clone()).await?;
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

    let _reader_task = spawn_incoming_reader(
        reader,
        db.clone(),
        remote,
        resolved_peer_id,
        connections.clone(),
        pending_files,
        fs,
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
) -> Result<()> {
    warn!("Inbound plaintext peer connection from {addr}");
    let (remote, resolved_peer_id) =
        perform_handshake(&mut stream, cfg, db, share_names, addr, fs.clone()).await?;
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

    let _reader_task = spawn_incoming_reader(
        reader,
        db.clone(),
        remote,
        resolved_peer_id,
        connections.clone(),
        pending_files,
        fs,
    );
    Ok(())
}

pub async fn connect_to_peer(
    peer_tls_addr: SocketAddr,
    peer_plain_addr: SocketAddr,
    server_name: &str,
    cfg: &AppConfig,
    db: &DbHandle,
    share_names: &[String],
    connections: SharedWriters,
    pending_files: PendingFiles,
    connector: TlsConnector,
    fs: Arc<dyn FileSystem>,
    net: Arc<dyn Net>,
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

    if !use_tls {
        warn!(
            "Connecting to peer {} at {} without TLS",
            server_name, target_addr
        );
    }

    let tcp = net.connect_tcp(target_addr).await?;
    if use_tls {
        let name = ServerName::try_from(server_name)
            .or_else(|_| ServerName::try_from(target_addr.ip().to_string().as_str()))
            .context("server name for TLS")?;
        let mut tls_stream = connector.connect(name, tcp).await?;
        let peer_fp = fingerprint_from_certificates(tls_stream.get_ref().1.peer_certificates());
        let (remote, peer_id) = perform_handshake(
            &mut tls_stream,
            cfg,
            db,
            share_names,
            target_addr,
            fs.clone(),
        )
        .await?;
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
        let _reader_task = spawn_incoming_reader(
            reader,
            db.clone(),
            remote,
            peer_id,
            connections.clone(),
            pending_files,
            fs,
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
        let _reader_task = spawn_incoming_reader(
            reader,
            db.clone(),
            remote,
            peer_id,
            connections.clone(),
            pending_files,
            fs,
        );
        info!("Established outbound plaintext to {}", target_addr);
    }
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
        shares: share_names.to_vec(),
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
    db: DbHandle,
    remote: HelloMessage,
    peer_id: i64,
    connections: SharedWriters,
    pending_files: PendingFiles,
    fs: Arc<dyn FileSystem>,
) -> tokio::task::JoinHandle<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(incoming_reader_loop(
        reader,
        db,
        remote,
        peer_id,
        connections,
        pending_files,
        fs,
    ))
}

async fn incoming_reader_loop<R>(
    mut reader: R,
    db: DbHandle,
    remote: HelloMessage,
    peer_id: i64,
    connections: SharedWriters,
    pending_files: PendingFiles,
    fs: Arc<dyn FileSystem>,
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
                    &db,
                    &connections,
                    &pending_files,
                    Arc::clone(&fs),
                    peer_id,
                    b,
                )
                .await;
            }
            Ok(Some(WireMessage::BatchAck(ack))) => {
                let db_guard = db.lock().await;
                if let Ok(share_row_id) = db_guard.get_share_row_id_by_share_id(&ack.share_id) {
                    let _ = db_guard.bump_last_seq_acked(peer_id, share_row_id, ack.upto_seq);
                }
                info!(
                    "Received ack for share {:?} upto seq {} from {}",
                    ack.share_id.0, ack.upto_seq, remote.pc_name
                );
            }
            Ok(Some(WireMessage::FileChunk(chunk))) => {
                handle_file_chunk_message(chunk, &pending_files, Arc::clone(&fs)).await;
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

async fn handle_batch_message(
    db: &DbHandle,
    connections: &SharedWriters,
    pending_files: &PendingFiles,
    fs: Arc<dyn FileSystem>,
    peer_id: i64,
    batch: models::BatchManifest,
) {
    let span = tracing::info_span!(
        "handle_batch",
        batch_id = %batch.batch_id,
        peer_id = peer_id,
        share_id = ?batch.share_id.0
    );
    async move {
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

        let mut max_seq_for_share = 0;
        for mut change in batch.changes.clone() {
            if is_replay(db, share_row_id, change.seq).await {
                if change.seq > 0 {
                    max_seq_for_share = max_seq_for_share.max(change.seq);
                }
                continue;
            }

            let existing = db
                .lock()
                .await
                .get_file_meta(share_row_id, &change.path)
                .ok()
                .flatten();

            if !should_apply_change(&change, existing.as_ref()) {
                continue;
            }

            change.meta = resolve_change_meta(&change, existing.clone());
            if let Some(meta) = &change.meta {
                let _ = db.lock().await.upsert_file_meta(share_row_id, meta);
            }

            match change.kind {
                ChangeKind::Delete => {
                    drop_existing_pending(pending_files, change.share_id, &change.path).await;
                    apply_delete_to_disk(&share_root, &change.path, fs.as_ref()).await;
                }
                _ => {
                    prepare_pending_file(
                        pending_files,
                        change.share_id,
                        &change.path,
                        &share_root,
                        fs.as_ref(),
                    )
                    .await;
                }
            }

            if let Some(seq) =
                append_change_and_ack(db, peer_id, share_row_id, &mut change, batch.created_at)
                    .await
            {
                max_seq_for_share = max_seq_for_share.max(seq);
            }
        }

        if max_seq_for_share > 0 {
            send_batch_ack(connections, peer_id, &batch.share_id, max_seq_for_share).await;
        }
    }
    .instrument(span)
    .await;
}

async fn prepare_pending_file(
    pending_files: &PendingFiles,
    share_id: ShareId,
    rel_path: &str,
    share_root: &Path,
    fs: &dyn FileSystem,
) {
    let target = share_root.join(rel_path);
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
    let mut guard = pending_files.lock().await;
    guard.insert(
        (share_id, rel_path.to_string()),
        InboundFileState {
            target_path: target,
            buffer: Vec::new(),
            expected_offset: 0,
        },
    );
}

async fn drop_existing_pending(pending_files: &PendingFiles, share_id: ShareId, rel_path: &str) {
    let mut guard = pending_files.lock().await;
    guard.remove(&(share_id, rel_path.to_string()));
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
) {
    let key = (chunk.share_id, chunk.path.clone());
    let mut completed: Option<(PathBuf, Vec<u8>)> = None;
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
                state.buffer.clear();
                state.expected_offset = 0;
            }
            state.buffer.extend_from_slice(&chunk.data);
            state.expected_offset = chunk.offset + chunk.data.len() as u64;
            if chunk.eof {
                let target = state.target_path.clone();
                let data = mem::take(&mut state.buffer);
                guard.remove(&key);
                completed = Some((target, data));
            }
        } else {
            warn!(
                share_id = ?chunk.share_id.0,
                path = %chunk.path,
                "Received file chunk with no pending file entry"
            );
        }
    }

    if let Some((target, data)) = completed {
        if let Err(e) = write_atomic(fs.as_ref(), &target, &data) {
            error!(
                path = %target.display(),
                error = %e,
                "Failed to materialize inbound file"
            );
        } else {
            info!(path = %target.display(), "Wrote inbound file");
        }
    }
}

async fn send_batch_ack(
    connections: &SharedWriters,
    target_peer_id: i64,
    share_id: &models::ShareId,
    upto_seq: i64,
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

fn should_apply_change(change: &FileChange, existing: Option<&FileMeta>) -> bool {
    match change.kind {
        ChangeKind::Delete => true,
        _ => change
            .meta
            .as_ref()
            .map(|m| should_apply(m, existing))
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

async fn is_replay(db: &DbHandle, share_row_id: i64, seq: i64) -> bool {
    if seq <= 0 {
        return false;
    }
    match db.lock().await.get_last_applied_seq(share_row_id) {
        Ok(last_applied) => seq <= last_applied,
        Err(_) => false,
    }
}

async fn append_change_and_ack(
    db: &DbHandle,
    peer_id: i64,
    share_row_id: i64,
    change: &mut FileChange,
    created_at: i64,
) -> Option<i64> {
    let Ok(seq) = db
        .lock()
        .await
        .append_change_log(share_row_id, change, created_at)
    else {
        return None;
    };

    change.seq = seq;
    let _ = db
        .lock()
        .await
        .bump_last_seq_acked(peer_id, share_row_id, seq);
    Some(seq)
}

fn should_apply(incoming: &FileMeta, existing: Option<&FileMeta>) -> bool {
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

        let share_cfg = ShareConfig {
            name: share_name.clone(),
            root_path: share_root,
            recursive: true,
            ignore_patterns: Vec::new(),
            max_file_size_bytes: None,
        };
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
