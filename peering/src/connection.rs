use anyhow::{bail, Context, Result};
use models::{AppConfig, ChangeKind, FileChange, FileMeta, HelloMessage, ShareConfig, ShareId, WireMessage};
use rustls::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{error, info, warn};
use utilities::disk_utilities::build_remote_share_root;
use utilities::{DynStream, FileSystem, Net};

use crate::writer::{recv_framed_message, send_framed_message, PeerWriter};
use crate::{DbHandle, SharedWriters};

pub async fn handle_connection(
    stream: DynStream,
    cfg: &AppConfig,
    db: &DbHandle,
    share_names: &[String],
    addr: SocketAddr,
    connections: SharedWriters,
    tls_acceptor: TlsAcceptor,
    fs: Arc<dyn FileSystem>,
    _net: Arc<dyn Net>,
) -> Result<()> {
    let tls_stream = tls_acceptor.accept(stream).await?;
    let mut tls_stream = tls_stream;
    let (remote, resolved_peer_id) =
        perform_handshake(&mut tls_stream, cfg, db, share_names, addr, fs.clone()).await?;

    let (reader, writer) = io::split(tls_stream);
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
    );
    Ok(())
}

pub async fn connect_to_peer(
    peer_addr: SocketAddr,
    server_name: &str,
    cfg: &AppConfig,
    db: &DbHandle,
    share_names: &[String],
    connections: SharedWriters,
    connector: TlsConnector,
    fs: Arc<dyn FileSystem>,
    net: Arc<dyn Net>,
) -> Result<()> {
    let tcp = net.connect_tcp(peer_addr).await?;
    let name = ServerName::try_from(server_name)
        .or_else(|_| ServerName::try_from(peer_addr.ip().to_string().as_str()))
        .context("server name for TLS")?;
    let mut tls_stream = connector.connect(name, tcp).await?;
    let (remote, peer_id) =
        perform_handshake(&mut tls_stream, cfg, db, share_names, peer_addr, fs.clone()).await?;

    let (reader, writer) = io::split(tls_stream);
    {
        let mut guard = connections.lock().await;
        guard.push((
            peer_id,
            Arc::new(AsyncMutex::new(PeerWriter::Client(writer))),
        ));
    }
    let _reader_task = spawn_incoming_reader(reader, db.clone(), remote, peer_id, connections.clone());
    info!("Established outbound TLS to {}", peer_addr);
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
        pc_name: cfg.pc_name.clone(),
        instance_id: cfg.instance_id.clone(),
        listen_port: cfg.listen_addr.port(),
        shares: share_names.to_vec(),
    };
    let msg = WireMessage::Hello(hello);
    send_framed_message(stream, &msg).await?;

    match recv_framed_message(stream).await? {
        Some(WireMessage::Hello(remote)) => {
            info!(
                "Handshake with peer {} (instance={}) at {} shares={:?}",
                remote.pc_name, remote.instance_id, addr, remote.shares
            );
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let peer_addr = SocketAddr::new(addr.ip(), remote.listen_port);
            let peer_id = db.lock().await.upsert_peer(
                &remote.pc_name,
                &remote.instance_id,
                peer_addr,
                now,
                "connected",
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
) -> tokio::task::JoinHandle<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(incoming_reader_loop(reader, db, remote, peer_id, connections))
}

async fn incoming_reader_loop<R>(
    mut reader: R,
    db: DbHandle,
    remote: HelloMessage,
    peer_id: i64,
    connections: SharedWriters,
) where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    loop {
        match recv_framed_message(&mut reader).await {
            Ok(Some(WireMessage::Hello(h))) => {
                info!("Unexpected Hello from {}: {:?}", h.pc_name, h);
            }
            Ok(Some(WireMessage::Batch(b))) => {
                handle_batch_message(&db, &connections, peer_id, b).await;
            }
            Ok(Some(WireMessage::BatchAck(ack))) => {
                if let Ok(share_row_id) = db.lock().await.get_share_row_id_by_share_id(&ack.share_id)
                {
                    let _ = db
                        .lock()
                        .await
                        .bump_last_seq_acked(peer_id, share_row_id, ack.upto_seq);
                }
                info!(
                    "Received ack for share {:?} upto seq {} from {}",
                    ack.share_id.0, ack.upto_seq, remote.pc_name
                );
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
    peer_id: i64,
    batch: models::BatchManifest,
) {
    let is_new = db
        .lock()
        .await
        .record_inbound_batch(&batch.batch_id)
        .unwrap_or(false);
    if !is_new {
        info!(
            "Duplicate batch {} from {} ignored",
            batch.batch_id, batch.from_node
        );
        return;
    }

    info!(
        "Received batch {} from {} with {} changes",
        batch.batch_id,
        batch.from_node,
        batch.changes.len()
    );

    let mut max_seq_for_share = 0;
    for mut change in batch.changes.clone() {
        let Some(share_row_id) = resolve_share_row_id(db, &change).await else {
            continue;
        };

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

        if is_replay(db, share_row_id, change.seq).await {
            continue;
        }

        if let Some(seq) = append_change_and_ack(db, peer_id, share_row_id, &mut change, batch.created_at).await {
            max_seq_for_share = max_seq_for_share.max(seq);
        }
    }

    if max_seq_for_share > 0 {
        send_batch_ack(connections, peer_id, &batch.share_id, max_seq_for_share).await;
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

async fn resolve_share_row_id(db: &DbHandle, change: &FileChange) -> Option<i64> {
    match db.lock().await.get_share_row_id_by_share_id(&change.share_id) {
        Ok(id) => Some(id),
        Err(e) => {
            info!("Unknown share for change {:?}: {e}", change.share_id.0);
            None
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
