#![allow(dead_code)]

use anyhow::Result;
use db::Db;
use models::{AppConfig, ShareContext, ShareId, TransferProgressRegistry, WireMessage};
use time::OffsetDateTime;
use tls::ManagedTls;
use tokio::sync::{mpsc, Mutex};
use tokio::task::{self, JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use utilities::{FileSystem, Net, SyncWrite};

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

mod commands;
mod connection;
mod discovery;
mod writer;

pub use commands::PeerCommand;

type DbHandle = Arc<Mutex<Db>>;
type SharedWriters = Arc<Mutex<Vec<(i64, Arc<tokio::sync::Mutex<writer::PeerWriter>>)>>>;
type PendingFiles = Arc<Mutex<HashMap<(ShareId, String), InboundFileState>>>;

struct InboundFileState {
    target_path: PathBuf,
    staging_path: PathBuf,
    writer: Option<Box<dyn SyncWrite>>,
    hasher: Sha256,
    expected_offset: u64,
    expected_hash: Option<[u8; 32]>,
    expected_size: Option<u64>,
}

pub struct PeerManager {
    cfg: AppConfig,
    db: DbHandle,
    tls: Arc<ManagedTls>,
    net_tx: mpsc::Sender<String>,
    fs: Arc<dyn FileSystem>,
    net: Arc<dyn Net>,
    shares: Arc<Vec<ShareContext>>,
    share_map: Arc<HashMap<[u8; 16], ShareContext>>,
    progress: Arc<TransferProgressRegistry>,
}

impl PeerManager {
    pub fn new(
        cfg: AppConfig,
        db: DbHandle,
        net_tx: mpsc::Sender<String>,
        shares: Vec<ShareContext>,
        fs: Arc<dyn FileSystem>,
        net: Arc<dyn Net>,
    ) -> Result<Self> {
        Self::with_progress(cfg, db, net_tx, shares, fs, net, TransferProgressRegistry::new())
    }

    pub fn with_progress(
        cfg: AppConfig,
        db: DbHandle,
        net_tx: mpsc::Sender<String>,
        shares: Vec<ShareContext>,
        fs: Arc<dyn FileSystem>,
        net: Arc<dyn Net>,
        progress: Arc<TransferProgressRegistry>,
    ) -> Result<Self> {
        let tls = Arc::new(ManagedTls::new(&cfg, fs.clone())?);
        let shares_arc = Arc::new(shares);
        let share_map = Arc::new(map_shares_by_id(shares_arc.as_ref()));
        Ok(Self {
            cfg,
            db,
            tls,
            net_tx,
            fs,
            net,
            shares: shares_arc,
            share_map,
            progress,
        })
    }

    pub fn progress(&self) -> Arc<TransferProgressRegistry> {
        Arc::clone(&self.progress)
    }

    pub async fn run(
        &self,
        net_rx: mpsc::Receiver<String>,
        token: CancellationToken,
    ) -> Result<()> {
        let (_cmd_tx, cmd_rx) = mpsc::channel(64);
        self.run_with_commands(net_rx, cmd_rx, token).await
    }

    pub async fn run_with_commands(
        &self,
        net_rx: mpsc::Receiver<String>,
        mut cmd_rx: mpsc::Receiver<PeerCommand>,
        token: CancellationToken,
    ) -> Result<()> {
        let connections: SharedWriters = Arc::new(Mutex::new(Vec::new()));
        let pending_files: PendingFiles = Arc::new(Mutex::new(HashMap::new()));

        let tls = self.tls.clone();
        let tls_watch = tls.clone().spawn_watcher(token.clone());

        let discovery = discovery::spawn_discovery(
            self.cfg.clone(),
            Arc::clone(&self.db),
            self.shares.clone(),
            tls.clone(),
            connections.clone(),
            self.net_tx.clone(),
            self.fs.clone(),
            self.net.clone(),
            pending_files.clone(),
            Arc::clone(&self.progress),
            token.clone(),
        );
        let listener = self.spawn_tcp_listener(
            connections.clone(),
            pending_files.clone(),
            tls.clone(),
            Arc::clone(&self.progress),
            token.clone(),
        );
        let plain_listener = self.spawn_plain_listener(
            connections.clone(),
            pending_files.clone(),
            Arc::clone(&self.progress),
            token.clone(),
        );
        let sender = self.spawn_outbox_worker(
            connections.clone(),
            self.share_map.clone(),
            self.fs.clone(),
            Arc::clone(&self.progress),
            net_rx,
            token.clone(),
        );

        let cmd_connections = connections.clone();
        let cmd_db = Arc::clone(&self.db);
        let cmd_token = token.clone();
        let cmd_loop = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cmd_token.cancelled() => break,
                    maybe = cmd_rx.recv() => {
                        let Some(cmd) = maybe else { break; };
                        if let Err(e) = dispatch_peer_command(&cmd_connections, &cmd_db, cmd).await {
                            warn!("PeerCommand failed: {e}");
                        }
                    }
                }
            }
        });

        tokio::select! {
            _ = token.cancelled() => {
                info!("PeerManager cancellation requested");
            }
            _ = async {
                let _ = tokio::join!(discovery, listener, plain_listener, sender, tls_watch, cmd_loop);
            } => {}
        }
        Ok(())
    }

    fn spawn_tcp_listener(
        &self,
        connections: SharedWriters,
        pending_files: PendingFiles,
        tls: Arc<ManagedTls>,
        progress: Arc<TransferProgressRegistry>,
        token: tokio_util::sync::CancellationToken,
    ) -> JoinHandle<()> {
        let cfg = self.cfg.clone();
        let db = Arc::clone(&self.db);
        let share_names: Vec<String> = self.shares.iter().map(|s| s.share_name.clone()).collect();
        let fs = self.fs.clone();
        let net = self.net.clone();

        tokio::spawn(async move {
            let listener = match net.bind_tcp_listener(cfg.listen_addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind TCP listener: {e}");
                    return;
                }
            };
            info!("TCP listener on {}", cfg.listen_addr);

            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    res = listener.accept() => {
                        match res {
                            Ok((stream, addr)) => {
                                info!("Incoming connection from {addr}");
                                let db = Arc::clone(&db);
                                let cfg = cfg.clone();
                                let share_names = share_names.clone();
                                let connections = connections.clone();
                                let pending_files = pending_files.clone();
                                let tls = tls.clone();
                                let fs = fs.clone();
                                let net = net.clone();
                                let progress = Arc::clone(&progress);
                                tokio::spawn(async move {
                                    let tls_acceptor = tls.acceptor().await;
                                    if let Err(e) =
                                        connection::handle_tls_connection(
                                            stream,
                                            &cfg,
                                            &db,
                                            &share_names,
                                            addr,
                                            connections,
                                            pending_files,
                                            tls_acceptor,
                                            fs,
                                            net,
                                            progress,
                                        )
                                        .await
                                    {
                                        error!("connection error from {addr}: {e}");
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Accept error: {e}");
                                break;
                            }
                        }
                    }
                }
            }
        })
    }

    fn spawn_plain_listener(
        &self,
        connections: SharedWriters,
        pending_files: PendingFiles,
        progress: Arc<TransferProgressRegistry>,
        token: tokio_util::sync::CancellationToken,
    ) -> JoinHandle<()> {
        let cfg = self.cfg.clone();
        let db = Arc::clone(&self.db);
        let share_names: Vec<String> = self.shares.iter().map(|s| s.share_name.clone()).collect();
        let fs = self.fs.clone();
        let net = self.net.clone();

        tokio::spawn(async move {
            let listener = match net.bind_tcp_listener(cfg.plain_listen_addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind plaintext TCP listener: {e}");
                    return;
                }
            };
            info!("Plaintext TCP listener on {}", cfg.plain_listen_addr);

            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    res = listener.accept() => {
                        match res {
                            Ok((stream, addr)) => {
                                warn!("Incoming plaintext connection from {addr}");
                                let db = Arc::clone(&db);
                                let cfg = cfg.clone();
                                let share_names = share_names.clone();
                                let connections = connections.clone();
                                let pending_files = pending_files.clone();
                                let fs = fs.clone();
                                let net = net.clone();
                                let progress = Arc::clone(&progress);
                                tokio::spawn(async move {
                                    if let Err(e) = connection::handle_plain_connection(
                                            stream,
                                            &cfg,
                                            &db,
                                            &share_names,
                                            addr,
                                            connections,
                                            pending_files,
                                            fs,
                                        net,
                                        progress,
                                    )
                                    .await
                                    {
                                        error!("plaintext connection error from {addr}: {e}");
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Plaintext accept error: {e}");
                                break;
                            }
                        }
                    }
                }
            }
        })
    }

    fn spawn_outbox_worker(
        &self,
        connections: SharedWriters,
        share_map: Arc<HashMap<[u8; 16], ShareContext>>,
        fs: Arc<dyn FileSystem>,
        progress: Arc<TransferProgressRegistry>,
        mut net_rx: mpsc::Receiver<String>,
        token: CancellationToken,
    ) -> JoinHandle<()> {
        let db = Arc::clone(&self.db);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = ticker.tick() => {},
                    recv = net_rx.recv() => {
                        if recv.is_none() {
                            break;
                        }
                    }
                }

                let now = OffsetDateTime::now_utc().unix_timestamp();
                let due = {
                    let db_guard = db.lock().await;
                    match db_guard.dequeue_due_outbound(16, now) {
                        Ok(d) => d,
                        Err(e) => {
                            error!("Failed to read outbound queue: {e}");
                            Vec::new()
                        }
                    }
                };

                if due.is_empty() {
                    continue;
                }

                for item in due {
                    let msg = WireMessage::Batch(item.manifest.clone());
                    let max_seq = item
                        .manifest
                        .changes
                        .iter()
                        .map(|c| c.seq)
                        .max()
                        .unwrap_or(0);
                    let target_peer = item.peer_id;
                    let mut any_sent = false;
                    let mut any_fail = false;

                    // Snapshot writers we can send to without holding the lock during awaits.
                    let writers: Vec<(i64, Arc<tokio::sync::Mutex<writer::PeerWriter>>)> = {
                        let guard = connections.lock().await;
                        guard
                            .iter()
                            .filter(|(pid, _)| target_peer.is_none() || target_peer == Some(*pid))
                            .map(|(pid, w)| (*pid, Arc::clone(w)))
                            .collect()
                    };

                    let mut sent_peer: Option<i64> = None;
                    for (pid, writer) in writers {
                        let mut guard = writer.lock().await;
                        if let Err(e) = guard.send(&msg).await {
                            any_fail = true;
                            warn!(
                                batch_id = %item.batch_id,
                                peer_id = pid,
                                error = %e,
                                "Failed to send batch"
                            );
                            continue;
                        }
                        let share_name = share_map
                            .get(&item.manifest.share_id.0)
                            .map(|s| s.share_name.clone())
                            .unwrap_or_else(|| "unknown".into());
                        let bytes_total: u64 = item
                            .manifest
                            .changes
                            .iter()
                            .filter_map(|c| c.meta.as_ref())
                            .filter(|m| !m.deleted)
                            .map(|m| m.size)
                            .sum();
                        let files_total = item
                            .manifest
                            .changes
                            .iter()
                            .filter(|c| {
                                !matches!(c.kind, models::ChangeKind::Delete)
                                    && c.meta.as_ref().map(|m| !m.deleted).unwrap_or(false)
                            })
                            .count() as u64;
                        progress.begin_outbound(
                            item.intent_id.as_deref(),
                            &item.batch_id,
                            item.peer_id,
                            &share_name,
                            files_total,
                            bytes_total,
                        );
                        if let Err(e) = send_file_chunks(
                            &mut guard,
                            &item.manifest,
                            &share_map,
                            fs.clone(),
                            Arc::clone(&progress),
                            item.intent_id.as_deref(),
                        )
                        .await
                        {
                            any_fail = true;
                            warn!(
                                batch_id = %item.batch_id,
                                peer_id = pid,
                                error = %e,
                                "Failed to send file data"
                            );
                            continue;
                        }
                        any_sent = true;
                        sent_peer = Some(pid);
                    }

                    if any_sent && !any_fail {
                        info!(batch_id = %item.batch_id, peer_id = ?target_peer, "Batch sent");
                        if let Some(pid) = target_peer.or(sent_peer) {
                            let _ = db.lock().await.on_outbound_batch_sent(
                                &item.batch_id,
                                pid,
                                &item.manifest.share_id,
                                max_seq,
                            );
                        } else {
                            let _ = db.lock().await.mark_outbound_sent(&item.batch_id);
                        }
                    } else {
                        let backoff = compute_backoff_secs(item.attempts + 1);
                        warn!(
                            batch_id = %item.batch_id,
                            peer_id = ?target_peer,
                            attempts = item.attempts + 1,
                            backoff_secs = backoff,
                            "Batch send failed (will retry)"
                        );
                        let _ = db.lock().await.mark_outbound_failed(
                            &item.batch_id,
                            "send failure",
                            backoff,
                        );
                    }
                }
            }
        })
    }
}

fn compute_backoff_secs(attempts: i64) -> i64 {
    let base = 2_i64.pow(attempts.clamp(1, 6) as u32);
    (base * 5).min(300)
}

fn map_shares_by_id(shares: &[ShareContext]) -> HashMap<[u8; 16], ShareContext> {
    let mut map = HashMap::new();
    for share in shares {
        map.insert(share.share_id.0, share.clone());
    }
    map
}

const FILE_CHUNK_SIZE: usize = 128 * 1024;

pub(crate) fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn finalize_hasher(hasher: Sha256) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

async fn send_file_chunks(
    writer: &mut writer::PeerWriter,
    manifest: &models::BatchManifest,
    share_map: &HashMap<[u8; 16], ShareContext>,
    fs: Arc<dyn FileSystem>,
    progress: Arc<TransferProgressRegistry>,
    intent_id: Option<&str>,
) -> anyhow::Result<()> {
    let Some(share_ctx) = share_map.get(&manifest.share_id.0) else {
        warn!(
            share_id = ?manifest.share_id.0,
            "Share not registered locally; cannot stream file contents"
        );
        return Ok(());
    };

    for change in &manifest.changes {
        if matches!(change.kind, models::ChangeKind::Delete) {
            continue;
        }
        let Some(meta) = &change.meta else {
            continue;
        };
        if meta.deleted {
            continue;
        }
        let full_path = share_ctx.root_path.join(&change.path);
        let file_len = match fs.metadata(&full_path) {
            Ok(md) => md.len,
            Err(e) => {
                warn!(
                    path = %change.path,
                    share = %share_ctx.share_name,
                    error = %e,
                    "Failed to stat file for outbound transfer"
                );
                continue;
            }
        };

        if file_len == 0 {
            let chunk = models::FileChunk {
                protocol_version: models::WIRE_PROTOCOL_VERSION,
                batch_id: manifest.batch_id.clone(),
                share_id: manifest.share_id,
                path: change.path.clone(),
                offset: 0,
                data: Vec::new(),
                eof: true,
            };
            writer.send(&WireMessage::FileChunk(chunk)).await?;
            progress.add_outbound_bytes(intent_id, &manifest.batch_id, 0, true);
            continue;
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel::<std::io::Result<(u64, Vec<u8>, bool)>>(2);
        let path = full_path.clone();
        let fs_read = fs.clone();
        let expected_len = file_len;
        task::spawn_blocking(move || {
            let mut reader = match fs_read.open_read(&path) {
                Ok(r) => r,
                Err(e) => {
                    let _ = tx.blocking_send(Err(e));
                    return;
                }
            };
            let mut offset = 0u64;
            let mut buf = vec![0u8; FILE_CHUNK_SIZE];
            while offset < expected_len {
                let want = ((expected_len - offset) as usize).min(FILE_CHUNK_SIZE);
                let mut filled = 0usize;
                while filled < want {
                    match reader.read(&mut buf[filled..want]) {
                        Ok(0) => break,
                        Ok(n) => filled += n,
                        Err(e) => {
                            let _ = tx.blocking_send(Err(e));
                            return;
                        }
                    }
                }
                if filled == 0 {
                    let _ = tx.blocking_send(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "short read while streaming file",
                    )));
                    return;
                }
                let data = buf[..filled].to_vec();
                let next = offset + filled as u64;
                let eof = next >= expected_len;
                if tx.blocking_send(Ok((offset, data, eof))).is_err() {
                    return;
                }
                offset = next;
                if eof {
                    break;
                }
            }
        });

        let mut hasher = Sha256::new();
        while let Some(item) = rx.recv().await {
            let (offset, data, eof) = item?;
            let n = data.len() as u64;
            hasher.update(&data);
            let chunk = models::FileChunk {
                protocol_version: models::WIRE_PROTOCOL_VERSION,
                batch_id: manifest.batch_id.clone(),
                share_id: manifest.share_id,
                path: change.path.clone(),
                offset,
                data,
                eof,
            };
            writer.send(&WireMessage::FileChunk(chunk)).await?;
            progress.add_outbound_bytes(intent_id, &manifest.batch_id, n, eof);
        }

        let computed = finalize_hasher(hasher);
        if computed != meta.hash {
            warn!(
                path = %change.path,
                share = %share_ctx.share_name,
                "File hash changed during send (recorded {:?}, current {:?})",
                meta.hash,
                computed,
            );
        }
    }
    Ok(())
}

async fn dispatch_peer_command(
    connections: &SharedWriters,
    db: &DbHandle,
    cmd: PeerCommand,
) -> anyhow::Result<()> {
    match cmd {
        PeerCommand::SendToPeer { peer_id, msg } => {
            send_to_peer_id(connections, peer_id, &msg).await?;
        }
        PeerCommand::SendToPeerKey { peer_key, msg } => {
            let peer_ids = resolve_peer_ids(db, &peer_key).await;
            for pid in peer_ids {
                let _ = send_to_peer_id(connections, pid, &msg).await;
            }
        }
        PeerCommand::Broadcast { msg } => {
            let writers: Vec<Arc<tokio::sync::Mutex<writer::PeerWriter>>> = {
                let guard = connections.lock().await;
                guard.iter().map(|(_, w)| Arc::clone(w)).collect()
            };
            for writer in writers {
                let mut g = writer.lock().await;
                let _ = g.send(&msg).await;
            }
        }
    }
    Ok(())
}

/// Send a wire message to a connected peer by database peer id.
pub async fn send_to_peer(
    connections: &SharedWriters,
    peer_id: i64,
    msg: &WireMessage,
) -> anyhow::Result<()> {
    send_to_peer_id(connections, peer_id, msg).await
}

async fn send_to_peer_id(
    connections: &SharedWriters,
    peer_id: i64,
    msg: &WireMessage,
) -> anyhow::Result<()> {
    let writer = {
        let guard = connections.lock().await;
        guard
            .iter()
            .find(|(pid, _)| *pid == peer_id)
            .map(|(_, w)| Arc::clone(w))
    };
    let Some(writer) = writer else {
        anyhow::bail!("peer {peer_id} is not connected");
    };
    let mut g = writer.lock().await;
    g.send(msg).await?;
    Ok(())
}

async fn resolve_peer_ids(db: &DbHandle, peer_key: &str) -> Vec<i64> {
    let peers = db.lock().await.list_peers().unwrap_or_default();
    peers
        .into_iter()
        .filter(|p| {
            let full = format!("{}@{}", p.pc_name, p.instance_id);
            peer_key == p.pc_name || peer_key == full
        })
        .map(|p| p.id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::compute_backoff_secs;

    #[test]
    fn backoff_is_capped_and_monotonic() {
        assert_eq!(compute_backoff_secs(0), 10);
        assert_eq!(compute_backoff_secs(1), 10);
        assert_eq!(compute_backoff_secs(2), 20);
        assert_eq!(compute_backoff_secs(3), 40);
        assert_eq!(compute_backoff_secs(6), 300);
        assert_eq!(compute_backoff_secs(100), 300);
    }
}
