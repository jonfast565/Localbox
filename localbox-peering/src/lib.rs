#![allow(dead_code)]

use anyhow::Result;
use db::Db;
use models::{AppConfig, ShareContext, ShareId, WireMessage};
use time::OffsetDateTime;
use tls::ManagedTls;
use tokio::sync::{mpsc, Mutex};
use tokio::task::{self, JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use utilities::{FileSystem, Net};

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

mod connection;
mod discovery;
mod writer;

type DbHandle = Arc<Mutex<Db>>;
type SharedWriters = Arc<Mutex<Vec<(i64, Arc<tokio::sync::Mutex<writer::PeerWriter>>)>>>;
type PendingFiles = Arc<Mutex<HashMap<(ShareId, String), InboundFileState>>>;

#[derive(Debug)]
struct InboundFileState {
    target_path: PathBuf,
    buffer: Vec<u8>,
    expected_offset: u64,
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
        })
    }

    pub async fn run(
        &self,
        net_rx: mpsc::Receiver<String>,
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
            token.clone(),
        );
        let listener = self.spawn_tcp_listener(
            connections.clone(),
            pending_files.clone(),
            tls.clone(),
            token.clone(),
        );
        let plain_listener =
            self.spawn_plain_listener(connections.clone(), pending_files.clone(), token.clone());
        let sender = self.spawn_outbox_worker(
            connections.clone(),
            self.share_map.clone(),
            self.fs.clone(),
            net_rx,
            token.clone(),
        );

        tokio::select! {
            _ = token.cancelled() => {
                info!("PeerManager cancellation requested");
            }
            _ = async {
                let _ = tokio::join!(discovery, listener, plain_listener, sender, tls_watch);
            } => {}
        }
        Ok(())
    }

    fn spawn_tcp_listener(
        &self,
        connections: SharedWriters,
        pending_files: PendingFiles,
        tls: Arc<ManagedTls>,
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
                    let file_payloads =
                        prepare_file_payloads(&share_map, &item.manifest, fs.clone()).await;
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
                        if let Err(e) =
                            send_file_chunks(&mut guard, &item.manifest, &file_payloads).await
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
                        if max_seq > 0 {
                            let db_guard = db.lock().await;
                            if let Ok(share_row_id) =
                                db_guard.get_share_row_id_by_share_id(&item.manifest.share_id)
                            {
                                let _ = db_guard.bump_last_seq_sent(pid, share_row_id, max_seq);
                            }
                        }
                    }

                    if any_sent && !any_fail {
                        info!(batch_id = %item.batch_id, peer_id = ?target_peer, "Batch sent");
                        let _ = db.lock().await.mark_outbound_sent(&item.batch_id);
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

async fn prepare_file_payloads(
    share_map: &HashMap<[u8; 16], ShareContext>,
    manifest: &models::BatchManifest,
    fs: Arc<dyn FileSystem>,
) -> Vec<Option<Arc<Vec<u8>>>> {
    let mut out = Vec::with_capacity(manifest.changes.len());
    let Some(share_ctx) = share_map.get(&manifest.share_id.0) else {
        warn!(
            share_id = ?manifest.share_id.0,
            "Share not registered locally; cannot stream file contents"
        );
        out.resize(manifest.changes.len(), None);
        return out;
    };

    for change in &manifest.changes {
        if !matches!(change.kind, models::ChangeKind::Delete) {
            let Some(meta) = &change.meta else {
                out.push(None);
                continue;
            };
            if meta.deleted {
                out.push(None);
                continue;
            }
            let full_path = share_ctx.root_path.join(&change.path);
            match read_file_async(fs.clone(), full_path.clone()).await {
                Ok(bytes) => {
                    let computed = hash_bytes(&bytes);
                    if computed != meta.hash {
                        warn!(
                            path = %change.path,
                            share = %share_ctx.share_name,
                            "File hash changed before send (recorded {:?}, current {:?}); sending latest bytes",
                            meta.hash,
                            computed,
                        );
                    }
                    out.push(Some(Arc::new(bytes)));
                }
                Err(e) => {
                    warn!(
                        path = %change.path,
                        share = %share_ctx.share_name,
                        error = %e,
                        "Failed to read file for outbound transfer"
                    );
                    out.push(None);
                }
            }
        } else {
            out.push(None);
        }
    }

    out
}

async fn read_file_async(fs: Arc<dyn FileSystem>, path: PathBuf) -> std::io::Result<Vec<u8>> {
    task::spawn_blocking(move || fs.read(&path))
        .await
        .unwrap_or_else(|e| {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))
        })
}

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

async fn send_file_chunks(
    writer: &mut writer::PeerWriter,
    manifest: &models::BatchManifest,
    payloads: &[Option<Arc<Vec<u8>>>],
) -> anyhow::Result<()> {
    for (change, payload) in manifest.changes.iter().zip(payloads.iter()) {
        let Some(data_arc) = payload else {
            continue;
        };
        let data = data_arc.as_ref();
        if data.is_empty() {
            let chunk = models::FileChunk {
                share_id: manifest.share_id,
                path: change.path.clone(),
                offset: 0,
                data: Vec::new(),
                eof: true,
            };
            writer.send(&WireMessage::FileChunk(chunk)).await?;
            continue;
        }
        let mut offset = 0u64;
        while (offset as usize) < data.len() {
            let end = ((offset as usize) + FILE_CHUNK_SIZE).min(data.len());
            let chunk_bytes = data[offset as usize..end].to_vec();
            let eof = end >= data.len();
            let chunk = models::FileChunk {
                share_id: manifest.share_id,
                path: change.path.clone(),
                offset,
                data: chunk_bytes,
                eof,
            };
            writer.send(&WireMessage::FileChunk(chunk)).await?;
            offset = end as u64;
        }
    }
    Ok(())
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
