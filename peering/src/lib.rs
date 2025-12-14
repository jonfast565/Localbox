#![allow(dead_code)]

use anyhow::Result;
use db::Db;
use models::{AppConfig, ShareContext, WireMessage};
use time::OffsetDateTime;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use utilities::{FileSystem, Net};
use tokio_util::sync::CancellationToken;

use std::sync::Arc;

mod connection;
mod discovery;
pub mod tls;
mod writer;

type DbHandle = Arc<Mutex<Db>>;
type SharedWriters = Arc<Mutex<Vec<(i64, Arc<tokio::sync::Mutex<writer::PeerWriter>>)>>>;

pub struct PeerManager {
    cfg: AppConfig,
    db: DbHandle,
    tls: tls::TlsComponents,
    net_tx: mpsc::Sender<String>,
    fs: Arc<dyn FileSystem>,
    net: Arc<dyn Net>,
    shares: Vec<ShareContext>,
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
        let tls = tls::TlsComponents::from_config(&cfg, fs.as_ref())?;
        Ok(Self {
            cfg,
            db,
            tls,
            net_tx,
            fs,
            net,
            shares,
        })
    }

    pub async fn run(&self, net_rx: mpsc::Receiver<String>, token: CancellationToken) -> Result<()> {
        let connections: SharedWriters = Arc::new(Mutex::new(Vec::new()));

        let discovery = discovery::spawn_discovery(
            self.cfg.clone(),
            Arc::clone(&self.db),
            self.shares.clone(),
            self.tls.connector.clone(),
            connections.clone(),
            self.net_tx.clone(),
            self.fs.clone(),
            self.net.clone(),
            token.clone(),
        );
        let listener = self.spawn_tcp_listener(connections.clone(), token.clone());
        let sender = self.spawn_outbox_worker(connections.clone(), net_rx, token.clone());

        tokio::select! {
            _ = token.cancelled() => {
                info!("PeerManager cancellation requested");
            }
            _ = async {
                let _ = tokio::join!(discovery, listener, sender);
            } => {}
        }
        Ok(())
    }

    fn spawn_tcp_listener(&self, connections: SharedWriters, token: tokio_util::sync::CancellationToken) -> JoinHandle<()> {
        let cfg = self.cfg.clone();
        let db = Arc::clone(&self.db);
        let share_names: Vec<String> = self.shares.iter().map(|s| s.share_name.clone()).collect();
        let tls_acceptor = self.tls.acceptor.clone();
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
                                let tls_acceptor = tls_acceptor.clone();
                                let fs = fs.clone();
                                let net = net.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = connection::handle_connection(
                                        stream,
                                        &cfg,
                                        &db,
                                        &share_names,
                                        addr,
                                        connections,
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


    fn spawn_outbox_worker(
        &self,
        connections: SharedWriters,
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

                    for (pid, writer) in writers {
                        if let Err(e) = writer.lock().await.send(&msg).await {
                            any_fail = true;
                            warn!(
                                batch_id = %item.batch_id,
                                peer_id = pid,
                                error = %e,
                                "Failed to send batch"
                            );
                        } else {
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
