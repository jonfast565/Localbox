//! Private BEP5 DHT mesh via irontide (bootstrap peers only — no public Mainline).

use anyhow::Result;
use irontide_core::Id20;
use irontide_dht::{DhtConfig, DhtHandle, IpVoteSource};
use irontide_utp::UtpSocket;
use models::{peer_dht_infohash, peer_dht_mutable_seed, AppConfig, TransferProgressRegistry};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tls::ManagedTls;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use utilities::{FileSystem, Net};

use crate::discovery::spawn_connect_task;
use crate::{DbHandle, PendingFiles, SharedWriters};

/// Compact endpoint record published via BEP44 mutable items + announce.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerEndpointRecord {
    pub pc_name: String,
    pub instance_id: String,
    pub tls_port: u16,
    pub plain_port: u16,
    pub utp_port: u16,
    pub candidates: Vec<String>,
}

fn bencode_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 16);
    out.extend_from_slice(bytes.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(bytes);
    out
}

fn peer_infohash(pc_name: &str) -> Id20 {
    Id20(peer_dht_infohash(pc_name))
}

pub fn spawn_dht(
    cfg: AppConfig,
    db: DbHandle,
    tls: Arc<ManagedTls>,
    connections: SharedWriters,
    fs: Arc<dyn FileSystem>,
    net: Arc<dyn Net>,
    pending_files: PendingFiles,
    progress: Arc<TransferProgressRegistry>,
    utp: Option<UtpSocket>,
    token: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = dht_loop(
            cfg,
            db,
            tls,
            connections,
            fs,
            net,
            pending_files,
            progress,
            utp,
            token,
        )
        .await
        {
            warn!("DHT loop exited: {e:#}");
        }
    })
}

async fn dht_loop(
    cfg: AppConfig,
    db: DbHandle,
    tls: Arc<ManagedTls>,
    connections: SharedWriters,
    fs: Arc<dyn FileSystem>,
    net: Arc<dyn Net>,
    pending_files: PendingFiles,
    progress: Arc<TransferProgressRegistry>,
    utp: Option<UtpSocket>,
    token: CancellationToken,
) -> Result<()> {
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", cfg.dht_port).parse()?;
    let bootstrap_nodes: Vec<String> = cfg
        .bootstrap_peers
        .iter()
        .map(|p| p.addr.clone())
        .collect();

    let state_dir = cfg
        .db_path
        .parent()
        .map(|p| p.join("dht-state"))
        .unwrap_or_else(|| PathBuf::from("dht-state"));
    let _ = std::fs::create_dir_all(&state_dir);

    let mut dht_cfg = DhtConfig::default();
    dht_cfg.bind_addr = bind_addr;
    // Private mesh only — never the public Mainline bootstrap list.
    dht_cfg.bootstrap_nodes = bootstrap_nodes;
    dht_cfg.enforce_node_id = false;
    dht_cfg.state_dir = Some(state_dir);
    dht_cfg.read_only_mode = false;

    let (dht, mut external_ip_rx) = DhtHandle::start(dht_cfg).await?;
    info!(
        "Private BEP5 DHT listening on {} (bootstrap={})",
        bind_addr,
        cfg.bootstrap_peers.len()
    );

    // Immediate TCP dials from bootstrap session_addr hints.
    for peer in &cfg.bootstrap_peers {
        if let (Some(session), Some(pc_name)) = (&peer.session_addr, &peer.pc_name) {
            if let Ok(addr) = session.parse::<SocketAddr>() {
                let plain = SocketAddr::new(addr.ip(), 0);
                let shares = crate::local_advertised_shares(&db, &cfg).await;
                let utp_hint = if cfg.utp_enabled() {
                    Some(SocketAddr::new(addr.ip(), cfg.utp_port))
                } else {
                    None
                };
                spawn_connect_task(
                    addr,
                    plain,
                    utp_hint,
                    pc_name,
                    &cfg,
                    &db,
                    &shares,
                    connections.clone(),
                    tls.clone(),
                    fs.clone(),
                    net.clone(),
                    pending_files.clone(),
                    Arc::clone(&progress),
                    utp.clone(),
                    token.clone(),
                );
            } else if let Ok(addrs) = tokio::net::lookup_host(session).await {
                if let Some(addr) = addrs.filter(|a| a.is_ipv4()).next() {
                    let plain = SocketAddr::new(addr.ip(), 0);
                    let shares = crate::local_advertised_shares(&db, &cfg).await;
                    let utp_hint = if cfg.utp_enabled() {
                        Some(SocketAddr::new(addr.ip(), cfg.utp_port))
                    } else {
                        None
                    };
                    spawn_connect_task(
                        addr,
                        plain,
                        utp_hint,
                        pc_name,
                        &cfg,
                        &db,
                        &shares,
                        connections.clone(),
                        tls.clone(),
                        fs.clone(),
                        net.clone(),
                        pending_files.clone(),
                        Arc::clone(&progress),
                        utp.clone(),
                        token.clone(),
                    );
                }
            }
        }
    }

    let mut reflexive: Option<IpAddr> = None;
    let mut announce_seq: i64 = 1;
    let mut interval = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            _ = token.cancelled() => {
                let _ = dht.shutdown_and_wait().await;
                break;
            }
            ip = external_ip_rx.recv() => {
                if let Some(ip) = ip {
                    info!(%ip, "DHT external IP consensus");
                    reflexive = Some(ip);
                    let _ = dht
                        .update_external_ip(ip, IpVoteSource::Dht(u64::from(cfg.dht_port)))
                        .await;
                }
            }
            _ = interval.tick() => {
                if let Err(e) = announce_self(&dht, &cfg, reflexive, &mut announce_seq).await {
                    warn!("DHT announce failed: {e:#}");
                }
                lookup_and_dial(
                    &dht,
                    &cfg,
                    &db,
                    &tls,
                    &connections,
                    &fs,
                    &net,
                    &pending_files,
                    &progress,
                    utp.clone(),
                    &token,
                ).await;
            }
        }
    }
    Ok(())
}

async fn announce_self(
    dht: &DhtHandle,
    cfg: &AppConfig,
    reflexive: Option<IpAddr>,
    seq: &mut i64,
) -> Result<()> {
    let info_hash = peer_infohash(&cfg.pc_name);
    let announce_port = if cfg.utp_enabled() {
        cfg.utp_port
    } else {
        cfg.listen_addr.port()
    };
    dht.announce(info_hash, announce_port).await?;

    let mut candidates = Vec::new();
    if let Some(ip) = reflexive {
        if cfg.utp_enabled() {
            candidates.push(SocketAddr::new(ip, cfg.utp_port).to_string());
        }
        candidates.push(SocketAddr::new(ip, cfg.listen_addr.port()).to_string());
    }
    let record = PeerEndpointRecord {
        pc_name: cfg.pc_name.clone(),
        instance_id: cfg.instance_id.clone(),
        tls_port: cfg.listen_addr.port(),
        plain_port: cfg.plain_listen_addr.port(),
        utp_port: cfg.advertised_utp_port(),
        candidates,
    };
    let json = serde_json::to_vec(&record)?;
    let value = bencode_string(&json);
    let seed = peer_dht_mutable_seed(&cfg.pc_name);
    dht.put_mutable(seed, value, *seq, b"localbox-v1".to_vec())
        .await?;
    *seq += 1;
    debug!(peer = %cfg.pc_name, "Published DHT endpoint record");
    Ok(())
}

async fn lookup_and_dial(
    dht: &DhtHandle,
    cfg: &AppConfig,
    db: &DbHandle,
    tls: &Arc<ManagedTls>,
    connections: &SharedWriters,
    fs: &Arc<dyn FileSystem>,
    net: &Arc<dyn Net>,
    pending_files: &PendingFiles,
    progress: &Arc<TransferProgressRegistry>,
    utp: Option<UtpSocket>,
    token: &CancellationToken,
) {
    let mut targets: HashSet<String> = HashSet::new();
    for peer in &cfg.bootstrap_peers {
        if let Some(name) = &peer.pc_name {
            if name != &cfg.pc_name {
                targets.insert(name.clone());
            }
        }
    }
    if let Ok(peers) = db.lock().await.list_peers() {
        for p in peers {
            if p.pc_name != cfg.pc_name {
                targets.insert(p.pc_name);
            }
        }
    }

    let shares = crate::local_advertised_shares(db, &cfg).await;

    for pc_name in targets {
        // BEP44 mutable record (richer candidates).
        let seed = peer_dht_mutable_seed(&pc_name);
        let pk = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        if let Ok(Some((value, _seq))) = dht.get_mutable(pk, b"localbox-v1".to_vec()).await {
            if let Some(record) = decode_endpoint_record(&value) {
                dial_from_record(
                    cfg,
                    db,
                    tls,
                    connections,
                    fs,
                    net,
                    pending_files,
                    progress,
                    utp.clone(),
                    token,
                    &shares,
                    &record,
                );
                continue;
            }
        }

        // Classic get_peers announce fallback.
        let info_hash = peer_infohash(&pc_name);
        if let Ok(mut rx) = dht.get_peers(info_hash).await {
            let deadline = tokio::time::sleep(Duration::from_secs(8));
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    _ = &mut deadline => break,
                    batch = rx.recv() => {
                        let Some(addrs) = batch else { break; };
                        for addr in addrs {
                            // Announced port is uTP when enable_utp, else TLS listen port.
                            let (tls_addr, utp_addr) = if cfg.utp_enabled() {
                                (
                                    SocketAddr::new(addr.ip(), 0),
                                    Some(addr),
                                )
                            } else {
                                (addr, None)
                            };
                            let plain = SocketAddr::new(addr.ip(), 0);
                            spawn_connect_task(
                                tls_addr,
                                plain,
                                utp_addr,
                                &pc_name,
                                cfg,
                                db,
                                &shares,
                                connections.clone(),
                                tls.clone(),
                                fs.clone(),
                                net.clone(),
                                pending_files.clone(),
                                Arc::clone(progress),
                                utp.clone(),
                                token.clone(),
                            );
                        }
                    }
                }
            }
        }
    }
}

fn decode_endpoint_record(value: &[u8]) -> Option<PeerEndpointRecord> {
    // Expect bencode string: <len>:<json>
    let colon = value.iter().position(|&b| b == b':')?;
    let json = &value[colon + 1..];
    serde_json::from_slice(json).ok()
}

fn dial_from_record(
    cfg: &AppConfig,
    db: &DbHandle,
    tls: &Arc<ManagedTls>,
    connections: &SharedWriters,
    fs: &Arc<dyn FileSystem>,
    net: &Arc<dyn Net>,
    pending_files: &PendingFiles,
    progress: &Arc<TransferProgressRegistry>,
    utp: Option<UtpSocket>,
    token: &CancellationToken,
    shares: &[models::AdvertisedShare],
    record: &PeerEndpointRecord,
) {
    if record.pc_name == cfg.pc_name {
        return;
    }
    let mut seen = HashSet::new();
    for cand in &record.candidates {
        let Ok(addr) = cand.parse::<SocketAddr>() else {
            continue;
        };
        if !seen.insert(addr.ip()) {
            continue;
        }
        let tls_addr = SocketAddr::new(
            addr.ip(),
            if record.tls_port != 0 {
                record.tls_port
            } else {
                addr.port()
            },
        );
        let plain_addr = SocketAddr::new(addr.ip(), record.plain_port);
        let utp_addr = if cfg.utp_enabled() && record.utp_port != 0 {
            Some(SocketAddr::new(addr.ip(), record.utp_port))
        } else {
            None
        };
        spawn_connect_task(
            tls_addr,
            plain_addr,
            utp_addr,
            &record.pc_name,
            cfg,
            db,
            shares,
            connections.clone(),
            tls.clone(),
            fs.clone(),
            net.clone(),
            pending_files.clone(),
            Arc::clone(progress),
            utp.clone(),
            token.clone(),
        );
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_record_bencode_round_trip() {
        let record = PeerEndpointRecord {
            pc_name: "box-a".into(),
            instance_id: "i1".into(),
            tls_port: 5000,
            plain_port: 5002,
            utp_port: 5004,
            candidates: vec!["1.2.3.4:5004".into()],
        };
        let json = serde_json::to_vec(&record).unwrap();
        let value = bencode_string(&json);
        let decoded = decode_endpoint_record(&value).unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn infohash_stable() {
        let a = peer_dht_infohash("alice");
        let b = peer_dht_infohash("alice");
        let c = peer_dht_infohash("bob");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
