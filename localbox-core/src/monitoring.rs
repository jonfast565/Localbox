use anyhow::{anyhow, Context, Result};
use db::Db;
use models::AppConfig;
use serde::Serialize;
use std::thread;
use std::time::{Duration, SystemTime};

#[derive(Debug, Serialize)]
pub struct MetricsSnapshot {
    pub queue_depth: u64,
    pub queue_due_now: u64,
    pub change_log_total: u64,
    pub peers: Vec<PeerSnapshot>,
    pub timestamp: i64,
}

#[derive(Debug, Serialize)]
pub struct PeerSnapshot {
    pub id: i64,
    pub pc_name: String,
    pub instance_id: String,
    pub last_seen: i64,
    pub state: String,
    pub prefer_tls: bool,
    pub stale_for_secs: i64,
}

pub struct MonitorOptions {
    pub interval_secs: u64,
    pub iterations: Option<u32>,
    pub queue_threshold: u64,
    pub stale_peer_seconds: i64,
    pub json: bool,
    pub exit_on_alert: bool,
}

pub fn run_monitor(cfg: &AppConfig, opts: &MonitorOptions) -> Result<()> {
    let db = Db::open(&cfg.db_path)
        .with_context(|| format!("failed to open DB {}", cfg.db_path.display()))?;
    let mut iteration = 0u32;
    loop {
        iteration = iteration.saturating_add(1);
        let snapshot = collect_metrics(&db)?;
        let alerts = evaluate_alerts(&snapshot, opts);
        if opts.json {
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
        } else {
            println!(
                "[{}] queue_depth={} due_now={} peers={} change_log={}",
                snapshot.timestamp,
                snapshot.queue_depth,
                snapshot.queue_due_now,
                snapshot.peers.len(),
                snapshot.change_log_total
            );
        }
        for alert in &alerts {
            eprintln!("ALERT: {alert}");
        }
        if !alerts.is_empty() && opts.exit_on_alert {
            let joined = alerts.join("; ");
            return Err(anyhow!(joined));
        }
        if let Some(limit) = opts.iterations {
            if iteration >= limit {
                break;
            }
        }
        thread::sleep(Duration::from_secs(opts.interval_secs.max(1)));
    }
    Ok(())
}

fn collect_metrics(db: &Db) -> Result<MetricsSnapshot> {
    let now = current_ts();
    let queue_depth = db.outbound_queue_depth()? as u64;
    let queue_due_now = db.outbound_queue_due_now(now)? as u64;
    let change_log_total = db.change_log_total()? as u64;
    let peers = db
        .list_peers()?
        .into_iter()
        .map(|p| PeerSnapshot {
            id: p.id,
            pc_name: p.pc_name,
            instance_id: p.instance_id,
            last_seen: p.last_seen,
            state: p.state,
            prefer_tls: p.prefer_tls,
            stale_for_secs: now.saturating_sub(p.last_seen),
        })
        .collect();
    Ok(MetricsSnapshot {
        queue_depth,
        queue_due_now,
        change_log_total,
        peers,
        timestamp: now,
    })
}

fn evaluate_alerts(snapshot: &MetricsSnapshot, opts: &MonitorOptions) -> Vec<String> {
    let mut alerts = Vec::new();
    if snapshot.queue_depth > opts.queue_threshold {
        alerts.push(format!(
            "outbound queue depth {} exceeds threshold {}",
            snapshot.queue_depth, opts.queue_threshold
        ));
    }
    if snapshot.queue_due_now > opts.queue_threshold {
        alerts.push(format!(
            "outbound batches due now {} exceeds threshold {}",
            snapshot.queue_due_now, opts.queue_threshold
        ));
    }
    let stale: Vec<_> = snapshot
        .peers
        .iter()
        .filter(|p| p.stale_for_secs > opts.stale_peer_seconds)
        .map(|p| format!("{}@{}", p.pc_name, p.instance_id))
        .collect();
    if !stale.is_empty() {
        alerts.push(format!(
            "{} peer(s) have not checked in for {}s: {}",
            stale.len(),
            opts.stale_peer_seconds,
            stale.join(", ")
        ));
    }
    alerts
}

fn current_ts() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
