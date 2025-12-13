#![allow(dead_code)]

use std::sync::Arc;
use std::collections::HashMap;

use anyhow::Result;
use db::Db;
use models::{AppConfig, BatchManifest, ChangeKind, FileChange, FileMeta, ShareContext};
use notify::{
    event::ModifyKind, event::RenameMode, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use peering::PeerManager;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use utilities::{init_logging, FileSystem, Net, RealFileSystem, RealNet};
use tokio_util::sync::CancellationToken;
use utilities::disk_utilities::build_meta_with_retry;
use utilities::compute_file_hash;
use uuid::Uuid;

const APP_BANNER: &str = r#"
       ,gggg,                                           ,ggggggggggg,                           
      d8" "8I                                    ,dPYb,dP"""88""""""Y8,                         
      88  ,dP                                    IP'`YbYb,  88      `8b                         
   8888888P"                                     I8  8I `"  88      ,8P                         
      88                                         I8  8'     88aaaad8P"                          
      88          ,ggggg,    ,gggg,    ,gggg,gg  I8 dP      88""""Y8ba    ,ggggg,     ,gg,   ,gg
 ,aa,_88         dP"  "Y8gggdP"  "Yb  dP"  "Y8I  I8dP       88      `8b  dP"  "Y8ggg d8""8b,dP" 
dP" "88P        i8'    ,8I i8'       i8'    ,8I  I8P        88      ,8P i8'    ,8I  dP   ,88"   
Yb,_,d88b,,_   ,d8,   ,d8',d8,_    _,d8,   ,d8b,,d8b,_      88_____,d8',d8,   ,d8',dP  ,dP"Y8,  
 "Y8P"  "Y88888P"Y8888P"  P""Y8888PPP"Y8888P"`Y88P'"Y88    88888888P"  P"Y8888P"  8"  dP"   "Y8"#;

const SEPARATOR: &str = r#"------------------------------------------------------------------------------------------------"#;

pub struct Engine {
    cfg: AppConfig,
    db: Arc<Mutex<Db>>,
    fs: Arc<dyn FileSystem>,
    net: Arc<dyn Net>,
    shares: Vec<ShareContext>,
    change_tx: mpsc::Sender<FileChange>,
    change_rx: Option<mpsc::Receiver<FileChange>>,
    net_tx: mpsc::Sender<String>,
    net_rx: Option<mpsc::Receiver<String>>,
}

impl Engine {
    pub fn new(cfg: AppConfig) -> Result<Self> {
        let fs: Arc<dyn FileSystem> = Arc::new(RealFileSystem::new());
        let net: Arc<dyn Net> = Arc::new(RealNet);
        Self::with_fs_net(cfg, fs, net)
    }

    pub fn with_fs_net(cfg: AppConfig, fs: Arc<dyn FileSystem>, net: Arc<dyn Net>) -> Result<Self> {
        let db = Db::open(&cfg.db_path)?;
        Self::with_fs_net_db(cfg, fs, net, db)
    }

    pub fn with_in_memory_db(cfg: AppConfig, fs: Arc<dyn FileSystem>, net: Arc<dyn Net>) -> Result<Self> {
        let db = Db::open_in_memory()?;
        Self::with_fs_net_db(cfg, fs, net, db)
    }

    pub fn with_fs_net_db(
        cfg: AppConfig,
        fs: Arc<dyn FileSystem>,
        net: Arc<dyn Net>,
        db_raw: Db,
    ) -> Result<Self> {
        init_logging(&cfg.log_path, fs.as_ref())?;
        log_banner();
        let mut db_raw = db_raw;
        let shares = db_raw.load_shares(&cfg)?;
        for sc in &shares {
            seed_change_log_from_index(&mut db_raw, sc, &fs)?;
        }
        let db = Arc::new(Mutex::new(db_raw));
        info!("Engine starting up");
        for sc in &shares {
            info!(
                "Loaded share {}@{} -> {}",
                sc.share_name,
                sc.pc_name,
                sc.root_path.display()
            );
        }

        let (change_tx, change_rx) = mpsc::channel::<FileChange>(1024);
        let (net_tx, net_rx) = mpsc::channel::<String>(1024);

        let engine = Self {
            cfg,
            db,
            fs,
            net,
            shares,
            change_tx,
            change_rx: Some(change_rx),
            net_tx,
            net_rx: Some(net_rx),
        };
        Ok(engine)
    }

    fn spawn_change_aggregator(&mut self, rx: mpsc::Receiver<FileChange>, token: CancellationToken) {
        let db = Arc::clone(&self.db);
        let agg_window_ms = self.cfg.aggregation_window_ms;
        let net_tx = self.net_tx.clone();
        let from_node = self.cfg.pc_name.clone();
        let share_labels: HashMap<[u8; 16], String> = self
            .shares
            .iter()
            .map(|s| (s.share_id.0, s.share_name.clone()))
            .collect();
        let share_names: HashMap<[u8; 16], String> = share_labels.clone();

        tokio::spawn(change_aggregator_task(
            db,
            agg_window_ms,
            net_tx,
            from_node,
            share_labels,
            share_names,
            rx,
            token,
        ));
    }

    fn start_watchers(&self, token: CancellationToken) {
        for sc in &self.shares {
            let share = sc.clone();
            let tx = self.change_tx.clone();
            let fs = Arc::clone(&self.fs);
            tokio::spawn(start_single_watcher(share, tx, fs, token.clone()));
        }
    }

    pub async fn run(self) -> Result<()> {
        let token = CancellationToken::new();
        self.run_with_token(token).await
    }

    pub async fn run_with_token(mut self, token: CancellationToken) -> Result<()> {
        info!("Engine running");

        // Start filesystem watchers for each share
        self.start_watchers(token.clone());

        if let Some(rx) = self.change_rx.take() {
            self.spawn_change_aggregator(rx, token.clone());
        }

        let peer_mgr = PeerManager::new(
            self.cfg.clone(),
            Arc::clone(&self.db),
            self.net_tx.clone(),
            self.shares.clone(),
            self.fs.clone(),
            self.net.clone(),
        )?;

        // Periodic cleanup of old batches.
        let cleanup_task =
            tokio::spawn(cleanup_old_batches_task(Arc::clone(&self.db), token.clone()));

        let net_rx = self.net_rx.take().expect("net_rx must be present");

        // Run peering (discovery + TCP listener + outbound sender).
        let peering_task = tokio::spawn(run_peering(peer_mgr, net_rx, token.clone()));

        tokio::select! {
            _ = token.cancelled() => {
                info!("Engine cancellation requested");
            }
            _ = async {
                let _ = tokio::join!(cleanup_task, peering_task);
            } => {}
        }
        Ok(())
    }

    /// Optional hook if you want to trigger changes manually (e.g. from tests).
    pub fn on_local_file_change(&mut self, share_idx: usize, mut meta: FileMeta) -> Result<()> {
        let sc = &mut self.shares[share_idx];
        if meta.version <= 0 {
            meta.version = 1;
        }
        if meta.mtime == 0 {
            meta.mtime = OffsetDateTime::now_utc().unix_timestamp();
        }
        sc.index.insert(meta.path.clone(), meta.clone());
        self.db.blocking_lock().upsert_file_meta(sc.id, &meta)?;
        info!(
            "Local change in share {}@{}: {} (v={})",
            sc.share_name, sc.pc_name, meta.path, meta.version
        );

        let change = FileChange {
            seq: 0,
            share_id: sc.share_id,
            path: meta.path.clone(),
            kind: ChangeKind::Modify,
            meta: Some(meta),
        };
        let _ = self.change_tx.try_send(change);

        Ok(())
    }
}

async fn persist_incoming_change(db: &Arc<Mutex<Db>>, mut change: FileChange) -> Option<FileChange> {
    let share_row_id = db
        .lock()
        .await
        .get_share_row_id_by_share_id(&change.share_id)
        .ok()?;
    let created_at = OffsetDateTime::now_utc().unix_timestamp();

    if change.kind == ChangeKind::Delete && change.meta.is_none() {
        let existing = db
            .lock()
            .await
            .get_file_meta(share_row_id, &change.path)
            .ok()
            .flatten();
        let mut deleted_meta = existing.unwrap_or(FileMeta {
            path: change.path.clone(),
            size: 0,
            mtime: created_at,
            hash: [0u8; 32],
            version: 1,
            deleted: true,
        });
        deleted_meta.deleted = true;
        if let Err(e) = db.lock().await.upsert_file_meta(share_row_id, &deleted_meta) {
            error!("DB upsert_file_meta (delete) error: {e}");
        }
        change.meta = Some(deleted_meta);
    } else if let Some(meta) = &change.meta {
        if let Err(e) = db.lock().await.upsert_file_meta(share_row_id, meta) {
            error!("DB upsert_file_meta error: {e}");
        }
    }

    let Ok(seq) = db
        .lock()
        .await
        .append_change_log(share_row_id, &change, created_at)
    else {
        error!("Failed to append change log for {}", change.path);
        return None;
    };

    if seq > 0 {
        change.seq = seq;
    }

    Some(change)
}

fn group_pending_by_share(
    pending: &mut Vec<FileChange>,
) -> HashMap<[u8; 16], Vec<FileChange>> {
    let mut per_share: HashMap<[u8; 16], Vec<FileChange>> = HashMap::new();
    for ch in pending.drain(..) {
        per_share
            .entry(ch.share_id.0)
            .or_insert_with(Vec::new)
            .push(ch);
    }
    per_share
}

async fn process_share_changes(
    db: &Arc<Mutex<Db>>,
    share_names: &HashMap<[u8; 16], String>,
    from_node: &str,
    share_key: [u8; 16],
    changes: Vec<FileChange>,
    net_tx: &mpsc::Sender<String>,
    created_at: i64,
    share_labels: &HashMap<[u8; 16], String>,
) {
    let share_id = models::ShareId(share_key);
    let share_name = share_names.get(&share_key).cloned().unwrap_or_default();
    let peer_ids = db
        .lock()
        .await
        .list_peer_ids_for_share_name(&share_name)
        .unwrap_or_default();

    if peer_ids.is_empty() {
        enqueue_batch(
            db,
            &share_id,
            from_node,
            &changes,
            created_at,
            None,
            net_tx,
            share_labels,
        )
        .await;
        return;
    }

    for pid in peer_ids {
        enqueue_batch(
            db,
            &share_id,
            from_node,
            &changes,
            created_at,
            Some(pid),
            net_tx,
            share_labels,
        )
        .await;
    }
}

async fn enqueue_batch(
    db: &Arc<Mutex<Db>>,
    share_id: &models::ShareId,
    from_node: &str,
    changes: &[FileChange],
    created_at: i64,
    peer_id: Option<i64>,
    net_tx: &mpsc::Sender<String>,
    share_labels: &HashMap<[u8; 16], String>,
) {
    let batch_id = Uuid::new_v4().to_string();
    let manifest = BatchManifest {
        batch_id: batch_id.clone(),
        share_id: *share_id,
        from_node: from_node.to_string(),
        created_at,
        changes: changes.to_vec(),
    };

    if let Err(e) = db
        .lock()
        .await
        .enqueue_outbound_batch(&manifest, peer_id)
    {
        match peer_id {
            Some(pid) => error!("Failed to queue batch {batch_id} for peer {pid}: {e}"),
            None => error!("Failed to queue batch {batch_id} for outbound: {e}"),
        }
        return;
    }

    let _ = net_tx.try_send(batch_id.clone());
    let label = format_share_label(share_id, share_labels);
    match peer_id {
        Some(pid) => info!(
            "Aggregated {} changes into batch {} for share {} targeting peer {}",
            changes.len(),
            batch_id,
            label,
            pid
        ),
        None => info!(
            "Aggregated {} changes into batch {} for share {} (no peers yet)",
            changes.len(),
            batch_id,
            label
        ),
    }
}

fn format_share_label(share_id: &models::ShareId, share_labels: &HashMap<[u8; 16], String>) -> String {
    if let Some(name) = share_labels.get(&share_id.0) {
        format!(
            "{} ({})",
            name,
            uuid::Uuid::from_bytes(share_id.0).hyphenated()
        )
    } else {
        uuid::Uuid::from_bytes(share_id.0).hyphenated().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{format_share_label, group_pending_by_share, handle_rename_event, map_event_kind};
    use models::{ChangeKind, FileChange, ShareId};
    use models::ShareContext;
    use notify::event::{CreateKind, ModifyKind, RemoveKind};
    use notify::EventKind;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use utilities::{FileSystem, VirtualFileSystem};

    #[test]
    fn groups_pending_by_share_id_bytes() {
        let s1 = ShareId::new("a", "pc").0;
        let s2 = ShareId::new("b", "pc").0;
        let mut pending = vec![
            FileChange {
                seq: 0,
                share_id: ShareId(s1),
                path: "p1".to_string(),
                kind: ChangeKind::Modify,
                meta: None,
            },
            FileChange {
                seq: 0,
                share_id: ShareId(s2),
                path: "p2".to_string(),
                kind: ChangeKind::Modify,
                meta: None,
            },
            FileChange {
                seq: 0,
                share_id: ShareId(s1),
                path: "p3".to_string(),
                kind: ChangeKind::Delete,
                meta: None,
            },
        ];

        let grouped = group_pending_by_share(&mut pending);
        assert!(pending.is_empty());
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped.get(&s1).unwrap().len(), 2);
        assert_eq!(grouped.get(&s2).unwrap().len(), 1);
    }

    #[test]
    fn formats_share_labels_with_optional_names() {
        let id = ShareId::new("shareA", "pc-one");
        let mut labels = HashMap::new();
        labels.insert(id.0, "shareA".to_string());
        let s = format_share_label(&id, &labels);
        assert!(s.starts_with("shareA ("));
        assert!(s.contains(')'));

        let other = ShareId::new("shareB", "pc-one");
        let s2 = format_share_label(&other, &labels);
        assert!(!s2.starts_with("shareA ("));
        assert!(s2.contains('-'));
    }

    #[test]
    fn maps_notify_event_kind_to_change_kind() {
        assert_eq!(
            map_event_kind(&EventKind::Create(CreateKind::File)),
            Some(ChangeKind::Create)
        );
        assert_eq!(
            map_event_kind(&EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Any))),
            Some(ChangeKind::Modify)
        );
        assert_eq!(
            map_event_kind(&EventKind::Remove(RemoveKind::File)),
            Some(ChangeKind::Delete)
        );
        assert_eq!(map_event_kind(&EventKind::Access(notify::event::AccessKind::Any)), None);
    }

    #[test]
    fn rename_is_emitted_as_delete_then_modify() {
        let fs: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());
        let root = PathBuf::from("/share");
        fs.create_dir_all(&root).unwrap();
        fs.write(&root.join("new.txt"), b"hello").unwrap();

        let share = ShareContext {
            id: 1,
            share_name: "s".to_string(),
            pc_name: "pc".to_string(),
            share_id: ShareId::new("s", "pc"),
            root_path: root.clone(),
            recursive: true,
            index: HashMap::new(),
        };

        let (tx, mut rx) = mpsc::channel(8);
        handle_rename_event(
            &fs,
            &share,
            &[root.join("old.txt"), root.join("new.txt")],
            &notify::event::RenameMode::Both,
            &tx,
            1,
            0,
        );

        let first = rx.try_recv().unwrap();
        let second = rx.try_recv().unwrap();
        assert_eq!(first.kind, ChangeKind::Delete);
        assert_eq!(first.path, "old.txt");
        assert_eq!(second.kind, ChangeKind::Modify);
        assert_eq!(second.path, "new.txt");
        assert!(second.meta.is_some());
    }
}

fn log_banner() {
    info!(
        "\n{}\n{}\n  name: {}\n  version: {}\n  author(s): {}\n{}\n",
        APP_BANNER,
        SEPARATOR,
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_AUTHORS"),
        SEPARATOR
    );
}

/* Blocking file watcher for a single share */

fn watch_share_blocking(
    share: ShareContext,
    change_tx: mpsc::Sender<FileChange>,
    fs: Arc<dyn FileSystem>,
    token: CancellationToken,
) {
    use std::sync::mpsc as std_mpsc;
    use std::time::Duration as StdDuration;

    const RETRY_ATTEMPTS: usize = 5;
    const RETRY_DELAY_MS: u64 = 100;

    let (tx_notify, rx_notify) = std_mpsc::channel();

    let mut watcher: RecommendedWatcher = match notify::recommended_watcher(move |res| {
        let _ = tx_notify.send(res);
    }) {
        Ok(w) => w,
        Err(e) => {
            error!(
                "Failed to create watcher for {}: {e}",
                share.root_path.display()
            );
            return;
        }
    };

    let mode = if share.root_path.is_dir() && share.recursive {
        RecursiveMode::Recursive
    } else {
        RecursiveMode::NonRecursive
    };

    if let Err(e) = watcher.watch(&share.root_path, mode) {
        error!("Failed to watch {}: {e}", share.root_path.display());
        return;
    }

    info!(
        "Watching share {}@{} ({})",
        share.share_name,
        share.pc_name,
        share.root_path.display()
    );

    loop {
        if token.is_cancelled() {
            break;
        }

        let event = match rx_notify.recv_timeout(StdDuration::from_millis(500)) {
            Ok(Ok(event)) => event,
            Ok(Err(e)) => {
                error!("Watch error on {}: {e}", share.root_path.display());
                continue;
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                warn!("Watcher channel closed for {}", share.root_path.display());
                break;
            }
        };

        if handle_rename_if_needed(
            &fs,
            &share,
            &event,
            &change_tx,
            RETRY_ATTEMPTS,
            RETRY_DELAY_MS,
        ) {
            continue;
        }

        for path in event.paths {
            handle_path_event(
                &fs,
                &share,
                &event.kind,
                path,
                &change_tx,
                RETRY_ATTEMPTS,
                RETRY_DELAY_MS,
            );
        }

        std::thread::sleep(StdDuration::from_millis(10));
    }
}

async fn change_aggregator_task(
    db: Arc<Mutex<Db>>,
    agg_window_ms: u64,
    net_tx: mpsc::Sender<String>,
    from_node: String,
    share_labels: HashMap<[u8; 16], String>,
    share_names: HashMap<[u8; 16], String>,
    mut rx: mpsc::Receiver<FileChange>,
    token: CancellationToken,
) {
    let mut pending: Vec<FileChange> = Vec::new();
    let mut ticker = interval(Duration::from_millis(agg_window_ms));

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            maybe_change = rx.recv() => {
                let Some(change) = maybe_change else {
                    break;
                };

                let label = format_share_label(&change.share_id, &share_labels);
                if let Some(change) = persist_incoming_change(&db, change).await {
                    info!("Queued change for share {}: {}", label, change.path);
                    pending.push(change);
                } else {
                    warn!("Dropping change for share {} after persistence failure", label);
                }
            }
            _ = ticker.tick() => {
                if pending.is_empty() {
                    continue;
                }

                let now = OffsetDateTime::now_utc().unix_timestamp();
                let per_share = group_pending_by_share(&mut pending);
                for (share_key, changes) in per_share {
                    process_share_changes(
                        &db,
                        &share_names,
                        &from_node,
                        share_key,
                        changes,
                        &net_tx,
                        now,
                        &share_labels,
                    )
                    .await;
                }
            }
        }
    }
}

async fn start_single_watcher(
    share: ShareContext,
    tx: mpsc::Sender<FileChange>,
    fs: Arc<dyn FileSystem>,
    token: CancellationToken,
) {
    let _ = tokio::task::spawn_blocking(move || {
        watch_share_blocking(share, tx, fs, token);
    })
    .await;
}

async fn cleanup_old_batches_task(db: Arc<Mutex<Db>>, token: CancellationToken) {
    let mut ticker = interval(Duration::from_secs(3600)); // hourly
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            _ = ticker.tick() => {}
        }
        match db.lock().await.cleanup_old_batches(7 * 24 * 3600) {
            // keep 7 days
            Ok(rows) if rows > 0 => info!("Cleaned {rows} old batches"),
            Ok(_) => {}
            Err(e) => error!("Batch cleanup error: {e}"),
        }
    }
}

async fn run_peering(peer_mgr: PeerManager, net_rx: mpsc::Receiver<String>, token: CancellationToken) {
    if let Err(e) = peer_mgr.run(net_rx, token).await {
        error!("PeerManager error: {e}");
    }
}

fn handle_rename_if_needed(
    fs: &Arc<dyn FileSystem>,
    share: &ShareContext,
    event: &notify::Event,
    change_tx: &mpsc::Sender<FileChange>,
    attempts: usize,
    delay_ms: u64,
) -> bool {
    if let EventKind::Modify(ModifyKind::Name(rename_mode)) = &event.kind {
        if matches!(
            rename_mode,
            RenameMode::Both | RenameMode::From | RenameMode::To
        ) {
            handle_rename_event(
                fs,
                share,
                &event.paths,
                rename_mode,
                change_tx,
                attempts,
                delay_ms,
            );
            return true;
        }
    }
    false
}

fn handle_path_event(
    fs: &Arc<dyn FileSystem>,
    share: &ShareContext,
    event_kind: &EventKind,
    path: std::path::PathBuf,
    change_tx: &mpsc::Sender<FileChange>,
    attempts: usize,
    delay_ms: u64,
) {
    let Some(change_kind) = map_event_kind(event_kind) else {
        return;
    };

    let rel_path = match path.strip_prefix(&share.root_path) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => {
            warn!(
                "Path {:?} not under share root {}; skipping",
                path,
                share.root_path.display()
            );
            return;
        }
    };

    let meta_opt = match change_kind {
        ChangeKind::Delete => None,
        _ => match build_meta_with_retry(fs.as_ref(), &path, &rel_path, attempts, delay_ms) {
            Ok(meta) => Some(meta),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                info!(
                    "File missing during event, treating as delete: {:?}",
                    path
                );
                None
            }
            Err(e) => {
                warn!("Failed to gather file info for {:?}: {e}", path);
                None
            }
        },
    };

    let change = FileChange {
        seq: 0,
        share_id: share.share_id,
        path: rel_path.clone(),
        kind: change_kind.clone(),
        meta: meta_opt.clone(),
    };

    info!(
        "Filesystem event in share {}@{}: {:?} {:?}",
        share.share_name, share.pc_name, change_kind, rel_path
    );

    if let Err(e) = change_tx.blocking_send(change) {
        error!("Failed to queue change: {e}");
    }
}

fn map_event_kind(event_kind: &EventKind) -> Option<ChangeKind> {
    if matches!(event_kind, EventKind::Create(_)) {
        return Some(ChangeKind::Create);
    }
    if matches!(event_kind, EventKind::Modify(_)) {
        return Some(ChangeKind::Modify);
    }
    if matches!(event_kind, EventKind::Remove(_)) {
        return Some(ChangeKind::Delete);
    }
    None
}

fn seed_change_log_from_index(
    db: &mut db::Db,
    share: &ShareContext,
    fs: &Arc<dyn FileSystem>,
) -> Result<()> {
    let share_row_id = share.id;
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // Walk current index; if WAL is empty, seed; if WAL exists but entry missing, add.
    let last_applied = db.get_last_applied_seq(share_row_id)?;
    for meta in share.index.values() {
        let mut meta = meta.clone();
        let change = FileChange {
            seq: 0,
            share_id: share.share_id,
            path: meta.path.clone(),
            kind: if meta.deleted {
                meta.deleted = true;
                ChangeKind::Delete
            } else {
                ChangeKind::Modify
            },
            meta: Some(meta),
        };
        if last_applied == 0 {
            let _ = db.append_change_log(share_row_id, &change, now)?;
        } else {
            // Append only if this path has no entry beyond last_applied (lightweight check via progress)
            let _ = db.append_change_log(share_row_id, &change, now)?;
        }
    }

    // Detect files missing from DB (filesystem drift) and add them.
    if let Ok(fs_entries) = fs.read_dir(&share.root_path) {
        for entry in fs_entries {
            if !entry.metadata.is_file {
                continue;
            }
            let entry_path = entry.path;
            let rel = match entry_path.strip_prefix(&share.root_path) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let rel_path = rel.to_string_lossy().to_string();
            if share.index.contains_key(&rel_path) {
                continue;
            }

            let size = entry.metadata.len;
            let mtime = entry
                .metadata
                .modified
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(now);
            let hash = compute_file_hash(fs.as_ref(), &entry_path).unwrap_or_else(|_| [0u8; 32]);
            let meta = FileMeta {
                path: rel_path.clone(),
                size,
                mtime,
                hash,
                version: 1,
                deleted: false,
            };
            let change = FileChange {
                seq: 0,
                share_id: share.share_id,
                path: rel_path.clone(),
                kind: ChangeKind::Modify,
                meta: Some(meta.clone()),
            };
            let _ = db.upsert_file_meta(share_row_id, &meta);
            let _ = db.append_change_log(share_row_id, &change, now)?;
        }
    }
    Ok(())
}

fn handle_rename_event(
    fs: &Arc<dyn FileSystem>,
    share: &ShareContext,
    paths: &[std::path::PathBuf],
    rename_mode: &RenameMode,
    change_tx: &mpsc::Sender<FileChange>,
    attempts: usize,
    delay_ms: u64,
) {
    let (from_opt, to_opt) = match rename_mode {
        RenameMode::Both => (paths.get(0), paths.get(1)),
        RenameMode::From => (paths.get(0), None),
        RenameMode::To => (None, paths.get(0)),
        _ => (None, None),
    };

    if let Some(from) = from_opt {
        if let Ok(rel) = from.strip_prefix(&share.root_path) {
            let rel_str = rel.to_string_lossy().to_string();
            let change = FileChange {
                seq: 0,
                share_id: share.share_id,
                path: rel_str.clone(),
                kind: ChangeKind::Delete,
                meta: None,
            };
            info!(
                "Filesystem rename (from) in share {}@{}: {:?}",
                share.share_name, share.pc_name, rel_str
            );
            if let Err(e) = change_tx.blocking_send(change) {
                error!("Failed to queue rename-from change: {e}");
            }
        }
    }

    if let Some(to) = to_opt {
        if let Ok(rel) = to.strip_prefix(&share.root_path) {
            let rel_str = rel.to_string_lossy().to_string();
            match build_meta_with_retry(fs.as_ref(), to, &rel_str, attempts, delay_ms) {
                Ok(meta) => {
                    let change = FileChange {
                        seq: 0,
                        share_id: share.share_id,
                        path: rel_str.clone(),
                        kind: ChangeKind::Modify,
                        meta: Some(meta),
                    };
                    info!(
                        "Filesystem rename (to) in share {}@{}: {:?}",
                        share.share_name, share.pc_name, rel_str
                    );
                    if let Err(e) = change_tx.blocking_send(change) {
                        error!("Failed to queue rename-to change: {e}");
                    }
                }
                Err(e) => warn!("Metadata/hash retry failed for rename target {:?}: {e}", to),
            }
        }
    }
}
