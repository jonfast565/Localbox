#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use db::{Db, JournalOrigin};
use models::{AppConfig, ChangeKind, FileChange, FileMeta, ShareContext};
use peering::PeerCommand;
use notify::{
    event::ModifyKind, event::RenameMode, EventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use peering::PeerManager;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use utilities::compute_file_hash;
use utilities::disk_utilities::build_meta_with_retry_limited;
use utilities::{init_logging, FileSystem, Net, RealFileSystem, RealNet};
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
    workdir: Option<PathBuf>,
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

    pub fn with_in_memory_db(
        cfg: AppConfig,
        fs: Arc<dyn FileSystem>,
        net: Arc<dyn Net>,
    ) -> Result<Self> {
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
        let workdir = std::env::current_dir().ok();
        let mut db_raw = db_raw;
        let shares = db_raw.load_shares(&cfg)?;
        for sc in &shares {
            seed_journal_from_index(&mut db_raw, sc, &fs, workdir.as_deref())?;
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
            workdir,
        };
        Ok(engine)
    }

    fn spawn_change_aggregator(
        &mut self,
        rx: mpsc::Receiver<FileChange>,
        token: CancellationToken,
    ) {
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
        let cfg = self.cfg.clone();

        tokio::spawn(change_aggregator_task(
            db,
            cfg,
            agg_window_ms,
            net_tx,
            from_node,
            share_labels,
            share_names,
            rx,
            token,
        ));
    }

    pub fn db_handle(&self) -> Arc<Mutex<Db>> {
        Arc::clone(&self.db)
    }

    pub fn config(&self) -> &AppConfig {
        &self.cfg
    }

    pub fn shares(&self) -> &[ShareContext] {
        &self.shares
    }

    pub fn net_tx(&self) -> mpsc::Sender<String> {
        self.net_tx.clone()
    }

    fn start_watchers(&self, token: CancellationToken) {
        for sc in &self.shares {
            let share = sc.clone();
            let tx = self.change_tx.clone();
            let fs = Arc::clone(&self.fs);
            let workdir = self.workdir.clone();
            tokio::spawn(start_single_watcher(
                share,
                tx,
                fs,
                workdir,
                token.clone(),
            ));
        }
    }

    pub async fn run(self) -> Result<()> {
        let token = CancellationToken::new();
        self.run_with_token(token).await
    }

    pub async fn run_with_token(self, token: CancellationToken) -> Result<()> {
        let (cmd_tx, cmd_rx) = mpsc::channel::<PeerCommand>(256);
        self.run_inner(token, cmd_rx, Some(cmd_tx), true, None)
            .await
    }

    /// Run engine with an existing peer-command channel and optional in-process shell.
    pub async fn run_with_peer_commands(
        self,
        token: CancellationToken,
        cmd_tx: mpsc::Sender<PeerCommand>,
        cmd_rx: mpsc::Receiver<PeerCommand>,
        interactive: bool,
    ) -> Result<()> {
        self.run_inner(token, cmd_rx, Some(cmd_tx), true, Some(interactive))
            .await
    }

    async fn run_inner(
        mut self,
        token: CancellationToken,
        cmd_rx: mpsc::Receiver<PeerCommand>,
        cmd_tx: Option<mpsc::Sender<PeerCommand>>,
        start_control: bool,
        interactive: Option<bool>,
    ) -> Result<()> {
        info!("Engine running");

        self.start_watchers(token.clone());

        if let Some(rx) = self.change_rx.take() {
            self.spawn_change_aggregator(rx, token.clone());
        }

        let progress = models::TransferProgressRegistry::new();
        let peer_mgr = PeerManager::with_progress(
            self.cfg.clone(),
            Arc::clone(&self.db),
            self.net_tx.clone(),
            self.shares.clone(),
            self.fs.clone(),
            self.net.clone(),
            Arc::clone(&progress),
        )?;

        let cleanup_task = tokio::spawn(cleanup_old_batches_task(
            Arc::clone(&self.db),
            token.clone(),
        ));

        let net_rx = self.net_rx.take().expect("net_rx must be present");

        let peering_task = {
            let token = token.clone();
            tokio::spawn(async move {
                if let Err(e) = peer_mgr.run_with_commands(net_rx, cmd_rx, token).await {
                    error!("PeerManager exited with error: {e}");
                }
            })
        };

        let share_hooks = crate::service::ShareHooks {
            change_tx: self.change_tx.clone(),
            fs: Arc::clone(&self.fs),
            workdir: self.workdir.clone(),
            token: token.clone(),
        };

        let control_task = if start_control {
            if let Some(cmd_tx) = cmd_tx.clone() {
                let cfg = self.cfg.clone();
                let db = Arc::clone(&self.db);
                let net_tx = self.net_tx.clone();
                let progress = Arc::clone(&progress);
                let share_hooks = share_hooks.clone();
                let token = token.clone();
                Some(tokio::spawn(async move {
                    if let Err(e) = crate::control::run_control_server(
                        cfg,
                        db,
                        net_tx,
                        cmd_tx,
                        progress,
                        Some(share_hooks),
                        token,
                    )
                    .await
                    {
                        error!("Control server exited: {e}");
                    }
                }))
            } else {
                None
            }
        } else {
            None
        };

        let shell_task = if interactive.unwrap_or(false) {
            if let Some(cmd_tx) = cmd_tx {
                let cfg = self.cfg.clone();
                let db = Arc::clone(&self.db);
                let net_tx = self.net_tx.clone();
                let progress = Arc::clone(&progress);
                let share_hooks = share_hooks.clone();
                let token = token.clone();
                Some(tokio::spawn(async move {
                    if let Err(e) = crate::shell::run_inprocess_shell(
                        cfg,
                        db,
                        net_tx,
                        cmd_tx,
                        progress,
                        Some(share_hooks),
                        token,
                    )
                    .await
                    {
                        error!("Interactive shell exited: {e}");
                    }
                }))
            } else {
                None
            }
        } else {
            None
        };

        tokio::select! {
            _ = token.cancelled() => {
                info!("Engine cancellation requested");
            }
            _ = async {
                match (control_task, shell_task) {
                    (Some(c), Some(s)) => {
                        let _ = tokio::join!(cleanup_task, peering_task, c, s);
                    }
                    (Some(c), None) => {
                        let _ = tokio::join!(cleanup_task, peering_task, c);
                    }
                    (None, Some(s)) => {
                        let _ = tokio::join!(cleanup_task, peering_task, s);
                    }
                    (None, None) => {
                        let _ = tokio::join!(cleanup_task, peering_task);
                    }
                }
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

async fn persist_incoming_change(
    db: &Arc<Mutex<Db>>,
    mut change: FileChange,
) -> Option<FileChange> {
    let db_guard = db.lock().await;
    let share_row_id = db_guard
        .get_share_row_id_by_share_id(&change.share_id)
        .ok()?;
    let created_at = OffsetDateTime::now_utc().unix_timestamp();
    // Peek the seq the journal will assign so `meta.version` can carry it. Safe
    // because we hold the DB lock across both calls, so nothing can allocate in
    // between; the append below is still the authority.
    let seq = db_guard.next_journal_seq(share_row_id).ok()?;
    change.seq = seq;

    if change.kind == ChangeKind::Delete && change.meta.is_none() {
        let existing = db_guard
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
        deleted_meta.version = seq;
        deleted_meta.deleted = true;
        if let Err(e) = db_guard.upsert_file_meta(share_row_id, &deleted_meta) {
            error!("DB upsert_file_meta (delete) error: {e}");
        }
        change.meta = Some(deleted_meta);
    } else if let Some(meta) = &mut change.meta {
        meta.version = seq;
        if let Err(e) = db_guard.upsert_file_meta(share_row_id, meta) {
            error!("DB upsert_file_meta error: {e}");
        }
    }

    match db_guard.append_journal_entry(share_row_id, &change, created_at, JournalOrigin::Local) {
        Ok(Some(seq)) => {
            change.seq = seq;
            Some(change)
        }
        Ok(None) => {
            // Locally authored entries mint a fresh MAX+1 seq and are exempt from
            // the origin index, so there is nothing they can collide with.
            error!(
                "Journal append for {} was unexpectedly a no-op",
                change.path
            );
            None
        }
        Err(e) => {
            error!("Failed to append journal entry for {}: {e}", change.path);
            None
        }
    }
}

fn group_pending_by_share(pending: &mut Vec<FileChange>) -> HashMap<[u8; 16], Vec<FileChange>> {
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
    cfg: &AppConfig,
    share_names: &HashMap<[u8; 16], String>,
    from_node: &str,
    share_key: [u8; 16],
    _changes: Vec<FileChange>,
    net_tx: &mpsc::Sender<String>,
    _created_at: i64,
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
        return;
    }

    let label = format_share_label(&share_id, share_labels);
    for pid in peer_ids {
        let peer_key = {
            let guard = db.lock().await;
            guard.get_peer(pid).ok().flatten().map(|p| {
                format!("{}@{}", p.pc_name, p.instance_id)
            })
        };
        if let Some(ref pk) = peer_key {
            if !cfg.resolve_allow_push(&share_name, pk) {
                continue;
            }
        }
        if !cfg
            .resolve_sync_mode(&share_name, peer_key.as_deref())
            .is_auto()
        {
            continue;
        }
        let (from_seq, to_seq) = {
            let guard = db.lock().await;
            let Ok(share_row_id) = guard.get_share_row_id_by_share_id(&share_id) else {
                continue;
            };
            let (_, last_acked) = guard.get_peer_progress(pid, share_row_id).unwrap_or((0, 0));
            let max_seq = guard.max_journal_seq(share_row_id).unwrap_or(0);
            (last_acked, max_seq)
        };
        if to_seq <= from_seq {
            continue;
        }
        match db.lock().await.create_and_materialize_intent(
            models::IntentKind::SyncCatchup,
            models::IntentOrigin::AutoSync,
            &share_name,
            share_id,
            Some(pid),
            models::IntentBasis::JournalRange { from_seq, to_seq },
            None,
            from_node,
        ) {
            Ok((intent_id, batch_ids)) => {
                for bid in &batch_ids {
                    let _ = net_tx.try_send(bid.clone());
                }
                info!(
                    intent_id = %intent_id,
                    peer_id = pid,
                    share = %label,
                    from_seq,
                    to_seq,
                    batches = batch_ids.len(),
                    "Queued SyncCatchup intent from share journal"
                );
            }
            Err(e) => error!(
                "Failed SyncCatchup intent for peer {pid} share {label}: {e}"
            ),
        }
    }
}

fn format_share_label(
    share_id: &models::ShareId,
    share_labels: &HashMap<[u8; 16], String>,
) -> String {
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
    use super::{
        format_share_label, group_pending_by_share, handle_path_event, handle_rename_event,
        map_event_kind,
    };
    use models::ShareContext;
    use models::{ChangeKind, ConflictPolicy, FileChange, ShareId};
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
            map_event_kind(&EventKind::Modify(ModifyKind::Data(
                notify::event::DataChange::Any
            ))),
            Some(ChangeKind::Modify)
        );
        assert_eq!(
            map_event_kind(&EventKind::Remove(RemoveKind::File)),
            Some(ChangeKind::Delete)
        );
        assert_eq!(
            map_event_kind(&EventKind::Access(notify::event::AccessKind::Any)),
            None
        );
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
            ignore_patterns: Vec::new(),
            sync_allow: Vec::new(),
            conflict: ConflictPolicy::LastWriteWins,
            max_file_size_bytes: None,
            index: HashMap::new(),
        };

        let (tx, mut rx) = mpsc::channel(8);
        handle_rename_event(
            &fs,
            &share,
            &[root.join("old.txt"), root.join("new.txt")],
            &notify::event::RenameMode::Both,
            &tx,
            None,
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

    #[test]
    fn ignores_paths_under_workdir() {
        let fs: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());
        let root = PathBuf::from("/share");
        let workdir = root.join(".localbox");
        fs.create_dir_all(&workdir).unwrap();
        fs.write(&workdir.join("state.db"), b"data").unwrap();

        let share = ShareContext {
            id: 1,
            share_name: "s".to_string(),
            pc_name: "pc".to_string(),
            share_id: ShareId::new("s", "pc"),
            root_path: root.clone(),
            recursive: true,
            ignore_patterns: Vec::new(),
            sync_allow: Vec::new(),
            conflict: ConflictPolicy::LastWriteWins,
            max_file_size_bytes: None,
            index: HashMap::new(),
        };

        let (tx, mut rx) = mpsc::channel(8);
        handle_path_event(
            &fs,
            &share,
            &EventKind::Create(CreateKind::File),
            workdir.join("state.db"),
            &tx,
            Some(workdir.as_path()),
            1,
            0,
        );

        assert!(rx.try_recv().is_err());
    }

    /// Seeding must be idempotent: before this was fixed, both arms of a dead
    /// if/else appended unconditionally, so every restart re-journaled the whole
    /// index under fresh seqs -- inflating max_journal_seq and re-sending
    /// everything to every peer.
    #[test]
    fn seed_journal_from_index_is_idempotent_across_restarts() {
        use super::seed_journal_from_index;
        use models::{
            AppConfig, ApplicationState, ConflictPolicy, FileMeta, ShareConfig, TransferMode,
        };

        let fs: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());
        let root = PathBuf::from("/seed-share");
        let cfg = AppConfig {
            pc_name: "pc-one".into(),
            instance_id: "inst".into(),
            display_name: String::new(),
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            plain_listen_addr: "127.0.0.1:0".parse().unwrap(),
            use_tls_for_peers: false,
            discovery_port: 0,
        discovery_send_ports: Vec::new(),
            dht_port: 5003,
            utp_port: 5004,
            enable_dht: false,
        enable_utp: false,
            bootstrap_peers: Vec::new(),
            aggregation_window_ms: 100,
            db_path: PathBuf::new(),
            log_path: PathBuf::new(),
            tls_cert_path: PathBuf::new(),
            tls_key_path: PathBuf::new(),
            tls_ca_cert_path: PathBuf::new(),
            tls_pinned_ca_fingerprints: Vec::new(),
            tls_peer_fingerprints: HashMap::new(),
            tls_insecure_shared_cert: false,
            remote_share_root: PathBuf::from("remote"),
            shares: vec![ShareConfig {
                name: "shareA".into(),
                root_path: root.clone(),
                recursive: true,
                ignore_patterns: Vec::new(),
                sync_allow: Vec::new(),
                max_file_size_bytes: None,
                sync: TransferMode::Manual,
                pull: TransferMode::Manual,
                request_handling: None,
                conflict: ConflictPolicy::LastWriteWins,
            }],
            app_state: ApplicationState::MirrorHost,
            request_handling: TransferMode::Manual,
            peer_policies: Vec::new(),
            quarantined_peers: Vec::new(),
            control_socket: PathBuf::from("localbox.sock"),
        };

        let mut db = db::Db::open_in_memory().unwrap();
        let mut share = db.load_shares(&cfg).unwrap().remove(0);
        for name in ["one.txt", "two.txt"] {
            share.index.insert(
                name.to_string(),
                FileMeta {
                    path: name.to_string(),
                    size: 3,
                    mtime: 100,
                    hash: [5u8; 32],
                    version: 1,
                    deleted: false,
                },
            );
        }

        seed_journal_from_index(&mut db, &share, &fs, None).unwrap();
        let after_first = (
            db.journal_entry_count().unwrap(),
            db.max_journal_seq(share.id).unwrap(),
        );
        assert_eq!(after_first, (2, 2));

        // Restart: same index, same journal.
        seed_journal_from_index(&mut db, &share, &fs, None).unwrap();
        assert_eq!(
            (
                db.journal_entry_count().unwrap(),
                db.max_journal_seq(share.id).unwrap()
            ),
            after_first,
            "re-seeding must not append duplicate entries"
        );
    }
}

pub(crate) fn log_banner() {
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
    workdir: Option<PathBuf>,
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
            workdir.as_deref(),
            RETRY_ATTEMPTS,
            RETRY_DELAY_MS,
        ) {
            continue;
        }

        for path in event.paths {
            if is_in_workdir(workdir.as_deref(), &path) {
                continue;
            }
            handle_path_event(
                &fs,
                &share,
                &event.kind,
                path,
                &change_tx,
                workdir.as_deref(),
                RETRY_ATTEMPTS,
                RETRY_DELAY_MS,
            );
        }

        std::thread::sleep(StdDuration::from_millis(10));
    }
}

async fn change_aggregator_task(
    db: Arc<Mutex<Db>>,
    cfg: AppConfig,
    agg_window_ms: u64,
    net_tx: mpsc::Sender<String>,
    from_node: String,
    share_labels: HashMap<[u8; 16], String>,
    share_names: HashMap<[u8; 16], String>,
    mut rx: mpsc::Receiver<FileChange>,
    token: CancellationToken,
) {
    let mut pending: Vec<FileChange> = Vec::new();
    const MAX_PENDING_CHANGES: usize = 50_000;
    let mut ticker = interval(Duration::from_millis(agg_window_ms));

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            maybe_change = rx.recv() => {
                let Some(change) = maybe_change else {
                    break;
                };

                let label = format_share_label(&change.share_id, &share_labels);
                // Always persist to the share journal; SyncCatchup intents are gated by sync policy.
                if let Some(change) = persist_incoming_change(&db, change).await {
                    info!("Logged change for share {}: {}", label, change.path);
                    if pending.len() >= MAX_PENDING_CHANGES {
                        warn!(
                            "Dropping change due to pending buffer limit ({}): {}",
                            MAX_PENDING_CHANGES,
                            change.path
                        );
                    } else {
                        pending.push(change);
                    }
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
                        &cfg,
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

pub(crate) async fn start_single_watcher(
    share: ShareContext,
    tx: mpsc::Sender<FileChange>,
    fs: Arc<dyn FileSystem>,
    workdir: Option<PathBuf>,
    token: CancellationToken,
) {
    let _ = tokio::task::spawn_blocking(move || {
        watch_share_blocking(share, tx, fs, workdir, token);
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

async fn run_peering(
    peer_mgr: PeerManager,
    net_rx: mpsc::Receiver<String>,
    token: CancellationToken,
) {
    if let Err(e) = peer_mgr.run(net_rx, token).await {
        error!("PeerManager error: {e}");
    }
}

fn is_in_workdir(workdir: Option<&Path>, path: &Path) -> bool {
    workdir.map(|wd| path.starts_with(wd)).unwrap_or(false)
}

fn handle_rename_if_needed(
    fs: &Arc<dyn FileSystem>,
    share: &ShareContext,
    event: &notify::Event,
    change_tx: &mpsc::Sender<FileChange>,
    workdir: Option<&Path>,
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
                workdir,
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
    workdir: Option<&Path>,
    attempts: usize,
    delay_ms: u64,
) {
    if is_in_workdir(workdir, &path) {
        return;
    }

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

    if !utilities::ignore::is_path_allowed(
        &rel_path,
        &share.sync_allow,
        &share.ignore_patterns,
    ) {
        return;
    }
    if path
        .file_name()
        .and_then(|n| n.to_str())
        .map(utilities::is_staging_tmp_name)
        .unwrap_or(false)
    {
        return;
    }

    let meta_opt = match change_kind {
        ChangeKind::Delete => None,
        _ => match build_meta_with_retry_limited(
            fs.as_ref(),
            &path,
            &rel_path,
            attempts,
            delay_ms,
            share.max_file_size_bytes,
        ) {
            Ok(meta) => Some(meta),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                info!("File missing during event, treating as delete: {:?}", path);
                None
            }
            Err(e) => {
                warn!(
                    "Failed to gather file info for {:?} ({}): {e}",
                    path, share.share_name
                );
                None
            }
        },
    };

    if !matches!(change_kind, ChangeKind::Delete) && meta_opt.is_none() {
        return;
    }

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

pub(crate) fn seed_journal_from_index(
    db: &mut db::Db,
    share: &ShareContext,
    fs: &Arc<dyn FileSystem>,
    workdir: Option<&Path>,
) -> Result<()> {
    let share_row_id = share.id;
    let now = OffsetDateTime::now_utc().unix_timestamp();

    // Walk the current index; seed the journal with any path it does not yet
    // cover. Skipping already-journaled paths is what keeps this idempotent:
    // without it every restart re-appended the whole index under fresh seqs,
    // inflating max_journal_seq and re-sending everything to every peer.
    for meta in share.index.values() {
        let mut meta = meta.clone();
        let full_path = share.root_path.join(&meta.path);
        if is_in_workdir(workdir, &full_path) {
            continue;
        }
        if db.journal_has_path(share_row_id, &meta.path)? {
            continue;
        }
        let seq = db.next_journal_seq(share_row_id)?;
        meta.version = seq;
        let meta_for_change = meta.clone();
        let change = FileChange {
            seq,
            share_id: share.share_id,
            path: meta.path.clone(),
            kind: if meta.deleted {
                meta.deleted = true;
                ChangeKind::Delete
            } else {
                ChangeKind::Modify
            },
            meta: Some(meta_for_change),
        };
        let _ = db.upsert_file_meta(share_row_id, &meta);
        db.append_journal_entry(share_row_id, &change, now, JournalOrigin::Local)?;
    }

    // Detect files missing from DB (filesystem drift) and add them.
    if let Ok(fs_entries) = fs.read_dir(&share.root_path) {
        for entry in fs_entries {
            if !entry.metadata.is_file {
                continue;
            }
            if is_in_workdir(workdir, &entry.path) {
                continue;
            }
            let entry_path = entry.path;
            let rel = match entry_path.strip_prefix(&share.root_path) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let rel_path = rel.to_string_lossy().to_string();
            if !utilities::ignore::is_path_allowed(
                &rel_path,
                &share.sync_allow,
                &share.ignore_patterns,
            ) {
                continue;
            }
            if let Some(max) = share.max_file_size_bytes {
                if entry.metadata.len > max {
                    continue;
                }
            }
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
            let seq = db.next_journal_seq(share_row_id)?;
            let meta = FileMeta {
                path: rel_path.clone(),
                size,
                mtime,
                hash,
                version: seq,
                deleted: false,
            };
            let change = FileChange {
                seq,
                share_id: share.share_id,
                path: rel_path.clone(),
                kind: ChangeKind::Modify,
                meta: Some(meta.clone()),
            };
            let _ = db.upsert_file_meta(share_row_id, &meta);
            db.append_journal_entry(share_row_id, &change, now, JournalOrigin::Local)?;
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
    workdir: Option<&Path>,
    attempts: usize,
    delay_ms: u64,
) {
    if paths.iter().any(|p| is_in_workdir(workdir, p)) {
        return;
    }
    let (from_opt, to_opt) = match rename_mode {
        RenameMode::Both => (paths.get(0), paths.get(1)),
        RenameMode::From => (paths.get(0), None),
        RenameMode::To => (None, paths.get(0)),
        _ => (None, None),
    };

    if let Some(from) = from_opt {
        if let Ok(rel) = from.strip_prefix(&share.root_path) {
            let rel_str = rel.to_string_lossy().to_string();
            if !utilities::ignore::is_path_allowed(
                &rel_str,
                &share.sync_allow,
                &share.ignore_patterns,
            ) {
                return;
            }
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
            if !utilities::ignore::is_path_allowed(
                &rel_str,
                &share.sync_allow,
                &share.ignore_patterns,
            ) {
                return;
            }
            match build_meta_with_retry_limited(
                fs.as_ref(),
                to,
                &rel_str,
                attempts,
                delay_ms,
                share.max_file_size_bytes,
            ) {
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
