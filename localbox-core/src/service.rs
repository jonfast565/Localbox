use anyhow::{anyhow, bail, Context, Result};
use db::{Db, PendingTransferRequest};
use models::{
    format_chat_thread_title, peer_key, peer_thread_id, share_thread_id, AppConfig, ChatAttachment,
    ChatMessage, ChatMessageRecord, ControlEvent, FileChange, IntentBasis, IntentKind, IntentOrigin,
    IntentStatus, ShareConfig, ShareContext, ShareId, ThreadKind, ThreadSummary,
    TransferProgressRegistry, TransferReply, TransferReplyStatus, TransferRequest, WireMessage,
    WIRE_PROTOCOL_VERSION,
};
use tokio::sync::broadcast;
use peering::PeerCommand;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use utilities::{FileSystem, RealFileSystem};
use uuid::Uuid;

use crate::config::{add_share_to_config, DEFAULT_CONFIG_PATH};
use crate::engine::{rescan_share, seed_journal_from_index, start_single_watcher};
use crate::intent_ops;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ControlRequest {
    Ping,
    Status,
    Push {
        share: String,
        peer: Option<String>,
        path: Option<String>,
    },
    Pull {
        share: String,
        peer: String,
        path: Option<String>,
    },
    Request {
        share: String,
        peer: String,
        path: Option<String>,
    },
    Reply {
        id: String,
        accept: bool,
        reason: Option<String>,
    },
    PendingRequests,
    Intents {
        #[serde(default)]
        all: bool,
        limit: Option<usize>,
    },
    IntentShow {
        id: String,
    },
    ChatSend {
        peer: Option<String>,
        share: Option<String>,
        thread: Option<String>,
        message: Option<String>,
        file: Option<String>,
        share_dest: Option<String>,
    },
    ChatInbox,
    ChatThreads,
    ChatShow {
        thread: String,
        limit: Option<usize>,
    },
    ChatRead {
        thread: String,
    },
    ChatRename {
        thread: String,
        title: String,
    },
    ChatDeleteMessage {
        message: String,
    },
    ChatDeleteThread {
        thread: String,
    },
    TransferProgress {
        intent_id: Option<String>,
    },
    PeerList,
    PeerQuarantine {
        peer: String,
    },
    PeerUnquarantine {
        peer: String,
    },
    /// List local shares from the DB registry.
    ShareList,
    /// Add (or update) a local share in the DB registry and start watching it.
    ShareAdd {
        name: String,
        path: String,
        #[serde(default = "default_true")]
        recursive: bool,
    },
    /// Reconcile a share's journal against disk, or every local share when
    /// `share` is omitted. Journals adds, modifications and deletions that
    /// happened while the daemon was not watching.
    Rescan {
        share: Option<String>,
    },
    /// Requeue dead-lettered outbound batches (all, or one by id) with a fresh
    /// attempt count. For when the peer that was unreachable has come back.
    QueueRetry {
        batch: Option<String>,
    },
    /// List effective settings (and which keys are saved in the DB).
    ConfigList,
    /// Get one setting's effective value.
    ConfigGet {
        key: String,
    },
    /// Persist a setting to the DB (overrides config.toml) and update live cfg.
    ConfigSet {
        key: String,
        value: serde_json::Value,
    },
    /// Remove a DB-saved setting (fall back to config.toml / defaults).
    ConfigUnset {
        key: String,
    },
    /// Tail the engine log file (`log_path`). Returns the last `limit` lines.
    Logs {
        /// Max lines to return (default 100, capped).
        limit: Option<usize>,
    },
    /// Switch this control connection into a push event stream.
    /// Responds once with an ack, then writes [`ControlEvent`] JSON lines.
    Subscribe {
        /// Optional topic filter (`chat`, `transfer`, `batch`). Empty = all.
        #[serde(default)]
        topics: Vec<String>,
    },
    /// Disconnect this control client only; does not stop the daemon.
    Quit,
    /// Cancel the engine (`CancellationToken`) and shut down the daemon.
    Shutdown,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResponse {
    pub ok: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl ControlResponse {
    pub fn ok(msg: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: msg.into(),
            data: None,
        }
    }

    pub fn ok_data(msg: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            ok: true,
            message: msg.into(),
            data: Some(data),
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: msg.into(),
            data: None,
        }
    }
}

/// Runtime hooks so the control plane can register shares into the live engine.
#[derive(Clone)]
pub struct ShareHooks {
    pub change_tx: mpsc::Sender<FileChange>,
    pub fs: Arc<dyn FileSystem>,
    pub workdir: Option<PathBuf>,
    pub token: CancellationToken,
}

#[derive(Clone)]
pub struct ControlService {
    /// Live effective config (updated by ConfigSet; peering may need restart for bind keys).
    pub cfg: Arc<std::sync::RwLock<AppConfig>>,
    pub db: Arc<Mutex<Db>>,
    pub net_tx: mpsc::Sender<String>,
    pub peer_cmd_tx: mpsc::Sender<PeerCommand>,
    pub progress: Arc<TransferProgressRegistry>,
    /// Fan-out for GUI / control subscribers (`Subscribe`).
    pub events: broadcast::Sender<ControlEvent>,
    pub share_hooks: Option<ShareHooks>,
    pub token: CancellationToken,
}

impl ControlService {
    fn cfg_snapshot(&self) -> AppConfig {
        self.cfg
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub async fn handle(&self, req: ControlRequest) -> ControlResponse {
        match self.handle_inner(req).await {
            Ok(r) => r,
            Err(e) => ControlResponse::err(e.to_string()),
        }
    }

    async fn handle_inner(&self, req: ControlRequest) -> Result<ControlResponse> {
        match req {
            ControlRequest::Ping => Ok(ControlResponse::ok("pong")),
            ControlRequest::Quit => Ok(ControlResponse::ok("bye")),
            ControlRequest::ConfigList => self.config_list().await,
            ControlRequest::ConfigGet { key } => self.config_get(&key).await,
            ControlRequest::ConfigSet { key, value } => self.config_set(&key, value).await,
            ControlRequest::ConfigUnset { key } => self.config_unset(&key).await,
            ControlRequest::Shutdown => {
                self.token.cancel();
                Ok(ControlResponse::ok("shutting down"))
            }
            ControlRequest::Status => {
                let db = self.db.lock().await;
                let peers = db.list_peers()?.len();
                let shares = db.list_shares_table()?.len();
                let queue = db.outbound_queue_depth()?;
                let dead_lettered = db.outbound_dead_letter_count()?;
                let pending = db.list_pending_transfer_requests()?.len();
                let intents = db
                    .list_transfer_intents(Some(&IntentStatus::active_statuses()), 50)?
                    .len();
                Ok(ControlResponse::ok_data(
                    "status",
                    serde_json::json!({
                        "peers": peers,
                        "shares": shares,
                        "queue_depth": queue,
                        "dead_lettered": dead_lettered,
                        "pending_requests": pending,
                        "active_intents": intents,
                    }),
                ))
            }
            ControlRequest::Push { share, peer, path } => {
                let (intent_ids, batch_ids) = self
                    .enqueue_push(
                        &share,
                        peer.as_deref(),
                        path.as_deref(),
                        IntentOrigin::User,
                    )
                    .await?;
                Ok(ControlResponse::ok(format!(
                    "queued {} Push intent(s), {} batch(es)",
                    intent_ids.len(),
                    batch_ids.len()
                )))
            }
            ControlRequest::Pull { share, peer, path }
            | ControlRequest::Request { share, peer, path } => {
                let id = self.send_transfer_request(&share, &peer, path.as_deref()).await?;
                Ok(ControlResponse::ok(format!("sent transfer request {id}")))
            }
            ControlRequest::Reply { id, accept, reason } => {
                self.reply_transfer(&id, accept, reason.as_deref()).await?;
                Ok(ControlResponse::ok(if accept {
                    format!("accepted {id}")
                } else {
                    format!("declined {id}")
                }))
            }
            ControlRequest::PendingRequests => {
                let pending = self.db.lock().await.list_pending_transfer_requests()?;
                Ok(ControlResponse::ok_data(
                    "pending",
                    serde_json::to_value(pending)?,
                ))
            }
            ControlRequest::Intents { all, limit } => {
                let lim = limit.unwrap_or(200);
                let intents = if all {
                    self.db.lock().await.list_transfer_intents(None, lim)?
                } else {
                    intent_ops::list_active_intents(&self.db, lim).await?
                };
                let mut enriched = Vec::with_capacity(intents.len());
                for intent in intents {
                    let pending_batches = self
                        .db
                        .lock()
                        .await
                        .count_pending_batches_for_intent(&intent.id)
                        .unwrap_or(0);
                    let progress = self.progress.snapshot(Some(&intent.id));
                    let mut v = serde_json::to_value(&intent)?;
                    if let Some(obj) = v.as_object_mut() {
                        obj.insert("pending_batches".into(), serde_json::json!(pending_batches));
                        obj.insert("progress".into(), serde_json::to_value(progress)?);
                    }
                    enriched.push(v);
                }
                Ok(ControlResponse::ok_data(
                    "intents",
                    serde_json::Value::Array(enriched),
                ))
            }
            ControlRequest::IntentShow { id } => {
                let intent = self
                    .db
                    .lock()
                    .await
                    .get_transfer_intent(&id)?
                    .ok_or_else(|| anyhow!("intent '{id}' not found"))?;
                let pending_batches = self
                    .db
                    .lock()
                    .await
                    .count_pending_batches_for_intent(&id)
                    .unwrap_or(0);
                let progress = self.progress.snapshot(Some(&id));
                let mut v = serde_json::to_value(&intent)?;
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("pending_batches".into(), serde_json::json!(pending_batches));
                    obj.insert("progress".into(), serde_json::to_value(progress)?);
                }
                Ok(ControlResponse::ok_data("intent", v))
            }
            ControlRequest::ChatSend {
                peer,
                share,
                thread,
                message,
                file,
                share_dest,
            } => {
                let mid = self
                    .chat_send(peer, share, thread, message, file, share_dest)
                    .await?;
                Ok(ControlResponse::ok(format!("sent chat message {mid}")))
            }
            ControlRequest::ChatInbox | ControlRequest::ChatThreads => {
                let inbox = self.db.lock().await.list_inbox()?;
                Ok(ControlResponse::ok_data(
                    "inbox",
                    serde_json::to_value(inbox)?,
                ))
            }
            ControlRequest::ChatShow { thread, limit } => {
                let msgs = self
                    .db
                    .lock()
                    .await
                    .list_thread_messages(&thread, limit.unwrap_or(100))?;
                Ok(ControlResponse::ok_data(
                    "messages",
                    serde_json::to_value(msgs)?,
                ))
            }
            ControlRequest::ChatRead { thread } => {
                self.db.lock().await.mark_thread_read(&thread)?;
                Ok(ControlResponse::ok(format!("marked {thread} read")))
            }
            ControlRequest::ChatRename { thread, title } => {
                let renamed = self.db.lock().await.rename_chat_thread(&thread, &title)?;
                if renamed {
                    Ok(ControlResponse::ok(format!("renamed {thread}")))
                } else {
                    bail!("thread '{thread}' not found or title empty");
                }
            }
            ControlRequest::ChatDeleteMessage { message } => {
                let deleted = self.db.lock().await.delete_chat_message(&message)?;
                if deleted {
                    Ok(ControlResponse::ok(format!("deleted message {message}")))
                } else {
                    bail!("message '{message}' not found");
                }
            }
            ControlRequest::ChatDeleteThread { thread } => {
                let deleted = self.db.lock().await.delete_chat_thread(&thread)?;
                if deleted {
                    Ok(ControlResponse::ok(format!("deleted thread {thread}")))
                } else {
                    bail!("thread '{thread}' not found");
                }
            }
            ControlRequest::TransferProgress { intent_id } => {
                let snap = self.progress.snapshot(intent_id.as_deref());
                Ok(ControlResponse::ok_data(
                    "transfer_progress",
                    serde_json::to_value(snap)?,
                ))
            }
            ControlRequest::PeerList => {
                let peers = self.db.lock().await.list_peers_info()?;
                Ok(ControlResponse::ok_data(
                    "peers",
                    serde_json::to_value(peers)?,
                ))
            }
            ControlRequest::PeerQuarantine { peer } => {
                let found = self.db.lock().await.set_peer_quarantined(&peer, true)?;
                let cfg_path = std::env::current_dir()
                    .unwrap_or_default()
                    .join("config.toml");
                let _ = crate::config::set_quarantined_peer_in_config(&cfg_path, &peer, true);
                if found {
                    Ok(ControlResponse::ok(format!("quarantined {peer}")))
                } else {
                    Ok(ControlResponse::ok(format!(
                        "quarantined {peer} in config (peer not yet in DB)"
                    )))
                }
            }
            ControlRequest::PeerUnquarantine { peer } => {
                let found = self.db.lock().await.set_peer_quarantined(&peer, false)?;
                let cfg_path = std::env::current_dir()
                    .unwrap_or_default()
                    .join("config.toml");
                let _ = crate::config::set_quarantined_peer_in_config(&cfg_path, &peer, false);
                if found {
                    Ok(ControlResponse::ok(format!("unquarantined {peer}")))
                } else {
                    Ok(ControlResponse::ok(format!(
                        "removed {peer} from config quarantine list"
                    )))
                }
            }
            ControlRequest::ShareList => {
                let shares = self
                    .db
                    .lock()
                    .await
                    .list_shares_for_pc(&self.cfg_snapshot().pc_name)?;
                Ok(ControlResponse::ok_data(
                    "shares",
                    serde_json::to_value(shares)?,
                ))
            }
            ControlRequest::ShareAdd {
                name,
                path,
                recursive,
            } => {
                let ctx = self.add_share(&name, Path::new(&path), recursive).await?;
                Ok(ControlResponse::ok_data(
                    format!(
                        "added share '{}' -> {}",
                        ctx.share_name,
                        ctx.root_path.display()
                    ),
                    serde_json::json!({
                        "id": ctx.id,
                        "share_name": ctx.share_name,
                        "pc_name": ctx.pc_name,
                        "root_path": ctx.root_path,
                        "recursive": ctx.recursive,
                    }),
                ))
            }
            ControlRequest::Rescan { share } => self.rescan(share.as_deref()).await,
            ControlRequest::QueueRetry { batch } => {
                let revived = self
                    .db
                    .lock()
                    .await
                    .retry_dead_letter_batches(batch.as_deref())?;
                if revived > 0 {
                    // Wake the outbox rather than wait out its 5s tick.
                    let _ = self.net_tx.try_send(String::new());
                }
                Ok(ControlResponse::ok_data(
                    format!("requeued {revived} dead-lettered batch(es)"),
                    serde_json::json!({ "requeued": revived }),
                ))
            }
            ControlRequest::Logs { limit } => self.tail_logs(limit).await,
            ControlRequest::Subscribe { .. } => {
                // Handled specially in the control server connection loop.
                Ok(ControlResponse::ok("subscribed"))
            }
        }
    }

    async fn tail_logs(&self, limit: Option<usize>) -> Result<ControlResponse> {
        const DEFAULT_LIMIT: usize = 100;
        const MAX_LIMIT: usize = 10_000;
        let limit = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        let path = self.cfg_snapshot().log_path;
        let path_display = path.display().to_string();
        let (lines, truncated, total_lines) =
            tokio::task::spawn_blocking(move || read_log_tail(&path, limit))
                .await
                .context("join log tail task")??;
        Ok(ControlResponse::ok_data(
            "logs",
            serde_json::json!({
                "path": path_display,
                "limit": limit,
                "truncated": truncated,
                "total_lines": total_lines,
                "lines": lines,
            }),
        ))
    }

    async fn add_share(
        &self,
        name: &str,
        root_path: &Path,
        recursive: bool,
    ) -> Result<ShareContext> {
        if !self.cfg_snapshot().app_state.can_share() {
            bail!(
                "app_state {:?} cannot host local shares",
                self.cfg_snapshot().app_state
            );
        }
        let name = name.trim();
        if name.is_empty() {
            bail!("share name cannot be empty");
        }
        let root_path = if root_path.is_absolute() {
            root_path.to_path_buf()
        } else {
            std::env::current_dir()
                .unwrap_or_default()
                .join(root_path)
        };
        let md = std::fs::metadata(&root_path).with_context(|| {
            format!("share root '{}' is not accessible", root_path.display())
        })?;
        if !md.is_dir() {
            bail!("share root '{}' is not a directory", root_path.display());
        }

        let sc = ShareConfig {
            name: name.to_string(),
            root_path: root_path.clone(),
            recursive,
            ignore_patterns: Vec::new(),
            sync_allow: Vec::new(),
            max_file_size_bytes: None,
            sync: Default::default(),
            pull: Default::default(),
            request_handling: None,
            conflict: Default::default(),
        };
        let share_id = ShareId::new(&sc.name, &self.cfg_snapshot().pc_name);
        let fs: Arc<dyn FileSystem> = self
            .share_hooks
            .as_ref()
            .map(|h| h.fs.clone())
            .unwrap_or_else(|| Arc::new(RealFileSystem::new()));
        let workdir = self
            .share_hooks
            .as_ref()
            .and_then(|h| h.workdir.clone())
            .or_else(|| std::env::current_dir().ok());

        let ctx = {
            let mut db = self.db.lock().await;
            let id = db.upsert_share(&self.cfg_snapshot().pc_name, &sc, &share_id)?;
            let ctx = ShareContext {
                id,
                share_name: sc.name.clone(),
                pc_name: self.cfg_snapshot().pc_name.clone(),
                share_id,
                root_path: sc.root_path.clone(),
                recursive: sc.recursive,
                ignore_patterns: sc.ignore_patterns.clone(),
                sync_allow: sc.sync_allow.clone(),
                conflict: sc.conflict,
                max_file_size_bytes: sc.max_file_size_bytes,
                index: HashMap::new(),
            };
            seed_journal_from_index(&mut db, &ctx, &fs, workdir.as_deref())?;
            ctx
        };

        let cfg_path = std::env::current_dir()
            .unwrap_or_default()
            .join(DEFAULT_CONFIG_PATH);
        let _ = add_share_to_config(&cfg_path, &sc.name, &sc.root_path, sc.recursive);

        if let Some(hooks) = &self.share_hooks {
            let share = ctx.clone();
            let tx = hooks.change_tx.clone();
            let fs = hooks.fs.clone();
            let workdir = hooks.workdir.clone();
            let token = hooks.token.clone();
            tokio::spawn(async move {
                start_single_watcher(share, tx, fs, workdir, token).await;
            });
        }

        Ok(ctx)
    }

    /// Reconcile one share, or every locally-owned share, against disk.
    ///
    /// Reloads each share's index from the DB first: `rescan_share` decides
    /// what drifted by comparing disk against `ShareContext::index`, so a stale
    /// in-memory copy would report changes that were already journaled.
    async fn rescan(&self, share: Option<&str>) -> Result<ControlResponse> {
        let cfg = self.cfg_snapshot();
        let fs: Arc<dyn FileSystem> = self
            .share_hooks
            .as_ref()
            .map(|h| h.fs.clone())
            .unwrap_or_else(|| Arc::new(RealFileSystem::new()));
        let workdir = self
            .share_hooks
            .as_ref()
            .and_then(|h| h.workdir.clone())
            .or_else(|| std::env::current_dir().ok());

        let mut db = self.db.lock().await;
        let mut contexts = db.load_shares(&cfg)?;
        if let Some(name) = share {
            contexts.retain(|c| c.share_name == name);
            if contexts.is_empty() {
                bail!("no local share named '{name}'");
            }
        }

        let mut results = Vec::new();
        let mut total = 0usize;
        for ctx in &contexts {
            let summary = rescan_share(&mut db, ctx, &fs, workdir.as_deref())?;
            total += summary.total();
            if !summary.is_empty() {
                info!(
                    share = %ctx.share_name,
                    added = summary.added,
                    modified = summary.modified,
                    deleted = summary.deleted,
                    seeded = summary.seeded,
                    "Rescan journaled offline drift"
                );
            }
            results.push(serde_json::json!({
                "share_name": ctx.share_name,
                "root_path": ctx.root_path,
                "seeded": summary.seeded,
                "added": summary.added,
                "modified": summary.modified,
                "deleted": summary.deleted,
            }));
        }

        // Nudge the outbox so anything journaled here goes out now rather than
        // waiting for the next tick.
        if total > 0 {
            let _ = self.net_tx.try_send(String::new());
        }

        Ok(ControlResponse::ok_data(
            format!(
                "rescanned {} share(s); {} change(s) journaled",
                results.len(),
                total
            ),
            serde_json::json!({ "shares": results, "changes": total }),
        ))
    }

    async fn enqueue_push(
        &self,
        share_name: &str,
        peer: Option<&str>,
        path: Option<&str>,
        origin: IntentOrigin,
    ) -> Result<(Vec<String>, Vec<String>)> {
        let share_id = ShareId::new(share_name, &self.cfg_snapshot().pc_name);
        let paths = path.map(|p| vec![p.to_string()]).unwrap_or_default();
        let peer_ids = {
            let db = self.db.lock().await;
            let _ = db
                .get_share_row_id_by_share_id(&share_id)
                .with_context(|| format!("unknown local share '{share_name}'"))?;
            if let Some(peer_key) = peer {
                let p = db
                    .find_peer_by_key(peer_key)?
                    .ok_or_else(|| anyhow!("peer '{peer_key}' not found"))?;
                vec![p.id]
            } else {
                db.list_peer_ids_for_share_name(share_name)?
            }
        };
        if peer_ids.is_empty() {
            bail!("no peers to push to");
        }
        let mut intent_ids = Vec::new();
        let mut batch_ids = Vec::new();
        for pid in peer_ids {
            let peer_key = {
                let db = self.db.lock().await;
                db.get_peer(pid)?
                    .map(|p| format!("{}@{}", p.pc_name, p.instance_id))
            };
            if let Some(ref pk) = peer_key {
                if !self.cfg_snapshot().resolve_allow_push(share_name, pk) {
                    bail!("allow_push=false for peer {pk}");
                }
            }
            let (intent_id, batches) = crate::intent_ops::enqueue_intent(
                &self.db,
                &self.net_tx,
                IntentKind::SnapshotPush,
                origin,
                share_name,
                share_id,
                Some(pid),
                IntentBasis::Snapshot {
                    paths: paths.clone(),
                },
                None,
                &self.cfg_snapshot().pc_name,
            )
            .await?;
            if batches.is_empty() {
                bail!("no indexed files to push for share '{share_name}'");
            }
            intent_ids.push(intent_id);
            batch_ids.extend(batches);
        }
        Ok((intent_ids, batch_ids))
    }

    async fn send_transfer_request(
        &self,
        share_name: &str,
        peer_key_str: &str,
        path: Option<&str>,
    ) -> Result<String> {
        if !self.cfg_snapshot().resolve_allow_request(share_name, peer_key_str) {
            bail!("allow_request=false for peer {peer_key_str}");
        }
        let peer = self
            .db
            .lock()
            .await
            .find_peer_by_key(peer_key_str)?
            .ok_or_else(|| anyhow!("peer '{peer_key_str}' not found"))?;
        let share_id = ShareId::new(share_name, &peer.pc_name);
        // How far of *their* journal we already hold — the peer's namespace.
        let since_seq = {
            let db = self.db.lock().await;
            match db.get_share_row_id_by_share_id(&share_id) {
                Ok(row) => db.inbound_watermark(peer.id, row).unwrap_or(0),
                Err(_) => 0,
            }
        };
        let request_id = Uuid::new_v4().to_string();
        let req = TransferRequest {
            protocol_version: WIRE_PROTOCOL_VERSION,
            request_id: request_id.clone(),
            share_name: share_name.to_string(),
            share_id,
            paths: path.map(|p| vec![p.to_string()]).unwrap_or_default(),
            since_seq,
            from_pc: self.cfg_snapshot().pc_name.clone(),
            from_instance: self.cfg_snapshot().instance_id.clone(),
        };
        self.db
            .lock()
            .await
            .insert_transfer_request(&req, Some(peer.id), "out", "pending")?;
        let _ = crate::intent_ops::record_pull_request_intent(
            &self.db,
            share_name,
            share_id,
            peer.id,
            req.paths.clone(),
            since_seq,
            &request_id,
        )
        .await?;
        self.peer_cmd_tx
            .send(PeerCommand::SendToPeer {
                peer_id: peer.id,
                msg: WireMessage::TransferRequest(req),
            })
            .await
            .map_err(|e| anyhow!("peer command channel closed: {e}"))?;
        Ok(request_id)
    }

    async fn reply_transfer(
        &self,
        request_id: &str,
        accept: bool,
        reason: Option<&str>,
    ) -> Result<()> {
        let pending: PendingTransferRequest = self
            .db
            .lock()
            .await
            .get_transfer_request(request_id)?
            .ok_or_else(|| anyhow!("request '{request_id}' not found"))?;
        let peer_id = pending
            .peer_id
            .ok_or_else(|| anyhow!("request has no peer id"))?;
        if accept {
            let since_seq = pending.since_seq;
            let paths = pending.paths.clone();
            let share_name = pending.share_name.clone();
            let req_id = pending.request_id.clone();
            let from_key = format!("{}@{}", pending.from_pc, pending.from_instance);
            if !self.cfg_snapshot().resolve_allow_pull(&share_name, &from_key) {
                bail!("allow_pull=false for peer {from_key}");
            }
            let local_share_id = ShareId::new(&share_name, &self.cfg_snapshot().pc_name);
            let basis = if !paths.is_empty() {
                IntentBasis::Snapshot { paths }
            } else {
                let max_seq = {
                    let db = self.db.lock().await;
                    let row = db.get_share_row_id_by_share_id(&local_share_id)?;
                    db.max_journal_seq(row)?
                };
                IntentBasis::JournalRange {
                    from_seq: since_seq,
                    to_seq: max_seq,
                }
            };
            let _ = crate::intent_ops::enqueue_intent(
                &self.db,
                &self.net_tx,
                IntentKind::PullFulfill,
                IntentOrigin::Reply,
                &share_name,
                local_share_id,
                Some(peer_id),
                basis,
                Some(&req_id),
                &self.cfg_snapshot().pc_name,
            )
            .await?;
            self.db
                .lock()
                .await
                .update_transfer_request_status(request_id, "accepted", None)?;
        } else {
            self.db.lock().await.update_transfer_request_status(
                request_id,
                "declined",
                reason,
            )?;
        }
        let reply = TransferReply {
            protocol_version: WIRE_PROTOCOL_VERSION,
            request_id: request_id.to_string(),
            status: if accept {
                TransferReplyStatus::Accept
            } else {
                TransferReplyStatus::Decline
            },
            reason: reason.map(|s| s.to_string()),
        };
        self.peer_cmd_tx
            .send(PeerCommand::SendToPeer {
                peer_id,
                msg: WireMessage::TransferReply(reply),
            })
            .await
            .map_err(|e| anyhow!("peer command channel closed: {e}"))?;
        Ok(())
    }

    async fn chat_send(
        &self,
        peer: Option<String>,
        share: Option<String>,
        thread: Option<String>,
        message: Option<String>,
        file: Option<String>,
        share_dest: Option<String>,
    ) -> Result<String> {
        let local_key = peer_key(&self.cfg_snapshot().pc_name, &self.cfg_snapshot().instance_id);
        // Peer is preferred when both are set: share is optional context on a peer DM.
        // Share-only remains for CLI/share-thread broadcasts.
        let (kind, thread_id, peer_key_opt, share_name_opt, title) =
            if let Some(peer_s) = peer.clone() {
                let remote = self
                    .db
                    .lock()
                    .await
                    .find_peer_by_key(&peer_s)?
                    .ok_or_else(|| anyhow!("peer '{peer_s}' not found"))?;
                let remote_key = peer_key(&remote.pc_name, &remote.instance_id);
                let tid = thread.unwrap_or_else(|| peer_thread_id(&local_key, &remote_key));
                let peer_label = if remote.display_name.trim().is_empty() {
                    remote_key.clone()
                } else {
                    remote.display_name.clone()
                };
                let share_opt = share.clone().filter(|s| !s.trim().is_empty());
                let title = format_chat_thread_title(
                    ThreadKind::Peer,
                    Some(&peer_label),
                    share_opt.as_deref(),
                );
                (
                    ThreadKind::Peer,
                    tid,
                    Some(remote_key),
                    share_opt,
                    title,
                )
            } else if let Some(share_name) = share.clone() {
                let tid = thread.unwrap_or_else(|| share_thread_id(&share_name));
                let title = format_chat_thread_title(ThreadKind::Share, None, Some(&share_name));
                (
                    ThreadKind::Share,
                    tid,
                    None,
                    Some(share_name),
                    title,
                )
            } else {
                bail!("chat send requires --peer (share is optional)");
            };

        let body = message.unwrap_or_default();
        let attachment_share = share_dest.or(share.clone());
        let attachment_path = file;
        if body.is_empty() && attachment_path.is_none() {
            bail!("chat send requires --message and/or --file");
        }

        let now = OffsetDateTime::now_utc().unix_timestamp();
        let message_id = Uuid::new_v4().to_string();
        {
            let db = self.db.lock().await;
            db.ensure_chat_thread(
                &thread_id,
                kind,
                peer_key_opt.as_deref(),
                share_name_opt.as_deref(),
                &title,
                now,
            )?;
            let record = ChatMessageRecord {
                id: message_id.clone(),
                thread_id: thread_id.clone(),
                from_peer: local_key.clone(),
                body: body.clone(),
                attachment_share: attachment_share.clone(),
                attachment_path: attachment_path.clone(),
                created_at: now,
                direction: "out".into(),
                status: "sent".into(),
            };
            let _ = db.insert_chat_message(&record, false)?;
        }

        let attachment = match (attachment_share.clone(), attachment_path.clone()) {
            (Some(share_name), Some(path)) => Some(ChatAttachment { share_name, path }),
            _ => None,
        };
        let wire = ChatMessage {
            protocol_version: WIRE_PROTOCOL_VERSION,
            thread_id: thread_id.clone(),
            message_id: message_id.clone(),
            thread_kind: kind,
            peer_key: peer_key_opt.clone(),
            share_name: share_name_opt.clone(),
            from_pc: self.cfg_snapshot().pc_name.clone(),
            from_instance: self.cfg_snapshot().instance_id.clone(),
            body,
            attachment,
            created_at: now,
        };

        if let Some(pk) = peer_key_opt {
            self.peer_cmd_tx
                .send(PeerCommand::SendToPeerKey {
                    peer_key: pk,
                    msg: WireMessage::ChatMessage(wire),
                })
                .await
                .map_err(|e| anyhow!("peer command channel closed: {e}"))?;
        } else {
            self.peer_cmd_tx
                .send(PeerCommand::Broadcast {
                    msg: WireMessage::ChatMessage(wire),
                })
                .await
                .map_err(|e| anyhow!("peer command channel closed: {e}"))?;
        }

        if let (Some(dest), Some(path)) = (attachment_share, attachment_path) {
            let _ = self
                .enqueue_push(&dest, peer.as_deref(), Some(&path), IntentOrigin::Chat)
                .await;
        }

        let _: Option<ThreadSummary> = None;
        Ok(message_id)
    }

    async fn config_list(&self) -> Result<ControlResponse> {
        use crate::settings::{read_setting, SETTABLE_KEYS};
        let cfg = self.cfg_snapshot();
        let saved = self.db.lock().await.list_settings()?;
        let mut rows = Vec::new();
        for key in SETTABLE_KEYS {
            let value = read_setting(&cfg, key)?;
            let source = if saved.contains_key(*key) {
                "database"
            } else {
                "config_or_default"
            };
            rows.push(serde_json::json!({
                "key": key,
                "value": value,
                "source": source,
                "restart_required": crate::settings::requires_restart(key),
            }));
        }
        Ok(ControlResponse::ok_data(
            "settings",
            serde_json::Value::Array(rows),
        ))
    }

    async fn config_get(&self, key: &str) -> Result<ControlResponse> {
        use crate::settings::{is_settable_key, read_setting, requires_restart};
        if !is_settable_key(key) {
            bail!("unknown setting '{key}'");
        }
        let cfg = self.cfg_snapshot();
        let value = read_setting(&cfg, key)?;
        let saved = self.db.lock().await.get_setting(key)?;
        let source = if saved.is_some() {
            "database"
        } else {
            "config_or_default"
        };
        Ok(ControlResponse::ok_data(
            "setting",
            serde_json::json!({
                "key": key,
                "value": value,
                "source": source,
                "restart_required": requires_restart(key),
            }),
        ))
    }

    async fn config_set(&self, key: &str, value: serde_json::Value) -> Result<ControlResponse> {
        use crate::settings::{apply_setting, is_settable_key, requires_restart};
        if !is_settable_key(key) {
            bail!("unknown setting '{key}'");
        }
        {
            let mut cfg = self.cfg.write().unwrap_or_else(|e| e.into_inner());
            apply_setting(&mut cfg, key, &value)?;
        }
        let raw = serde_json::to_string(&value)?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.db.lock().await.set_setting(key, &raw, now)?;
        let mut msg = format!("set {key} (saved to database, overrides config.toml)");
        if requires_restart(key) {
            msg.push_str("; restart required for this setting to take full effect");
        }
        Ok(ControlResponse::ok(msg))
    }

    async fn config_unset(&self, key: &str) -> Result<ControlResponse> {
        use crate::settings::{is_settable_key, requires_restart};
        if !is_settable_key(key) {
            bail!("unknown setting '{key}'");
        }
        let removed = self.db.lock().await.delete_setting(key)?;
        if !removed {
            return Ok(ControlResponse::ok(format!(
                "{key} was not saved in the database"
            )));
        }
        // Reload effective config from file+defaults+remaining DB (no CLI).
        if let Ok(base) = crate::config::resolve_effective_config(None) {
            let mut guard = self.cfg.write().unwrap_or_else(|e| e.into_inner());
            *guard = base;
        }
        let mut msg =
            format!("unset {key} from database; effective value reloaded from config/defaults");
        if requires_restart(key) {
            msg.push_str("; restart recommended for listeners");
        }
        Ok(ControlResponse::ok(msg))
    }
}

/// Read the last `limit` lines from `path`.
/// Returns `(lines, truncated, total_lines)`.
fn read_log_tail(path: &Path, limit: usize) -> Result<(Vec<String>, bool, usize)> {
    if !path.exists() {
        return Ok((Vec::new(), false, 0));
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read log file {}", path.display()))?;
    let all: Vec<&str> = text.lines().collect();
    let total = all.len();
    let truncated = total > limit;
    let start = total.saturating_sub(limit);
    let lines = all[start..].iter().map(|s| (*s).to_string()).collect();
    Ok((lines, truncated, total))
}
