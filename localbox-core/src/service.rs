use anyhow::{anyhow, bail, Context, Result};
use db::{Db, PendingTransferRequest};
use models::{
    peer_key, peer_thread_id, share_thread_id, AppConfig, ChatAttachment, ChatMessage,
    ChatMessageRecord, IntentBasis, IntentKind, IntentOrigin, IntentStatus, ShareId, ThreadKind,
    ThreadSummary, TransferReply, TransferReplyStatus, TransferRequest, WireMessage,
    WIRE_PROTOCOL_VERSION,
};
use peering::PeerCommand;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::{mpsc, Mutex};
use uuid::Uuid;

use crate::intent_ops;

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
    Quit,
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

#[derive(Clone)]
pub struct ControlService {
    pub cfg: AppConfig,
    pub db: Arc<Mutex<Db>>,
    pub net_tx: mpsc::Sender<String>,
    pub peer_cmd_tx: mpsc::Sender<PeerCommand>,
}

impl ControlService {
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
            ControlRequest::Status => {
                let db = self.db.lock().await;
                let peers = db.list_peers()?.len();
                let shares = db.list_shares_table()?.len();
                let queue = db.outbound_queue_depth()?;
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
                Ok(ControlResponse::ok_data(
                    "intents",
                    serde_json::to_value(intents)?,
                ))
            }
            ControlRequest::IntentShow { id } => {
                let intent = self
                    .db
                    .lock()
                    .await
                    .get_transfer_intent(&id)?
                    .ok_or_else(|| anyhow!("intent '{id}' not found"))?;
                Ok(ControlResponse::ok_data(
                    "intent",
                    serde_json::to_value(intent)?,
                ))
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
        }
    }

    async fn enqueue_push(
        &self,
        share_name: &str,
        peer: Option<&str>,
        path: Option<&str>,
        origin: IntentOrigin,
    ) -> Result<(Vec<String>, Vec<String>)> {
        let share_id = ShareId::new(share_name, &self.cfg.pc_name);
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
                &self.cfg.pc_name,
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
            from_pc: self.cfg.pc_name.clone(),
            from_instance: self.cfg.instance_id.clone(),
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
            let local_share_id = ShareId::new(&share_name, &self.cfg.pc_name);
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
                &self.cfg.pc_name,
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
        let local_key = peer_key(&self.cfg.pc_name, &self.cfg.instance_id);
        let (kind, thread_id, peer_key_opt, share_name_opt, title) =
            if let Some(share_name) = share.clone() {
                let tid = thread.unwrap_or_else(|| share_thread_id(&share_name));
                (
                    ThreadKind::Share,
                    tid,
                    None,
                    Some(share_name.clone()),
                    share_name,
                )
            } else if let Some(peer_s) = peer.clone() {
                let remote = self
                    .db
                    .lock()
                    .await
                    .find_peer_by_key(&peer_s)?
                    .ok_or_else(|| anyhow!("peer '{peer_s}' not found"))?;
                let remote_key = peer_key(&remote.pc_name, &remote.instance_id);
                let tid = thread.unwrap_or_else(|| peer_thread_id(&local_key, &remote_key));
                (
                    ThreadKind::Peer,
                    tid,
                    Some(remote_key.clone()),
                    None,
                    remote_key,
                )
            } else {
                bail!("chat send requires --peer or --share");
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
            db.insert_chat_message(&record, false)?;
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
            from_pc: self.cfg.pc_name.clone(),
            from_instance: self.cfg.instance_id.clone(),
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
}
