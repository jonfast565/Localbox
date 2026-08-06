//! Single path from TransferIntent → outbound_queue.
//!
//! Peering also calls [`db::Db::create_and_materialize_intent`] directly (core depends on
//! peering, not the reverse).

use anyhow::{Context, Result};
use db::Db;
use models::{
    IntentBasis, IntentKind, IntentOrigin, IntentStatus, ShareId, TransferIntent,
};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// Create, materialize, and wake the outbox worker for an intent.
pub async fn enqueue_intent(
    db: &Arc<Mutex<Db>>,
    net_tx: &mpsc::Sender<String>,
    kind: IntentKind,
    origin: IntentOrigin,
    share_name: &str,
    share_id: ShareId,
    peer_id: Option<i64>,
    basis: IntentBasis,
    request_id: Option<&str>,
    from_node: &str,
) -> Result<(String, Vec<String>)> {
    let (intent_id, batch_ids) = db
        .lock()
        .await
        .create_and_materialize_intent(
            kind,
            origin,
            share_name,
            share_id,
            peer_id,
            basis,
            request_id,
            from_node,
        )
        .with_context(|| format!("materialize {kind:?} intent for share '{share_name}'"))?;
    for batch_id in &batch_ids {
        let _ = net_tx.try_send(batch_id.clone());
    }
    Ok((intent_id, batch_ids))
}

/// Record a pull request intent (no batches; wire TransferRequest is separate).
pub async fn record_pull_request_intent(
    db: &Arc<Mutex<Db>>,
    share_name: &str,
    share_id: ShareId,
    peer_id: i64,
    paths: Vec<String>,
    since_seq: i64,
    request_id: &str,
) -> Result<String> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let id = uuid::Uuid::new_v4().to_string();
    let basis = if paths.is_empty() {
        IntentBasis::JournalRange {
            from_seq: since_seq,
            to_seq: since_seq, // filled when peer fulfills; tracks request scope
        }
    } else {
        IntentBasis::Snapshot { paths }
    };
    let intent = TransferIntent {
        id: id.clone(),
        kind: IntentKind::PullRequest,
        origin: IntentOrigin::User,
        status: IntentStatus::InFlight,
        share_name: share_name.to_string(),
        share_id,
        peer_id: Some(peer_id),
        basis,
        request_id: Some(request_id.to_string()),
        last_error: None,
        created_at: now,
        updated_at: now,
    };
    db.lock().await.insert_transfer_intent(&intent)?;
    Ok(id)
}

pub async fn list_active_intents(db: &Arc<Mutex<Db>>, limit: usize) -> Result<Vec<TransferIntent>> {
    let statuses = [
        IntentStatus::Pending,
        IntentStatus::Materialized,
        IntentStatus::InFlight,
    ];
    Ok(db
        .lock()
        .await
        .list_transfer_intents(Some(&statuses), limit)?)
}
