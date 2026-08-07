use serde::{Deserialize, Serialize};

/// Control-plane push events for GUI / subscribers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ControlEvent {
    ChatReceived {
        thread_id: String,
        message_id: String,
        from_peer: String,
        #[serde(default)]
        preview: String,
    },
    TransferRequestPending {
        request_id: String,
        share_name: String,
        from_peer: String,
        #[serde(default)]
        direction: String,
    },
    BatchReceived {
        batch_id: String,
        #[serde(default)]
        share_name: String,
        from_peer: String,
        change_count: usize,
    },
    /// An outbound batch exhausted `outbound_max_attempts` and will never be
    /// retried. Terminal, and the only notice an operator gets that data did
    /// not reach a peer.
    BatchDeadLettered {
        batch_id: String,
        #[serde(default)]
        peer_id: Option<i64>,
        #[serde(default)]
        intent_id: Option<String>,
        attempts: i64,
        #[serde(default)]
        last_error: String,
    },
}

impl ControlEvent {
    pub fn title(&self) -> &'static str {
        match self {
            ControlEvent::ChatReceived { .. } => "New chat message",
            ControlEvent::TransferRequestPending { .. } => "Transfer request",
            ControlEvent::BatchReceived { .. } => "Files received",
            ControlEvent::BatchDeadLettered { .. } => "Transfer gave up",
        }
    }

    pub fn body(&self) -> String {
        match self {
            ControlEvent::ChatReceived {
                from_peer, preview, ..
            } => {
                if preview.trim().is_empty() {
                    format!("From {from_peer}")
                } else {
                    format!("{from_peer}: {preview}")
                }
            }
            ControlEvent::TransferRequestPending {
                share_name,
                from_peer,
                direction,
                ..
            } => {
                if direction.is_empty() {
                    format!("{share_name} from {from_peer}")
                } else {
                    format!("{direction} {share_name} from {from_peer}")
                }
            }
            ControlEvent::BatchReceived {
                share_name,
                from_peer,
                change_count,
                ..
            } => {
                let share = if share_name.is_empty() {
                    "share"
                } else {
                    share_name.as_str()
                };
                format!("{change_count} change(s) in {share} from {from_peer}")
            }
            ControlEvent::BatchDeadLettered {
                batch_id,
                attempts,
                last_error,
                ..
            } => {
                let reason = if last_error.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {last_error}")
                };
                format!("Batch {batch_id} failed {attempts} time(s) and was dropped{reason}")
            }
        }
    }

    pub fn dedupe_key(&self) -> String {
        match self {
            ControlEvent::ChatReceived { message_id, .. } => format!("chat:{message_id}"),
            ControlEvent::TransferRequestPending { request_id, .. } => {
                format!("xfer:{request_id}")
            }
            ControlEvent::BatchReceived { batch_id, .. } => format!("batch:{batch_id}"),
            ControlEvent::BatchDeadLettered { batch_id, .. } => format!("deadletter:{batch_id}"),
        }
    }
}
