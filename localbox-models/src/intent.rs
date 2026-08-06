use serde::{Deserialize, Serialize};

use crate::share::ShareId;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    Push,
    PullRequest,
    PullFulfill,
    SyncCatchup,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            IntentKind::Push => "push",
            IntentKind::PullRequest => "pull_request",
            IntentKind::PullFulfill => "pull_fulfill",
            IntentKind::SyncCatchup => "sync_catchup",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "push" => Some(IntentKind::Push),
            "pull_request" => Some(IntentKind::PullRequest),
            "pull_fulfill" => Some(IntentKind::PullFulfill),
            "sync_catchup" => Some(IntentKind::SyncCatchup),
            _ => None,
        }
    }

    /// Only SyncCatchup advances peer_progress watermarks.
    pub fn updates_peer_progress(self) -> bool {
        matches!(self, IntentKind::SyncCatchup)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntentOrigin {
    User,
    AutoPush,
    AutoPull,
    Chat,
    Reply,
}

impl IntentOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            IntentOrigin::User => "user",
            IntentOrigin::AutoPush => "auto_push",
            IntentOrigin::AutoPull => "auto_pull",
            IntentOrigin::Chat => "chat",
            IntentOrigin::Reply => "reply",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "user" => Some(IntentOrigin::User),
            "auto_push" => Some(IntentOrigin::AutoPush),
            "auto_pull" => Some(IntentOrigin::AutoPull),
            "chat" => Some(IntentOrigin::Chat),
            "reply" => Some(IntentOrigin::Reply),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Pending,
    Materialized,
    InFlight,
    Acked,
    Declined,
    Failed,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            IntentStatus::Pending => "pending",
            IntentStatus::Materialized => "materialized",
            IntentStatus::InFlight => "in_flight",
            IntentStatus::Acked => "acked",
            IntentStatus::Declined => "declined",
            IntentStatus::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(IntentStatus::Pending),
            "materialized" => Some(IntentStatus::Materialized),
            "in_flight" => Some(IntentStatus::InFlight),
            "acked" => Some(IntentStatus::Acked),
            "declined" => Some(IntentStatus::Declined),
            "failed" => Some(IntentStatus::Failed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IntentBasis {
    /// Current file index; empty paths = whole share.
    Snapshot { paths: Vec<String> },
    /// Continuous sync from the local share journal.
    JournalRange { from_seq: i64, to_seq: i64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferIntent {
    pub id: String,
    pub kind: IntentKind,
    pub origin: IntentOrigin,
    pub status: IntentStatus,
    pub share_name: String,
    pub share_id: ShareId,
    pub peer_id: Option<i64>,
    pub basis: IntentBasis,
    pub request_id: Option<String>,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}
