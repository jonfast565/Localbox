use serde::{Deserialize, Serialize};

use crate::share::ShareId;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    /// User-initiated transfer of the current file index. Carries no journal seq.
    SnapshotPush,
    PullRequest,
    PullFulfill,
    /// Continuous sync from the share journal. The only kind that owns a seq range.
    SyncCatchup,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            IntentKind::SnapshotPush => "snapshot_push",
            IntentKind::PullRequest => "pull_request",
            IntentKind::PullFulfill => "pull_fulfill",
            IntentKind::SyncCatchup => "sync_catchup",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            // "push" is the pre-v7 spelling, kept so old rows still parse.
            "snapshot_push" | "push" => Some(IntentKind::SnapshotPush),
            "pull_request" => Some(IntentKind::PullRequest),
            "pull_fulfill" => Some(IntentKind::PullFulfill),
            "sync_catchup" => Some(IntentKind::SyncCatchup),
            _ => None,
        }
    }

    /// Only SyncCatchup is confirmed by a `BatchAck` and advances seq watermarks.
    /// Every other kind completes once its batches reach the transport.
    pub fn awaits_ack(self) -> bool {
        matches!(self, IntentKind::SyncCatchup)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntentOrigin {
    User,
    /// Automatic journal sync triggered by the `sync = "auto"` policy.
    /// Attaches to SyncCatchup intents, never to SnapshotPush.
    AutoSync,
    AutoPull,
    Chat,
    Reply,
}

impl IntentOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            IntentOrigin::User => "user",
            IntentOrigin::AutoSync => "auto_sync",
            IntentOrigin::AutoPull => "auto_pull",
            IntentOrigin::Chat => "chat",
            IntentOrigin::Reply => "reply",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "user" => Some(IntentOrigin::User),
            // "auto_push" is the pre-v7 spelling, kept so old rows still parse.
            "auto_sync" | "auto_push" => Some(IntentOrigin::AutoSync),
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
    /// Every batch reached the transport and no ack is expected. Terminal.
    /// This is the success state for snapshot pushes, pull fulfillments and
    /// accepted pull requests — none of which the peer confirms.
    Sent,
    /// The peer confirmed delivery with a `BatchAck`. Terminal.
    /// Only ever reached by `SyncCatchup`; see [`IntentKind::awaits_ack`].
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
            IntentStatus::Sent => "sent",
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
            "sent" => Some(IntentStatus::Sent),
            "acked" => Some(IntentStatus::Acked),
            "declined" => Some(IntentStatus::Declined),
            "failed" => Some(IntentStatus::Failed),
            _ => None,
        }
    }

    /// Whether this intent is finished, whatever the outcome. Terminality is
    /// deliberately kind-free so callers can reason from status alone.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            IntentStatus::Sent
                | IntentStatus::Acked
                | IntentStatus::Declined
                | IntentStatus::Failed
        )
    }

    pub fn is_active(self) -> bool {
        !self.is_terminal()
    }

    pub const ALL: [IntentStatus; 7] = [
        IntentStatus::Pending,
        IntentStatus::Materialized,
        IntentStatus::InFlight,
        IntentStatus::Sent,
        IntentStatus::Acked,
        IntentStatus::Declined,
        IntentStatus::Failed,
    ];

    /// The non-terminal statuses, for filtering "still in progress" intents.
    /// Derived from [`Self::is_terminal`] so the two can never drift.
    pub fn active_statuses() -> Vec<IntentStatus> {
        IntentStatus::ALL
            .into_iter()
            .filter(|s| s.is_active())
            .collect()
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
