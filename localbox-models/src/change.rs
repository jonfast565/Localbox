use serde::{Deserialize, Serialize};

use crate::default_wire_protocol_version;
use crate::share::ShareId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMeta {
    pub path: String, // relative to root
    pub size: u64,
    pub mtime: i64, // unix timestamp
    pub hash: [u8; 32],
    pub version: i64,
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeKind {
    Create,
    Modify,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub seq: i64, // monotonic per share
    pub share_id: ShareId,
    pub path: String,
    pub kind: ChangeKind,
    pub meta: Option<FileMeta>, // None for delete
}

/// One row of a share's journal.
///
/// `change.seq` is this node's locally allocated position. `origin_seq` is the
/// authoring node's position, which lives in a different numbering namespace and
/// must never be compared against, or assigned into, `change.seq`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Authoring peer's DB row id; `None` when authored on this node.
    pub origin_peer_id: Option<i64>,
    /// Authoring peer's journal position; 0 for snapshot-derived (manual push)
    /// entries, which hold no position in any journal.
    pub origin_seq: i64,
    pub change: FileChange,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileChunk {
    /// Wire protocol version (defaulted for legacy peers).
    #[serde(default = "default_wire_protocol_version")]
    pub protocol_version: u16,
    /// Links payload chunks to the preceding `BatchManifest.batch_id`.
    /// Empty string = legacy peers that omit the field. Intent ids stay DB-local.
    #[serde(default)]
    pub batch_id: String,
    pub share_id: ShareId,
    pub path: String,
    pub offset: u64,
    pub data: Vec<u8>,
    pub eof: bool,
}

/// What a batch was built from — the receiver's contract for how to interpret
/// `FileChange.seq` and whether any watermark may move.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BatchBasis {
    /// Built from a range of the sender's journal. Every `FileChange.seq` is a
    /// real position in the sender's namespace, and the range is declared by
    /// `journal_from_seq`/`journal_to_seq`.
    Journal,
    /// Built from the sender's current file index (a manual push). Carries no
    /// journal positions: every `seq` is 0 and no watermark may advance.
    #[default]
    Snapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchManifest {
    #[serde(default = "default_wire_protocol_version")]
    pub protocol_version: u16,
    pub batch_id: String, // e.g. UUID string
    pub share_id: ShareId,
    pub from_node: String, // pc_name
    pub created_at: i64,   // unix timestamp
    /// How to interpret `changes[].seq`. Defaults to `Snapshot`, the
    /// conservative reading: assume no journal positions and move nothing.
    #[serde(default)]
    pub basis: BatchBasis,
    /// The journal range this batch covers, in the *sender's* namespace.
    /// `from` exclusive, `to` inclusive; both 0 for a snapshot batch.
    ///
    /// The receiver advances its inbound watermark to `journal_to_seq` even when
    /// individual changes were filtered out locally — otherwise one skipped
    /// change pins the watermark and the sender re-sends the range forever.
    #[serde(default)]
    pub journal_from_seq: i64,
    #[serde(default)]
    pub journal_to_seq: i64,
    pub changes: Vec<FileChange>,
}
