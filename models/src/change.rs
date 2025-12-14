use serde::{Deserialize, Serialize};

use crate::share::ShareId;
use crate::default_wire_protocol_version;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchManifest {
    #[serde(default = "default_wire_protocol_version")]
    pub protocol_version: u16,
    pub batch_id: String, // e.g. UUID string
    pub share_id: ShareId,
    pub from_node: String, // pc_name
    pub created_at: i64,   // unix timestamp
    pub changes: Vec<FileChange>,
}
