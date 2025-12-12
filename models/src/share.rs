use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

use crate::change::FileMeta;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ShareId(pub [u8; 16]); // e.g. UUID bytes

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareContext {
    pub id: i64, // DB row id
    pub share_name: String,
    pub pc_name: String,
    pub share_id: ShareId,
    pub root_path: PathBuf,
    pub recursive: bool,
    pub index: HashMap<String, FileMeta>,
}

impl ShareId {
    pub fn new(name: &str, pc_name: &str) -> Self {
        // For deterministic IDs across restarts, use a fixed namespace UUID
        static NAMESPACE_BYTES: [u8; 16] = [
            0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65,
            0x43, 0x21,
        ];
        let ns = Uuid::from_bytes(NAMESPACE_BYTES);
        let uuid = Uuid::new_v5(&ns, format!("{name}@{pc_name}").as_bytes());
        ShareId(*uuid.as_bytes())
    }
}
