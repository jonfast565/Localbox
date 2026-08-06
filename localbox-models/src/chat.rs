use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::default_wire_protocol_version;

/// Namespace for deterministic chat thread IDs.
static THREAD_NS: [u8; 16] = [
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ThreadKind {
    Peer,
    Share,
}

impl ThreadKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ThreadKind::Peer => "peer",
            ThreadKind::Share => "share",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "peer" => Some(ThreadKind::Peer),
            "share" => Some(ThreadKind::Share),
            _ => None,
        }
    }
}

/// Canonical peer key: `pc_name@instance_id`.
pub fn peer_key(pc_name: &str, instance_id: &str) -> String {
    format!("{pc_name}@{instance_id}")
}

/// Deterministic peer DM thread id shared by both sides.
pub fn peer_thread_id(local_key: &str, remote_key: &str) -> String {
    let (a, b) = if local_key <= remote_key {
        (local_key, remote_key)
    } else {
        (remote_key, local_key)
    };
    let ns = Uuid::from_bytes(THREAD_NS);
    Uuid::new_v5(&ns, format!("peer:{a}|{b}").as_bytes()).to_string()
}

/// Deterministic share-scoped thread id.
pub fn share_thread_id(share_name: &str) -> String {
    let ns = Uuid::from_bytes(THREAD_NS);
    Uuid::new_v5(&ns, format!("share:{share_name}").as_bytes()).to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatAttachment {
    pub share_name: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    #[serde(default = "default_wire_protocol_version")]
    pub protocol_version: u16,
    pub thread_id: String,
    pub message_id: String,
    pub thread_kind: ThreadKind,
    #[serde(default)]
    pub peer_key: Option<String>,
    #[serde(default)]
    pub share_name: Option<String>,
    pub from_pc: String,
    pub from_instance: String,
    pub body: String,
    #[serde(default)]
    pub attachment: Option<ChatAttachment>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatAck {
    #[serde(default = "default_wire_protocol_version")]
    pub protocol_version: u16,
    pub message_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadSummary {
    pub id: String,
    pub kind: ThreadKind,
    pub peer_key: Option<String>,
    pub share_name: Option<String>,
    pub title: String,
    pub updated_at: i64,
    pub unread_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessageRecord {
    pub id: String,
    pub thread_id: String,
    pub from_peer: String,
    pub body: String,
    pub attachment_share: Option<String>,
    pub attachment_path: Option<String>,
    pub created_at: i64,
    pub direction: String, // "in" | "out"
    pub status: String,
}
