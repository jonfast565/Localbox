use serde::{Deserialize, Serialize};

use crate::change::{BatchManifest, FileChunk};
use crate::chat::{ChatAck, ChatMessage};
use crate::default_wire_protocol_version;
use crate::share::ShareId;
use crate::transfer::{TransferPushOffer, TransferReply, TransferRequest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloMessage {
    #[serde(default = "default_wire_protocol_version")]
    pub protocol_version: u16,
    pub pc_name: String,
    pub instance_id: String,
    /// TLS port
    pub listen_port: u16,
    /// Plain (no TLS) port
    #[serde(default)]
    pub plain_port: u16,
    /// Whether the sender prefers TLS when connecting to peers.
    #[serde(default = "default_use_tls_for_peers")]
    pub use_tls_for_peers: bool,
    pub shares: Vec<String>,
    #[serde(default = "default_accepts_remote_shares")]
    pub accepts_remote_shares: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchAck {
    #[serde(default = "default_wire_protocol_version")]
    pub protocol_version: u16,
    pub share_id: ShareId,
    pub upto_seq: i64,
    /// Optional link to the acked `BatchManifest.batch_id` (empty/absent = legacy).
    #[serde(default)]
    pub batch_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WireMessage {
    Hello(HelloMessage),
    Batch(BatchManifest),
    BatchAck(BatchAck),
    FileChunk(FileChunk),
    TransferRequest(TransferRequest),
    TransferReply(TransferReply),
    TransferPushOffer(TransferPushOffer),
    ChatMessage(ChatMessage),
    ChatAck(ChatAck),
}

pub fn wire_message_protocol_version(msg: &WireMessage) -> u16 {
    match msg {
        WireMessage::Hello(h) => h.protocol_version,
        WireMessage::Batch(b) => b.protocol_version,
        WireMessage::BatchAck(a) => a.protocol_version,
        WireMessage::FileChunk(c) => c.protocol_version,
        WireMessage::TransferRequest(r) => r.protocol_version,
        WireMessage::TransferReply(r) => r.protocol_version,
        WireMessage::TransferPushOffer(o) => o.protocol_version,
        WireMessage::ChatMessage(m) => m.protocol_version,
        WireMessage::ChatAck(a) => a.protocol_version,
    }
}

fn default_use_tls_for_peers() -> bool {
    true
}

fn default_accepts_remote_shares() -> bool {
    true
}
