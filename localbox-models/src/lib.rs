#![allow(dead_code)]

/// v3: FileChunk carries protocol_version + batch_id; BatchAck may include batch_id.
/// TransferIntent ids remain DB-local (batch_uuid ↔ intent).
pub const WIRE_PROTOCOL_VERSION: u16 = 3;

pub fn default_wire_protocol_version() -> u16 {
    WIRE_PROTOCOL_VERSION
}

pub mod change;
pub mod chat;
pub mod config;
pub mod intent;
pub mod peer;
pub mod share;
pub mod transfer;
pub mod wire;

pub use change::{BatchManifest, ChangeKind, FileChange, FileChunk, FileMeta};
pub use chat::{
    peer_key, peer_thread_id, share_thread_id, ChatAck, ChatAttachment, ChatMessage,
    ChatMessageRecord, ThreadKind, ThreadSummary,
};
pub use config::{
    AppConfig, ApplicationState, PeerPolicy, ShareConfig, TransferMode,
};
pub use intent::{
    IntentBasis, IntentKind, IntentOrigin, IntentStatus, TransferIntent,
};
pub use peer::{Peer, PeerState};
pub use share::{ShareContext, ShareId};
pub use transfer::{
    TransferPushOffer, TransferReply, TransferReplyStatus, TransferRequest,
};
pub use wire::{BatchAck, HelloMessage, WireMessage};

/// Alias used by config/docs for inbound request handling policy.
pub type RequestHandling = TransferMode;
