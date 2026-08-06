#![allow(dead_code)]

/// v3: FileChunk carries protocol_version + batch_id; BatchAck may include batch_id.
/// v4: BatchManifest declares its `BatchBasis` and journal range, so the receiver
///     knows whether `FileChange.seq` holds real journal positions. `BatchAck.upto_seq`
///     is always in the sender's namespace (0 for snapshot batches).
/// TransferIntent ids remain DB-local (batch_uuid ↔ intent).
///
/// v4 is a flag day: `parse_wire_message` rejects anything stamped above the
/// local version, so all nodes must be upgraded together.
pub const WIRE_PROTOCOL_VERSION: u16 = 4;

pub fn default_wire_protocol_version() -> u16 {
    WIRE_PROTOCOL_VERSION
}

pub mod change;
pub mod chat;
pub mod config;
pub mod intent;
pub mod peer;
pub mod progress;
pub mod share;
pub mod transfer;
pub mod wire;

pub use change::{
    BatchBasis, BatchManifest, ChangeKind, FileChange, FileChunk, FileMeta, JournalEntry,
};
pub use chat::{
    peer_key, peer_thread_id, share_thread_id, ChatAck, ChatAttachment, ChatMessage,
    ChatMessageRecord, ThreadKind, ThreadSummary,
};
pub use config::{
    peer_keys_match, AppConfig, ApplicationState, ConflictPolicy, PeerPolicy, ShareConfig,
    TransferMode,
};
pub use intent::{
    IntentBasis, IntentKind, IntentOrigin, IntentStatus, TransferIntent,
};
pub use peer::{Peer, PeerState};
pub use progress::{
    TransferDirection, TransferProgressRegistry, TransferProgressSnapshot,
};
pub use share::{ShareContext, ShareId};
pub use transfer::{
    TransferPushOffer, TransferReply, TransferReplyStatus, TransferRequest,
};
pub use wire::{BatchAck, HelloMessage, WireMessage};

/// Alias used by config/docs for inbound request handling policy.
pub type RequestHandling = TransferMode;
