use serde::{Deserialize, Serialize};

use crate::default_wire_protocol_version;
use crate::share::ShareId;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransferReplyStatus {
    Accept,
    Decline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequest {
    #[serde(default = "default_wire_protocol_version")]
    pub protocol_version: u16,
    pub request_id: String,
    pub share_id: ShareId,
    pub share_name: String,
    /// Request changes since this seq (0 = full / bootstrap).
    #[serde(default)]
    pub since_seq: i64,
    /// Optional path filter; empty means whole share.
    #[serde(default)]
    pub paths: Vec<String>,
    pub from_pc: String,
    pub from_instance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferReply {
    #[serde(default = "default_wire_protocol_version")]
    pub protocol_version: u16,
    pub request_id: String,
    pub status: TransferReplyStatus,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferPushOffer {
    #[serde(default = "default_wire_protocol_version")]
    pub protocol_version: u16,
    pub offer_id: String,
    pub share_id: ShareId,
    pub share_name: String,
    #[serde(default)]
    pub paths: Vec<String>,
    pub from_pc: String,
    pub from_instance: String,
}
