use serde::{Deserialize, Serialize};

use crate::change::BatchManifest;
use crate::share::ShareId;
use crate::default_wire_protocol_version;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloMessage {
    #[serde(default = "default_wire_protocol_version")]
    pub protocol_version: u16,
    pub pc_name: String,
    pub instance_id: String,
    pub listen_port: u16,
    pub shares: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchAck {
    #[serde(default = "default_wire_protocol_version")]
    pub protocol_version: u16,
    pub share_id: ShareId,
    pub upto_seq: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WireMessage {
    Hello(HelloMessage),
    Batch(BatchManifest),
    BatchAck(BatchAck),
}

pub fn wire_message_protocol_version(msg: &WireMessage) -> u16 {
    match msg {
        WireMessage::Hello(h) => h.protocol_version,
        WireMessage::Batch(b) => b.protocol_version,
        WireMessage::BatchAck(a) => a.protocol_version,
    }
}
