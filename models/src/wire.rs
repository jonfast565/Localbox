use serde::{Deserialize, Serialize};

use crate::change::BatchManifest;
use crate::share::ShareId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloMessage {
    pub pc_name: String,
    pub instance_id: String,
    pub listen_port: u16,
    pub shares: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchAck {
    pub share_id: ShareId,
    pub upto_seq: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WireMessage {
    Hello(HelloMessage),
    Batch(BatchManifest),
    BatchAck(BatchAck),
}
