#![allow(dead_code)]

pub const WIRE_PROTOCOL_VERSION: u16 = 1;

pub fn default_wire_protocol_version() -> u16 {
    WIRE_PROTOCOL_VERSION
}

pub mod change;
pub mod config;
pub mod peer;
pub mod share;
pub mod wire;

pub use change::{BatchManifest, ChangeKind, FileChange, FileMeta};
pub use config::{AppConfig, ShareConfig};
pub use peer::{Peer, PeerState};
pub use share::{ShareContext, ShareId};
pub use wire::{BatchAck, HelloMessage, WireMessage};
