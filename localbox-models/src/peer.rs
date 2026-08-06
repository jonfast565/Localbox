use std::net::SocketAddr;

use crate::advertise::AdvertisedShare;

#[derive(Debug, Clone)]
pub enum PeerState {
    Disconnected,
    Connecting,
    Connected,
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub id: i64, // DB row id
    pub pc_name: String,
    pub instance_id: String,
    pub display_name: String,
    pub app_state: String,
    pub addr: SocketAddr,
    pub last_seen_ts: i64, // unix timestamp
    pub shares: Vec<AdvertisedShare>,
    pub state: PeerState,
}
