use std::net::SocketAddr;

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
    pub addr: SocketAddr,
    pub last_seen_ts: i64,   // unix timestamp
    pub shares: Vec<String>, // share names
    pub state: PeerState,
}
