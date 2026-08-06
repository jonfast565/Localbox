use models::WireMessage;

/// Commands the control plane / engine can send into PeerManager.
#[derive(Debug)]
pub enum PeerCommand {
    /// Send a wire message to a specific peer row id.
    SendToPeer { peer_id: i64, msg: WireMessage },
    /// Send a wire message to all connected peers matching pc_name (optional @instance).
    SendToPeerKey { peer_key: String, msg: WireMessage },
    /// Broadcast a wire message to all connected peers.
    Broadcast { msg: WireMessage },
}
