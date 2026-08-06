use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TransferMode {
    #[default]
    Manual,
    Auto,
}

impl TransferMode {
    pub fn is_auto(self) -> bool {
        matches!(self, TransferMode::Auto)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub pc_name: String,
    pub instance_id: String,
    pub listen_addr: SocketAddr,
    /// Plain (no TLS) listen address for peer connections.
    pub plain_listen_addr: SocketAddr,
    /// Whether this node prefers TLS when talking to peers.
    #[serde(default = "default_use_tls_for_peers")]
    pub use_tls_for_peers: bool,
    pub discovery_port: u16,
    pub aggregation_window_ms: u64,
    pub db_path: PathBuf,
    pub log_path: PathBuf,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub tls_ca_cert_path: PathBuf,
    #[serde(default)]
    pub tls_pinned_ca_fingerprints: Vec<String>,
    #[serde(default)]
    pub tls_peer_fingerprints: HashMap<String, Vec<String>>,
    /// Accept peers whose certificate is not issued to the name they claim.
    ///
    /// Off by default. Turning it on lets an entire network share one common
    /// certificate instead of holding one per node, at the cost of peers being
    /// unable to tell each other apart: anyone with the shared bundle can act as
    /// any node. Connections accepted this way are stamped insecure in the DB,
    /// the same way plaintext ones are.
    #[serde(default)]
    pub tls_insecure_shared_cert: bool,
    pub remote_share_root: PathBuf,
    pub shares: Vec<ShareConfig>,
    #[serde(default = "default_app_state")]
    pub app_state: ApplicationState,
    /// How inbound transfer requests are handled by default.
    #[serde(default)]
    pub request_handling: TransferMode,
    /// Optional per-peer transfer policy overrides.
    #[serde(default)]
    pub peer_policies: Vec<PeerPolicy>,
    /// Unix domain socket for control plane (CLI/GUI).
    #[serde(default = "default_control_socket")]
    pub control_socket: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareConfig {
    pub name: String,
    pub root_path: PathBuf,
    pub recursive: bool,
    #[serde(default)]
    pub ignore_patterns: Vec<String>,
    pub max_file_size_bytes: Option<u64>,
    /// Auto-sync local journal changes to peers via SyncCatchup (default: manual).
    /// Note: this gates *journal sync*, not `IntentKind::SnapshotPush` — a manual
    /// `localbox push` works regardless of this setting.
    /// `push` is the pre-v7 spelling of this key.
    #[serde(default, alias = "push")]
    pub sync: TransferMode,
    /// Auto-pull / request from peers (default: manual).
    #[serde(default)]
    pub pull: TransferMode,
    /// Override global request_handling for this share.
    #[serde(default)]
    pub request_handling: Option<TransferMode>,
}

impl ShareConfig {
    pub fn new(name: impl Into<String>, root_path: PathBuf, recursive: bool) -> Self {
        Self {
            name: name.into(),
            root_path,
            recursive,
            ignore_patterns: Vec::new(),
            max_file_size_bytes: None,
            sync: TransferMode::Manual,
            pull: TransferMode::Manual,
            request_handling: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerPolicy {
    /// Peer key as `pc_name` or `pc_name@instance_id`.
    pub peer: String,
    /// Optional share name; if omitted, applies to all shares.
    #[serde(default)]
    pub share: Option<String>,
    /// `push` is the pre-v7 spelling of this key.
    #[serde(default, alias = "push")]
    pub sync: Option<TransferMode>,
    #[serde(default)]
    pub pull: Option<TransferMode>,
    #[serde(default)]
    pub request_handling: Option<TransferMode>,
}

impl AppConfig {
    /// Whether journal sync (SyncCatchup) runs automatically for this share/peer.
    /// Does not gate manual `IntentKind::SnapshotPush`.
    pub fn resolve_sync_mode(&self, share_name: &str, peer_key: Option<&str>) -> TransferMode {
        if let Some(peer) = peer_key {
            if let Some(p) = self.find_peer_policy(peer, Some(share_name)) {
                if let Some(mode) = p.sync {
                    return mode;
                }
            }
            if let Some(p) = self.find_peer_policy(peer, None) {
                if let Some(mode) = p.sync {
                    return mode;
                }
            }
        }
        self.shares
            .iter()
            .find(|s| s.name == share_name)
            .map(|s| s.sync)
            .unwrap_or(TransferMode::Manual)
    }

    pub fn resolve_pull_mode(&self, share_name: &str, peer_key: Option<&str>) -> TransferMode {
        if let Some(peer) = peer_key {
            if let Some(p) = self.find_peer_policy(peer, Some(share_name)) {
                if let Some(mode) = p.pull {
                    return mode;
                }
            }
            if let Some(p) = self.find_peer_policy(peer, None) {
                if let Some(mode) = p.pull {
                    return mode;
                }
            }
        }
        self.shares
            .iter()
            .find(|s| s.name == share_name)
            .map(|s| s.pull)
            .unwrap_or(TransferMode::Manual)
    }

    pub fn resolve_request_handling(
        &self,
        share_name: &str,
        peer_key: Option<&str>,
    ) -> TransferMode {
        if let Some(peer) = peer_key {
            if let Some(p) = self.find_peer_policy(peer, Some(share_name)) {
                if let Some(mode) = p.request_handling {
                    return mode;
                }
            }
            if let Some(p) = self.find_peer_policy(peer, None) {
                if let Some(mode) = p.request_handling {
                    return mode;
                }
            }
        }
        if let Some(share) = self.shares.iter().find(|s| s.name == share_name) {
            if let Some(mode) = share.request_handling {
                return mode;
            }
        }
        self.request_handling
    }

    fn find_peer_policy(
        &self,
        peer_key: &str,
        share: Option<&str>,
    ) -> Option<&PeerPolicy> {
        self.peer_policies.iter().find(|p| {
            peer_keys_match(&p.peer, peer_key)
                && match (p.share.as_deref(), share) {
                    (None, None) => true,
                    (Some(a), Some(b)) => a == b,
                    (None, Some(_)) => true,
                    (Some(_), None) => false,
                }
        })
    }
}

fn peer_keys_match(configured: &str, actual: &str) -> bool {
    if configured == actual {
        return true;
    }
    // Allow matching by pc_name only when configured without @instance.
    if !configured.contains('@') {
        return actual == configured || actual.starts_with(&format!("{configured}@"));
    }
    false
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApplicationState {
    #[serde(rename = "mirror_only", alias = "mirror-only", alias = "mirroronly")]
    MirrorOnly,
    #[serde(rename = "host_only", alias = "host-only", alias = "hostonly")]
    HostOnly,
    #[serde(rename = "mirrorhost", alias = "mirror_host", alias = "mirror-host")]
    MirrorHost,
    #[serde(rename = "zombie")]
    Zombie,
}

impl ApplicationState {
    pub fn can_share(self) -> bool {
        matches!(
            self,
            ApplicationState::HostOnly | ApplicationState::MirrorHost
        )
    }

    pub fn can_host_remote(self) -> bool {
        matches!(
            self,
            ApplicationState::MirrorOnly | ApplicationState::MirrorHost
        )
    }

    pub fn is_zombie(self) -> bool {
        matches!(self, ApplicationState::Zombie)
    }
}

impl Default for ApplicationState {
    fn default() -> Self {
        ApplicationState::MirrorHost
    }
}

fn default_use_tls_for_peers() -> bool {
    true
}

fn default_app_state() -> ApplicationState {
    ApplicationState::MirrorHost
}

fn default_control_socket() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(r"\\.\pipe\localbox")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("localbox.sock")
    }
}
