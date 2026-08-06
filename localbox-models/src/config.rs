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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConflictPolicy {
    #[default]
    LastWriteWins,
    KeepBoth,
    OwnerWins,
}

/// Seed node for the private BEP5 DHT mesh (and optional direct session dial).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapPeer {
    /// DHT UDP endpoint as `host:port`.
    pub addr: String,
    /// Optional TCP/TLS session endpoint as `host:port` for an immediate dial.
    #[serde(default)]
    pub session_addr: Option<String>,
    /// Optional peer name used for DHT lookup / dial ServerName.
    #[serde(default)]
    pub pc_name: Option<String>,
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
    /// UDP port for private BEP5 DHT (irontide). Default 5003.
    #[serde(default = "default_dht_port")]
    pub dht_port: u16,
    /// UDP port for uTP peer sessions (irontide). Default 5004.
    #[serde(default = "default_utp_port")]
    pub utp_port: u16,
    /// Run the private DHT node (also implied when `bootstrap_peers` is non-empty).
    #[serde(default)]
    pub enable_dht: bool,
    /// Private-mesh DHT bootstrap peers (no public Mainline routers).
    #[serde(default)]
    pub bootstrap_peers: Vec<BootstrapPeer>,
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
    /// Peer keys (`pc_name` or `pc_name@instance_id`) that must be refused.
    #[serde(default)]
    pub quarantined_peers: Vec<String>,
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
    /// Optional allowlist; empty means all non-ignored paths are eligible.
    #[serde(default)]
    pub sync_allow: Vec<String>,
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
    #[serde(default)]
    pub conflict: ConflictPolicy,
}

impl ShareConfig {
    pub fn new(name: impl Into<String>, root_path: PathBuf, recursive: bool) -> Self {
        Self {
            name: name.into(),
            root_path,
            recursive,
            ignore_patterns: Vec::new(),
            sync_allow: Vec::new(),
            max_file_size_bytes: None,
            sync: TransferMode::Manual,
            pull: TransferMode::Manual,
            request_handling: None,
            conflict: ConflictPolicy::LastWriteWins,
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
    #[serde(default)]
    pub conflict: Option<ConflictPolicy>,
    #[serde(default)]
    pub sync_allow: Option<Vec<String>>,
    #[serde(default)]
    pub ignore_patterns: Option<Vec<String>>,
    /// Accept inbound file data (batches/chunks) from this peer. Default true.
    #[serde(default)]
    pub allow_push: Option<bool>,
    /// Fulfill TransferRequests from this peer. Default true.
    #[serde(default)]
    pub allow_pull: Option<bool>,
    /// Send TransferRequests / auto-pull to this peer. Default true.
    #[serde(default)]
    pub allow_request: Option<bool>,
}

impl AppConfig {
    /// Whether the private BEP5 DHT should run.
    pub fn wan_discovery_enabled(&self) -> bool {
        self.enable_dht || !self.bootstrap_peers.is_empty()
    }

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

    pub fn resolve_conflict_policy(
        &self,
        share_name: &str,
        peer_key: Option<&str>,
    ) -> ConflictPolicy {
        if let Some(peer) = peer_key {
            if let Some(p) = self.find_peer_policy(peer, Some(share_name)) {
                if let Some(policy) = p.conflict {
                    return policy;
                }
            }
            if let Some(p) = self.find_peer_policy(peer, None) {
                if let Some(policy) = p.conflict {
                    return policy;
                }
            }
        }
        self.shares
            .iter()
            .find(|s| s.name == share_name)
            .map(|s| s.conflict)
            .unwrap_or(ConflictPolicy::LastWriteWins)
    }

    /// Resolved sync_allow (peer override wins). Empty = no allowlist restriction.
    pub fn resolve_sync_allow(&self, share_name: &str, peer_key: Option<&str>) -> Vec<String> {
        if let Some(peer) = peer_key {
            if let Some(p) = self.find_peer_policy(peer, Some(share_name)) {
                if let Some(ref allow) = p.sync_allow {
                    return allow.clone();
                }
            }
            if let Some(p) = self.find_peer_policy(peer, None) {
                if let Some(ref allow) = p.sync_allow {
                    return allow.clone();
                }
            }
        }
        self.shares
            .iter()
            .find(|s| s.name == share_name)
            .map(|s| s.sync_allow.clone())
            .unwrap_or_default()
    }

    /// Resolved ignore patterns (peer override replaces share list when set).
    pub fn resolve_ignore_patterns(&self, share_name: &str, peer_key: Option<&str>) -> Vec<String> {
        if let Some(peer) = peer_key {
            if let Some(p) = self.find_peer_policy(peer, Some(share_name)) {
                if let Some(ref ignore) = p.ignore_patterns {
                    return ignore.clone();
                }
            }
            if let Some(p) = self.find_peer_policy(peer, None) {
                if let Some(ref ignore) = p.ignore_patterns {
                    return ignore.clone();
                }
            }
        }
        self.shares
            .iter()
            .find(|s| s.name == share_name)
            .map(|s| s.ignore_patterns.clone())
            .unwrap_or_default()
    }

    pub fn resolve_allow_push(&self, share_name: &str, peer_key: &str) -> bool {
        self.resolve_allow_flag(share_name, peer_key, |p| p.allow_push)
    }

    pub fn resolve_allow_pull(&self, share_name: &str, peer_key: &str) -> bool {
        self.resolve_allow_flag(share_name, peer_key, |p| p.allow_pull)
    }

    pub fn resolve_allow_request(&self, share_name: &str, peer_key: &str) -> bool {
        self.resolve_allow_flag(share_name, peer_key, |p| p.allow_request)
    }

    fn resolve_allow_flag(
        &self,
        share_name: &str,
        peer_key: &str,
        f: impl Fn(&PeerPolicy) -> Option<bool>,
    ) -> bool {
        if let Some(p) = self.find_peer_policy(peer_key, Some(share_name)) {
            if let Some(v) = f(p) {
                return v;
            }
        }
        if let Some(p) = self.find_peer_policy(peer_key, None) {
            if let Some(v) = f(p) {
                return v;
            }
        }
        true
    }

    pub fn is_peer_quarantined(&self, peer_key: &str) -> bool {
        self.quarantined_peers
            .iter()
            .any(|q| peer_keys_match(q, peer_key))
    }

    pub fn find_peer_policy(&self, peer_key: &str, share: Option<&str>) -> Option<&PeerPolicy> {
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

pub fn peer_keys_match(configured: &str, actual: &str) -> bool {
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

fn default_dht_port() -> u16 {
    5003
}

fn default_utp_port() -> u16 {
    5004
}

/// Infohash for announcing/looking up a Localbox peer on the private DHT.
pub fn peer_dht_infohash(pc_name: &str) -> [u8; 20] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("localbox-peer-v1:{pc_name}").as_bytes());
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..20]);
    out
}

/// Deterministic ed25519 seed for BEP44 mutable endpoint records (location only;
/// session trust remains mTLS).
pub fn peer_dht_mutable_seed(pc_name: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("localbox-dht-seed-v1:{pc_name}").as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
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
