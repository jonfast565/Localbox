use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

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
    pub remote_share_root: PathBuf,
    pub shares: Vec<ShareConfig>,
    #[serde(default = "default_app_state")]
    pub app_state: ApplicationState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareConfig {
    pub name: String,
    pub root_path: PathBuf,
    pub recursive: bool,
    #[serde(default)]
    pub ignore_patterns: Vec<String>,
    pub max_file_size_bytes: Option<u64>,
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
