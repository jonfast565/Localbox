use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub pc_name: String,
    pub instance_id: String,
    pub listen_addr: SocketAddr,
    pub discovery_port: u16,
    pub aggregation_window_ms: u64,
    pub db_path: PathBuf,
    pub log_path: PathBuf,
    pub tls_cert_path: PathBuf,
    pub tls_key_path: PathBuf,
    pub tls_ca_cert_path: PathBuf,
    #[serde(default)]
    pub tls_pinned_ca_fingerprints: Vec<String>,
    pub remote_share_root: PathBuf,
    pub shares: Vec<ShareConfig>,
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
