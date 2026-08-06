//! Sparse settings overlays: CLI/REPL/UI → DB → config.toml → defaults.
//!
//! `db_path` is never taken from the settings table (needed to open the DB).
//! Network / TLS path changes are persisted but typically need a process restart.

use anyhow::{anyhow, bail, Result};
use models::{AppConfig, ApplicationState, TransferMode};
use serde_json::Value;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

/// Keys that may be stored in the DB `settings` table / set via control plane.
pub const SETTABLE_KEYS: &[&str] = &[
    "instance_id",
    "display_name",
    "listen_port",
    "plain_listen_port",
    "discovery_port",
    "dht_port",
    "utp_port",
    "enable_dht",
    "enable_utp",
    "aggregation_window_ms",
    "log_path",
    "tls_cert_path",
    "tls_key_path",
    "tls_ca_cert_path",
    "tls_pinned_ca_fingerprints",
    "tls_peer_fingerprints",
    "tls_insecure_shared_cert",
    "use_tls_for_peers",
    "remote_share_root",
    "app_state",
    "request_handling",
    "peer_policies",
    "quarantined_peers",
    "bootstrap_peers",
    "control_socket",
];

/// Keys that bind sockets / change identity; take effect after restart.
pub fn requires_restart(key: &str) -> bool {
    matches!(
        key,
        "instance_id"
            | "listen_port"
            | "plain_listen_port"
            | "discovery_port"
            | "dht_port"
            | "utp_port"
            | "enable_dht"
            | "enable_utp"
            | "control_socket"
            | "log_path"
            | "tls_cert_path"
            | "tls_key_path"
            | "tls_ca_cert_path"
            | "remote_share_root"
            | "bootstrap_peers"
    )
}

pub fn is_settable_key(key: &str) -> bool {
    SETTABLE_KEYS.contains(&key)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingSource {
    Default,
    ConfigFile,
    Database,
    Runtime,
}

impl SettingSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::ConfigFile => "config",
            Self::Database => "database",
            Self::Runtime => "runtime",
        }
    }
}

/// Apply a JSON value to one AppConfig field.
pub fn apply_setting(cfg: &mut AppConfig, key: &str, value: &Value) -> Result<()> {
    if !is_settable_key(key) {
        bail!("unknown or unsettable setting key '{key}'");
    }
    match key {
        "instance_id" => cfg.instance_id = json_string(value, key)?,
        "display_name" => cfg.display_name = json_string(value, key)?,
        "listen_port" => {
            let port = json_u16(value, key)?;
            cfg.listen_addr = SocketAddr::new(cfg.listen_addr.ip(), port);
        }
        "plain_listen_port" => {
            let port = json_u16(value, key)?;
            cfg.plain_listen_addr = SocketAddr::new(cfg.plain_listen_addr.ip(), port);
        }
        "discovery_port" => cfg.discovery_port = json_u16(value, key)?,
        "dht_port" => cfg.dht_port = json_u16(value, key)?,
        "utp_port" => cfg.utp_port = json_u16(value, key)?,
        "enable_dht" => cfg.enable_dht = json_bool(value, key)?,
        "enable_utp" => cfg.enable_utp = json_bool(value, key)?,
        "aggregation_window_ms" => cfg.aggregation_window_ms = json_u64(value, key)?,
        "log_path" => cfg.log_path = PathBuf::from(json_string(value, key)?),
        "tls_cert_path" => cfg.tls_cert_path = PathBuf::from(json_string(value, key)?),
        "tls_key_path" => cfg.tls_key_path = PathBuf::from(json_string(value, key)?),
        "tls_ca_cert_path" => cfg.tls_ca_cert_path = PathBuf::from(json_string(value, key)?),
        "tls_pinned_ca_fingerprints" => {
            cfg.tls_pinned_ca_fingerprints = serde_json::from_value(value.clone())
                .map_err(|e| anyhow!("{key}: {e}"))?;
        }
        "tls_peer_fingerprints" => {
            cfg.tls_peer_fingerprints = serde_json::from_value(value.clone())
                .map_err(|e| anyhow!("{key}: {e}"))?;
        }
        "tls_insecure_shared_cert" => cfg.tls_insecure_shared_cert = json_bool(value, key)?,
        "use_tls_for_peers" => cfg.use_tls_for_peers = json_bool(value, key)?,
        "remote_share_root" => cfg.remote_share_root = PathBuf::from(json_string(value, key)?),
        "app_state" => {
            let s = json_string(value, key)?;
            cfg.app_state = parse_app_state(&s)?;
        }
        "request_handling" => {
            cfg.request_handling = if let Ok(m) = serde_json::from_value::<TransferMode>(value.clone())
            {
                m
            } else {
                TransferMode::from_str_cfg(&json_string(value, key)?)?
            };
        }
        "peer_policies" => {
            cfg.peer_policies = serde_json::from_value(value.clone())
                .map_err(|e| anyhow!("{key}: {e}"))?;
        }
        "quarantined_peers" => {
            cfg.quarantined_peers = serde_json::from_value(value.clone())
                .map_err(|e| anyhow!("{key}: {e}"))?;
        }
        "bootstrap_peers" => {
            cfg.bootstrap_peers = serde_json::from_value(value.clone())
                .map_err(|e| anyhow!("{key}: {e}"))?;
        }
        "control_socket" => cfg.control_socket = PathBuf::from(json_string(value, key)?),
        _ => bail!("unhandled setting key '{key}'"),
    }
    Ok(())
}

/// Read one field from the effective AppConfig as JSON.
pub fn read_setting(cfg: &AppConfig, key: &str) -> Result<Value> {
    if !is_settable_key(key) {
        bail!("unknown or unsettable setting key '{key}'");
    }
    let v = match key {
        "instance_id" => Value::String(cfg.instance_id.clone()),
        "display_name" => Value::String(cfg.display_name.clone()),
        "listen_port" => Value::from(cfg.listen_addr.port()),
        "plain_listen_port" => Value::from(cfg.plain_listen_addr.port()),
        "discovery_port" => Value::from(cfg.discovery_port),
        "dht_port" => Value::from(cfg.dht_port),
        "utp_port" => Value::from(cfg.utp_port),
        "enable_dht" => Value::Bool(cfg.enable_dht),
        "enable_utp" => Value::Bool(cfg.enable_utp),
        "aggregation_window_ms" => Value::from(cfg.aggregation_window_ms),
        "log_path" => Value::String(cfg.log_path.display().to_string()),
        "tls_cert_path" => Value::String(cfg.tls_cert_path.display().to_string()),
        "tls_key_path" => Value::String(cfg.tls_key_path.display().to_string()),
        "tls_ca_cert_path" => Value::String(cfg.tls_ca_cert_path.display().to_string()),
        "tls_pinned_ca_fingerprints" => serde_json::to_value(&cfg.tls_pinned_ca_fingerprints)?,
        "tls_peer_fingerprints" => serde_json::to_value(&cfg.tls_peer_fingerprints)?,
        "tls_insecure_shared_cert" => Value::Bool(cfg.tls_insecure_shared_cert),
        "use_tls_for_peers" => Value::Bool(cfg.use_tls_for_peers),
        "remote_share_root" => Value::String(cfg.remote_share_root.display().to_string()),
        "app_state" => Value::String(app_state_str(cfg.app_state).to_string()),
        "request_handling" => Value::String(transfer_mode_str(cfg.request_handling).to_string()),
        "peer_policies" => serde_json::to_value(&cfg.peer_policies)?,
        "quarantined_peers" => serde_json::to_value(&cfg.quarantined_peers)?,
        "bootstrap_peers" => serde_json::to_value(&cfg.bootstrap_peers)?,
        "control_socket" => Value::String(cfg.control_socket.display().to_string()),
        _ => bail!("unhandled setting key '{key}'"),
    };
    Ok(v)
}

/// Overlay DB-saved settings onto a config built from file/defaults.
pub fn apply_db_settings(
    cfg: &mut AppConfig,
    settings: &HashMap<String, String>,
) -> Result<Vec<String>> {
    apply_db_settings_filtered(cfg, settings, |_| false)
}

/// Like [`apply_db_settings`], but skips keys for which `skip` returns true
/// (used so CLI `RunArgs` still win over DB).
pub fn apply_db_settings_filtered(
    cfg: &mut AppConfig,
    settings: &HashMap<String, String>,
    skip: impl Fn(&str) -> bool,
) -> Result<Vec<String>> {
    let mut applied = Vec::new();
    for key in SETTABLE_KEYS {
        if skip(key) {
            continue;
        }
        if let Some(raw) = settings.get(*key) {
            let value: Value = serde_json::from_str(raw)
                .map_err(|e| anyhow!("settings[{key}] invalid JSON: {e}"))?;
            apply_setting(cfg, key, &value)?;
            applied.push((*key).to_string());
        }
    }
    Ok(applied)
}

/// Parse a CLI/REPL value string into JSON (numbers/bools/JSON, else string).
pub fn parse_value_literal(raw: &str) -> Result<Value> {
    let trimmed = raw.trim();
    if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
        return Ok(v);
    }
    Ok(Value::String(trimmed.to_string()))
}

trait TransferModeParse {
    fn from_str_cfg(s: &str) -> Result<TransferMode>;
}

impl TransferModeParse for TransferMode {
    fn from_str_cfg(s: &str) -> Result<TransferMode> {
        match s.to_ascii_lowercase().as_str() {
            "manual" => Ok(TransferMode::Manual),
            "auto" => Ok(TransferMode::Auto),
            other => bail!("expected manual|auto, got {other}"),
        }
    }
}

fn transfer_mode_str(m: TransferMode) -> &'static str {
    match m {
        TransferMode::Manual => "manual",
        TransferMode::Auto => "auto",
    }
}

fn parse_app_state(s: &str) -> Result<ApplicationState> {
    match s
        .to_ascii_lowercase()
        .replace('-', "_")
        .replace(' ', "")
        .as_str()
    {
        "mirror_only" | "mirroronly" => Ok(ApplicationState::MirrorOnly),
        "host_only" | "hostonly" => Ok(ApplicationState::HostOnly),
        "mirrorhost" | "mirror_host" => Ok(ApplicationState::MirrorHost),
        "zombie" => Ok(ApplicationState::Zombie),
        other => bail!("unknown app_state '{other}'"),
    }
}

fn app_state_str(s: ApplicationState) -> &'static str {
    match s {
        ApplicationState::MirrorOnly => "mirror_only",
        ApplicationState::HostOnly => "host_only",
        ApplicationState::MirrorHost => "mirrorhost",
        ApplicationState::Zombie => "zombie",
    }
}

fn json_string(value: &Value, key: &str) -> Result<String> {
    match value {
        Value::String(s) => Ok(s.clone()),
        other => Ok(other.to_string().trim_matches('"').to_string()).and_then(|s| {
            if other.is_string() {
                Ok(s)
            } else if other.is_number() || other.is_boolean() {
                // allow bare literals already parsed
                Ok(other.to_string())
            } else {
                Err(anyhow!("{key}: expected string, got {other}"))
            }
        }),
    }
    .or_else(|_| match value {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        other => Err(anyhow!("{key}: expected string-like, got {other}")),
    })
}

fn json_bool(value: &Value, key: &str) -> Result<bool> {
    match value {
        Value::Bool(b) => Ok(*b),
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            other => bail!("{key}: expected bool, got '{other}'"),
        },
        other => bail!("{key}: expected bool, got {other}"),
    }
}

fn json_u16(value: &Value, key: &str) -> Result<u16> {
    match value {
        Value::Number(n) => n
            .as_u64()
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| anyhow!("{key}: expected u16")),
        Value::String(s) => s
            .parse::<u16>()
            .map_err(|e| anyhow!("{key}: expected u16 ({e})")),
        other => bail!("{key}: expected u16, got {other}"),
    }
}

fn json_u64(value: &Value, key: &str) -> Result<u64> {
    match value {
        Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| anyhow!("{key}: expected u64")),
        Value::String(s) => s
            .parse::<u64>()
            .map_err(|e| anyhow!("{key}: expected u64 ({e})")),
        other => bail!("{key}: expected u64, got {other}"),
    }
}

/// Rebuild listen addrs after port overlays while preserving unspecified bind.
pub fn normalize_listen_addrs(cfg: &mut AppConfig) {
    if cfg.listen_addr.ip().is_unspecified() {
        cfg.listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), cfg.listen_addr.port());
    }
    if cfg.plain_listen_addr.ip().is_unspecified() {
        cfg.plain_listen_addr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), cfg.plain_listen_addr.port());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use models::ApplicationState;
    use std::net::{IpAddr, Ipv4Addr};

    fn sample() -> AppConfig {
        AppConfig {
            pc_name: "pc".into(),
            instance_id: "i".into(),
            display_name: String::new(),
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5000),
            plain_listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5002),
            use_tls_for_peers: true,
            discovery_port: 5001,
            dht_port: 5003,
            utp_port: 5004,
            enable_dht: false,
            enable_utp: false,
            bootstrap_peers: Vec::new(),
            aggregation_window_ms: 2000,
            db_path: PathBuf::from("sync.db"),
            log_path: PathBuf::from("sync.log"),
            tls_cert_path: PathBuf::from("c.pem"),
            tls_key_path: PathBuf::from("k.pem"),
            tls_ca_cert_path: PathBuf::from("ca.pem"),
            tls_pinned_ca_fingerprints: Vec::new(),
            tls_peer_fingerprints: HashMap::new(),
            tls_insecure_shared_cert: false,
            remote_share_root: PathBuf::from("remote"),
            shares: Vec::new(),
            app_state: ApplicationState::MirrorHost,
            request_handling: TransferMode::Manual,
            peer_policies: Vec::new(),
            quarantined_peers: Vec::new(),
            control_socket: PathBuf::from("localbox.sock"),
        }
    }

    #[test]
    fn db_overlay_beats_defaults() {
        let mut cfg = sample();
        let mut map = HashMap::new();
        map.insert("enable_utp".into(), "true".into());
        map.insert("listen_port".into(), "6000".into());
        apply_db_settings(&mut cfg, &map).unwrap();
        assert!(cfg.enable_utp);
        assert_eq!(cfg.listen_addr.port(), 6000);
    }

    #[test]
    fn bootstrap_peers_json() {
        let mut cfg = sample();
        let v = serde_json::json!([{
            "addr": "1.2.3.4:5003",
            "pc_name": "home",
            "session_addr": "1.2.3.4:5000"
        }]);
        apply_setting(&mut cfg, "bootstrap_peers", &v).unwrap();
        assert_eq!(cfg.bootstrap_peers.len(), 1);
        assert_eq!(cfg.bootstrap_peers[0].pc_name.as_deref(), Some("home"));
    }
}
