use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use models::{AppConfig, ShareConfig};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

const DEFAULT_INSTANCE_ID: &str = "instance-1";
const DEFAULT_LISTEN_PORT: u16 = 5000;
const DEFAULT_PLAIN_LISTEN_PORT: u16 = 5002;
const DEFAULT_DISCOVERY_PORT: u16 = 5001;
const DEFAULT_AGG_WINDOW_MS: u64 = 2000;
const DEFAULT_DB_PATH: &str = "sync.db";
const DEFAULT_LOG_PATH: &str = "sync.log";
const DEFAULT_TLS_CERT_PATH: &str = "certs/localbox.cert.pem";
const DEFAULT_TLS_KEY_PATH: &str = "certs/localbox.key.pem";
const DEFAULT_TLS_CA_CERT_PATH: &str = "certs/ca.cert.pem";
const DEFAULT_REMOTE_SHARE_ROOT: &str = "remote-shares";
const DEFAULT_CONFIG_PATH: &str = "config.toml";

#[derive(Debug, Parser)]
#[command(name = "localbox", about = "LocalBox core engine")]
pub struct Cli {
    /// Path to a TOML config file (defaults to ./config.toml if it exists)
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub run: RunArgs,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate a config.toml template
    Init(InitArgs),
    /// Validate merged configuration (config.toml + CLI overrides)
    Validate(ValidateArgs),
    /// TLS trust store operations (CA import/export/fingerprints/rotation)
    Tls(TlsArgs),
    /// Show current status (peers, shares, progress, queue depth) from the local DB
    Status(StatusArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Overwrite existing config.toml
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct ValidateArgs {}

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Print as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct TlsArgs {
    #[command(subcommand)]
    pub command: TlsCommand,
}

#[derive(Debug, Subcommand)]
pub enum TlsCommand {
    /// Ensure TLS materials exist (generate if missing) and print fingerprints
    Ensure,
    /// List trusted CA fingerprints (from tls_ca_cert_path)
    List,
    /// Print certificate SHA-256 fingerprints (leaf or CA bundle)
    Fingerprint(FingerprintArgs),
    /// Export this node's CA certificate (from tls_cert_path chain)
    ExportCa(ExportCaArgs),
    /// Import CA certificate(s) into tls_ca_cert_path (deduped by fingerprint)
    ImportCa(ImportCaArgs),
    /// Rotate this node's CA + leaf cert and optionally export the new CA
    Rotate(RotateArgs),
}

#[derive(Debug, Args)]
pub struct FingerprintArgs {
    /// Optional PEM file to fingerprint (otherwise uses configured paths)
    #[arg(long, value_name = "PATH")]
    pub file: Option<PathBuf>,

    /// Print only leaf certificate fingerprints (from tls_cert_path)
    #[arg(long)]
    pub leaf: bool,

    /// Print only CA/trust-store fingerprints (from tls_ca_cert_path)
    #[arg(long)]
    pub ca: bool,
}

#[derive(Debug, Args)]
pub struct ExportCaArgs {
    /// Output path for the exported CA certificate PEM
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,
}

#[derive(Debug, Args)]
pub struct ImportCaArgs {
    /// Input PEM file containing one or more CA certificates
    #[arg(long, value_name = "PATH")]
    pub r#in: PathBuf,
}

#[derive(Debug, Args)]
pub struct RotateArgs {
    /// Write backups alongside existing files using a .bak-<timestamp> suffix
    #[arg(long)]
    pub backup: bool,

    /// Optional path to write the newly-generated CA certificate PEM (for distribution)
    #[arg(long, value_name = "PATH")]
    pub export_ca: Option<PathBuf>,
}
#[derive(Debug, Args, Default)]
pub struct RunArgs {
    /// Instance identifier for this node
    #[arg(long)]
    pub instance_id: Option<String>,

    /// TCP listen port for peer connections
    #[arg(long)]
    pub listen_port: Option<u16>,

    /// TCP listen port for plaintext peer connections (no TLS)
    #[arg(long)]
    pub plain_listen_port: Option<u16>,

    /// UDP discovery port
    #[arg(long)]
    pub discovery_port: Option<u16>,

    /// Aggregation window in milliseconds
    #[arg(long)]
    pub aggregation_window_ms: Option<u64>,

    /// Path to the SQLite DB
    #[arg(long)]
    pub db_path: Option<PathBuf>,

    /// Path to the log file
    #[arg(long)]
    pub log_path: Option<PathBuf>,

    /// Path to TLS certificate (PEM)
    #[arg(long)]
    pub tls_cert_path: Option<PathBuf>,

    /// Path to TLS private key (PEM, PKCS8)
    #[arg(long)]
    pub tls_key_path: Option<PathBuf>,

    /// Path to CA certificate (PEM)
    #[arg(long)]
    pub tls_ca_cert_path: Option<PathBuf>,

    /// Root folder where remote/peer-owned shares are synced
    #[arg(long)]
    pub remote_share_root: Option<PathBuf>,

    /// Whether to use TLS when connecting to peers (default: true)
    #[arg(long)]
    pub use_tls_for_peers: Option<bool>,

    /// Shares to watch in the form name=path[,recursive=true|false] (repeatable)
    #[arg(
        long = "share",
        value_name = "NAME=PATH[,recursive=true|false]",
        value_parser = parse_share_arg
    )]
    pub shares: Vec<ShareCli>,
}

impl Cli {
    pub fn resolve_app_config(&self) -> Result<AppConfig> {
        self.resolve_app_config_inner(true)
    }

    pub fn resolve_app_config_allow_empty_shares(&self) -> Result<AppConfig> {
        self.resolve_app_config_inner(false)
    }

    fn resolve_app_config_inner(&self, require_shares: bool) -> Result<AppConfig> {
        let file_cfg = load_optional_file_config(self.config.as_deref())?;

        let pc_name = hostname::get()
            .unwrap_or_else(|_| "unknown-pc".into())
            .to_string_lossy()
            .into_owned();

        let instance_id = self
            .run
            .instance_id
            .clone()
            .or_else(|| file_cfg.as_ref().and_then(|c| c.instance_id.clone()))
            .unwrap_or_else(|| DEFAULT_INSTANCE_ID.to_string());

        let listen_port = self
            .run
            .listen_port
            .or_else(|| file_cfg.as_ref().and_then(|c| c.listen_port))
            .unwrap_or(DEFAULT_LISTEN_PORT);
        let plain_listen_port = self
            .run
            .plain_listen_port
            .or_else(|| file_cfg.as_ref().and_then(|c| c.plain_listen_port))
            .unwrap_or(DEFAULT_PLAIN_LISTEN_PORT);

        let discovery_port = self
            .run
            .discovery_port
            .or_else(|| file_cfg.as_ref().and_then(|c| c.discovery_port))
            .unwrap_or(DEFAULT_DISCOVERY_PORT);

        let aggregation_window_ms = self
            .run
            .aggregation_window_ms
            .or_else(|| file_cfg.as_ref().and_then(|c| c.aggregation_window_ms))
            .unwrap_or(DEFAULT_AGG_WINDOW_MS);

        let db_path = self
            .run
            .db_path
            .clone()
            .or_else(|| file_cfg.as_ref().and_then(|c| c.db_path.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DB_PATH));

        let log_path = self
            .run
            .log_path
            .clone()
            .or_else(|| file_cfg.as_ref().and_then(|c| c.log_path.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_LOG_PATH));

        let tls_cert_path = self
            .run
            .tls_cert_path
            .clone()
            .or_else(|| file_cfg.as_ref().and_then(|c| c.tls_cert_path.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_TLS_CERT_PATH));

        let tls_key_path = self
            .run
            .tls_key_path
            .clone()
            .or_else(|| file_cfg.as_ref().and_then(|c| c.tls_key_path.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_TLS_KEY_PATH));

        let tls_ca_cert_path = self
            .run
            .tls_ca_cert_path
            .clone()
            .or_else(|| file_cfg.as_ref().and_then(|c| c.tls_ca_cert_path.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_TLS_CA_CERT_PATH));

        let remote_share_root = self
            .run
            .remote_share_root
            .clone()
            .or_else(|| file_cfg.as_ref().and_then(|c| c.remote_share_root.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_REMOTE_SHARE_ROOT));

        let use_tls_for_peers = self
            .run
            .use_tls_for_peers
            .or_else(|| file_cfg.as_ref().and_then(|c| c.use_tls_for_peers))
            .unwrap_or(true);

        let tls_pinned_ca_fingerprints = file_cfg
            .as_ref()
            .and_then(|c| c.tls_pinned_ca_fingerprints.clone())
            .unwrap_or_default();

        let shares = merge_shares(
            file_cfg
                .as_ref()
                .and_then(|c| c.shares.clone())
                .unwrap_or_default(),
            self.run.shares.clone(),
        )?;

        if require_shares && shares.is_empty() {
            let config_hint = match &self.config {
                Some(p) => format!("or add shares to {}", p.display()),
                None => format!("or create {} with `localbox init`", DEFAULT_CONFIG_PATH),
            };
            return Err(anyhow!(
                "no shares configured; pass `--share NAME=PATH[,recursive=true|false]` {}",
                config_hint
            ));
        }

        Ok(AppConfig {
            pc_name,
            instance_id,
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), listen_port),
            plain_listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), plain_listen_port),
            use_tls_for_peers,
            discovery_port,
            aggregation_window_ms,
            db_path,
            log_path,
            tls_cert_path,
            tls_key_path,
            tls_ca_cert_path,
            tls_pinned_ca_fingerprints,
            remote_share_root,
            shares,
        })
    }
}

pub fn init_config_template(path: &Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        return Err(anyhow!(
            "refusing to overwrite existing config at {}; pass --force to overwrite",
            path.display()
        ));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
    }

    std::fs::write(path, default_config_template())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

pub fn validate_app_config(cfg: &AppConfig) -> Result<()> {
    validate_share_configs(&cfg.shares)?;
    validate_share_paths(&cfg.shares)?;
    validate_remote_share_root(&cfg.remote_share_root)?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ShareCli {
    pub name: String,
    pub root: PathBuf,
    pub recursive: bool,
}

impl ShareCli {
    fn into_share_config(self) -> ShareConfig {
        ShareConfig {
            name: self.name,
            root_path: self.root,
            recursive: self.recursive,
            ignore_patterns: Vec::new(),
            max_file_size_bytes: None,
        }
    }
}

impl FromStr for ShareCli {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_share_arg(s)
    }
}

fn parse_share_arg(raw: &str) -> Result<ShareCli, String> {
    let (name, remainder) = raw
        .split_once('=')
        .ok_or_else(|| "share must be NAME=PATH".to_string())?;

    if name.trim().is_empty() {
        return Err("share name cannot be empty".to_string());
    }
    if name != name.trim() {
        return Err("share name cannot have leading/trailing whitespace".to_string());
    }

    let mut path_and_opts = remainder.splitn(2, ',');
    let path = path_and_opts
        .next()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| "share path cannot be empty".to_string())?;

    let mut recursive = true;
    if let Some(opts) = path_and_opts.next() {
        for opt in opts.split(',') {
            let (key, value) = opt
                .split_once('=')
                .ok_or_else(|| format!("invalid option '{opt}', expected key=value"))?;
            match key {
                "recursive" => {
                    recursive = value
                        .parse::<bool>()
                        .map_err(|_| format!("recursive must be true or false (got {value})"))?
                }
                _ => return Err(format!("unknown share option '{key}'")),
            }
        }
    }

    Ok(ShareCli {
        name: name.to_string(),
        root: PathBuf::from(path),
        recursive,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    instance_id: Option<String>,
    listen_port: Option<u16>,
    plain_listen_port: Option<u16>,
    discovery_port: Option<u16>,
    aggregation_window_ms: Option<u64>,
    db_path: Option<PathBuf>,
    log_path: Option<PathBuf>,
    tls_cert_path: Option<PathBuf>,
    tls_key_path: Option<PathBuf>,
    tls_ca_cert_path: Option<PathBuf>,
    tls_pinned_ca_fingerprints: Option<Vec<String>>,
    use_tls_for_peers: Option<bool>,
    remote_share_root: Option<PathBuf>,
    shares: Option<Vec<FileShareConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileShareConfig {
    name: String,
    root_path: PathBuf,
    #[serde(default = "default_recursive")]
    recursive: bool,
    #[serde(default)]
    ignore_patterns: Vec<String>,
    max_file_size_bytes: Option<u64>,
}

fn default_recursive() -> bool {
    true
}

fn load_optional_file_config(explicit_path: Option<&Path>) -> Result<Option<FileConfig>> {
    if let Some(path) = explicit_path {
        let cfg = load_file_config(path)
            .with_context(|| format!("failed to read config from {}", path.display()))?;
        return Ok(Some(cfg));
    }

    let default_path = Path::new(DEFAULT_CONFIG_PATH);
    if default_path.exists() {
        let cfg = load_file_config(default_path)
            .with_context(|| format!("failed to read config from {}", default_path.display()))?;
        return Ok(Some(cfg));
    }

    Ok(None)
}

fn load_file_config(path: &Path) -> Result<FileConfig> {
    if !path.exists() {
        return Err(anyhow!(
            "config file not found at {}; run `localbox init --config {}` to generate a template",
            path.display(),
            path.display()
        ));
    }

    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let cfg: FileConfig = toml::from_str(&raw)
        .map_err(|e| anyhow!("invalid TOML in {}: {e}", path.display()))?;

    if let Some(shares) = &cfg.shares {
        validate_file_share_names_unique(shares, path)?;
    }

    Ok(cfg)
}

fn validate_file_share_names_unique(shares: &[FileShareConfig], path: &Path) -> Result<()> {
    let mut seen = HashSet::new();
    let mut dups = Vec::new();
    for s in shares {
        if !seen.insert(s.name.as_str()) {
            dups.push(s.name.clone());
        }
    }
    if !dups.is_empty() {
        dups.sort();
        dups.dedup();
        return Err(anyhow!(
            "duplicate share names in {}: {}",
            path.display(),
            dups.join(", ")
        ));
    }
    Ok(())
}

fn merge_shares(file_shares: Vec<FileShareConfig>, cli_shares: Vec<ShareCli>) -> Result<Vec<ShareConfig>> {
    let mut out: Vec<ShareConfig> = Vec::new();
    let mut idx_by_name: HashMap<String, usize> = HashMap::new();

    for s in file_shares {
        let name = s.name.trim().to_string();
        if name.is_empty() {
            return Err(anyhow!("config share name cannot be empty"));
        }
        if idx_by_name.contains_key(&name) {
            continue;
        }
        idx_by_name.insert(name.clone(), out.len());
        out.push(ShareConfig {
            name,
            root_path: s.root_path,
            recursive: s.recursive,
            ignore_patterns: s.ignore_patterns,
            max_file_size_bytes: s.max_file_size_bytes,
        });
    }

    for s in cli_shares {
        if let Some(idx) = idx_by_name.get(&s.name).copied() {
            let existing = out[idx].clone();
            out[idx] = ShareConfig {
                name: s.name,
                root_path: s.root,
                recursive: s.recursive,
                ignore_patterns: existing.ignore_patterns,
                max_file_size_bytes: existing.max_file_size_bytes,
            };
        } else {
            idx_by_name.insert(s.name.clone(), out.len());
            out.push(s.into_share_config());
        }
    }

    Ok(out)
}

fn validate_share_configs(shares: &[ShareConfig]) -> Result<()> {
    let mut seen = HashSet::new();
    let mut dups = Vec::new();

    for s in shares {
        let trimmed = s.name.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("share name cannot be empty"));
        }
        if trimmed != s.name {
            return Err(anyhow!(
                "share name '{}' has leading/trailing whitespace",
                s.name
            ));
        }
        if !seen.insert(trimmed.to_string()) {
            dups.push(trimmed.to_string());
        }
    }

    if !dups.is_empty() {
        dups.sort();
        dups.dedup();
        return Err(anyhow!("duplicate share names: {}", dups.join(", ")));
    }

    Ok(())
}

fn validate_share_paths(shares: &[ShareConfig]) -> Result<()> {
    for share in shares {
        let md = std::fs::metadata(&share.root_path).map_err(|e| {
            anyhow!(
                "share '{}' root_path '{}' is not accessible: {}",
                share.name,
                share.root_path.display(),
                e
            )
        })?;
        if !md.is_dir() {
            return Err(anyhow!(
                "share '{}' root_path '{}' is not a directory",
                share.name,
                share.root_path.display()
            ));
        }
    }
    Ok(())
}

fn validate_remote_share_root(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let md = std::fs::metadata(path).map_err(|e| {
        anyhow!(
            "remote_share_root '{}' is not accessible: {}",
            path.display(),
            e
        )
    })?;
    if md.is_file() {
        return Err(anyhow!(
            "remote_share_root '{}' must be a directory (it is a file)",
            path.display()
        ));
    }
    Ok(())
}

fn default_config_template() -> String {
    format!(
        r#"# Localbox configuration (TOML)
#
# This file is intentionally checked into .gitignore.
# `pc_name` is derived from your hostname at runtime.

instance_id = "{instance_id}"
listen_port = {listen_port}
plain_listen_port = {plain_listen_port}
discovery_port = {discovery_port}
aggregation_window_ms = {agg_ms}

db_path = "{db_path}"
log_path = "{log_path}"

tls_cert_path = "{tls_cert_path}"
tls_key_path = "{tls_key_path}"
tls_ca_cert_path = "{tls_ca_cert_path}"

remote_share_root = "{remote_share_root}"

# Optional: restrict trust to specific CA fingerprints (SHA-256 hex; spaces/colons ignored).
# tls_pinned_ca_fingerprints = [
#   "AA:BB:CC:...",
# ]

# Whether to use TLS when talking to peers (otherwise plaintext)
use_tls_for_peers = true

[[shares]]
name = "docs"
root_path = "C:/path/to/docs"
recursive = true
# ignore_patterns = ["**/.git/**", "**/*.tmp"]
# max_file_size_bytes = 1073741824 # 1 GiB
"#,
        instance_id = DEFAULT_INSTANCE_ID,
        listen_port = DEFAULT_LISTEN_PORT,
        plain_listen_port = DEFAULT_PLAIN_LISTEN_PORT,
        discovery_port = DEFAULT_DISCOVERY_PORT,
        agg_ms = DEFAULT_AGG_WINDOW_MS,
        db_path = DEFAULT_DB_PATH,
        log_path = DEFAULT_LOG_PATH,
        tls_cert_path = DEFAULT_TLS_CERT_PATH,
        tls_key_path = DEFAULT_TLS_KEY_PATH,
        tls_ca_cert_path = DEFAULT_TLS_CA_CERT_PATH,
        remote_share_root = DEFAULT_REMOTE_SHARE_ROOT
    )
}

#[cfg(test)]
mod tests {
    use super::{default_config_template, parse_share_arg, validate_app_config, Cli};
    use clap::Parser;
    use models::AppConfig;
    use std::path::PathBuf;
    use uuid::Uuid;

    #[test]
    fn parse_share_arg_basic_and_recursive() {
        let s = parse_share_arg("docs=/tmp/docs,recursive=false").unwrap();
        assert_eq!(s.name, "docs");
        assert_eq!(s.root, PathBuf::from("/tmp/docs"));
        assert!(!s.recursive);

        let s = parse_share_arg("pics=C:/pics").unwrap();
        assert_eq!(s.name, "pics");
        assert!(s.recursive);
    }

    #[test]
    fn parse_share_arg_rejects_invalid() {
        assert!(parse_share_arg("noequals").is_err());
        assert!(parse_share_arg("=C:/x").is_err());
        assert!(parse_share_arg("x=").is_err());
        assert!(parse_share_arg("x=C:/x,wat=true").is_err());
        assert!(parse_share_arg("x=C:/x,recursive=maybe").is_err());
        assert!(parse_share_arg(" x=C:/x").is_err());
    }

    #[test]
    fn cli_requires_shares_when_no_config_exists() {
        let path = std::env::temp_dir().join(format!("localbox-empty-{}.toml", Uuid::new_v4()));
        std::fs::write(&path, "\n").unwrap();

        let path_str = path.to_string_lossy().to_string();
        let cli = Cli::try_parse_from([
            "localbox".to_string(),
            "--config".to_string(),
            path_str,
        ])
        .unwrap();
        let err = cli.resolve_app_config().unwrap_err().to_string();
        assert!(err.contains("no shares configured"));
        assert!(err.contains("--share"));

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn template_is_valid_toml() {
        let tpl = default_config_template();
        let parsed: toml::Value = toml::from_str(&tpl).unwrap();
        assert!(parsed.get("shares").is_some());
    }

    #[test]
    fn validate_app_config_checks_share_paths() {
        let tmp_dir = std::env::temp_dir().join(format!("localbox-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cfg = AppConfig {
            pc_name: "pc".to_string(),
            instance_id: "i".to_string(),
            listen_addr: "0.0.0.0:5000".parse().unwrap(),
            plain_listen_addr: "0.0.0.0:5002".parse().unwrap(),
            use_tls_for_peers: true,
            discovery_port: 5001,
            aggregation_window_ms: 10,
            db_path: PathBuf::from("db"),
            log_path: PathBuf::from("log"),
            tls_cert_path: PathBuf::from("cert"),
            tls_key_path: PathBuf::from("key"),
            tls_ca_cert_path: PathBuf::from("ca"),
            tls_pinned_ca_fingerprints: Vec::new(),
            remote_share_root: PathBuf::from("remote"),
            shares: vec![models::ShareConfig {
                name: "s".to_string(),
                root_path: tmp_dir.clone(),
                recursive: true,
                ignore_patterns: Vec::new(),
                max_file_size_bytes: None,
            }],
        };
        validate_app_config(&cfg).unwrap();
        std::fs::remove_dir_all(&tmp_dir).unwrap();
    }
}
