use crate::engine::log_banner;
use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use models::{
    AppConfig, ApplicationState, BootstrapPeer, ConflictPolicy, PeerPolicy, ShareConfig,
    TransferMode,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use utilities::write_file_atomic;

const DEFAULT_INSTANCE_ID: &str = "instance-1";
const DEFAULT_LISTEN_PORT: u16 = 5000;
const DEFAULT_PLAIN_LISTEN_PORT: u16 = 5002;
const DEFAULT_DISCOVERY_PORT: u16 = 5001;
const DEFAULT_DHT_PORT: u16 = 5003;
const DEFAULT_UTP_PORT: u16 = 5004;
const DEFAULT_AGG_WINDOW_MS: u64 = 2000;
const DEFAULT_DB_PATH: &str = "sync.db";
const DEFAULT_LOG_PATH: &str = "sync.log";
const DEFAULT_TLS_CERT_PATH: &str = "certs/localbox.cert.pem";
const DEFAULT_TLS_KEY_PATH: &str = "certs/localbox.key.pem";
const DEFAULT_TLS_CA_CERT_PATH: &str = "certs/ca.cert.pem";
const DEFAULT_REMOTE_SHARE_ROOT: &str = "remote-shares";
const DEFAULT_CONTROL_SOCKET: &str = "localbox.sock";
const DEFAULT_CA_DIR: &str = "ca";
const DEFAULT_CA_NAME: &str = "localbox-network-ca";
pub const DEFAULT_CONFIG_PATH: &str = "config.toml";

#[derive(Debug, Parser)]
#[command(name = "localbox", about = "LocalBox Core Engine", version = env!("CARGO_PKG_VERSION"))]
pub struct Cli {
    /// Path to a TOML config file (defaults to ./config.toml if it exists)
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the LocalBox engine with the provided overrides
    Run(RunArgs),
    /// Attach an interactive shell to a running daemon (or use `run --interactive`)
    Shell(ShellArgs),
    /// Alias for shell
    Interactive(ShellArgs),
    /// Stop a running daemon via the control plane (`Shutdown`)
    Stop(StopArgs),
    /// Manually push share changes to peers
    Push(PushArgs),
    /// Request/pull share changes from a peer
    Pull(PullArgs),
    /// Alias for pull (send TransferRequest)
    Request(PullArgs),
    /// Accept or decline a pending inbound transfer request
    Reply(ReplyArgs),
    /// List transfer intents (outbox)
    Intents(IntentsArgs),
    /// Chat with peers / share threads
    Chat(ChatArgs),
    /// Generate a config.toml template
    Init(InitArgs),
    /// Validate merged configuration (config.toml + CLI overrides)
    Validate(ValidateArgs),
    /// Re-hash files on disk and compare to the stored metadata
    Audit(AuditArgs),
    /// Watch metrics and emit alerts
    Monitor(MonitorArgs),
    /// TLS trust store operations (CA import/export/fingerprints/rotation)
    Tls(TlsArgs),
    /// Shared network CA: create a root, sign node certificates, install them
    Ca(CaArgs),
    /// Join a network by enrolling with a token (no files to copy)
    Enroll(EnrollArgs),
    /// Create or accept signed bootstrap invites
    Bootstrap(BootstrapArgs),
    /// Show current status (peers, shares, progress, queue depth) from the local DB
    Status(StatusArgs),
    /// List / quarantine / unquarantine peers
    Peer(PeerArgs),
    /// List / add local shares on a running node (control plane)
    Share(ShareArgs),
    /// Get / set / list / unset settings (DB overrides config.toml)
    Config(ConfigArgs),
}

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCliCommand,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCliCommand {
    /// List effective settings and whether each is saved in the DB
    List {
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Show one setting
    Get {
        key: String,
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Set a setting (persisted in DB; overrides config.toml)
    Set {
        key: String,
        value: String,
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Remove a DB-saved setting (fall back to config.toml / defaults)
    Unset {
        key: String,
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
pub struct ShareArgs {
    #[command(subcommand)]
    pub command: ShareCliCommand,
}

#[derive(Debug, Subcommand)]
pub enum ShareCliCommand {
    /// List local shares from the running node's DB registry
    List {
        /// Control socket path (defaults to config / localbox.sock)
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Add a local share to a running node (DB + watcher + config.toml)
    Add {
        /// Share name
        #[arg(long)]
        name: String,
        /// Directory to share
        #[arg(long, value_name = "DIR")]
        path: PathBuf,
        /// Watch recursively (default: true)
        #[arg(long, default_value_t = true)]
        recursive: bool,
        /// Control socket path (defaults to config / localbox.sock)
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
pub struct PeerArgs {
    #[command(subcommand)]
    pub command: PeerCliCommand,
}

#[derive(Debug, Subcommand)]
pub enum PeerCliCommand {
    /// List known peers from the local DB
    List,
    /// Quarantine a peer (refuse connections; persist in DB + config.toml)
    Quarantine {
        /// Peer key (`pc_name` or `pc_name@instance_id`)
        peer: String,
    },
    /// Remove a peer from quarantine
    Unquarantine {
        /// Peer key (`pc_name` or `pc_name@instance_id`)
        peer: String,
    },
}

#[derive(Debug, Args)]
pub struct ShellArgs {
    /// Control socket path (defaults to config / localbox.sock)
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct StopArgs {
    /// Control socket path (defaults to config / localbox.sock)
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct PushArgs {
    #[arg(long)]
    pub share: String,
    #[arg(long)]
    pub peer: Option<String>,
    #[arg(long)]
    pub path: Option<String>,
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct PullArgs {
    #[arg(long)]
    pub share: String,
    #[arg(long)]
    pub peer: String,
    #[arg(long)]
    pub path: Option<String>,
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ReplyArgs {
    #[arg(long)]
    pub id: String,
    /// accept or decline
    pub action: String,
    #[arg(long)]
    pub reason: Option<String>,
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct IntentsArgs {
    /// Include completed (acked/failed/declined) intents
    #[arg(long)]
    pub all: bool,
    #[arg(long)]
    pub limit: Option<usize>,
    /// Show a single intent by id
    #[arg(long)]
    pub id: Option<String>,
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ChatArgs {
    #[command(subcommand)]
    pub command: ChatCommand,
}

#[derive(Debug, Subcommand)]
pub enum ChatCommand {
    Send(ChatSendArgs),
    Inbox(ChatSocketArgs),
    Threads(ChatSocketArgs),
    Show(ChatShowArgs),
    Read(ChatReadArgs),
}

#[derive(Debug, Args)]
pub struct ChatSocketArgs {
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ChatSendArgs {
    #[arg(long)]
    pub peer: Option<String>,
    #[arg(long)]
    pub share: Option<String>,
    #[arg(long)]
    pub thread: Option<String>,
    #[arg(long)]
    pub message: Option<String>,
    #[arg(long)]
    pub file: Option<String>,
    #[arg(long)]
    pub share_dest: Option<String>,
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ChatShowArgs {
    #[arg(long)]
    pub thread: String,
    #[arg(long)]
    pub limit: Option<usize>,
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ChatReadArgs {
    #[arg(long)]
    pub thread: String,
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
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
pub struct AuditArgs {
    /// Limit verification to a single share name
    #[arg(long, value_name = "NAME")]
    pub share: Option<String>,
}

#[derive(Debug, Args)]
pub struct MonitorArgs {
    /// Poll interval in seconds
    #[arg(long, default_value_t = 10)]
    pub interval_secs: u64,

    /// Optional maximum iterations before exiting (default: run forever)
    #[arg(long)]
    pub iterations: Option<u32>,

    /// Queue depth threshold that triggers an alert
    #[arg(long, default_value_t = 100)]
    pub queue_threshold: u64,

    /// Consider peers stale if last_seen is older than this many seconds
    #[arg(long, default_value_t = 300)]
    pub stale_peer_seconds: i64,

    /// Emit JSON snapshots instead of human-readable logs
    #[arg(long)]
    pub json: bool,

    /// Exit with an error as soon as an alert fires
    #[arg(long)]
    pub exit_on_alert: bool,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Print as JSON
    #[arg(long)]
    pub json: bool,

    #[command(subcommand)]
    pub section: Option<StatusSection>,
}

#[derive(Debug, Subcommand, Clone, Copy, PartialEq, Eq)]
pub enum StatusSection {
    /// Show DB status
    Db,
    /// Show outbound queue status
    Queue,
    /// Show metrics
    Metrics,
    /// Show peers
    Peers,
    /// Show shares
    Shares,
    /// Show peer progress
    PeerProgress,
}

#[derive(Debug, Args)]
pub struct BootstrapArgs {
    #[command(subcommand)]
    pub command: BootstrapCommand,
}

#[derive(Debug, Subcommand)]
pub enum BootstrapCommand {
    /// Issue a signed invite bundle for a peer
    Invite(BootstrapInviteArgs),
    /// Accept and verify an invite bundle
    Accept(BootstrapAcceptArgs),
    /// Accept an invite and immediately generate a response bundle
    Join(BootstrapJoinArgs),
}

#[derive(Debug, Args)]
pub struct BootstrapInviteArgs {
    /// The peer name to embed in the invite
    #[arg(long)]
    pub peer: String,

    /// Output path for the invite bundle (JSON)
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,

    /// Overwrite any existing invite at --out
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct BootstrapAcceptArgs {
    /// Path to the invite bundle to import
    #[arg(long, value_name = "PATH")]
    pub file: PathBuf,

    /// Allow updating config/trust even if entries already exist
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct BootstrapJoinArgs {
    /// The peer name to embed in the response invite
    #[arg(long)]
    pub peer: String,

    /// Output path for the new invite bundle to send back
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,

    /// Optional incoming invite file to accept before generating the response
    #[arg(long, value_name = "PATH")]
    pub incoming: Option<PathBuf>,

    /// Overwrite files / update config entries if they already exist
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct CaArgs {
    #[command(subcommand)]
    pub command: CaCommand,
}

#[derive(Debug, Subcommand)]
pub enum CaCommand {
    /// Create a network root CA (run once, on the machine that will issue certs)
    Init(CaInitArgs),
    /// Print the root CA's fingerprint and validity
    Show(CaShowArgs),
    /// Generate a private key + CSR on this machine (the key never leaves it)
    Request(CaRequestArgs),
    /// Sign a CSR as a named node, using the root CA
    Sign(CaSignArgs),
    /// Install a signed chain + key into this node's configured TLS paths
    Install(CaInstallArgs),
    /// Mint a single-use enrollment token for one node
    Token(CaTokenArgs),
    /// Serve enrollment requests so new machines can enroll with a token
    Serve(CaServeArgs),
    /// INSECURE: issue one certificate for every node to share (no per-node identity)
    ProvisionShared(CaProvisionSharedArgs),
}

#[derive(Debug, Args)]
pub struct CaProvisionSharedArgs {
    /// Directory holding the CA certificate and key
    #[arg(long, value_name = "DIR", default_value = DEFAULT_CA_DIR)]
    pub dir: PathBuf,

    /// Directory to write the shared bundle into
    #[arg(long, value_name = "DIR")]
    pub out_dir: PathBuf,

    /// Name to put on the shared certificate
    #[arg(long, default_value = "localbox-shared")]
    pub name: String,

    /// Certificate lifetime (e.g. 365d, 24h, 30m, 90s); bare numbers mean days
    #[arg(
        long,
        visible_alias = "days",
        value_name = "DURATION",
        default_value_t = tls::DEFAULT_LEAF_VALIDITY
    )]
    pub lifetime: tls::CertLifetime,

    /// Overwrite existing files in the output directory
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct CaTokenArgs {
    /// Directory holding the CA certificate and key
    #[arg(long, value_name = "DIR", default_value = DEFAULT_CA_DIR)]
    pub dir: PathBuf,

    /// Node name this token authorizes (must match that machine's hostname)
    #[arg(long)]
    pub name: String,

    /// How long the token stays valid, in seconds
    #[arg(long, default_value_t = tls::DEFAULT_TOKEN_TTL_SECS)]
    pub ttl_secs: i64,
}

#[derive(Debug, Args)]
pub struct CaServeArgs {
    /// Directory holding the CA certificate and key
    #[arg(long, value_name = "DIR", default_value = DEFAULT_CA_DIR)]
    pub dir: PathBuf,

    /// Address to listen on for enrollment requests
    #[arg(long, value_name = "ADDR")]
    pub listen: Option<SocketAddr>,

    /// Lifetime for certificates issued through enrollment (e.g. 365d, 24h, 30m, 90s)
    #[arg(
        long,
        visible_alias = "days",
        value_name = "DURATION",
        default_value_t = tls::DEFAULT_LEAF_VALIDITY
    )]
    pub lifetime: tls::CertLifetime,
}

#[derive(Debug, Args)]
pub struct EnrollArgs {
    /// Enrollment server address, as host:port
    #[arg(long, value_name = "HOST:PORT")]
    pub server: String,

    /// The enrollment token issued by `localbox ca token`
    #[arg(long)]
    pub token: String,

    /// Also pin the network root's fingerprint in config.toml (recommended)
    #[arg(long)]
    pub pin: bool,

    /// Install even if the issued name differs from this machine's hostname
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct CaInitArgs {
    /// Directory to hold the CA certificate and key
    #[arg(long, value_name = "DIR", default_value = DEFAULT_CA_DIR)]
    pub dir: PathBuf,

    /// Common name for the root certificate
    #[arg(long, default_value = DEFAULT_CA_NAME)]
    pub name: String,

    /// Root certificate lifetime (e.g. 3650d, 24h, 30m, 90s); bare numbers mean days
    #[arg(
        long,
        visible_alias = "days",
        value_name = "DURATION",
        default_value_t = tls::DEFAULT_CA_VALIDITY
    )]
    pub lifetime: tls::CertLifetime,

    /// Replace an existing CA (invalidates every certificate it has issued)
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct CaShowArgs {
    /// Directory holding the CA certificate
    #[arg(long, value_name = "DIR", default_value = DEFAULT_CA_DIR)]
    pub dir: PathBuf,
}

#[derive(Debug, Args)]
pub struct CaRequestArgs {
    /// Node name to request a certificate for (defaults to this machine's hostname)
    #[arg(long)]
    pub name: Option<String>,

    /// Where to write the certificate signing request
    #[arg(long, value_name = "PATH", default_value = "request.csr.pem")]
    pub csr_out: PathBuf,

    /// Where to write the newly generated private key
    #[arg(long, value_name = "PATH", default_value = "request.key.pem")]
    pub key_out: PathBuf,

    /// Overwrite existing output files
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct CaSignArgs {
    /// Directory holding the CA certificate and key
    #[arg(long, value_name = "DIR", default_value = DEFAULT_CA_DIR)]
    pub dir: PathBuf,

    /// Path to the certificate signing request to sign
    #[arg(long, value_name = "PATH")]
    pub csr: PathBuf,

    /// Node name to issue the certificate for (the CSR's own claim is ignored)
    #[arg(long)]
    pub name: String,

    /// Where to write the signed leaf + CA chain
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,

    /// Certificate lifetime (e.g. 365d, 24h, 30m, 90s); bare numbers mean days
    #[arg(
        long,
        visible_alias = "days",
        value_name = "DURATION",
        default_value_t = tls::DEFAULT_LEAF_VALIDITY
    )]
    pub lifetime: tls::CertLifetime,

    /// Overwrite an existing file at --out
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct CaInstallArgs {
    /// Signed certificate chain (leaf followed by the issuing CA)
    #[arg(long, value_name = "PATH")]
    pub chain: PathBuf,

    /// Private key matching the leaf in --chain
    #[arg(long, value_name = "PATH")]
    pub key: PathBuf,

    /// Also pin the root CA's fingerprint in config.toml
    #[arg(long)]
    pub pin: bool,
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
    /// Bundle TLS materials (cert/key/CA/fingerprints) for peer provisioning
    Provision(ProvisionArgs),
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

#[derive(Debug, Args)]
pub struct ProvisionArgs {
    /// Directory to write the exported bundle (must exist or be creatable)
    #[arg(long, value_name = "DIR")]
    pub out_dir: PathBuf,

    /// Overwrite existing files in the output directory
    #[arg(long)]
    pub force: bool,

    /// Optional filename for an additional CA export (helpful for distribution)
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

    /// Node name override (defaults to hostname)
    #[arg(long)]
    pub pc_name: Option<String>,

    /// UDP port for private BEP5 DHT
    #[arg(long)]
    pub dht_port: Option<u16>,

    /// UDP port for uTP peer sessions
    #[arg(long)]
    pub utp_port: Option<u16>,

    /// Enable private BEP5 DHT (implied when bootstrap_peers are configured)
    #[arg(long)]
    pub enable_dht: Option<bool>,

    /// Enable TLS-over-uTP listen/dial (LAN UDP discovery always stays on)
    #[arg(long)]
    pub enable_utp: Option<bool>,

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

    /// Application state (mirror-only, host-only, mirrorhost, zombie)
    #[arg(long, value_enum)]
    pub app_state: Option<AppStateArg>,

    /// Run engine with an in-process interactive shell (ephemeral host)
    #[arg(long)]
    pub interactive: bool,

    /// Unix domain socket path for the control plane
    #[arg(long, value_name = "PATH")]
    pub control_socket: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AppStateArg {
    #[value(name = "mirror-only", alias = "mirror_only", alias = "mirroronly")]
    MirrorOnly,
    #[value(name = "host-only", alias = "host_only", alias = "hostonly")]
    HostOnly,
    #[value(name = "mirrorhost", alias = "mirror-host", alias = "mirror_host")]
    MirrorHost,
    #[value(name = "zombie")]
    Zombie,
}

impl From<AppStateArg> for ApplicationState {
    fn from(arg: AppStateArg) -> Self {
        match arg {
            AppStateArg::MirrorOnly => ApplicationState::MirrorOnly,
            AppStateArg::HostOnly => ApplicationState::HostOnly,
            AppStateArg::MirrorHost => ApplicationState::MirrorHost,
            AppStateArg::Zombie => ApplicationState::Zombie,
        }
    }
}

/// Resolve config.toml + DB settings + defaults (no CLI RunArgs).
pub fn resolve_effective_config(config_path: Option<&Path>) -> Result<AppConfig> {
    let cli = Cli {
        config: config_path.map(|p| p.to_path_buf()),
        command: Command::Validate(ValidateArgs {}),
    };
    cli.resolve_app_config()
}

impl Cli {
    pub fn resolve_app_config(&self) -> Result<AppConfig> {
        self.resolve_app_config_inner(None)
    }

    /// Shares are optional at startup; kept as an alias of [`Self::resolve_app_config`].
    pub fn resolve_app_config_allow_empty_shares(&self) -> Result<AppConfig> {
        self.resolve_app_config()
    }

    pub fn resolve_app_config_with_overrides(&self, overrides: &RunArgs) -> Result<AppConfig> {
        self.resolve_app_config_inner(Some(overrides))
    }

    /// Shares are optional at startup; kept as an alias of [`Self::resolve_app_config_with_overrides`].
    pub fn resolve_app_config_allow_empty_shares_with_overrides(
        &self,
        overrides: &RunArgs,
    ) -> Result<AppConfig> {
        self.resolve_app_config_with_overrides(overrides)
    }

    fn resolve_app_config_inner(&self, overrides: Option<&RunArgs>) -> Result<AppConfig> {
        let file_cfg = load_optional_file_config(self.config.as_deref())?;
        let default_run = RunArgs::default();
        let cli_run = match &self.command {
            Command::Run(r) => Some(r),
            _ => None,
        };
        let run = overrides.or(cli_run).unwrap_or(&default_run);

        let pc_name = run
            .pc_name
            .clone()
            .or_else(|| file_cfg.as_ref().and_then(|c| c.pc_name.clone()))
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| {
                hostname::get()
                    .unwrap_or_else(|_| "unknown-pc".into())
                    .to_string_lossy()
                    .into_owned()
            });

        let instance_id = run
            .instance_id
            .clone()
            .or_else(|| file_cfg.as_ref().and_then(|c| c.instance_id.clone()))
            .unwrap_or_else(|| DEFAULT_INSTANCE_ID.to_string());

        let display_name = file_cfg
            .as_ref()
            .and_then(|c| c.display_name.clone())
            .unwrap_or_default();

        let listen_port = run
            .listen_port
            .or_else(|| file_cfg.as_ref().and_then(|c| c.listen_port))
            .unwrap_or(DEFAULT_LISTEN_PORT);
        let plain_listen_port = run
            .plain_listen_port
            .or_else(|| file_cfg.as_ref().and_then(|c| c.plain_listen_port))
            .unwrap_or(DEFAULT_PLAIN_LISTEN_PORT);

        let discovery_port = run
            .discovery_port
            .or_else(|| file_cfg.as_ref().and_then(|c| c.discovery_port))
            .unwrap_or(DEFAULT_DISCOVERY_PORT);
        let discovery_send_ports = file_cfg
            .as_ref()
            .and_then(|c| c.discovery_send_ports.clone())
            .unwrap_or_default();

        let dht_port = run
            .dht_port
            .or_else(|| file_cfg.as_ref().and_then(|c| c.dht_port))
            .unwrap_or(DEFAULT_DHT_PORT);
        let utp_port = run
            .utp_port
            .or_else(|| file_cfg.as_ref().and_then(|c| c.utp_port))
            .unwrap_or(DEFAULT_UTP_PORT);
        let bootstrap_peers = file_cfg
            .as_ref()
            .and_then(|c| c.bootstrap_peers.clone())
            .unwrap_or_default();
        let enable_dht = run
            .enable_dht
            .or_else(|| file_cfg.as_ref().and_then(|c| c.enable_dht))
            .unwrap_or(!bootstrap_peers.is_empty());
        let enable_utp = run
            .enable_utp
            .or_else(|| file_cfg.as_ref().and_then(|c| c.enable_utp))
            .unwrap_or(false);

        let aggregation_window_ms = run
            .aggregation_window_ms
            .or_else(|| file_cfg.as_ref().and_then(|c| c.aggregation_window_ms))
            .unwrap_or(DEFAULT_AGG_WINDOW_MS);

        let db_path = run
            .db_path
            .clone()
            .or_else(|| file_cfg.as_ref().and_then(|c| c.db_path.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DB_PATH));

        let log_path = run
            .log_path
            .clone()
            .or_else(|| file_cfg.as_ref().and_then(|c| c.log_path.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_LOG_PATH));

        let tls_cert_path = run
            .tls_cert_path
            .clone()
            .or_else(|| file_cfg.as_ref().and_then(|c| c.tls_cert_path.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_TLS_CERT_PATH));

        let tls_key_path = run
            .tls_key_path
            .clone()
            .or_else(|| file_cfg.as_ref().and_then(|c| c.tls_key_path.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_TLS_KEY_PATH));

        let tls_ca_cert_path = run
            .tls_ca_cert_path
            .clone()
            .or_else(|| file_cfg.as_ref().and_then(|c| c.tls_ca_cert_path.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_TLS_CA_CERT_PATH));

        let remote_share_root = run
            .remote_share_root
            .clone()
            .or_else(|| file_cfg.as_ref().and_then(|c| c.remote_share_root.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_REMOTE_SHARE_ROOT));

        let use_tls_for_peers = run
            .use_tls_for_peers
            .or_else(|| file_cfg.as_ref().and_then(|c| c.use_tls_for_peers))
            .unwrap_or(true);

        let app_state = run
            .app_state
            .map(ApplicationState::from)
            .or_else(|| file_cfg.as_ref().and_then(|c| c.app_state))
            .unwrap_or_default();

        let tls_pinned_ca_fingerprints = file_cfg
            .as_ref()
            .and_then(|c| c.tls_pinned_ca_fingerprints.clone())
            .unwrap_or_default();
        let tls_peer_fingerprints = file_cfg
            .as_ref()
            .and_then(|c| c.tls_peer_fingerprints.clone())
            .unwrap_or_default();
        let tls_insecure_shared_cert = file_cfg
            .as_ref()
            .and_then(|c| c.tls_insecure_shared_cert)
            .unwrap_or(false);

        let shares = merge_shares(
            file_cfg
                .as_ref()
                .and_then(|c| c.shares.clone())
                .unwrap_or_default(),
            run.shares.clone(),
        )?;

        let request_handling = file_cfg
            .as_ref()
            .and_then(|c| c.request_handling)
            .unwrap_or_default();
        let peer_policies = file_cfg
            .as_ref()
            .and_then(|c| c.peer_policies.clone())
            .unwrap_or_default();
        let quarantined_peers = file_cfg
            .as_ref()
            .and_then(|c| c.quarantined_peers.clone())
            .unwrap_or_default();
        let control_socket = run
            .control_socket
            .clone()
            .or_else(|| file_cfg.as_ref().and_then(|c| c.control_socket.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONTROL_SOCKET));

        let mut cfg = AppConfig {
            pc_name,
            instance_id,
            display_name,
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), listen_port),
            plain_listen_addr: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                plain_listen_port,
            ),
            use_tls_for_peers,
            discovery_port,
            discovery_send_ports,
            dht_port,
            utp_port,
            enable_dht,
            enable_utp,
            bootstrap_peers,
            aggregation_window_ms,
            db_path,
            log_path,
            tls_cert_path,
            tls_key_path,
            tls_ca_cert_path,
            tls_pinned_ca_fingerprints,
            tls_peer_fingerprints,
            tls_insecure_shared_cert,
            remote_share_root,
            shares,
            app_state,
            request_handling,
            peer_policies,
            quarantined_peers,
            control_socket,
        };

        // Resolution: defaults/file → DB saved → CLI RunArgs (already applied above).
        // Re-apply DB under CLI so persisted overrides beat config.toml.
        if cfg.db_path.exists() {
            if let Ok(db) = db::Db::open(&cfg.db_path) {
                if let Ok(settings) = db.list_settings() {
                    let run = run;
                    let _ = crate::settings::apply_db_settings_filtered(
                        &mut cfg,
                        &settings,
                        |key| cli_overrides_key(run, key),
                    );
                }
            }
        }

        Ok(cfg)
    }
}

/// Whether a `run` CLI flag already set this settings key (CLI wins over DB).
fn cli_overrides_key(run: &RunArgs, key: &str) -> bool {
    match key {
        "instance_id" => run.instance_id.is_some(),
        "listen_port" => run.listen_port.is_some(),
        "plain_listen_port" => run.plain_listen_port.is_some(),
        "discovery_port" => run.discovery_port.is_some(),
        "pc_name" => run.pc_name.is_some(),
        "discovery_send_ports" => false,
        "dht_port" => run.dht_port.is_some(),
        "utp_port" => run.utp_port.is_some(),
        "enable_dht" => run.enable_dht.is_some(),
        "enable_utp" => run.enable_utp.is_some(),
        "aggregation_window_ms" => run.aggregation_window_ms.is_some(),
        "log_path" => run.log_path.is_some(),
        "tls_cert_path" => run.tls_cert_path.is_some(),
        "tls_key_path" => run.tls_key_path.is_some(),
        "tls_ca_cert_path" => run.tls_ca_cert_path.is_some(),
        "use_tls_for_peers" => run.use_tls_for_peers.is_some(),
        "remote_share_root" => run.remote_share_root.is_some(),
        "app_state" => run.app_state.is_some(),
        "control_socket" => run.control_socket.is_some(),
        // No dedicated RunArgs; DB may always overlay file for these:
        "tls_pinned_ca_fingerprints"
        | "tls_peer_fingerprints"
        | "tls_insecure_shared_cert"
        | "request_handling"
        | "peer_policies"
        | "quarantined_peers"
        | "bootstrap_peers" => false,
        _ => false,
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

/// Upsert a `[[shares]]` entry in a TOML config file.
/// Returns `true` if the file was modified.
pub fn add_share_to_config(
    config_path: &Path,
    name: &str,
    root_path: &Path,
    recursive: bool,
) -> Result<bool> {
    let mut doc: toml::Value = if config_path.exists() {
        toml::from_str(
            &std::fs::read_to_string(config_path)
                .with_context(|| format!("failed to read {}", config_path.display()))?,
        )
        .with_context(|| format!("failed to parse {}", config_path.display()))?
    } else {
        toml::Value::Table(toml::map::Map::new())
    };
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow!("config {} is not a table", config_path.display()))?;
    let entry = table
        .entry("shares")
        .or_insert_with(|| toml::Value::Array(Vec::new()));
    let arr = entry
        .as_array_mut()
        .ok_or_else(|| anyhow!("shares must be an array of tables"))?;

    let root_s = root_path.to_string_lossy().to_string();
    let mut changed = false;
    let mut found = false;
    for item in arr.iter_mut() {
        let Some(t) = item.as_table_mut() else {
            continue;
        };
        if t.get("name").and_then(|v| v.as_str()) != Some(name) {
            continue;
        }
        found = true;
        if t.get("root_path").and_then(|v| v.as_str()) != Some(root_s.as_str()) {
            t.insert("root_path".into(), toml::Value::String(root_s.clone()));
            changed = true;
        }
        let prev_rec = t.get("recursive").and_then(|v| v.as_bool()).unwrap_or(true);
        if prev_rec != recursive {
            t.insert("recursive".into(), toml::Value::Boolean(recursive));
            changed = true;
        }
        break;
    }
    if !found {
        let mut share = toml::map::Map::new();
        share.insert("name".into(), toml::Value::String(name.to_string()));
        share.insert("root_path".into(), toml::Value::String(root_s));
        share.insert("recursive".into(), toml::Value::Boolean(recursive));
        arr.push(toml::Value::Table(share));
        changed = true;
    }

    if !changed {
        return Ok(false);
    }
    if let Some(parent) = config_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
    }
    let updated = toml::to_string_pretty(&doc)?;
    write_file_atomic(config_path, updated.as_bytes())
        .with_context(|| format!("failed to write {}", config_path.display()))?;
    Ok(true)
}

/// Add or remove a peer string in `quarantined_peers` in a TOML config file.
/// Returns `true` if the file was modified.
pub fn set_quarantined_peer_in_config(
    config_path: &Path,
    peer: &str,
    quarantined: bool,
) -> Result<bool> {
    let mut doc: toml::Value = if config_path.exists() {
        toml::from_str(
            &std::fs::read_to_string(config_path)
                .with_context(|| format!("failed to read {}", config_path.display()))?,
        )
        .with_context(|| format!("failed to parse {}", config_path.display()))?
    } else {
        toml::Value::Table(toml::map::Map::new())
    };
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow!("config {} is not a table", config_path.display()))?;
    let entry = table
        .entry("quarantined_peers")
        .or_insert_with(|| toml::Value::Array(Vec::new()));
    let arr = entry
        .as_array_mut()
        .ok_or_else(|| anyhow!("quarantined_peers must be an array"))?;

    let already_present = arr.iter().any(|v| v.as_str() == Some(peer));
    let changed = if quarantined {
        if already_present {
            false
        } else {
            arr.push(toml::Value::String(peer.to_string()));
            true
        }
    } else if already_present {
        arr.retain(|v| v.as_str() != Some(peer));
        true
    } else {
        false
    };

    if !changed {
        return Ok(false);
    }
    let updated = toml::to_string_pretty(&doc)?;
    write_file_atomic(config_path, updated.as_bytes())
        .with_context(|| format!("failed to write {}", config_path.display()))?;
    Ok(true)
}

pub fn validate_app_config(cfg: &AppConfig) -> Result<()> {
    validate_share_configs(&cfg.shares)?;
    if cfg.app_state.can_share() {
        validate_share_paths(&cfg.shares)?;
    }
    if cfg.app_state.can_host_remote() {
        validate_remote_share_root(&cfg.remote_share_root)?;
    }
    validate_tls_peer_fingerprints(&cfg.tls_peer_fingerprints)?;
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
            sync_allow: Vec::new(),
            max_file_size_bytes: None,
            sync: Default::default(),
            pull: Default::default(),
            request_handling: None,
            conflict: ConflictPolicy::LastWriteWins,
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
    /// Optional override for the node name (defaults to hostname).
    pc_name: Option<String>,
    instance_id: Option<String>,
    /// Optional human-facing label advertised to peers.
    display_name: Option<String>,
    listen_port: Option<u16>,
    plain_listen_port: Option<u16>,
    discovery_port: Option<u16>,
    /// Extra discovery UDP ports to fan out DISCOVER packets to.
    #[serde(default)]
    discovery_send_ports: Option<Vec<u16>>,
    dht_port: Option<u16>,
    utp_port: Option<u16>,
    enable_dht: Option<bool>,
    enable_utp: Option<bool>,
    #[serde(default)]
    bootstrap_peers: Option<Vec<BootstrapPeer>>,
    aggregation_window_ms: Option<u64>,
    db_path: Option<PathBuf>,
    log_path: Option<PathBuf>,
    tls_cert_path: Option<PathBuf>,
    tls_key_path: Option<PathBuf>,
    tls_ca_cert_path: Option<PathBuf>,
    tls_pinned_ca_fingerprints: Option<Vec<String>>,
    tls_peer_fingerprints: Option<HashMap<String, Vec<String>>>,
    tls_insecure_shared_cert: Option<bool>,
    use_tls_for_peers: Option<bool>,
    remote_share_root: Option<PathBuf>,
    shares: Option<Vec<FileShareConfig>>,
    app_state: Option<ApplicationState>,
    #[serde(default)]
    request_handling: Option<TransferMode>,
    #[serde(default)]
    peer_policies: Option<Vec<PeerPolicy>>,
    #[serde(default)]
    quarantined_peers: Option<Vec<String>>,
    control_socket: Option<PathBuf>,
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
    #[serde(default)]
    sync_allow: Vec<String>,
    max_file_size_bytes: Option<u64>,
    /// Gates journal sync (SyncCatchup), not manual push.
    /// `push` is the pre-v7 spelling of this key.
    #[serde(default, alias = "push")]
    sync: TransferMode,
    #[serde(default)]
    pull: TransferMode,
    #[serde(default)]
    request_handling: Option<TransferMode>,
    #[serde(default)]
    conflict: ConflictPolicy,
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
    log_banner();

    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let cfg: FileConfig =
        toml::from_str(&raw).map_err(|e| anyhow!("invalid TOML in {}: {e}", path.display()))?;

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

fn merge_shares(
    file_shares: Vec<FileShareConfig>,
    cli_shares: Vec<ShareCli>,
) -> Result<Vec<ShareConfig>> {
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
            sync_allow: s.sync_allow,
            max_file_size_bytes: s.max_file_size_bytes,
            sync: s.sync,
            pull: s.pull,
            request_handling: s.request_handling,
            conflict: s.conflict,
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
                sync_allow: existing.sync_allow,
                max_file_size_bytes: existing.max_file_size_bytes,
                sync: existing.sync,
                pull: existing.pull,
                request_handling: existing.request_handling,
                conflict: existing.conflict,
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

fn validate_tls_peer_fingerprints(map: &HashMap<String, Vec<String>>) -> Result<()> {
    for (peer, fps) in map {
        let trimmed = peer.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("tls_peer_fingerprints keys cannot be empty"));
        }
        if trimmed != peer {
            return Err(anyhow!(
                "tls_peer_fingerprints key '{}' has surrounding whitespace",
                peer
            ));
        }
        if fps.is_empty() {
            return Err(anyhow!(
                "tls_peer_fingerprints entry for '{}' must contain at least one fingerprint",
                peer
            ));
        }
        for fp in fps {
            let normalized = fp.trim();
            if normalized.is_empty() {
                return Err(anyhow!(
                    "tls_peer_fingerprints entry for '{}' contains an empty fingerprint",
                    peer
                ));
            }
            if !normalized
                .chars()
                .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | ' '))
            {
                return Err(anyhow!(
                    "tls_peer_fingerprints value '{}' for '{}' must be hex with optional ':' or spaces",
                    fp,
                    peer
                ));
            }
        }
    }
    Ok(())
}

fn default_config_template() -> String {
    format!(
        r#"# Localbox configuration (TOML)
#
# This file is intentionally checked into .gitignore.
# `pc_name` defaults to your hostname; override for dual local instances.
# pc_name = "alice"

instance_id = "{instance_id}"
# Optional label advertised to peers (defaults to hostname / pc_name).
# display_name = "Living Room"
listen_port = {listen_port}
plain_listen_port = {plain_listen_port}
discovery_port = {discovery_port}
# Extra ports to fan out DISCOVER packets to (same-host dual instances).
# discovery_send_ports = [5001, 6001]
# LAN UDP discovery (discovery_port) always runs.
# Optional WAN stack — both default off; enable independently as needed.
dht_port = {dht_port}
utp_port = {utp_port}
enable_dht = false
enable_utp = false

# Private BEP5 DHT bootstrap mesh (do not list public Mainline routers).
# Setting [[bootstrap_peers]] also implies enable_dht unless you set enable_dht = false.
# [[bootstrap_peers]]
# addr = "bootstrap.example.com:5003"
# session_addr = "bootstrap.example.com:5000"
# pc_name = "home-server"

aggregation_window_ms = {agg_ms}

# Application state: mirror_only, host_only, mirrorhost, zombie
app_state = "mirrorhost"

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

# Optional: pin individual peer leaf certificates (per pc_name).
# [tls_peer_fingerprints]
# "workstation-1" = [
#   "11:22:33:...",
# ]

# INSECURE. Lets every node share one common certificate instead of holding its
# own. Peers can then no longer tell each other apart -- anyone with the shared
# bundle can act as any node -- and such connections are recorded as insecure.
# Only turn this on if convenience genuinely outweighs peer identity for you.
# tls_insecure_shared_cert = false

# Whether to use TLS when talking to peers (otherwise plaintext)
use_tls_for_peers = true

# How inbound TransferRequest messages are handled: "manual" | "auto"
request_handling = "manual"

# Local control socket for `localbox shell` / dead CLI commands
control_socket = "{control_socket}"

# Optional per-peer transfer overrides / ACLs:
# [[peer_policies]]
# peer = "workstation-b"
# share = "docs"
# sync = "auto"
# pull = "manual"
# allow_push = true       # accept inbound file data from peer
# allow_pull = true       # fulfill their TransferRequest
# allow_request = true    # we may pull/request from them
# sync_allow = ["public/**"]
# conflict = "keep_both"
# quarantined_peers = ["compromised-host"]

# Shares are optional at startup. Uncomment and edit, or add later with:
#   localbox share add --name docs --path /path/to/docs
# [[shares]]
# name = "docs"
# root_path = "C:/path/to/docs"
# recursive = true
# # sync/pull default to "manual" (no automatic transfers).
# # `sync = "auto"` streams journal changes to peers continuously; it does not
# # affect `localbox push`, which is always available on demand.
# sync = "manual"
# pull = "manual"
# # ignore_patterns = ["**/.git/**", "**/*.tmp"]
# # sync_allow = ["docs/**"]  # empty = all non-ignored paths
# # conflict = "last_write_wins"  # last_write_wins | keep_both | owner_wins
# # max_file_size_bytes = 1073741824 # 1 GiB
"#,
        instance_id = DEFAULT_INSTANCE_ID,
        listen_port = DEFAULT_LISTEN_PORT,
        plain_listen_port = DEFAULT_PLAIN_LISTEN_PORT,
        discovery_port = DEFAULT_DISCOVERY_PORT,
        dht_port = DEFAULT_DHT_PORT,
        utp_port = DEFAULT_UTP_PORT,
        agg_ms = DEFAULT_AGG_WINDOW_MS,
        db_path = DEFAULT_DB_PATH,
        log_path = DEFAULT_LOG_PATH,
        tls_cert_path = DEFAULT_TLS_CERT_PATH,
        tls_key_path = DEFAULT_TLS_KEY_PATH,
        tls_ca_cert_path = DEFAULT_TLS_CA_CERT_PATH,
        remote_share_root = DEFAULT_REMOTE_SHARE_ROOT,
        control_socket = DEFAULT_CONTROL_SOCKET
    )
}

#[cfg(test)]
mod tests {
    use super::{default_config_template, parse_share_arg, validate_app_config, Cli};
    use clap::Parser;
    use models::{AppConfig, ApplicationState, ConflictPolicy};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use utilities::test_temp_path;

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
    fn cli_allows_empty_shares_when_no_config_exists() {
        let path = test_temp_path("localbox-empty").with_extension("toml");
        std::fs::write(&path, "\n").unwrap();

        let path_str = path.to_string_lossy().to_string();
        let cli = Cli::try_parse_from([
            "localbox".to_string(),
            "run".to_string(),
            "--config".to_string(),
            path_str,
        ])
        .unwrap();
        let cfg = cli.resolve_app_config().unwrap();
        assert!(cfg.shares.is_empty());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn mirror_only_state_does_not_require_share_configs() {
        let path = test_temp_path("localbox-mirror").with_extension("toml");
        std::fs::write(&path, "\n").unwrap();
        let path_str = path.to_string_lossy().to_string();
        let cli = Cli::try_parse_from([
            "localbox".to_string(),
            "run".to_string(),
            "--config".to_string(),
            path_str.clone(),
            "--app-state".to_string(),
            "mirror-only".to_string(),
        ])
        .unwrap();
        let cfg = cli.resolve_app_config().unwrap();
        assert!(cfg.shares.is_empty());
        assert!(matches!(cfg.app_state, ApplicationState::MirrorOnly));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn template_is_valid_toml() {
        let tpl = default_config_template();
        let parsed: toml::Value = toml::from_str(&tpl).unwrap();
        assert!(parsed.get("instance_id").is_some());
        // Example [[shares]] is commented out so a fresh init can start without paths.
        assert!(parsed.get("shares").is_none());
    }

    /// `sync` gates journal sync; `push` is the pre-v7 spelling of the same key.
    /// `FileShareConfig` is `deny_unknown_fields`, so this pins that the alias is
    /// still an accepted field name rather than a hard parse error.
    #[test]
    fn share_sync_accepts_legacy_push_spelling() {
        let legacy: super::FileShareConfig = toml::from_str(
            "name = \"docs\"\nroot_path = \"/docs\"\nrecursive = true\npush = \"auto\"\n",
        )
        .expect("legacy `push` key must still parse");
        assert!(legacy.sync.is_auto());

        let current: super::FileShareConfig = toml::from_str(
            "name = \"docs\"\nroot_path = \"/docs\"\nrecursive = true\nsync = \"auto\"\n",
        )
        .expect("`sync` key must parse");
        assert!(current.sync.is_auto());

        // Absent means manual, unchanged from before the rename.
        let bare: super::FileShareConfig =
            toml::from_str("name = \"docs\"\nroot_path = \"/docs\"\nrecursive = true\n").unwrap();
        assert!(!bare.sync.is_auto());
    }

    #[test]
    fn validate_app_config_checks_share_paths() {
        let tmp_dir = test_temp_path("localbox-test");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let cfg = AppConfig {
            pc_name: "pc".to_string(),
            instance_id: "i".to_string(),
            display_name: String::new(),
            listen_addr: "0.0.0.0:5000".parse().unwrap(),
            plain_listen_addr: "0.0.0.0:5002".parse().unwrap(),
            use_tls_for_peers: true,
            discovery_port: 5001,
        discovery_send_ports: Vec::new(),
            dht_port: 5003,
            utp_port: 5004,
            enable_dht: false,
        enable_utp: false,
            bootstrap_peers: Vec::new(),
            aggregation_window_ms: 10,
            db_path: PathBuf::from("db"),
            log_path: PathBuf::from("log"),
            tls_cert_path: PathBuf::from("cert"),
            tls_key_path: PathBuf::from("key"),
            tls_ca_cert_path: PathBuf::from("ca"),
            tls_pinned_ca_fingerprints: Vec::new(),
            tls_peer_fingerprints: HashMap::new(),
            tls_insecure_shared_cert: false,
            remote_share_root: PathBuf::from("remote"),
            shares: vec![models::ShareConfig {
                name: "s".to_string(),
                root_path: tmp_dir.clone(),
                recursive: true,
                ignore_patterns: Vec::new(),
                sync_allow: Vec::new(),
                max_file_size_bytes: None,
                sync: Default::default(),
                pull: Default::default(),
                request_handling: None,
                conflict: ConflictPolicy::LastWriteWins,
            }],
            app_state: ApplicationState::MirrorHost,
            request_handling: Default::default(),
            peer_policies: Vec::new(),
            quarantined_peers: Vec::new(),
            control_socket: std::path::PathBuf::from("localbox.sock"),
        };
        validate_app_config(&cfg).unwrap();
        std::fs::remove_dir_all(&tmp_dir).unwrap();
    }

    #[test]
    fn mirror_only_state_skips_share_path_validation() {
        let cfg = AppConfig {
            pc_name: "pc".to_string(),
            instance_id: "i".to_string(),
            display_name: String::new(),
            listen_addr: "0.0.0.0:5000".parse().unwrap(),
            plain_listen_addr: "0.0.0.0:5002".parse().unwrap(),
            use_tls_for_peers: true,
            discovery_port: 5001,
        discovery_send_ports: Vec::new(),
            dht_port: 5003,
            utp_port: 5004,
            enable_dht: false,
        enable_utp: false,
            bootstrap_peers: Vec::new(),
            aggregation_window_ms: 10,
            db_path: PathBuf::from("db"),
            log_path: PathBuf::from("log"),
            tls_cert_path: PathBuf::from("cert"),
            tls_key_path: PathBuf::from("key"),
            tls_ca_cert_path: PathBuf::from("ca"),
            tls_pinned_ca_fingerprints: Vec::new(),
            tls_peer_fingerprints: HashMap::new(),
            tls_insecure_shared_cert: false,
            remote_share_root: PathBuf::from("remote"),
            shares: vec![models::ShareConfig {
                name: "s".to_string(),
                root_path: PathBuf::from("/definitely/not/real"),
                recursive: true,
                ignore_patterns: Vec::new(),
                sync_allow: Vec::new(),
                max_file_size_bytes: None,
                sync: Default::default(),
                pull: Default::default(),
                request_handling: None,
                conflict: ConflictPolicy::LastWriteWins,
            }],
            app_state: ApplicationState::MirrorOnly,
            request_handling: Default::default(),
            peer_policies: Vec::new(),
            quarantined_peers: Vec::new(),
            control_socket: std::path::PathBuf::from("localbox.sock"),
        };
        validate_app_config(&cfg).unwrap();
    }
}
