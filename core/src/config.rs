use clap::Parser;
use models::{AppConfig, ShareConfig};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug, Parser)]
#[command(name = "localbox", about = "LocalBox core engine")]
pub struct CliConfig {
    /// Instance identifier for this node
    #[arg(long, default_value = "instance-1")]
    pub instance_id: String,

    /// TCP listen port for peer connections
    #[arg(long, default_value_t = 5000)]
    pub listen_port: u16,

    /// UDP discovery port
    #[arg(long, default_value_t = 5001)]
    pub discovery_port: u16,

    /// Aggregation window in milliseconds
    #[arg(long, default_value_t = 2000)]
    pub aggregation_window_ms: u64,

    /// Path to the SQLite DB
    #[arg(long, default_value = "sync.db")]
    pub db_path: PathBuf,

    /// Path to the log file
    #[arg(long, default_value = "sync.log")]
    pub log_path: PathBuf,

    /// Path to TLS certificate (PEM)
    #[arg(long, default_value = "certs/localbox.cert.pem")]
    pub tls_cert_path: PathBuf,

    /// Path to TLS private key (PEM, PKCS8)
    #[arg(long, default_value = "certs/localbox.key.pem")]
    pub tls_key_path: PathBuf,

    /// Path to CA certificate (PEM)
    #[arg(long, default_value = "certs/ca.cert.pem")]
    pub tls_ca_cert_path: PathBuf,

    /// Root folder where remote/peer-owned shares are synced
    #[arg(long, default_value = "remote-shares")]
    pub remote_share_root: PathBuf,

    /// Additional shares to watch in the form name=path[,recursive=true|false]
    #[arg(
        long = "share",
        value_name = "NAME=PATH[,recursive=true|false]",
        value_parser = parse_share_arg
    )]
    pub shares: Vec<ShareCli>,

    /// Name of the default share
    #[arg(long, default_value = "clinic-docs")]
    pub share_name: String,

    /// Root path for the default share
    #[arg(long, default_value = "C:/Repos/IsoCabFlattener")]
    pub share_root: PathBuf,

    /// Whether to watch the share recursively
    #[arg(long, default_value_t = true)]
    pub share_recursive: bool,
}

impl CliConfig {
    pub fn into_app_config(self) -> AppConfig {
        // PC name is derived at runtime so we keep CLI minimal
        let pc_name = hostname::get()
            .unwrap_or_else(|_| "unknown-pc".into())
            .to_string_lossy()
            .into_owned();

        let shares: Vec<ShareConfig> = if !self.shares.is_empty() {
            self.shares
                .into_iter()
                .map(ShareCli::into_share_config)
                .collect()
        } else {
            vec![ShareConfig {
                name: self.share_name,
                root_path: self.share_root,
                recursive: self.share_recursive,
            }]
        };

        AppConfig {
            pc_name,
            instance_id: self.instance_id,
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.listen_port),
            discovery_port: self.discovery_port,
            aggregation_window_ms: self.aggregation_window_ms,
            db_path: self.db_path,
            log_path: self.log_path,
            tls_cert_path: self.tls_cert_path,
            tls_key_path: self.tls_key_path,
            tls_ca_cert_path: self.tls_ca_cert_path,
            remote_share_root: self.remote_share_root,
            shares,
        }
    }
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
