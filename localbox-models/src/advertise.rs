use serde::{Deserialize, Serialize};

use crate::config::TransferMode;

/// Share metadata advertised to peers over Hello / discovery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvertisedShare {
    pub name: String,
    #[serde(default = "default_recursive")]
    pub recursive: bool,
    #[serde(default)]
    pub sync: TransferMode,
    #[serde(default)]
    pub pull: TransferMode,
}

impl AdvertisedShare {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            recursive: true,
            sync: TransferMode::Manual,
            pull: TransferMode::Manual,
        }
    }

    pub fn encode_discovery_token(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.name,
            self.recursive,
            transfer_mode_token(self.sync),
            transfer_mode_token(self.pull),
        )
    }

    /// Parse `name` or `name:recursive:sync:pull` discovery tokens.
    pub fn parse_discovery_token(token: &str) -> Option<Self> {
        let token = token.trim();
        if token.is_empty() {
            return None;
        }
        let mut parts = token.split(':');
        let name = parts.next()?.to_string();
        if name.is_empty() {
            return None;
        }
        let recursive = parts
            .next()
            .map(|s| s.parse::<bool>().unwrap_or(true))
            .unwrap_or(true);
        let sync = parts
            .next()
            .map(parse_transfer_mode_token)
            .unwrap_or(TransferMode::Manual);
        let pull = parts
            .next()
            .map(parse_transfer_mode_token)
            .unwrap_or(TransferMode::Manual);
        Some(Self {
            name,
            recursive,
            sync,
            pull,
        })
    }
}

fn default_recursive() -> bool {
    true
}

fn transfer_mode_token(mode: TransferMode) -> &'static str {
    match mode {
        TransferMode::Manual => "manual",
        TransferMode::Auto => "auto",
    }
}

fn parse_transfer_mode_token(s: &str) -> TransferMode {
    match s.trim().to_ascii_lowercase().as_str() {
        "auto" => TransferMode::Auto,
        _ => TransferMode::Manual,
    }
}

/// Encode a list of advertised shares for the discovery `shares=` field.
pub fn encode_discovery_shares(shares: &[AdvertisedShare]) -> String {
    shares
        .iter()
        .map(AdvertisedShare::encode_discovery_token)
        .collect::<Vec<_>>()
        .join(",")
}

/// Decode discovery `shares=` (plain names or structured tokens).
pub fn decode_discovery_shares(s: &str) -> Vec<AdvertisedShare> {
    s.split(',')
        .filter_map(AdvertisedShare::parse_discovery_token)
        .collect()
}

/// Escape a discovery KV value so whitespace / `=` do not break parsing.
pub fn escape_discovery_value(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace('=', "%3D")
}

pub fn unescape_discovery_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &s[i + 1..i + 3];
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}
