//! Persistent GUI-only preferences (not part of the engine control plane).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT_LOG_TAIL_LINES: usize = 100;
pub const MIN_LOG_TAIL_LINES: usize = 10;
pub const MAX_LOG_TAIL_LINES: usize = 5_000;

pub const DEFAULT_CHAT_SPLIT_RATIO: f32 = 0.28;
pub const DEFAULT_STATUS_SPLIT_RATIO: f32 = 0.5;
pub const DEFAULT_TRANSFERS_SPLIT_RATIO: f32 = 0.5;
pub const MIN_SPLIT_RATIO: f32 = 0.15;
pub const MAX_SPLIT_RATIO: f32 = 0.85;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiPrefs {
    /// Rolling window size for the Logs tab (last N lines).
    #[serde(default = "default_log_tail_lines")]
    pub log_tail_lines: usize,
    /// Chat inbox width as a fraction of the chat pane row.
    #[serde(default = "default_chat_split_ratio")]
    pub chat_split_ratio: f32,
    /// Status shares height as a fraction of the shares/peers stack.
    #[serde(default = "default_status_split_ratio")]
    pub status_split_ratio: f32,
    /// Transfers pending width as a fraction of the pending/intents row.
    #[serde(default = "default_transfers_split_ratio")]
    pub transfers_split_ratio: f32,
}

impl Default for GuiPrefs {
    fn default() -> Self {
        Self {
            log_tail_lines: DEFAULT_LOG_TAIL_LINES,
            chat_split_ratio: DEFAULT_CHAT_SPLIT_RATIO,
            status_split_ratio: DEFAULT_STATUS_SPLIT_RATIO,
            transfers_split_ratio: DEFAULT_TRANSFERS_SPLIT_RATIO,
        }
    }
}

fn default_log_tail_lines() -> usize {
    DEFAULT_LOG_TAIL_LINES
}

fn default_chat_split_ratio() -> f32 {
    DEFAULT_CHAT_SPLIT_RATIO
}

fn default_status_split_ratio() -> f32 {
    DEFAULT_STATUS_SPLIT_RATIO
}

fn default_transfers_split_ratio() -> f32 {
    DEFAULT_TRANSFERS_SPLIT_RATIO
}

impl GuiPrefs {
    pub fn clamp_log_tail_lines(n: usize) -> usize {
        n.clamp(MIN_LOG_TAIL_LINES, MAX_LOG_TAIL_LINES)
    }

    pub fn clamp_split_ratio(ratio: f32) -> f32 {
        if !ratio.is_finite() {
            return 0.5;
        }
        ratio.clamp(MIN_SPLIT_RATIO, MAX_SPLIT_RATIO)
    }

    pub fn load(path: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        match toml::from_str::<GuiPrefs>(&text) {
            Ok(mut prefs) => {
                prefs.log_tail_lines = Self::clamp_log_tail_lines(prefs.log_tail_lines);
                prefs.chat_split_ratio = Self::clamp_split_ratio(prefs.chat_split_ratio);
                prefs.status_split_ratio = Self::clamp_split_ratio(prefs.status_split_ratio);
                prefs.transfers_split_ratio = Self::clamp_split_ratio(prefs.transfers_split_ratio);
                prefs
            }
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let text = toml::to_string_pretty(self).unwrap_or_default();
        std::fs::write(path, text)
    }
}

pub fn default_prefs_path() -> PathBuf {
    PathBuf::from("localbox-gui.toml")
}
