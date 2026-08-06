use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    In,
    Out,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferProgressSnapshot {
    pub key: String,
    pub intent_id: Option<String>,
    pub batch_id: Option<String>,
    pub peer_id: Option<i64>,
    pub share_name: Option<String>,
    pub path: Option<String>,
    pub direction: TransferDirection,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub files_done: u64,
    pub files_total: u64,
    pub updated_at: i64,
}

#[derive(Debug, Default)]
struct ProgressState {
    /// Aggregate per intent (or per batch when intent unknown).
    by_key: HashMap<String, TransferProgressSnapshot>,
}

#[derive(Debug, Default)]
pub struct TransferProgressRegistry {
    inner: Mutex<ProgressState>,
}

impl TransferProgressRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn begin_outbound(
        &self,
        intent_id: Option<&str>,
        batch_id: &str,
        peer_id: Option<i64>,
        share_name: &str,
        files_total: u64,
        bytes_total: u64,
    ) {
        let key = intent_id
            .map(|id| format!("intent:{id}"))
            .unwrap_or_else(|| format!("batch:{batch_id}"));
        let now = now_secs();
        let mut guard = self.inner.lock().unwrap();
        guard.by_key.insert(
            key.clone(),
            TransferProgressSnapshot {
                key,
                intent_id: intent_id.map(|s| s.to_string()),
                batch_id: Some(batch_id.to_string()),
                peer_id,
                share_name: Some(share_name.to_string()),
                path: None,
                direction: TransferDirection::Out,
                bytes_done: 0,
                bytes_total,
                files_done: 0,
                files_total,
                updated_at: now,
            },
        );
    }

    pub fn add_outbound_bytes(&self, intent_id: Option<&str>, batch_id: &str, n: u64, file_done: bool) {
        let key = intent_id
            .map(|id| format!("intent:{id}"))
            .unwrap_or_else(|| format!("batch:{batch_id}"));
        let now = now_secs();
        let mut guard = self.inner.lock().unwrap();
        if let Some(entry) = guard.by_key.get_mut(&key) {
            entry.bytes_done = entry.bytes_done.saturating_add(n);
            if file_done {
                entry.files_done = entry.files_done.saturating_add(1);
            }
            entry.updated_at = now;
        }
    }

    pub fn note_inbound_file(
        &self,
        batch_id: Option<&str>,
        path: &str,
        bytes_done: u64,
        bytes_total: Option<u64>,
        eof: bool,
    ) {
        let key = format!(
            "in:{}:{}",
            batch_id.unwrap_or("_"),
            path
        );
        let now = now_secs();
        let mut guard = self.inner.lock().unwrap();
        let entry = guard.by_key.entry(key.clone()).or_insert_with(|| {
            TransferProgressSnapshot {
                key: key.clone(),
                intent_id: None,
                batch_id: batch_id.map(|s| s.to_string()),
                peer_id: None,
                share_name: None,
                path: Some(path.to_string()),
                direction: TransferDirection::In,
                bytes_done: 0,
                bytes_total: bytes_total.unwrap_or(0),
                files_done: 0,
                files_total: 1,
                updated_at: now,
            }
        });
        entry.bytes_done = bytes_done;
        if let Some(total) = bytes_total {
            entry.bytes_total = total;
        }
        if eof {
            entry.files_done = 1;
        }
        entry.updated_at = now;
    }

    pub fn clear_intent(&self, intent_id: &str) {
        let key = format!("intent:{intent_id}");
        let mut guard = self.inner.lock().unwrap();
        guard.by_key.remove(&key);
    }

    pub fn snapshot(&self, intent_id: Option<&str>) -> Vec<TransferProgressSnapshot> {
        let guard = self.inner.lock().unwrap();
        let mut out: Vec<_> = match intent_id {
            Some(id) => {
                let prefix = format!("intent:{id}");
                guard
                    .by_key
                    .values()
                    .filter(|e| e.intent_id.as_deref() == Some(id) || e.key == prefix)
                    .cloned()
                    .collect()
            }
            None => guard.by_key.values().cloned().collect(),
        };
        out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        out
    }
}
