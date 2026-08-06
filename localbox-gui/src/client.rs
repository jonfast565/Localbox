//! Control-plane client for the Localbox GUI (Unix socket or Windows named pipe).

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ControlRequest {
    Ping,
    Status,
    Push {
        share: String,
        peer: Option<String>,
        path: Option<String>,
    },
    Pull {
        share: String,
        peer: String,
        path: Option<String>,
    },
    Request {
        share: String,
        peer: String,
        path: Option<String>,
    },
    Reply {
        id: String,
        accept: bool,
        reason: Option<String>,
    },
    PendingRequests,
    Intents {
        #[serde(default)]
        all: bool,
        limit: Option<usize>,
    },
    IntentShow {
        id: String,
    },
    ChatSend {
        peer: Option<String>,
        share: Option<String>,
        thread: Option<String>,
        message: Option<String>,
        file: Option<String>,
        share_dest: Option<String>,
    },
    ChatInbox,
    ChatThreads,
    ChatShow {
        thread: String,
        limit: Option<usize>,
    },
    ChatRead {
        thread: String,
    },
    TransferProgress {
        intent_id: Option<String>,
    },
    PeerList,
    PeerQuarantine {
        peer: String,
    },
    PeerUnquarantine {
        peer: String,
    },
    ShareList,
    ShareAdd {
        name: String,
        path: String,
        #[serde(default = "default_true")]
        recursive: bool,
    },
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResponse {
    pub ok: bool,
    pub message: String,
    #[serde(default)]
    pub data: Option<Value>,
}

pub async fn send_request(socket: &Path, req: &ControlRequest) -> Result<ControlResponse> {
    #[cfg(unix)]
    {
        use tokio::net::UnixStream;
        let stream = UnixStream::connect(socket).await.with_context(|| {
            format!("connect {}: start `localbox run` first", socket.display())
        })?;
        exchange(stream, req).await
    }

    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ClientOptions;
        let pipe = windows_pipe_name(socket);
        let stream = ClientOptions::new()
            .open(&pipe)
            .with_context(|| format!("connect pipe {pipe}: start `localbox run` first"))?;
        exchange(stream, req).await
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (socket, req);
        anyhow::bail!("unsupported platform for control client")
    }
}

async fn exchange<S>(stream: S, req: &ControlRequest) -> Result<ControlResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut bytes = serde_json::to_vec(req)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    let mut lines = BufReader::new(reader).lines();
    let line = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("control server closed"))?;
    Ok(serde_json::from_str(&line)?)
}

#[cfg(windows)]
fn windows_pipe_name(path: &Path) -> String {
    let s = path.to_string_lossy();
    if s.starts_with(r"\\.\pipe\") || s.starts_with("//./pipe/") {
        s.replace('/', r"\")
    } else {
        let leaf = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("localbox");
        let leaf = leaf.trim_end_matches(".sock");
        format!(r"\\.\pipe\{leaf}")
    }
}
