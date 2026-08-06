//! Control plane: Unix domain socket (Unix) or named pipe (Windows).

use anyhow::{Context, Result};
use db::Db;
use models::{AppConfig, TransferProgressRegistry};
use peering::PeerCommand;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::service::{ControlRequest, ControlResponse, ControlService};

pub async fn run_control_server(
    cfg: AppConfig,
    db: Arc<Mutex<Db>>,
    net_tx: mpsc::Sender<String>,
    cmd_tx: mpsc::Sender<PeerCommand>,
    progress: Arc<TransferProgressRegistry>,
    token: CancellationToken,
) -> Result<()> {
    let path = cfg.control_socket.clone();
    let service = ControlService {
        cfg,
        db,
        net_tx,
        peer_cmd_tx: cmd_tx,
        progress,
    };

    #[cfg(unix)]
    {
        run_unix_server(path, service, token).await
    }

    #[cfg(windows)]
    {
        run_windows_server(path, service, token).await
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, service, token);
        anyhow::bail!("control plane is only supported on Unix or Windows")
    }
}

#[cfg(unix)]
async fn run_unix_server(
    path: PathBuf,
    service: ControlService,
    token: CancellationToken,
) -> Result<()> {
    use tokio::net::UnixListener;

    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("bind control socket {}", path.display()))?;
    info!(socket = %path.display(), "Control server listening (unix)");

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        let service = service.clone();
                        let token = token.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, service, token).await {
                                warn!("Control client ended: {e}");
                            }
                        });
                    }
                    Err(e) => warn!("Control accept error: {e}"),
                }
            }
        }
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[cfg(windows)]
async fn run_windows_server(
    path: PathBuf,
    service: ControlService,
    token: CancellationToken,
) -> Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let pipe_name = windows_pipe_name(&path);
    info!(pipe = %pipe_name, "Control server listening (named pipe)");

    loop {
        if token.is_cancelled() {
            break;
        }
        let mut server = ServerOptions::new()
            .first_pipe_instance(false)
            .create(&pipe_name)
            .with_context(|| format!("create named pipe {pipe_name}"))?;

        tokio::select! {
            _ = token.cancelled() => break,
            connect = server.connect() => {
                if let Err(e) = connect {
                    warn!("Named pipe connect error: {e}");
                    continue;
                }
                let service = service.clone();
                let token = token.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(server, service, token).await {
                        warn!("Control client ended: {e}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_client<S>(
    stream: S,
    service: ControlService,
    token: CancellationToken,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            line = lines.next_line() => {
                let Some(line) = line? else { break; };
                if line.trim().is_empty() {
                    continue;
                }
                let resp = match serde_json::from_str::<ControlRequest>(&line) {
                    Ok(req) => {
                        if matches!(req, ControlRequest::Quit) {
                            let r = service.handle(req).await;
                            write_json_line(&mut writer, &r).await?;
                            break;
                        }
                        service.handle(req).await
                    }
                    Err(e) => ControlResponse::err(format!("invalid request: {e}")),
                };
                write_json_line(&mut writer, &resp).await?;
            }
        }
    }
    Ok(())
}

async fn write_json_line<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    resp: &ControlResponse,
) -> Result<()> {
    let mut bytes = serde_json::to_vec(resp)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn send_control_request(
    socket: &Path,
    req: &ControlRequest,
) -> Result<ControlResponse> {
    #[cfg(unix)]
    {
        use tokio::net::UnixStream;
        let stream = UnixStream::connect(socket).await.with_context(|| {
            format!(
                "failed to connect to control socket {}; start `localbox run` or `localbox run --interactive`",
                socket.display()
            )
        })?;
        exchange_request(stream, req).await
    }

    #[cfg(windows)]
    {
        use tokio::net::windows::named_pipe::ClientOptions;
        let pipe_name = windows_pipe_name(socket);
        let stream = ClientOptions::new().open(&pipe_name).with_context(|| {
            format!(
                "failed to connect to control pipe {pipe_name}; start `localbox run` or `localbox run --interactive`"
            )
        })?;
        exchange_request(stream, req).await
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (socket, req);
        anyhow::bail!("control plane is only supported on Unix or Windows")
    }
}

async fn exchange_request<S>(stream: S, req: &ControlRequest) -> Result<ControlResponse>
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
        .ok_or_else(|| anyhow::anyhow!("control server closed connection"))?;
    Ok(serde_json::from_str(&line)?)
}

/// Normalize a config path into a Windows named-pipe path.
#[cfg(windows)]
pub fn windows_pipe_name(path: &Path) -> String {
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

#[cfg(not(windows))]
#[allow(dead_code)]
pub fn windows_pipe_name(path: &Path) -> String {
    path.display().to_string()
}
