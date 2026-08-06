//! Spawn or attach to a Localbox runtime for the GUI.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::client::{self, ControlRequest};

const READY_TIMEOUT: Duration = Duration::from_secs(15);
const READY_POLL: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    /// Connected to an already-running daemon; GUI will not stop it on exit.
    Attached,
    /// GUI spawned the child and will kill it on exit.
    Managed,
}

pub struct RuntimeHandle {
    #[allow(dead_code)]
    pub socket: PathBuf,
    pub mode: RuntimeMode,
    child: Option<Child>,
}

impl RuntimeHandle {
    pub fn label(&self) -> &'static str {
        match self.mode {
            RuntimeMode::Attached => "attached",
            RuntimeMode::Managed => "managed",
        }
    }
}

impl Drop for RuntimeHandle {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub fn default_control_socket() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(r"\\.\pipe\localbox")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("localbox.sock")
    }
}

/// Resolve the control socket: explicit override wins; otherwise peek config.toml.
pub fn resolve_socket(
    socket_arg: PathBuf,
    socket_was_default: bool,
    config: Option<&Path>,
) -> Result<PathBuf> {
    if !socket_was_default {
        return Ok(socket_arg);
    }
    if let Some(cfg) = config {
        if let Some(from_cfg) = control_socket_from_config(cfg)? {
            return Ok(from_cfg);
        }
    }
    Ok(socket_arg)
}

pub fn control_socket_from_config(path: &Path) -> Result<Option<PathBuf>> {
    #[derive(Deserialize)]
    struct Peek {
        control_socket: Option<PathBuf>,
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read config {}", path.display()))?;
    let peek: Peek = toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(peek.control_socket)
}

pub fn resolve_core_binary(override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        return Ok(p.to_path_buf());
    }
    if let Ok(env_path) = env::var("LOCALBOX_CORE") {
        let p = PathBuf::from(env_path);
        if !p.as_os_str().is_empty() {
            return Ok(p);
        }
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join(core_binary_name());
            if sibling.is_file() {
                return Ok(sibling);
            }
        }
    }
    Ok(PathBuf::from(core_binary_name()))
}

fn core_binary_name() -> &'static str {
    #[cfg(windows)]
    {
        "localbox-core.exe"
    }
    #[cfg(not(windows))]
    {
        "localbox-core"
    }
}

pub async fn probe_alive(socket: &Path) -> bool {
    matches!(
        client::send_request(socket, &ControlRequest::Ping).await,
        Ok(resp) if resp.ok
    )
}

fn spawn_runtime(bin: &Path, config: Option<&Path>, socket: &Path) -> Result<Child> {
    let mut cmd = Command::new(bin);
    if let Some(cfg) = config {
        cmd.arg("--config").arg(cfg);
    }
    cmd.arg("run").arg("--control-socket").arg(socket);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    cmd.spawn()
        .with_context(|| format!("spawn runtime {}", bin.display()))
}

pub struct EnsureOpts<'a> {
    pub socket: PathBuf,
    pub config: Option<&'a Path>,
    pub core: Option<&'a Path>,
    pub no_runtime: bool,
}

/// Attach to a live control plane, or spawn `localbox-core run` when none is listening.
pub async fn ensure_runtime(opts: EnsureOpts<'_>) -> Result<RuntimeHandle> {
    let socket = opts.socket;

    if probe_alive(&socket).await {
        return Ok(RuntimeHandle {
            socket,
            mode: RuntimeMode::Attached,
            child: None,
        });
    }

    if opts.no_runtime {
        bail!(
            "no runtime on {} (pass without --no-runtime to spawn, or start `localbox-core run`)",
            socket.display()
        );
    }

    let bin = resolve_core_binary(opts.core)?;
    let mut child = spawn_runtime(&bin, opts.config, &socket)?;
    let deadline = Instant::now() + READY_TIMEOUT;

    loop {
        if let Ok(Some(status)) = child.try_wait() {
            bail!(
                "runtime {} exited before control socket was ready (status {status})",
                bin.display()
            );
        }
        if probe_alive(&socket).await {
            return Ok(RuntimeHandle {
                socket,
                mode: RuntimeMode::Managed,
                child: Some(child),
            });
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(anyhow!(
                "timed out waiting for runtime on {} after spawning {}",
                socket.display(),
                bin.display()
            ));
        }
        sleep(READY_POLL).await;
    }
}
