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

    /// Kill a GUI-owned child process. No-op when attached (no child).
    pub fn kill_managed(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(())
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

/// Where to park a spawned runtime's raw stderr, alongside its configured log.
///
/// Only startup failures and panics land here — tracing's console stream goes to
/// stdout, which we drop because the file log already has it.
fn stderr_sink_path(config: Option<&Path>) -> Option<PathBuf> {
    #[derive(Deserialize)]
    struct Peek {
        log_path: Option<PathBuf>,
    }
    let text = std::fs::read_to_string(config?).ok()?;
    let log_path = toml::from_str::<Peek>(&text).ok()?.log_path?;
    let stem = log_path.file_stem()?.to_str()?;
    Some(log_path.with_file_name(format!("{stem}.stderr.log")))
}

fn stderr_sink(config: Option<&Path>) -> Stdio {
    stderr_sink_path(config)
        .and_then(|path| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()
        })
        .map_or_else(Stdio::null, Stdio::from)
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
    // Tie the child's lifetime to this process: our own teardown is best-effort, and an
    // orphaned daemon keeps running. It watches this pid and exits when we are gone.
    cmd.env(localbox_core::engine::PARENT_PID_ENV, std::process::id().to_string());
    // Never inherit our console: an inherited stream lets the daemon scribble over
    // whatever terminal launched us, and outlive us doing it. stdout is tracing's
    // console mirror of `log_path`, which the Logs tab already tails, so drop it and
    // keep only stderr — the startup errors and panics that never reach the log.
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr_sink(config));
    cmd.spawn()
        .with_context(|| format!("spawn runtime {}", bin.display()))
}

#[derive(Debug, Clone)]
pub struct EnsureOpts {
    pub socket: PathBuf,
    pub config: Option<PathBuf>,
    pub core: Option<PathBuf>,
    pub no_runtime: bool,
}

/// Attach to a live control plane, or spawn `localbox-core run` when none is listening.
pub async fn ensure_runtime(opts: EnsureOpts) -> Result<RuntimeHandle> {
    ensure_runtime_inner(opts, false).await
}

/// Like [`ensure_runtime`], but if a daemon is already listening, shut it down and
/// spawn a fresh `localbox-core` from the resolved binary (avoids sticking to a stale process).
pub async fn restart_runtime(opts: EnsureOpts) -> Result<RuntimeHandle> {
    ensure_runtime_inner(opts, true).await
}

async fn ensure_runtime_inner(opts: EnsureOpts, replace_existing: bool) -> Result<RuntimeHandle> {
    let socket = opts.socket;

    if probe_alive(&socket).await {
        if !replace_existing || opts.no_runtime {
            return Ok(RuntimeHandle {
                socket,
                mode: RuntimeMode::Attached,
                child: None,
            });
        }
        // User explicitly started/restarted from the GUI — replace whatever is on the socket.
        let _ = client::send_request(&socket, &ControlRequest::Shutdown).await;
        let deadline = Instant::now() + Duration::from_secs(3);
        while probe_alive(&socket).await {
            if Instant::now() >= deadline {
                bail!(
                    "timed out waiting for old runtime on {} to exit after shutdown",
                    socket.display()
                );
            }
            sleep(READY_POLL).await;
        }
    }

    if opts.no_runtime {
        bail!(
            "no runtime on {} (pass without --no-runtime to spawn, or start `localbox-core run`)",
            socket.display()
        );
    }

    let bin = resolve_core_binary(opts.core.as_deref())?;
    let mut child = spawn_runtime(&bin, opts.config.as_deref(), &socket)?;
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

/// Stop a runtime: kill a managed child, or send `Shutdown` when attached.
pub async fn stop_runtime(handle: &mut RuntimeHandle) -> Result<&'static str> {
    match handle.mode {
        RuntimeMode::Managed => {
            // Prefer a clean control-plane shutdown, then force-kill if needed.
            let _ = client::send_request(&handle.socket, &ControlRequest::Shutdown).await;
            let deadline = Instant::now() + Duration::from_secs(2);
            if let Some(child) = handle.child.as_mut() {
                loop {
                    match child.try_wait() {
                        Ok(Some(_)) => {
                            handle.child = None;
                            return Ok("stopped managed runtime");
                        }
                        Ok(None) if Instant::now() < deadline => sleep(READY_POLL).await,
                        _ => break,
                    }
                }
            }
            handle.kill_managed()?;
            Ok("stopped managed runtime")
        }
        RuntimeMode::Attached => {
            let resp = client::send_request(&handle.socket, &ControlRequest::Shutdown).await?;
            if resp.ok {
                Ok("sent shutdown to attached daemon")
            } else {
                bail!(resp.message)
            }
        }
    }
}

/// Synchronously stop a GUI-owned child (safe during window teardown).
pub fn stop_managed_sync(handle: &mut RuntimeHandle) {
    if handle.mode != RuntimeMode::Managed {
        return;
    }
    let _ = handle.kill_managed();
}
