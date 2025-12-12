#![allow(dead_code)]

use std::ffi::OsStr;
use std::io;
use std::path::Path;
use std::thread;
use std::time::Duration;

use anyhow::Result;
use once_cell::sync::OnceCell;
use sha2::{Digest, Sha256};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub mod disk_utilities;
pub mod filesystem;
pub mod net;

pub use filesystem::{DirEntry, FileSystem, FsMetadata, RealFileSystem, VirtualFileSystem};
pub use disk_utilities::{build_meta_with_retry, build_remote_share_root, relative_share_path};
pub use net::{DynStream, Net, RealNet, TcpListenerLike, UdpSocketLike, VirtualNet};

/// Guard for the non-blocking file writer so it is not dropped early.
static FILE_GUARD: OnceCell<WorkerGuard> = OnceCell::new();
/// Ensures logging is only initialized once.
static LOG_INIT: OnceCell<()> = OnceCell::new();

/// Initialize tracing-based logging with both console and file output.
///
/// Subsequent calls are no-ops so every binary can call this helper
/// confidently and share the same configuration.
pub fn init_logging(log_path: &Path, fs: &dyn FileSystem) -> Result<()> {
    LOG_INIT
        .get_or_try_init(|| configure_logging(log_path, fs))
        .map(|_| ())
}

/// Compute a SHA-256 hash for the file at `path` with default retry parameters.
pub fn compute_file_hash(fs: &dyn FileSystem, path: &Path) -> io::Result<[u8; 32]> {
    retry_hash(fs, path, 5, 100)
}

/// Retry fetching metadata for a path a limited number of times with a fixed delay.
pub fn retry_metadata(
    fs: &dyn FileSystem,
    path: &Path,
    attempts: usize,
    delay_ms: u64,
) -> io::Result<FsMetadata> {
    retry_io(path, attempts, delay_ms, || fs.metadata(path))
}

/// Retry hashing a file a limited number of times with a fixed delay.
pub fn retry_hash(
    fs: &dyn FileSystem,
    path: &Path,
    attempts: usize,
    delay_ms: u64,
) -> io::Result<[u8; 32]> {
    retry_io(path, attempts, delay_ms, || compute_file_hash_once(fs, path))
}

/// Generic retry helper for IO operations against `path`.
pub fn retry_io<T, F>(path: &Path, attempts: usize, delay_ms: u64, mut op: F) -> io::Result<T>
where
    F: FnMut() -> io::Result<T>,
{
    let mut last_err = None;
    for attempt in 1..=attempts {
        match op() {
            Ok(v) => return Ok(v),
            Err(e) => {
                last_err = Some(e);
                if attempt < attempts {
                    thread::sleep(Duration::from_millis(delay_ms));
                    continue;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("operation failed on {}", path.display()),
        )
    }))
}

fn compute_file_hash_once(fs: &dyn FileSystem, path: &Path) -> io::Result<[u8; 32]> {
    let data = fs.read(path)?;
    let digest = Sha256::digest(&data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn configure_logging(log_path: &Path, fs: &dyn FileSystem) -> Result<()> {
    let log_dir = log_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let _ = fs.create_dir_all(log_dir);
    let file_name = log_path
        .file_name()
        .unwrap_or_else(|| OsStr::new("application.log"));

    let file_appender = tracing_appender::rolling::never(log_dir, file_name);
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);

    // Keep guard alive for the process lifetime.
    let _ = FILE_GUARD.set(guard);

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let console_layer = fmt::layer().with_writer(std::io::stdout);
    let file_layer = fmt::layer().with_ansi(false).with_writer(file_writer);

    tracing_subscriber::registry()
        .with(filter)
        .with(console_layer)
        .with(file_layer)
        .try_init()?;

    Ok(())
}
