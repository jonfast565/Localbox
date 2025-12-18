#![allow(dead_code)]

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use once_cell::sync::OnceCell;
use sha2::{Digest, Sha256};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub mod disk_utilities;
pub mod filesystem;
pub mod ignore;
pub mod net;

pub use disk_utilities::{
    build_meta_with_retry, build_meta_with_retry_limited, build_remote_share_root,
    relative_share_path,
};
pub use filesystem::{DirEntry, FileSystem, FsMetadata, RealFileSystem, VirtualFileSystem};
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
    retry_io(path, attempts, delay_ms, || {
        compute_file_hash_once(fs, path)
    })
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
    let mut reader = fs.open_read(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Write file contents via a temp file + rename when possible.
pub fn write_atomic(fs: &dyn FileSystem, path: &Path, data: &[u8]) -> io::Result<()> {
    if fs.as_any().is::<RealFileSystem>() {
        return write_file_atomic(path, data);
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().unwrap_or_else(|| OsStr::new("file"));
    let tmp = parent.join(format!(".{}.tmp", file_name.to_string_lossy()));

    fs.write(&tmp, data)?;
    let _ = fs.remove_file(path);
    fs.rename(&tmp, path)?;
    Ok(())
}

fn unique_tmp_name(base: &OsStr) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let mut stem = base.to_string_lossy().to_string();
    if stem.is_empty() {
        stem = "file".to_string();
    }
    PathBuf::from(format!(".{}.tmp-{}-{}", stem, pid, nonce))
}

fn sync_directory(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    let dir = File::open(path)?;
    dir.sync_data()
}

pub fn write_file_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(unique_tmp_name(
        path.file_name().unwrap_or_else(|| OsStr::new("file")),
    ));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    sync_directory(parent)?;
    Ok(())
}

pub fn copy_file_atomic(src: &Path, dst: &Path, overwrite: bool) -> io::Result<()> {
    if dst.exists() && !overwrite {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} already exists", dst.display()),
        ));
    }
    if let Some(parent) = dst.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let parent = dst
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(unique_tmp_name(
        dst.file_name().unwrap_or_else(|| OsStr::new("file")),
    ));
    {
        let mut reader = File::open(src)?;
        let mut writer = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;
        io::copy(&mut reader, &mut writer)?;
        writer.sync_all()?;
    }
    fs::rename(&tmp, dst)?;
    sync_directory(parent)?;
    Ok(())
}

pub fn rename_file_atomic(from: &Path, to: &Path) -> io::Result<()> {
    if let Some(parent) = to.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(from, to)?;
        sync_directory(parent)?;
    } else {
        fs::rename(from, to)?;
    }
    if let Some(parent) = from.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = sync_directory(parent);
        }
    }
    Ok(())
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
