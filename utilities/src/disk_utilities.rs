use std::io;
use std::path::{Component, Path, PathBuf, PrefixComponent};

use crate::{retry_hash, retry_metadata, FileSystem};
use models::FileMeta;

/// Build a root path for a remote share under a given base.
pub fn build_remote_share_root(
    base: &Path,
    pc_name: &str,
    instance_id: &str,
    share_name: &str,
) -> PathBuf {
    base.join(pc_name)
        .join(instance_id)
        .join(relative_share_path(share_name))
}

/// Convert an arbitrary share name/path into a safe relative path.
pub fn relative_share_path(share_name: &str) -> PathBuf {
    let mut rel = PathBuf::new();
    for comp in Path::new(share_name).components() {
        match comp {
            Component::Prefix(p) => rel.push(prefix_label(&p)),
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {}
            Component::Normal(c) => rel.push(c),
        }
    }

    if rel.as_os_str().is_empty() {
        rel.push(share_name);
    }

    rel
}

fn prefix_label(prefix: &PrefixComponent<'_>) -> String {
    match prefix.kind() {
        std::path::Prefix::Disk(d) | std::path::Prefix::VerbatimDisk(d) => {
            format!("drive-{}", (char::from(d)).to_ascii_uppercase())
        }
        std::path::Prefix::UNC(server, share) | std::path::Prefix::VerbatimUNC(server, share) => {
            format!(
                "unc-{}-{}",
                server.to_string_lossy(),
                share.to_string_lossy()
            )
        }
        _ => prefix
            .as_os_str()
            .to_string_lossy()
            .replace([':', '\\', '/'], "-"),
    }
}

/// Build file metadata with retries to tolerate transient IO errors.
pub fn build_meta_with_retry(
    fs: &dyn FileSystem,
    path: &Path,
    rel_path: &str,
    attempts: usize,
    delay_ms: u64,
) -> io::Result<FileMeta> {
    let md = retry_metadata(fs, path, attempts, delay_ms)?;
    let hash = retry_hash(fs, path, attempts, delay_ms)?;
    let mtime = md
        .modified
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Ok(models::FileMeta {
        path: rel_path.to_string(),
        size: md.len,
        mtime,
        hash,
        version: 1,
        deleted: false,
    })
}
