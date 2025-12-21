use std::io::ErrorKind;
use std::path::PathBuf;

use anyhow::Result;
use db::Db;
use utilities::{compute_file_hash, FileSystem};

#[derive(Debug)]
pub struct IntegrityIssue {
    pub share: String,
    pub path: String,
    pub kind: IntegrityIssueKind,
}

#[derive(Debug)]
pub enum IntegrityIssueKind {
    Missing,
    HashMismatch { expected: String, actual: String },
    IoError(String),
}

#[derive(Debug)]
pub struct IntegrityReport {
    pub checked: usize,
    pub issues: Vec<IntegrityIssue>,
}

pub fn audit_disk(
    db: &Db,
    fs: &dyn FileSystem,
    share_filter: Option<&str>,
) -> Result<IntegrityReport> {
    let shares = db.list_shares_table()?;
    let mut checked = 0usize;
    let mut issues = Vec::new();

    for share in shares {
        if let Some(filter) = share_filter {
            if share.share_name != filter {
                continue;
            }
        }
        let share_label = format!("{}@{}", share.share_name, share.pc_name);
        let root = PathBuf::from(&share.root_path);
        let metas = db.list_file_metas(share.id)?;
        for meta in metas {
            if meta.deleted {
                continue;
            }
            checked += 1;
            let full_path = root.join(&meta.path);
            match fs.metadata(&full_path) {
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    issues.push(IntegrityIssue {
                        share: share_label.clone(),
                        path: meta.path.clone(),
                        kind: IntegrityIssueKind::Missing,
                    });
                    continue;
                }
                Err(e) => {
                    issues.push(IntegrityIssue {
                        share: share_label.clone(),
                        path: meta.path.clone(),
                        kind: IntegrityIssueKind::IoError(e.to_string()),
                    });
                    continue;
                }
                Ok(_) => {}
            }

            match compute_file_hash(fs, &full_path) {
                Ok(hash) => {
                    if hash != meta.hash {
                        issues.push(IntegrityIssue {
                            share: share_label.clone(),
                            path: meta.path.clone(),
                            kind: IntegrityIssueKind::HashMismatch {
                                expected: to_hex(&meta.hash),
                                actual: to_hex(&hash),
                            },
                        });
                    }
                }
                Err(e) => issues.push(IntegrityIssue {
                    share: share_label.clone(),
                    path: meta.path.clone(),
                    kind: IntegrityIssueKind::IoError(e.to_string()),
                }),
            }
        }
    }

    Ok(IntegrityReport { checked, issues })
}

fn to_hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}
