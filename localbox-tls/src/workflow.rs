use crate::{fingerprint_hex, normalize_fingerprint};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashSet;
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use utilities::copy_file_atomic;

const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

pub struct CertFingerprint {
    pub fingerprint: String,
    pub der: Vec<u8>,
}

pub fn fingerprints_for_pem_file(path: &Path) -> Result<Vec<CertFingerprint>> {
    read_cert_der_from_pem(path)?
        .into_iter()
        .map(|der| {
            let fp = fingerprint_hex(&der);
            Ok(CertFingerprint {
                fingerprint: fp,
                der,
            })
        })
        .collect()
}

pub fn read_trust_store_fingerprints(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut reader = BufReader::new(std::io::Cursor::new(data));
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|e| anyhow!("failed to parse PEM certs from {}: {e}", path.display()))?;
    Ok(certs.into_iter().map(|der| fingerprint_hex(&der)).collect())
}

pub fn export_ca_from_chain_pem(cert_chain_path: &Path, out_path: &Path) -> Result<()> {
    let pem = fs::read_to_string(cert_chain_path)
        .with_context(|| format!("failed to read {}", cert_chain_path.display()))?;
    let blocks = extract_pem_cert_blocks(&pem);
    if blocks.len() < 2 {
        bail!(
            "{} does not contain a certificate chain (need leaf + CA); rotate TLS to regenerate a full chain",
            cert_chain_path.display()
        );
    }
    let ca_block = blocks
        .last()
        .ok_or_else(|| anyhow!("missing CA certificate in chain"))?;
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    if out_path.exists() {
        let _ = fs::remove_file(out_path);
    }
    fs::write(out_path, format!("{ca_block}\n"))
        .with_context(|| format!("failed to write {}", out_path.display()))?;
    Ok(())
}

pub fn import_ca_into_trust_store(trust_store_path: &Path, input_pem_path: &Path) -> Result<usize> {
    let input_pem = fs::read_to_string(input_pem_path)
        .with_context(|| format!("failed to read {}", input_pem_path.display()))?;
    let blocks = extract_pem_cert_blocks(&input_pem);
    if blocks.is_empty() {
        bail!("no PEM certificates found in {}", input_pem_path.display());
    }

    let mut existing_fps: HashSet<String> = read_trust_store_fingerprints(trust_store_path)?
        .into_iter()
        .map(|s| normalize_fingerprint(&s))
        .collect();

    let input_fps = fingerprints_for_pem_file(input_pem_path)?;
    if input_fps.len() != blocks.len() {
        bail!(
            "PEM parse mismatch for {} (cert blocks != parsed certs)",
            input_pem_path.display()
        );
    }

    let mut appended = 0usize;
    let mut to_append = String::new();
    for (fp, block) in input_fps.into_iter().zip(blocks.into_iter()) {
        let norm = normalize_fingerprint(&fp.fingerprint);
        if existing_fps.insert(norm) {
            to_append.push_str(&block);
            to_append.push('\n');
            to_append.push('\n');
            appended += 1;
        }
    }

    if appended == 0 {
        return Ok(0);
    }

    if let Some(parent) = trust_store_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }

    let mut existing_text = String::new();
    if trust_store_path.exists() {
        existing_text = fs::read_to_string(trust_store_path)
            .with_context(|| format!("failed to read {}", trust_store_path.display()))?;
        if !existing_text.ends_with('\n') {
            existing_text.push('\n');
        }
    }
    existing_text.push_str(&to_append);
    if trust_store_path.exists() {
        let _ = fs::remove_file(trust_store_path);
    }
    fs::write(trust_store_path, existing_text)
        .with_context(|| format!("failed to write {}", trust_store_path.display()))?;
    Ok(appended)
}

pub fn backup_file(path: &Path, suffix: &str) -> Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("invalid path {}", path.display()))?
        .to_string_lossy()
        .to_string();
    let backup_name = format!("{file_name}{suffix}");
    let backup_path = path.with_file_name(backup_name);
    copy_file_atomic(path, &backup_path, true)
        .with_context(|| format!("failed to create backup {}", backup_path.display()))?;
    Ok(Some(backup_path))
}

fn read_cert_der_from_pem(path: &Path) -> Result<Vec<Vec<u8>>> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut reader = BufReader::new(std::io::Cursor::new(data));
    let certs = rustls_pemfile::certs(&mut reader)
        .map_err(|e| anyhow!("failed to parse PEM certs from {}: {e}", path.display()))?;
    if certs.is_empty() {
        bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

fn extract_pem_cert_blocks(pem_text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = pem_text;
    loop {
        let Some(start) = rest.find(PEM_BEGIN) else {
            break;
        };
        let after_start = &rest[start..];
        let Some(end_rel) = after_start.find(PEM_END) else {
            break;
        };
        let end = start + end_rel + PEM_END.len();
        let block = rest[start..end].to_string();
        out.push(block);
        rest = &rest[end..];
    }
    out
}
