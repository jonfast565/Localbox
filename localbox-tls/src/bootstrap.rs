use crate::{fingerprint_hex, workflow};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use models::AppConfig;
use rand::{rngs::OsRng, RngCore};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, Signature, ECDSA_P256_SHA256_ASN1_SIGNING};
use webpki::{EndEntityCert, ECDSA_P256_SHA256};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fs;
use std::io::{BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;
use utilities::write_file_atomic;

#[derive(Debug, Serialize, Deserialize)]
pub struct InvitePayload {
    pub version: u32,
    pub issued_at: i64,
    pub issuer_pc_name: String,
    pub issuer_instance_id: String,
    pub peer_name: String,
    pub share_names: Vec<String>,
    pub ca_pem: String,
    pub leaf_cert_pem: String,
    pub leaf_fingerprint: String,
    pub token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedInvite {
    pub payload: InvitePayload,
    pub signature: String,
}

#[derive(Debug)]
pub struct AcceptResult {
    pub peer_name: String,
    pub fingerprint: String,
    pub token: String,
    pub ca_certs_added: usize,
    pub config_updated: bool,
}

pub fn issue_invite(cfg: &AppConfig, peer: &str, out: &Path, force: bool) -> Result<()> {
    if out.exists() && !force {
        bail!(
            "Refusing to overwrite existing invite at {} (pass --force to overwrite)",
            out.display()
        );
    }
    let ca_pem = fs::read_to_string(&cfg.tls_ca_cert_path)
        .with_context(|| format!("failed to read {}", cfg.tls_ca_cert_path.display()))?;
    let leaf_cert_pem = fs::read_to_string(&cfg.tls_cert_path)
        .with_context(|| format!("failed to read {}", cfg.tls_cert_path.display()))?;
    let leaf_der = {
        let mut reader = BufReader::new(leaf_cert_pem.as_bytes());
        rustls_pemfile::certs(&mut reader)
            .context("failed to parse leaf certificate")?
            .into_iter()
            .next()
            .ok_or_else(|| {
                anyhow!(
                    "leaf certificate missing from {}",
                    cfg.tls_cert_path.display()
                )
            })?
    };
    let leaf_fingerprint = fingerprint_hex(&leaf_der);
    let token = random_token();
    let payload = InvitePayload {
        version: 1,
        issued_at: current_ts(),
        issuer_pc_name: cfg.pc_name.clone(),
        issuer_instance_id: cfg.instance_id.clone(),
        peer_name: peer.to_string(),
        share_names: cfg.shares.iter().map(|s| s.name.clone()).collect(),
        ca_pem,
        leaf_cert_pem: leaf_cert_pem.clone(),
        leaf_fingerprint: leaf_fingerprint.clone(),
        token,
    };
    let payload_bytes = serde_json::to_vec(&payload)?;
    let signature = sign_payload(&cfg.tls_key_path, &payload_bytes)?;
    let signed = SignedInvite {
        payload,
        signature: BASE64.encode(signature.as_ref()),
    };
    let data = serde_json::to_vec_pretty(&signed)?;
    write_file_atomic(out, &data)?;
    Ok(())
}

pub fn accept_invite(
    cfg: &AppConfig,
    config_path: &Path,
    invite_path: &Path,
    force: bool,
) -> Result<AcceptResult> {
    if !config_path.exists() && !force {
        bail!(
            "Config file {} does not exist; run `localbox init` first or pass --force to create it",
            config_path.display()
        );
    }
    let raw = fs::read_to_string(invite_path)
        .with_context(|| format!("failed to read {}", invite_path.display()))?;
    let signed: SignedInvite = serde_json::from_str(&raw)
        .with_context(|| format!("invalid invite {}", invite_path.display()))?;
    if signed.payload.version != 1 {
        bail!("unsupported invite version {}", signed.payload.version);
    }
    let payload_bytes = serde_json::to_vec(&signed.payload)?;
    let signature = BASE64
        .decode(signed.signature.as_bytes())
        .context("invalid base64 signature in invite")?;

    let leaf_der = {
        let mut reader = BufReader::new(signed.payload.leaf_cert_pem.as_bytes());
        rustls_pemfile::certs(&mut reader)
            .context("failed to parse leaf certificates from invite")?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("invite is missing the leaf certificate"))?
    };
    let computed_fp = fingerprint_hex(&leaf_der);
    if computed_fp != signed.payload.leaf_fingerprint {
        bail!(
            "leaf fingerprint mismatch in invite (claimed {}, computed {})",
            signed.payload.leaf_fingerprint,
            computed_fp
        );
    }

    let leaf_cert = EndEntityCert::try_from(leaf_der.as_slice())
        .map_err(|_| anyhow!("invalid leaf certificate in invite"))?;
    leaf_cert
        .verify_signature(&ECDSA_P256_SHA256, &payload_bytes, &signature)
        .map_err(|_| anyhow!("signature verification failed for invite"))?;

    let ca_added = {
        let mut tmp = NamedTempFile::new().context("failed to create temp file for CA import")?;
        tmp.write_all(signed.payload.ca_pem.as_bytes())
            .context("failed to write CA PEM to temp file")?;
        tmp.flush()?;
        tmp.as_file().sync_all()?;
        workflow::import_ca_into_trust_store(&cfg.tls_ca_cert_path, tmp.path())
            .context("failed to import CA certificates")?
    };

    let config_updated = update_tls_peer_fingerprints(
        config_path,
        &signed.payload.issuer_pc_name,
        &computed_fp,
        force,
    )?;

    Ok(AcceptResult {
        peer_name: signed.payload.issuer_pc_name,
        fingerprint: computed_fp,
        token: signed.payload.token,
        ca_certs_added: ca_added,
        config_updated,
    })
}

fn sign_payload(key_path: &Path, payload: &[u8]) -> Result<Signature> {
    let key_data =
        fs::read(key_path).with_context(|| format!("failed to read {}", key_path.display()))?;
    let mut reader = BufReader::new(key_data.as_slice());
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .context("failed to parse PKCS#8 private key")?;
    let key = keys
        .pop()
        .ok_or_else(|| anyhow!("no PKCS#8 private key found in {}", key_path.display()))?;
    let rng = SystemRandom::new();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key, &rng)
        .map_err(|_| anyhow!("failed to build signing key pair"))?;
    pair.sign(&rng, payload)
        .map_err(|_| anyhow!("failed to sign invite payload"))
}

fn random_token() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    BASE64.encode(bytes)
}

fn current_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn update_tls_peer_fingerprints(
    config_path: &Path,
    peer: &str,
    fingerprint: &str,
    force: bool,
) -> Result<bool> {
    let mut doc: toml::Value = if config_path.exists() {
        toml::from_str(
            &fs::read_to_string(config_path)
                .with_context(|| format!("failed to read {}", config_path.display()))?,
        )
        .with_context(|| format!("failed to parse {}", config_path.display()))?
    } else {
        toml::Value::Table(toml::map::Map::new())
    };
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow!("config {} is not a table", config_path.display()))?;
    let fps_entry = table
        .entry("tls_peer_fingerprints")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
    let fps_table = fps_entry
        .as_table_mut()
        .ok_or_else(|| anyhow!("tls_peer_fingerprints must be a table"))?;
    let arr_entry = fps_table
        .entry(peer.to_string())
        .or_insert_with(|| toml::Value::Array(Vec::new()));
    let arr = arr_entry
        .as_array_mut()
        .ok_or_else(|| anyhow!("tls_peer_fingerprints for {} must be an array", peer))?;
    let already_present = arr.iter().any(|v| v.as_str() == Some(fingerprint));
    if already_present {
        if !force {
            return Ok(false);
        }
    } else {
        arr.push(toml::Value::String(fingerprint.to_string()));
    }
    let updated = toml::to_string_pretty(&doc)?;
    write_file_atomic(config_path, updated.as_bytes())?;
    Ok(!already_present || force)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{generate_tls_materials, persist_tls_materials};
    use models::{ApplicationState, ShareConfig};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tempfile::Builder;
    fn workspace_tempdir() -> tempfile::TempDir {
        Builder::new()
            .prefix("localbox-tls-test")
            .tempdir_in(".")
            .expect("create workspace-scoped tempdir")
    }

    #[test]
    fn invite_issue_and_accept_round_trip_updates_trust_and_config() {
        let tmp = workspace_tempdir();
        let host_cfg = sample_config(tmp.path(), "pc-host");
        let join_cfg = sample_config(tmp.path(), "pc-join");
        let invite_path = tmp.path().join("invite.json");
        let join_config_path = tmp.path().join("join-config.toml");

        issue_invite(&host_cfg, "pc-join", &invite_path, false)
            .expect("issue invite for round-trip test");
        assert!(invite_path.exists());

        // Basic sanity check on invite contents.
        let raw_invite =
            std::fs::read(&invite_path).expect("read invite file after issuing invite");
        let signed: SignedInvite =
            serde_json::from_slice(&raw_invite).expect("parse signed invite json");
        assert_eq!(signed.payload.peer_name, "pc-join");
        assert_eq!(signed.payload.issuer_pc_name, "pc-host");
        assert_eq!(signed.payload.share_names, vec!["docs".to_string()]);

        let payload_bytes =
            serde_json::to_vec(&signed.payload).expect("serialize invite payload for signature");
        let signature = BASE64
            .decode(signed.signature.as_bytes())
            .expect("decode invite signature");
        let mut reader = std::io::BufReader::new(signed.payload.leaf_cert_pem.as_bytes());
        let mut certs = rustls_pemfile::certs(&mut reader)
            .map_err(|_| "parse leaf certs from invite")
            .unwrap();
        assert!(!certs.is_empty(), "invite should contain a certificate");
        let leaf_der = certs.remove(0);
        let host_leaf = {
            let bytes = std::fs::read(&host_cfg.tls_cert_path)
                .expect("read host TLS cert for fingerprint comparison");
            let mut r = std::io::BufReader::new(bytes.as_slice());
            rustls_pemfile::certs(&mut r)
                .expect("parse host TLS cert chain")
                .remove(0)
        };
        assert_eq!(
            fingerprint_hex(&leaf_der),
            fingerprint_hex(&host_leaf),
            "invite leaf certificate must match host leaf"
        );
        let leaf_cert = EndEntityCert::try_from(leaf_der.as_slice())
            .expect("invite leaf cert must parse");
        leaf_cert
            .verify_signature(&ECDSA_P256_SHA256, &payload_bytes, &signature)
            .expect("invite signature must verify");

        // Accept invite (creating config.toml with --force semantics).
        let result = accept_invite(&join_cfg, &join_config_path, &invite_path, true)
            .expect("accept invite for join config");
        assert_eq!(result.peer_name, "pc-host");
        assert!(result.config_updated);
        assert!(result.ca_certs_added >= 1);
        assert!(!result.token.is_empty());

        let config_contents =
            std::fs::read_to_string(&join_config_path).expect("read generated join config");
        assert!(
            config_contents.contains(&result.fingerprint),
            "peer fingerprint must be written to config"
        );

        // Second acceptance should be a no-op for config/trust store.
        let second = accept_invite(&join_cfg, &join_config_path, &invite_path, false)
            .expect("re-accept invite should succeed");
        assert_eq!(second.ca_certs_added, 0);
        assert!(!second.config_updated);
    }

    #[test]
    fn accept_invite_rejects_tampered_payload() {
        let tmp = workspace_tempdir();
        let host_cfg = sample_config(tmp.path(), "pc-host");
        let join_cfg = sample_config(tmp.path(), "pc-join");
        let invite_path = tmp.path().join("invite.json");
        let join_config_path = tmp.path().join("join-config.toml");

        issue_invite(&host_cfg, "pc-join", &invite_path, false)
            .expect("issue invite for tampering test");
        let raw = std::fs::read(&invite_path).expect("read issued invite for tampering");
        let mut signed: SignedInvite =
            serde_json::from_slice(&raw).expect("parse invite json before tampering");
        signed.payload.peer_name = "pc-tampered".to_string();
        let tampered_path = tmp.path().join("invite-tampered.json");
        std::fs::write(
            &tampered_path,
            serde_json::to_vec(&signed).expect("serialize tampered invite"),
        )
        .expect("write tampered invite to disk");

        let err = accept_invite(&join_cfg, &join_config_path, &tampered_path, true).unwrap_err();
        assert!(
            err.to_string().contains("signature verification failed"),
            "tampering with payload should be detected"
        );
    }

    #[test]
    fn accept_invite_requires_existing_config_or_force() {
        let tmp = workspace_tempdir();
        let host_cfg = sample_config(tmp.path(), "pc-host");
        let join_cfg = sample_config(tmp.path(), "pc-join");
        let invite_path = tmp.path().join("invite.json");
        let missing_config_path = tmp.path().join("missing-config.toml");

        issue_invite(&host_cfg, "pc-join", &invite_path, false)
            .expect("issue invite for missing-config test");
        let err = accept_invite(&join_cfg, &missing_config_path, &invite_path, false)
            .expect_err("accept_invite should fail when config is missing without --force");
        assert!(
            err.to_string().contains("does not exist"),
            "missing config should require --force"
        );
    }

    #[test]
    fn sign_payload_round_trip_matches_leaf_certificate() {
        let tmp = workspace_tempdir();
        let cfg = sample_config(tmp.path(), "pc-roundtrip");
        let payload = b"payload-bytes";
        let sig =
            sign_payload(&cfg.tls_key_path, payload).expect("sign payload with generated key");
        let cert_bytes =
            std::fs::read(&cfg.tls_cert_path).expect("read generated leaf certificate");
        let mut reader = std::io::BufReader::new(cert_bytes.as_slice());
        let certs = rustls_pemfile::certs(&mut reader).expect("parse cert chain");
        assert!(!certs.is_empty(), "cert chain should not be empty");
        let leaf = certs.into_iter().next().expect("leaf cert present");
        let leaf_cert =
            EndEntityCert::try_from(leaf.as_slice()).expect("leaf certificate must parse");
        leaf_cert
            .verify_signature(&ECDSA_P256_SHA256, payload, sig.as_ref())
            .expect("signatures produced by sign_payload must verify");
    }

    fn sample_config(root: &Path, node: &str) -> AppConfig {
        use utilities::RealFileSystem;

        let cert_path = root.join(format!("{node}.cert.pem"));
        let key_path = root.join(format!("{node}.key.pem"));
        let ca_path = root.join(format!("{node}.ca.pem"));
        let share_root = root.join(format!("{node}-share"));
        let remote_root = root.join(format!("{node}-remote"));
        std::fs::create_dir_all(&share_root)
            .expect("create share root for sample config");
        std::fs::create_dir_all(&remote_root)
            .expect("create remote root for sample config");

        let cfg = AppConfig {
            pc_name: node.to_string(),
            instance_id: format!("{node}-inst"),
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            plain_listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            use_tls_for_peers: true,
            discovery_port: 0,
            aggregation_window_ms: 0,
            db_path: root.join(format!("{node}.db")),
            log_path: root.join(format!("{node}.log")),
            tls_cert_path: cert_path,
            tls_key_path: key_path,
            tls_ca_cert_path: ca_path,
            tls_pinned_ca_fingerprints: Vec::new(),
            tls_peer_fingerprints: HashMap::new(),
            remote_share_root: remote_root,
            shares: vec![ShareConfig {
                name: "docs".to_string(),
                root_path: share_root,
                recursive: true,
                ignore_patterns: Vec::new(),
                max_file_size_bytes: None,
            }],
            app_state: ApplicationState::MirrorHost,
        };

        let materials =
            generate_tls_materials(node).expect("generate TLS materials for sample config");
        persist_tls_materials(&cfg, &materials, &RealFileSystem::new())
            .expect("persist TLS materials for sample config");

        cfg
    }
}
