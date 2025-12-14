use anyhow::{anyhow, bail, Context, Result};
use models::AppConfig;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{info, warn};
use utilities::{write_atomic, FileSystem};

use std::io::BufReader;
use std::sync::Arc;

use sha2::{Digest, Sha256};

pub struct TlsComponents {
    pub acceptor: TlsAcceptor,
    pub connector: TlsConnector,
}

impl TlsComponents {
    pub fn from_config(cfg: &AppConfig, fs: &dyn FileSystem) -> Result<Self> {
        let (certs, key, ca_store) = match load_tls_from_files(cfg, fs) {
            Ok(tuple) => tuple,
            Err(e) => {
                if !cfg.tls_pinned_ca_fingerprints.is_empty() {
                    return Err(e).context("TLS pinning is enabled; refusing to auto-generate TLS materials");
                }
                warn!(
                    "Failed to load TLS materials from disk ({}). Generating ephemeral self-signed certs instead.",
                    e
                );
                let generated = generate_tls_materials(&cfg.pc_name)?;
                if let Err(write_err) = persist_tls_materials(cfg, &generated, fs) {
                    warn!("Could not write generated TLS materials to disk: {write_err}");
                }
                (generated.cert_chain, generated.key, generated.ca_store)
            }
        };

        let mut server_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::new(AllowAnyAuthenticatedClient::new(ca_store.clone())))
            .with_single_cert(certs.clone(), key.clone())?;
        server_config.alpn_protocols.push(b"localbox/1".to_vec());

        let mut client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(ca_store)
            .with_client_auth_cert(certs, key)?;
        client_config.alpn_protocols.push(b"localbox/1".to_vec());

        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(server_config)),
            connector: TlsConnector::from(Arc::new(client_config)),
        })
    }
}

fn load_certs(path: &std::path::Path, fs: &dyn FileSystem) -> Result<Vec<Certificate>> {
    let data = fs.read(path)?;
    let mut reader = BufReader::new(std::io::Cursor::new(data));
    let certs = rustls_pemfile::certs(&mut reader)?
        .into_iter()
        .map(Certificate)
        .collect();
    Ok(certs)
}

fn load_private_key(path: &std::path::Path, fs: &dyn FileSystem) -> Result<PrivateKey> {
    let data = fs.read(path)?;
    let mut reader = BufReader::new(std::io::Cursor::new(data));
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)?;
    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no PKCS8 keys in {}", path.display()))?;
    Ok(PrivateKey(key))
}

fn load_ca_store(path: &std::path::Path, fs: &dyn FileSystem) -> Result<Vec<Vec<u8>>> {
    let data = fs.read(path)?;
    let mut reader = BufReader::new(std::io::Cursor::new(data));
    let certs = rustls_pemfile::certs(&mut reader)?;
    if certs.is_empty() {
        bail!("no CA certificates could be loaded from {}", path.display());
    }
    Ok(certs)
}

fn load_tls_from_files(
    cfg: &AppConfig,
    fs: &dyn FileSystem,
) -> Result<(Vec<Certificate>, PrivateKey, RootCertStore)> {
    let certs = load_certs(&cfg.tls_cert_path, fs)
        .with_context(|| format!("loading certs from {}", cfg.tls_cert_path.display()))?;
    let key = load_private_key(&cfg.tls_key_path, fs)
        .with_context(|| format!("loading key from {}", cfg.tls_key_path.display()))?;
    let mut ca_certs = load_ca_store(&cfg.tls_ca_cert_path, fs)
        .with_context(|| format!("loading CA store from {}", cfg.tls_ca_cert_path.display()))?;

    if !cfg.tls_pinned_ca_fingerprints.is_empty() {
        ca_certs = pin_certs(ca_certs, &cfg.tls_pinned_ca_fingerprints)?;
    }

    let mut ca_store = RootCertStore::empty();
    let (added, _ignored) = ca_store.add_parsable_certificates(&ca_certs);
    if added == 0 {
        bail!(
            "no CA certificates could be loaded from {} (after pinning/filtering)",
            cfg.tls_ca_cert_path.display()
        );
    }
    Ok((certs, key, ca_store))
}

pub struct TlsMaterials {
    cert_chain: Vec<Certificate>,
    key: PrivateKey,
    ca_store: RootCertStore,
    pub cert_chain_pem: String,
    pub key_pem: String,
    pub ca_pem: String,
}

pub fn generate_tls_materials(node_name: &str) -> Result<TlsMaterials> {
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, format!("{node_name}-ca"));
        dn
    };
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_cert = rcgen::Certificate::from_params(ca_params)?;

    let mut leaf_params = CertificateParams::new(vec![node_name.to_string()]);
    leaf_params
        .subject_alt_names
        .push(SanType::DnsName(node_name.to_string()));
    leaf_params.key_pair = Some(KeyPair::generate(&PKCS_ECDSA_P256_SHA256)?);
    leaf_params.is_ca = IsCa::NoCa;
    let leaf = rcgen::Certificate::from_params(leaf_params)?;

    let leaf_der = leaf.serialize_der_with_signer(&ca_cert)?;
    let leaf_key = leaf.get_key_pair().serialize_der();
    let ca_der = ca_cert.serialize_der()?;
    let ca_pem = ca_cert.serialize_pem()?;
    let leaf_pem = leaf.serialize_pem_with_signer(&ca_cert)?;
    let key_pem = leaf.get_key_pair().serialize_pem();

    let mut ca_store = RootCertStore::empty();
    ca_store.add_parsable_certificates(&[ca_der.clone()]);

    let cert_chain = vec![Certificate(leaf_der), Certificate(ca_der)];
    let key = PrivateKey(leaf_key);
    Ok(TlsMaterials {
        cert_chain,
        key,
        ca_store,
        cert_chain_pem: format!("{leaf_pem}\n{ca_pem}"),
        key_pem,
        ca_pem,
    })
}

pub fn persist_tls_materials(cfg: &AppConfig, generated: &TlsMaterials, fs: &dyn FileSystem) -> Result<()> {
    if let Some(parent) = cfg.tls_cert_path.parent() {
        fs.create_dir_all(parent)?;
    }
    if let Some(parent) = cfg.tls_key_path.parent() {
        fs.create_dir_all(parent)?;
    }
    if let Some(parent) = cfg.tls_ca_cert_path.parent() {
        fs.create_dir_all(parent)?;
    }

    write_atomic(fs, &cfg.tls_cert_path, generated.cert_chain_pem.as_bytes())?;
    write_atomic(fs, &cfg.tls_key_path, generated.key_pem.as_bytes())?;

    // Preserve any existing trust store and append our CA if it's not present.
    let mut existing = String::new();
    if let Ok(bytes) = fs.read(&cfg.tls_ca_cert_path) {
        existing = String::from_utf8_lossy(&bytes).to_string();
    }
    let merged = merge_ca_bundle(&existing, &generated.ca_pem);
    write_atomic(fs, &cfg.tls_ca_cert_path, merged.as_bytes())?;
    info!(
        "Generated new TLS materials at {}, {}, {}",
        cfg.tls_cert_path.display(),
        cfg.tls_key_path.display(),
        cfg.tls_ca_cert_path.display()
    );
    Ok(())
}

fn merge_ca_bundle(existing_pem: &str, ca_pem: &str) -> String {
    let mut out = existing_pem.to_string();
    if !out.ends_with('\n') && !out.is_empty() {
        out.push('\n');
    }
    let existing_fps = fingerprints_from_pem(existing_pem);
    let ca_fps = fingerprints_from_pem(ca_pem);
    let already_present = ca_fps.iter().all(|fp| existing_fps.contains(fp));
    if !already_present {
        out.push_str(ca_pem);
        out.push('\n');
    }
    out
}

fn fingerprints_from_pem(pem: &str) -> Vec<String> {
    let mut reader = BufReader::new(std::io::Cursor::new(pem.as_bytes()));
    let certs = rustls_pemfile::certs(&mut reader).unwrap_or_default();
    certs.into_iter().map(|der| sha256_fp(&der)).collect()
}

fn sha256_fp(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    digest.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":")
}

fn pin_certs(certs: Vec<Vec<u8>>, pinned: &[String]) -> Result<Vec<Vec<u8>>> {
    let pinned_set: std::collections::HashSet<String> = pinned
        .iter()
        .map(|s| {
            s.chars()
                .filter(|c| c.is_ascii_hexdigit())
                .map(|c| c.to_ascii_uppercase())
                .collect::<String>()
        })
        .collect();

    let filtered: Vec<Vec<u8>> = certs
        .into_iter()
        .filter(|der| {
            let fp = sha256_fp(der);
            let norm: String = fp.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            pinned_set.contains(&norm)
        })
        .collect();

    if filtered.is_empty() {
        bail!("tls_pinned_ca_fingerprints did not match any certificates in the trust store");
    }
    Ok(filtered)
}
