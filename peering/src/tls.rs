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
use utilities::FileSystem;

use std::io::BufReader;
use std::sync::Arc;

pub struct TlsComponents {
    pub acceptor: TlsAcceptor,
    pub connector: TlsConnector,
}

impl TlsComponents {
    pub fn from_config(cfg: &AppConfig, fs: &dyn FileSystem) -> Result<Self> {
        let (certs, key, ca_store) = match load_tls_from_files(cfg, fs) {
            Ok(tuple) => tuple,
            Err(e) => {
                warn!(
                    "Failed to load TLS materials from disk ({}). Generating ephemeral self-signed certs instead.",
                    e
                );
                let generated = generate_ephemeral_tls(&cfg.pc_name)?;
                if let Err(write_err) = persist_generated_tls(cfg, &generated, fs) {
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

fn load_ca_store(path: &std::path::Path, fs: &dyn FileSystem) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    let data = fs.read(path)?;
    let mut reader = BufReader::new(std::io::Cursor::new(data));
    let certs = rustls_pemfile::certs(&mut reader)?;
    let (added, _ignored) = store.add_parsable_certificates(&certs);
    if added == 0 {
        bail!("no CA certificates could be loaded from {}", path.display());
    }
    Ok(store)
}

fn load_tls_from_files(
    cfg: &AppConfig,
    fs: &dyn FileSystem,
) -> Result<(Vec<Certificate>, PrivateKey, RootCertStore)> {
    let certs = load_certs(&cfg.tls_cert_path, fs)
        .with_context(|| format!("loading certs from {}", cfg.tls_cert_path.display()))?;
    let key = load_private_key(&cfg.tls_key_path, fs)
        .with_context(|| format!("loading key from {}", cfg.tls_key_path.display()))?;
    let ca_store = load_ca_store(&cfg.tls_ca_cert_path, fs)
        .with_context(|| format!("loading CA store from {}", cfg.tls_ca_cert_path.display()))?;
    Ok((certs, key, ca_store))
}

struct GeneratedTls {
    cert_chain: Vec<Certificate>,
    key: PrivateKey,
    ca_store: RootCertStore,
    leaf_pem: String,
    key_pem: String,
    ca_pem: String,
}

fn generate_ephemeral_tls(node_name: &str) -> Result<GeneratedTls> {
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
    Ok(GeneratedTls {
        cert_chain,
        key,
        ca_store,
        leaf_pem,
        key_pem,
        ca_pem,
    })
}

fn persist_generated_tls(cfg: &AppConfig, generated: &GeneratedTls, fs: &dyn FileSystem) -> Result<()> {
    if let Some(parent) = cfg.tls_cert_path.parent() {
        fs.create_dir_all(parent)?;
    }
    if let Some(parent) = cfg.tls_key_path.parent() {
        fs.create_dir_all(parent)?;
    }
    if let Some(parent) = cfg.tls_ca_cert_path.parent() {
        fs.create_dir_all(parent)?;
    }

    fs.write(&cfg.tls_cert_path, generated.leaf_pem.as_bytes())?;
    fs.write(&cfg.tls_key_path, generated.key_pem.as_bytes())?;
    fs.write(&cfg.tls_ca_cert_path, generated.ca_pem.as_bytes())?;
    info!(
        "Generated new TLS materials at {}, {}, {}",
        cfg.tls_cert_path.display(),
        cfg.tls_key_path.display(),
        cfg.tls_ca_cert_path.display()
    );
    Ok(())
}
