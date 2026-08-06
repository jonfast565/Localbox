use anyhow::{anyhow, bail, Context, Result};
use models::AppConfig;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType,
    PKCS_ECDSA_P256_SHA256,
};
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::{
    cipher_suite, kx_group, version, Certificate, ClientConfig, PrivateKey, RootCertStore,
    ServerConfig,
};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use utilities::{write_atomic, FileSystem};
use webpki::{EndEntityCert, SubjectNameRef};

use std::convert::TryFrom;
use std::io::BufReader;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

pub struct TlsComponents {
    pub acceptor: TlsAcceptor,
    pub connector: TlsConnector,
}

impl TlsComponents {
    pub fn from_config(cfg: &AppConfig, fs: &dyn FileSystem) -> Result<Self> {
        let loaded = match load_tls_from_files(cfg, fs) {
            Ok(loaded) => loaded,
            Err(e) => {
                if !cfg.tls_pinned_ca_fingerprints.is_empty() {
                    return Err(e).context(
                        "TLS pinning is enabled; refusing to auto-generate TLS materials",
                    );
                }
                warn!(
                    "Failed to load TLS materials from disk ({}). Generating ephemeral self-signed certs instead.",
                    e
                );
                let generated = generate_tls_materials(&cfg.pc_name)?;
                if let Err(write_err) = persist_tls_materials(cfg, &generated, fs) {
                    warn!("Could not write generated TLS materials to disk: {write_err}");
                }
                let ca_ders = {
                    let mut reader =
                        BufReader::new(std::io::Cursor::new(generated.ca_pem.as_bytes()));
                    rustls_pemfile::certs(&mut reader)?
                };
                LoadedTls {
                    certs: generated.cert_chain,
                    key: generated.key,
                    ca_store: generated.ca_store,
                    ca_ders,
                }
            }
        };
        let LoadedTls {
            certs,
            key,
            ca_store,
            ca_ders,
        } = loaded;

        let cipher_suites = [
            cipher_suite::TLS13_AES_256_GCM_SHA384,
            cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            cipher_suite::TLS13_AES_128_GCM_SHA256,
        ];
        let kx_groups = &[&kx_group::SECP256R1, &kx_group::X25519];
        let protocol_versions = &[&version::TLS13];

        let mut server_config = ServerConfig::builder()
            .with_cipher_suites(&cipher_suites)
            .with_kx_groups(kx_groups)
            .with_protocol_versions(protocol_versions)?
            .with_client_cert_verifier(Arc::new(AllowAnyAuthenticatedClient::new(ca_store.clone())))
            .with_single_cert(certs.clone(), key.clone())?;
        server_config.alpn_protocols.push(b"localbox/1".to_vec());

        let client_builder = ClientConfig::builder()
            .with_cipher_suites(&cipher_suites)
            .with_kx_groups(kx_groups)
            .with_protocol_versions(protocol_versions)?;
        let mut client_config = if cfg.tls_insecure_shared_cert {
            warn!(
                "tls_insecure_shared_cert is enabled: peer certificates are checked for a \
                 trusted issuer but NOT for peer identity, so peers cannot be told apart"
            );
            client_builder
                .with_custom_certificate_verifier(Arc::new(SharedCertServerVerifier { ca_ders }))
                .with_client_auth_cert(certs, key)?
        } else {
            client_builder
                .with_root_certificates(ca_store)
                .with_client_auth_cert(certs, key)?
        };
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

/// TLS material for one node, in the forms rustls and our own checks each need.
struct LoadedTls {
    certs: Vec<Certificate>,
    key: PrivateKey,
    ca_store: RootCertStore,
    /// The trusted CA certificates as raw DER, kept for the checks we perform
    /// ourselves — `RootCertStore` does not hand its anchors back out.
    ca_ders: Vec<Vec<u8>>,
}

fn load_tls_from_files(cfg: &AppConfig, fs: &dyn FileSystem) -> Result<LoadedTls> {
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
    Ok(LoadedTls {
        certs,
        key,
        ca_store,
        ca_ders: ca_certs,
    })
}

/// Signature algorithms accepted when validating a peer chain by hand.
///
/// Mirrors rustls's own list, which is not public.
static SUPPORTED_SIG_ALGS: &[&webpki::SignatureAlgorithm] = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

/// Verifies that a server's certificate chains to a trusted CA, but does not
/// require it to be issued for the host being dialed.
///
/// This exists solely for `tls_insecure_shared_cert`, where every node presents
/// the same certificate and so no certificate can carry the right hostname. The
/// chain is still verified — an untrusted CA is still refused — but the peer's
/// *identity* is no longer checked, which is the whole reason that mode is
/// labelled insecure.
struct SharedCertServerVerifier {
    ca_ders: Vec<Vec<u8>>,
}

impl rustls::client::ServerCertVerifier for SharedCertServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        now: SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        use rustls::{CertificateError, Error as TlsError};

        let anchors = self
            .ca_ders
            .iter()
            .map(|der| webpki::TrustAnchor::try_from_cert_der(der))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;
        let cert = EndEntityCert::try_from(end_entity.0.as_slice())
            .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;
        let intermediate_ders: Vec<&[u8]> = intermediates.iter().map(|c| c.0.as_slice()).collect();
        let time = webpki::Time::try_from(now).map_err(|_| TlsError::FailedToGetCurrentTime)?;

        cert.verify_for_usage(
            SUPPORTED_SIG_ALGS,
            &anchors,
            &intermediate_ders,
            time,
            webpki::KeyUsage::server_auth(),
            &[],
        )
        .map_err(|_| TlsError::InvalidCertificate(CertificateError::UnknownIssuer))?;

        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

pub struct TlsMaterials {
    pub cert_chain: Vec<Certificate>,
    pub key: PrivateKey,
    pub ca_store: RootCertStore,
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

pub fn persist_tls_materials(
    cfg: &AppConfig,
    generated: &TlsMaterials,
    fs: &dyn FileSystem,
) -> Result<()> {
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
    certs.into_iter().map(|der| fingerprint_hex(&der)).collect()
}

pub fn fingerprint_hex(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    digest
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn normalize_fingerprint(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

pub fn fingerprint_from_certificates(certs: Option<&[Certificate]>) -> Option<String> {
    certs
        .and_then(|chain| chain.first())
        .map(|cert| fingerprint_hex(&cert.0))
}

/// Check that a peer's leaf certificate was actually issued for the node name the
/// peer claims in its handshake.
///
/// Trusting a CA only says "this peer is a member of the network"; it says nothing
/// about *which* member. Without this binding any node holding a certificate from a
/// trusted CA could announce itself under another node's `pc_name` and receive that
/// node's shares.
pub fn verify_peer_cert_name(certs: Option<&[Certificate]>, claimed_name: &str) -> Result<()> {
    let Some(leaf) = certs.and_then(|chain| chain.first()) else {
        bail!("peer claiming to be {claimed_name} presented no TLS certificate");
    };
    let cert = EndEntityCert::try_from(leaf.0.as_slice())
        .map_err(|_| anyhow!("peer {claimed_name} presented an unparseable certificate"))?;
    let subject = SubjectNameRef::try_from_ascii_str(claimed_name).map_err(|_| {
        anyhow!(
            "peer name {claimed_name} is not a valid DNS name or IP address, so its \
             certificate cannot be bound to it; rename the node or re-issue its \
             certificate with a matching SAN"
        )
    })?;
    cert.verify_is_valid_for_subject_name(subject)
        .map_err(|_| {
            anyhow!("peer certificate is not valid for the claimed node name {claimed_name}")
        })?;
    Ok(())
}

fn pin_certs(certs: Vec<Vec<u8>>, pinned: &[String]) -> Result<Vec<Vec<u8>>> {
    let pinned_set: std::collections::HashSet<String> =
        pinned.iter().map(|s| normalize_fingerprint(s)).collect();

    let filtered: Vec<Vec<u8>> = certs
        .into_iter()
        .filter(|der| {
            let fp = normalize_fingerprint(&fingerprint_hex(der));
            pinned_set.contains(&fp)
        })
        .collect();

    if filtered.is_empty() {
        bail!("tls_pinned_ca_fingerprints did not match any certificates in the trust store");
    }
    Ok(filtered)
}

pub struct ManagedTls {
    cfg: AppConfig,
    fs: Arc<dyn FileSystem>,
    inner: RwLock<TlsComponents>,
    last_mtimes: Mutex<[Option<SystemTime>; 3]>,
}

impl ManagedTls {
    pub fn new(cfg: &AppConfig, fs: Arc<dyn FileSystem>) -> Result<Self, anyhow::Error> {
        let components = TlsComponents::from_config(cfg, fs.as_ref())?;
        let mtimes = Self::snapshot_mtimes(cfg, fs.as_ref());
        Ok(Self {
            cfg: cfg.clone(),
            fs,
            inner: RwLock::new(components),
            last_mtimes: Mutex::new(mtimes),
        })
    }

    pub async fn connector(&self) -> TlsConnector {
        self.inner.read().await.connector.clone()
    }

    pub async fn acceptor(&self) -> TlsAcceptor {
        self.inner.read().await.acceptor.clone()
    }

    pub fn spawn_watcher(self: Arc<Self>, token: CancellationToken) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = interval.tick() => {
                        if let Err(e) = self.try_reload().await {
                            warn!(error = %e, "Failed to reload TLS materials after detecting file changes");
                        }
                    }
                }
            }
        })
    }

    async fn try_reload(&self) -> Result<()> {
        let current = Self::snapshot_mtimes(&self.cfg, self.fs.as_ref());
        {
            let last = self.last_mtimes.lock().unwrap();
            if *last == current {
                return Ok(());
            }
        }

        let components = TlsComponents::from_config(&self.cfg, self.fs.as_ref())?;
        {
            let mut guard = self.inner.write().await;
            *guard = components;
        }
        {
            let mut last = self.last_mtimes.lock().unwrap();
            *last = current;
        }
        info!("Reloaded TLS materials after on-disk change");
        Ok(())
    }

    fn snapshot_mtimes(cfg: &AppConfig, fs: &dyn FileSystem) -> [Option<SystemTime>; 3] {
        [
            Self::metadata_mtime(fs, &cfg.tls_cert_path),
            Self::metadata_mtime(fs, &cfg.tls_key_path),
            Self::metadata_mtime(fs, &cfg.tls_ca_cert_path),
        ]
    }

    fn metadata_mtime(fs: &dyn FileSystem, path: &std::path::Path) -> Option<SystemTime> {
        match fs.metadata(path) {
            Ok(md) => md.modified,
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "Failed to fetch metadata for TLS material"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain_for(node: &str) -> Vec<Certificate> {
        generate_tls_materials(node)
            .expect("generate TLS materials for name-binding test")
            .cert_chain
    }

    #[test]
    fn peer_cert_name_accepts_matching_node_name() {
        let chain = chain_for("node-a");
        verify_peer_cert_name(Some(&chain), "node-a")
            .expect("certificate issued for node-a must verify for node-a");
    }

    #[test]
    fn peer_cert_name_rejects_impersonated_node_name() {
        let chain = chain_for("node-a");
        let err = verify_peer_cert_name(Some(&chain), "node-b")
            .expect_err("node-a's certificate must not satisfy a claim of being node-b");
        assert!(
            err.to_string()
                .contains("not valid for the claimed node name"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn peer_cert_name_rejects_missing_certificate() {
        let err = verify_peer_cert_name(None, "node-a")
            .expect_err("a peer with no certificate must be rejected");
        assert!(
            err.to_string().contains("presented no TLS certificate"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn peer_cert_name_accepts_unusual_but_bindable_hostnames() {
        // Underscores are irregular in DNS but webpki accepts them as presented
        // names, so hosts named this way keep working.
        let chain = chain_for("node_a");
        verify_peer_cert_name(Some(&chain), "node_a")
            .expect("an underscore hostname should still bind to its certificate");
    }

    #[test]
    fn peer_cert_name_rejects_names_that_cannot_be_bound() {
        // A name that cannot be expressed as a subject name can never be matched
        // against a SAN, so it must be rejected rather than waved through.
        let chain = chain_for("node a");
        let err = verify_peer_cert_name(Some(&chain), "node a")
            .expect_err("a name that cannot be expressed as a SAN must be rejected");
        assert!(
            err.to_string().contains("is not a valid DNS name"),
            "unexpected error: {err}"
        );
    }
}
