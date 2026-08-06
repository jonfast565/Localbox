//! Shared network certificate authority.
//!
//! The original trust model gave every node its own root CA, so trust was O(n²):
//! each pair of nodes had to exchange invite bundles and pin each other. This
//! module supports the alternative: one root CA for the whole network, whose
//! public certificate every node trusts and whose key signs one leaf per node.
//! Adding a machine then costs one signature and touches no other node's config.
//!
//! The root key is the single most sensitive file in the deployment. It is
//! written owner-only and is only ever needed on whichever machine issues
//! certificates.

use crate::{fingerprint_hex, normalize_fingerprint};
use anyhow::{anyhow, bail, Context, Result};
use models::AppConfig;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequest, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};
use utilities::{write_file_atomic, write_secret_file_atomic};
use webpki::SubjectNameRef;

/// Default lifetime for the network root, in days.
pub const DEFAULT_CA_VALIDITY_DAYS: u32 = 3650;
/// Default lifetime for an issued node certificate, in days.
///
/// Leaf lifetime is the revocation story for a shared root: there is no CRL, so
/// a decommissioned machine stops being trusted when its certificate expires.
pub const DEFAULT_LEAF_VALIDITY_DAYS: u32 = 365;

const CA_CERT_FILE: &str = "ca.cert.pem";
const CA_KEY_FILE: &str = "ca.key.pem";

/// A freshly generated network root CA.
pub struct NetworkCa {
    pub cert_pem: String,
    pub key_pem: String,
    pub fingerprint: String,
}

/// A private key and matching certificate signing request, both generated locally.
///
/// Deliberately not `Debug`: the key must not be printable by accident.
pub struct NodeCsr {
    pub csr_pem: String,
    pub key_pem: String,
}

/// Paths to the on-disk root CA material.
pub struct CaPaths {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl CaPaths {
    pub fn in_dir(dir: &Path) -> Self {
        Self {
            cert_path: dir.join(CA_CERT_FILE),
            key_path: dir.join(CA_KEY_FILE),
        }
    }
}

/// Reject node names that could never be bound to a certificate.
///
/// A leaf is only useful if the name it carries can be matched against the name a
/// peer claims at connection time, so names that cannot be expressed as a subject
/// name are refused here rather than producing a certificate that always fails.
pub fn validate_node_name(name: &str) -> Result<()> {
    if name.trim() != name || name.is_empty() {
        bail!("node name '{name}' must not be empty or padded with whitespace");
    }
    SubjectNameRef::try_from_ascii_str(name).map_err(|_| {
        anyhow!(
            "node name '{name}' is not a valid DNS name or IP address, so no certificate \
             could ever be bound to it"
        )
    })?;
    Ok(())
}

/// Create a new network root CA.
pub fn generate_network_ca(name: &str, validity_days: u32) -> Result<NetworkCa> {
    let mut params = CertificateParams::default();
    params.alg = &PKCS_ECDSA_P256_SHA256;
    params.key_pair = Some(KeyPair::generate(&PKCS_ECDSA_P256_SHA256)?);
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name.to_string());
        dn
    };
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params.use_authority_key_identifier_extension = true;
    let (not_before, not_after) = validity_window(validity_days)?;
    params.not_before = not_before;
    params.not_after = not_after;

    let ca = rcgen::Certificate::from_params(params)?;
    // Serialize exactly once: rcgen signs on each call and ECDSA signatures are
    // randomized, so a second call would yield a different certificate — and a
    // fingerprint that does not describe the CA we are about to write out.
    let cert_pem = ca.serialize_pem()?;
    let fingerprint = fingerprint_of_pem(&cert_pem)?;
    Ok(NetworkCa {
        cert_pem,
        key_pem: ca.get_key_pair().serialize_pem(),
        fingerprint,
    })
}

/// Write a generated root CA to disk, refusing to clobber an existing one.
///
/// Overwriting a live root would silently invalidate every certificate already
/// issued from it, so this never overwrites without `force`.
pub fn write_network_ca(paths: &CaPaths, ca: &NetworkCa, force: bool) -> Result<()> {
    for path in [&paths.cert_path, &paths.key_path] {
        if path.exists() && !force {
            bail!(
                "{} already exists; refusing to replace a live CA (pass --force only if you \
                 intend to invalidate every certificate it has issued)",
                path.display()
            );
        }
    }
    if paths.key_path.exists() {
        std::fs::remove_file(&paths.key_path)
            .with_context(|| format!("failed to replace {}", paths.key_path.display()))?;
    }
    write_file_atomic(&paths.cert_path, ca.cert_pem.as_bytes())
        .with_context(|| format!("failed to write {}", paths.cert_path.display()))?;
    write_secret_file_atomic(&paths.key_path, ca.key_pem.as_bytes())
        .with_context(|| format!("failed to write {}", paths.key_path.display()))?;
    Ok(())
}

/// A loaded root CA, ready to issue certificates.
pub struct CaSigner {
    inner: rcgen::Certificate,
    /// The root's certificate exactly as stored on disk.
    ///
    /// Kept verbatim rather than re-serialized from `inner`: loading a CA for
    /// signing only recovers the fields needed to sign, so re-serializing would
    /// produce a certificate with different bytes — and therefore a different
    /// fingerprint — from the root that peers actually trust.
    pub cert_pem: String,
    pub fingerprint: String,
}

impl CaSigner {
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key_pair =
            KeyPair::from_pem(key_pem).map_err(|e| anyhow!("failed to parse CA key: {e}"))?;
        let params = CertificateParams::from_ca_cert_pem(cert_pem, key_pair)
            .map_err(|e| anyhow!("failed to load CA certificate: {e}"))?;
        let inner = rcgen::Certificate::from_params(params)
            .map_err(|e| anyhow!("failed to prepare CA for signing: {e}"))?;
        Ok(Self {
            inner,
            cert_pem: cert_pem.to_string(),
            fingerprint: fingerprint_of_pem(cert_pem)?,
        })
    }
}

/// Load an on-disk root CA so it can sign certificates.
pub fn load_ca_signer(paths: &CaPaths) -> Result<CaSigner> {
    let cert_pem = std::fs::read_to_string(&paths.cert_path)
        .with_context(|| format!("failed to read {}", paths.cert_path.display()))?;
    let key_pem = std::fs::read_to_string(&paths.key_path).with_context(|| {
        format!(
            "failed to read {} (the CA key is only present on the machine that issues \
             certificates)",
            paths.key_path.display()
        )
    })?;
    CaSigner::from_pem(&cert_pem, &key_pem)
        .with_context(|| format!("failed to load CA from {}", paths.cert_path.display()))
}

/// Read the root CA certificate PEM and its fingerprint.
pub fn read_ca_cert(paths: &CaPaths) -> Result<(String, String)> {
    let cert_pem = std::fs::read_to_string(&paths.cert_path)
        .with_context(|| format!("failed to read {}", paths.cert_path.display()))?;
    let fp = fingerprint_of_pem(&cert_pem)?;
    Ok((cert_pem, fp))
}

/// SHA-256 fingerprint of the first certificate in a PEM blob.
pub fn fingerprint_of_pem(pem: &str) -> Result<String> {
    let mut reader = BufReader::new(pem.as_bytes());
    let der = rustls_pemfile::certs(&mut reader)
        .context("failed to parse certificate PEM")?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no certificate found in PEM data"))?;
    Ok(fingerprint_hex(&der))
}

/// Generate a private key and CSR for a node. The key never leaves this machine.
pub fn generate_node_csr(node_name: &str) -> Result<NodeCsr> {
    validate_node_name(node_name)?;
    let mut params = CertificateParams::new(vec![node_name.to_string()]);
    params.alg = &PKCS_ECDSA_P256_SHA256;
    params.key_pair = Some(KeyPair::generate(&PKCS_ECDSA_P256_SHA256)?);
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, node_name.to_string());
        dn
    };
    params.subject_alt_names = vec![SanType::DnsName(node_name.to_string())];
    let cert = rcgen::Certificate::from_params(params)?;
    Ok(NodeCsr {
        csr_pem: cert.serialize_request_pem()?,
        key_pem: cert.get_key_pair().serialize_pem(),
    })
}

/// Sign a CSR as `node_name`, returning a leaf + root chain in PEM form.
///
/// The name in the returned certificate comes from `node_name`, never from the
/// request: a CSR is attacker-controlled, so anything it asks for beyond "here is
/// my public key, and I can prove I hold the private half" is discarded. The
/// caller is responsible for deciding that `node_name` is authorized.
pub fn sign_node_csr(
    ca: &CaSigner,
    csr_pem: &str,
    node_name: &str,
    validity_days: u32,
) -> Result<String> {
    validate_node_name(node_name)?;
    // from_pem verifies the request's self-signature, which is the proof that the
    // requester holds the private key for the public key it is presenting.
    let mut csr = CertificateSigningRequest::from_pem(csr_pem)
        .map_err(|e| anyhow!("failed to parse certificate signing request: {e}"))?;

    csr.params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, node_name.to_string());
        dn
    };
    csr.params.subject_alt_names = vec![SanType::DnsName(node_name.to_string())];
    csr.params.is_ca = IsCa::NoCa;
    csr.params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    // Nodes act as both ends of a mutually authenticated connection.
    csr.params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let (not_before, not_after) = validity_window(validity_days)?;
    csr.params.not_before = not_before;
    csr.params.not_after = not_after;

    let leaf_pem = csr
        .serialize_pem_with_signer(&ca.inner)
        .map_err(|e| anyhow!("failed to sign certificate request: {e}"))?;
    Ok(format!(
        "{}\n{}",
        leaf_pem.trim_end(),
        ca.cert_pem.trim_end()
    ))
}

/// Result of installing issued material onto a node.
pub struct InstallResult {
    pub leaf_fingerprint: String,
    pub ca_fingerprint: String,
    pub ca_certs_added: usize,
}

/// Write an issued certificate chain, its private key, and the root CA into the
/// paths this node's config points at.
///
/// The root is merged into the existing trust store rather than replacing it, so
/// a node can be migrated to the shared root while it still trusts peers it
/// bootstrapped the old way.
pub fn install_node_materials(
    cfg: &AppConfig,
    chain_pem: &str,
    key_pem: &str,
    ca_pem: &str,
) -> Result<InstallResult> {
    let leaf_fingerprint = fingerprint_of_pem(chain_pem)?;
    let ca_fingerprint = fingerprint_of_pem(ca_pem)?;

    write_file_atomic(&cfg.tls_cert_path, chain_pem.as_bytes())
        .with_context(|| format!("failed to write {}", cfg.tls_cert_path.display()))?;
    if cfg.tls_key_path.exists() {
        std::fs::remove_file(&cfg.tls_key_path)
            .with_context(|| format!("failed to replace {}", cfg.tls_key_path.display()))?;
    }
    write_secret_file_atomic(&cfg.tls_key_path, key_pem.as_bytes())
        .with_context(|| format!("failed to write {}", cfg.tls_key_path.display()))?;
    let ca_certs_added =
        crate::workflow::import_ca_pem_into_trust_store(&cfg.tls_ca_cert_path, ca_pem)
            .with_context(|| format!("failed to update {}", cfg.tls_ca_cert_path.display()))?;

    Ok(InstallResult {
        leaf_fingerprint,
        ca_fingerprint,
        ca_certs_added,
    })
}

/// Confirm a certificate chain really was issued by the expected root.
///
/// Guards the enrollment path: a response is only worth installing if it chains to
/// the root the operator named, not merely to some root the sender chose.
pub fn chain_matches_ca(chain_pem: &str, expected_ca_fingerprint: &str) -> Result<()> {
    let mut reader = BufReader::new(chain_pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader).context("failed to parse certificate chain")?;
    if certs.len() < 2 {
        bail!("certificate chain is missing its issuing CA certificate");
    }
    let expected = normalize_fingerprint(expected_ca_fingerprint);
    let issuer_fp = normalize_fingerprint(&fingerprint_hex(certs.last().unwrap()));
    if issuer_fp != expected {
        bail!(
            "certificate chain was issued by an unexpected CA (got {}, expected {})",
            issuer_fp,
            expected
        );
    }
    Ok(())
}

/// One certificate and key intended to be copied to every node in a network.
///
/// Deliberately not `Debug`: it carries a private key.
pub struct SharedBundle {
    pub chain_pem: String,
    pub key_pem: String,
    pub ca_pem: String,
    pub ca_fingerprint: String,
}

/// Issue a single certificate for an entire network to share.
///
/// This trades away peer identity: every node presents the same certificate, so
/// nodes cannot distinguish each other and anyone who obtains the bundle can act
/// as any node. Nodes installing it must also set `tls_insecure_shared_cert`,
/// without which they will reject each other for exactly that reason. Prefer
/// per-node enrollment unless the convenience is genuinely worth this.
pub fn issue_shared_bundle(ca: &CaSigner, name: &str, validity_days: u32) -> Result<SharedBundle> {
    let csr = generate_node_csr(name)?;
    let chain_pem = sign_node_csr(ca, &csr.csr_pem, name, validity_days)?;
    Ok(SharedBundle {
        chain_pem,
        key_pem: csr.key_pem,
        ca_pem: ca.cert_pem.clone(),
        ca_fingerprint: ca.fingerprint.clone(),
    })
}

/// Pull the issuing CA certificate out of a leaf+CA chain.
pub fn ca_pem_from_chain(chain_pem: &str) -> Result<String> {
    let blocks = crate::workflow::extract_pem_cert_blocks(chain_pem);
    if blocks.len() < 2 {
        bail!(
            "certificate chain must contain the leaf followed by its issuing CA \
             (found {} certificate(s))",
            blocks.len()
        );
    }
    Ok(format!("{}\n", blocks.last().unwrap()))
}

/// Record a root CA fingerprint in `tls_pinned_ca_fingerprints` in config.toml.
///
/// Pinning the shared root means a certificate that merely lands in the trust
/// store — say, from an old invite — cannot quietly become an accepted issuer.
/// Returns true when the config was changed.
pub fn pin_ca_in_config(config_path: &Path, fingerprint: &str) -> Result<bool> {
    let mut doc: toml::Value = if config_path.exists() {
        toml::from_str(
            &std::fs::read_to_string(config_path)
                .with_context(|| format!("failed to read {}", config_path.display()))?,
        )
        .with_context(|| format!("failed to parse {}", config_path.display()))?
    } else {
        toml::Value::Table(toml::map::Map::new())
    };
    let table = doc
        .as_table_mut()
        .ok_or_else(|| anyhow!("config {} is not a table", config_path.display()))?;
    let entry = table
        .entry("tls_pinned_ca_fingerprints")
        .or_insert_with(|| toml::Value::Array(Vec::new()));
    let arr = entry
        .as_array_mut()
        .ok_or_else(|| anyhow!("tls_pinned_ca_fingerprints must be an array"))?;

    let normalized = normalize_fingerprint(fingerprint);
    let already_present = arr
        .iter()
        .any(|v| v.as_str().map(normalize_fingerprint) == Some(normalized.clone()));
    if already_present {
        return Ok(false);
    }
    arr.push(toml::Value::String(fingerprint.to_string()));
    let updated = toml::to_string_pretty(&doc)?;
    write_file_atomic(config_path, updated.as_bytes())
        .with_context(|| format!("failed to write {}", config_path.display()))?;
    Ok(true)
}

fn validity_window(days: u32) -> Result<(OffsetDateTime, OffsetDateTime)> {
    if days == 0 {
        bail!("validity must be at least one day");
    }
    let now = OffsetDateTime::now_utc();
    // Backdate slightly so a node whose clock is a little behind the issuer does
    // not reject a certificate that was just minted for it.
    let not_before = now - Duration::hours(1);
    let not_after = now
        .checked_add(Duration::days(i64::from(days)))
        .ok_or_else(|| anyhow!("validity of {days} days overflows the certificate date range"))?;
    Ok((not_before, not_after))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_peer_cert_name;
    use rustls::Certificate;

    fn chain_certs(chain_pem: &str) -> Vec<Certificate> {
        let mut reader = BufReader::new(chain_pem.as_bytes());
        rustls_pemfile::certs(&mut reader)
            .expect("parse signed chain")
            .into_iter()
            .map(Certificate)
            .collect()
    }

    #[test]
    fn signed_leaf_is_bound_to_the_authorized_name() {
        let ca = generate_network_ca("test-net", DEFAULT_CA_VALIDITY_DAYS).expect("generate CA");
        let signer = CaSigner::from_pem(&ca.cert_pem, &ca.key_pem).expect("load CA signer");
        let csr = generate_node_csr("node-a").expect("generate CSR");
        let chain = sign_node_csr(&signer, &csr.csr_pem, "node-a", 30).expect("sign CSR");

        let certs = chain_certs(&chain);
        assert_eq!(certs.len(), 2, "chain should carry the leaf and the root");
        verify_peer_cert_name(Some(&certs), "node-a").expect("leaf must bind to node-a");
        verify_peer_cert_name(Some(&certs), "node-b")
            .expect_err("leaf must not bind to another name");
        chain_matches_ca(&chain, &ca.fingerprint).expect("chain must match the issuing root");
    }

    #[test]
    fn csr_cannot_choose_its_own_identity() {
        let ca = generate_network_ca("test-net", DEFAULT_CA_VALIDITY_DAYS).expect("generate CA");
        let signer = CaSigner::from_pem(&ca.cert_pem, &ca.key_pem).expect("load CA signer");
        // A machine asks to be called "victim"; the CA authorizes it as "attacker".
        let csr = generate_node_csr("victim").expect("generate CSR");
        let chain = sign_node_csr(&signer, &csr.csr_pem, "attacker", 30).expect("sign CSR");

        let certs = chain_certs(&chain);
        verify_peer_cert_name(Some(&certs), "attacker").expect("leaf binds to the authorized name");
        verify_peer_cert_name(Some(&certs), "victim")
            .expect_err("the name requested in the CSR must be ignored");
    }

    #[test]
    fn chain_from_a_different_ca_is_rejected() {
        let ca = generate_network_ca("test-net", 3650).expect("generate CA");
        let other = generate_network_ca("other-net", 3650).expect("generate other CA");
        let signer = CaSigner::from_pem(&ca.cert_pem, &ca.key_pem).expect("load CA signer");
        let csr = generate_node_csr("node-a").expect("generate CSR");
        let chain = sign_node_csr(&signer, &csr.csr_pem, "node-a", 30).expect("sign CSR");

        let err = chain_matches_ca(&chain, &other.fingerprint)
            .expect_err("a chain from another root must be refused");
        assert!(
            err.to_string().contains("unexpected CA"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_shared_bundle_carries_no_per_node_identity() {
        let ca = generate_network_ca("test-net", DEFAULT_CA_VALIDITY_DAYS).expect("generate CA");
        let signer = CaSigner::from_pem(&ca.cert_pem, &ca.key_pem).expect("load CA signer");
        let bundle = issue_shared_bundle(&signer, "localbox-shared", 30).expect("issue bundle");

        // It chains to the network root, so the issuer check still passes...
        chain_matches_ca(&bundle.chain_pem, &ca.fingerprint).expect("bundle must chain to the CA");
        // ...but it names nobody in particular, which is exactly why nodes using
        // it must opt into tls_insecure_shared_cert.
        let certs = chain_certs(&bundle.chain_pem);
        verify_peer_cert_name(Some(&certs), "node-a")
            .expect_err("a shared certificate must not authenticate any specific node");
        verify_peer_cert_name(Some(&certs), "node-b")
            .expect_err("a shared certificate must not authenticate any specific node");
    }

    #[test]
    fn unbindable_node_names_are_refused() {
        let err = match generate_node_csr("node a") {
            Ok(_) => panic!("a name with a space cannot be bound to a certificate"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("not a valid DNS name"),
            "unexpected error: {err}"
        );
    }
}
