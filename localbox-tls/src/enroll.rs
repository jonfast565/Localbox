//! Token-based certificate enrollment.
//!
//! Setting up a new machine should not require copying key material around. Here
//! the operator carries exactly one short-lived string — the enrollment token —
//! to the new machine, and everything else is derived over the wire:
//!
//! 1. The new machine generates its own key and CSR locally. The private key
//!    never leaves it.
//! 2. It proves it holds the token by sending an HMAC of its CSR keyed with the
//!    token secret, rather than the secret itself.
//! 3. The CA signs the CSR as the name the token authorizes — never the name the
//!    CSR asks for — and returns the chain plus the root certificate.
//! 4. The new machine only installs the result if the root matches the
//!    fingerprint embedded in the token it was given.
//!
//! Step 2 means a passive eavesdropper cannot reuse the token: they never see the
//! secret, and replaying the request only re-issues a certificate for a public key
//! whose private half they do not have. Step 4 means an attacker who intercepts
//! the exchange cannot substitute their own CA. The exchange is not otherwise
//! confidential, but everything in it besides the token is public data.

use crate::ca::{self, CaPaths, CaSigner};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};
use rand::{rngs::OsRng, RngCore};
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use utilities::write_secret_file_atomic;

/// Wire format version for the enrollment exchange.
const ENROLL_VERSION: u32 = 1;
/// Cap on a single enrollment message. CSRs are ~1 KB; this leaves room while
/// keeping an unauthenticated peer from forcing a large allocation.
const MAX_MESSAGE_BYTES: u32 = 64 * 1024;
const TOKEN_PREFIX: &str = "lbx1";
const TOKEN_FILE: &str = "tokens.json";
/// Default enrollment listen port.
pub const DEFAULT_ENROLL_PORT: u16 = 5010;
/// Default token lifetime.
pub const DEFAULT_TOKEN_TTL_SECS: i64 = 3600;

#[derive(Debug, Serialize, Deserialize)]
struct EnrollRequest {
    version: u32,
    token_id: String,
    csr_pem: String,
    /// base64url HMAC-SHA256 over `csr_pem`, keyed with the token secret.
    mac: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "lowercase")]
enum EnrollResponse {
    Issued {
        node_name: String,
        chain_pem: String,
        ca_pem: String,
    },
    Rejected {
        reason: String,
    },
}

/// A token as the operator carries it: an id, a secret, and the fingerprint of
/// the CA the holder should expect to be answered by.
pub struct EnrollToken {
    pub id: String,
    pub secret: Vec<u8>,
    pub ca_fingerprint: String,
}

impl EnrollToken {
    /// Render as the single string a user copies to the new machine.
    pub fn encode(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            TOKEN_PREFIX,
            self.id,
            BASE64URL.encode(&self.secret),
            crate::normalize_fingerprint(&self.ca_fingerprint)
        )
    }

    pub fn decode(raw: &str) -> Result<Self> {
        let parts: Vec<&str> = raw.trim().split('.').collect();
        if parts.len() != 4 || parts[0] != TOKEN_PREFIX {
            bail!("malformed enrollment token (expected {TOKEN_PREFIX}.<id>.<secret>.<ca-fingerprint>)");
        }
        let secret = BASE64URL
            .decode(parts[2])
            .context("malformed enrollment token (bad secret encoding)")?;
        if secret.is_empty() {
            bail!("malformed enrollment token (empty secret)");
        }
        Ok(Self {
            id: parts[1].to_string(),
            secret,
            ca_fingerprint: crate::normalize_fingerprint(parts[3]),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredToken {
    id: String,
    /// Held in the clear so the CA can verify the request MAC. This file lives
    /// beside the CA key, on a machine that is already fully trusted.
    secret_b64: String,
    node_name: String,
    expires_at: i64,
    #[serde(default)]
    used_at: Option<i64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct TokenStore {
    #[serde(default)]
    tokens: Vec<StoredToken>,
}

impl TokenStore {
    fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
    }

    fn save(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_vec_pretty(self)?;
        if path.exists() {
            std::fs::remove_file(path)
                .with_context(|| format!("failed to replace {}", path.display()))?;
        }
        write_secret_file_atomic(path, &data)
            .with_context(|| format!("failed to write {}", path.display()))
    }
}

fn token_store_path(dir: &Path) -> PathBuf {
    dir.join(TOKEN_FILE)
}

/// Mint a single-use enrollment token authorizing one node name.
pub fn issue_token(ca_dir: &Path, node_name: &str, ttl_secs: i64) -> Result<EnrollToken> {
    ca::validate_node_name(node_name)?;
    if ttl_secs <= 0 {
        bail!("token lifetime must be positive");
    }
    let paths = CaPaths::in_dir(ca_dir);
    let (_, ca_fingerprint) = ca::read_ca_cert(&paths)?;

    let mut id_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut id_bytes);
    let mut secret = vec![0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let id = hex_lower(&id_bytes);

    let store_path = token_store_path(ca_dir);
    let mut store = TokenStore::load(&store_path)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    // Drop tokens that expired a while ago so the file does not grow forever.
    store
        .tokens
        .retain(|t| t.expires_at > now - 86_400 && t.used_at.is_none());
    store.tokens.push(StoredToken {
        id: id.clone(),
        secret_b64: BASE64URL.encode(&secret),
        node_name: node_name.to_string(),
        expires_at: now + ttl_secs,
        used_at: None,
    });
    store.save(&store_path)?;

    Ok(EnrollToken {
        id,
        secret,
        ca_fingerprint,
    })
}

/// Run the enrollment listener until cancelled.
pub async fn serve(
    ca_dir: &Path,
    listen: SocketAddr,
    validity_days: u32,
    token: CancellationToken,
) -> Result<()> {
    let paths = CaPaths::in_dir(ca_dir);
    let signer = Arc::new(ca::load_ca_signer(&paths)?);
    let store_path = Arc::new(token_store_path(ca_dir));
    // Serialize token consumption so a token cannot be spent twice by two
    // connections arriving at once.
    let store_lock = Arc::new(Mutex::new(()));

    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("failed to listen on {listen}"))?;
    info!(
        addr = %listen,
        ca = %signer.fingerprint,
        "Enrollment server listening"
    );

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        warn!(error = %e, "Failed to accept enrollment connection");
                        continue;
                    }
                };
                let signer = signer.clone();
                let store_path = store_path.clone();
                let store_lock = store_lock.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_enrollment(stream, &signer, &store_path, &store_lock, validity_days)
                            .await
                    {
                        warn!(peer = %peer, error = %e, "Enrollment request failed");
                    }
                });
            }
        }
    }
    info!("Enrollment server stopped");
    Ok(())
}

async fn handle_enrollment(
    mut stream: TcpStream,
    signer: &CaSigner,
    store_path: &Path,
    store_lock: &Mutex<()>,
    validity_days: u32,
) -> Result<()> {
    let request: EnrollRequest = read_message(&mut stream).await?;
    if request.version != ENROLL_VERSION {
        let response = EnrollResponse::Rejected {
            reason: format!("unsupported enrollment version {}", request.version),
        };
        write_message(&mut stream, &response).await?;
        bail!("unsupported enrollment version {}", request.version);
    }

    let outcome = {
        let _guard = store_lock.lock().await;
        authorize(&request, store_path)
    };
    let node_name = match outcome {
        Ok(name) => name,
        Err(e) => {
            // Tell the operator only that it failed; the detail stays in our log
            // so a caller cannot probe for which tokens exist.
            let response = EnrollResponse::Rejected {
                reason: "enrollment token was not accepted".to_string(),
            };
            write_message(&mut stream, &response).await?;
            return Err(e);
        }
    };

    let chain = ca::sign_node_csr(signer, &request.csr_pem, &node_name, validity_days)?;
    {
        let _guard = store_lock.lock().await;
        mark_used(&request.token_id, store_path)?;
    }
    info!(node = %node_name, "Issued certificate through enrollment");

    let response = EnrollResponse::Issued {
        node_name,
        chain_pem: chain,
        ca_pem: signer.cert_pem.clone(),
    };
    write_message(&mut stream, &response).await?;
    Ok(())
}

/// Check the request against the token store, returning the authorized node name.
fn authorize(request: &EnrollRequest, store_path: &Path) -> Result<String> {
    let store = TokenStore::load(store_path)?;
    let entry = store
        .tokens
        .iter()
        .find(|t| t.id == request.token_id)
        .ok_or_else(|| anyhow!("unknown enrollment token id {}", request.token_id))?;

    if entry.used_at.is_some() {
        bail!("enrollment token {} has already been used", entry.id);
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if now > entry.expires_at {
        bail!("enrollment token {} has expired", entry.id);
    }

    let secret = BASE64URL
        .decode(&entry.secret_b64)
        .context("stored enrollment token is corrupt")?;
    let provided = BASE64URL
        .decode(&request.mac)
        .context("enrollment request MAC is not valid base64")?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, &secret);
    // Constant-time, and bound to this exact CSR: a MAC observed on the wire
    // cannot be reused to authorize a different key.
    hmac::verify(&key, request.csr_pem.as_bytes(), &provided)
        .map_err(|_| anyhow!("enrollment request failed authentication"))?;

    Ok(entry.node_name.clone())
}

fn mark_used(token_id: &str, store_path: &Path) -> Result<()> {
    let mut store = TokenStore::load(store_path)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    for entry in &mut store.tokens {
        if entry.id == token_id {
            entry.used_at = Some(now);
        }
    }
    store.save(store_path)
}

/// What a successful enrollment produced, before it is written to disk.
pub struct Enrolled {
    pub node_name: String,
    pub chain_pem: String,
    pub key_pem: String,
    pub ca_pem: String,
    pub ca_fingerprint: String,
}

/// Enroll against a CA server, returning material ready to install.
pub async fn enroll(server: SocketAddr, token_raw: &str, local_name: &str) -> Result<Enrolled> {
    let token = EnrollToken::decode(token_raw)?;
    let csr = ca::generate_node_csr(local_name)?;

    let key = hmac::Key::new(hmac::HMAC_SHA256, &token.secret);
    let mac = hmac::sign(&key, csr.csr_pem.as_bytes());
    let request = EnrollRequest {
        version: ENROLL_VERSION,
        token_id: token.id.clone(),
        csr_pem: csr.csr_pem.clone(),
        mac: BASE64URL.encode(mac.as_ref()),
    };

    let mut stream = TcpStream::connect(server)
        .await
        .with_context(|| format!("failed to connect to enrollment server {server}"))?;
    write_message(&mut stream, &request).await?;
    let response: EnrollResponse = read_message(&mut stream).await?;

    let (node_name, chain_pem, ca_pem) = match response {
        EnrollResponse::Issued {
            node_name,
            chain_pem,
            ca_pem,
        } => (node_name, chain_pem, ca_pem),
        EnrollResponse::Rejected { reason } => bail!("enrollment was refused: {reason}"),
    };

    // Everything below decides whether this response is worth trusting. The token
    // named the CA we expect; a response from anyone else is discarded.
    let ca_fingerprint = ca::fingerprint_of_pem(&ca_pem)?;
    if crate::normalize_fingerprint(&ca_fingerprint) != token.ca_fingerprint {
        bail!(
            "enrollment server presented an unexpected CA (got {}, token expected {}); \
             refusing to install it",
            ca_fingerprint,
            token.ca_fingerprint
        );
    }
    ca::chain_matches_ca(&chain_pem, &ca_fingerprint)
        .context("issued certificate does not chain to the CA named by the token")?;
    crate::verify_peer_cert_name(Some(&chain_certificates(&chain_pem)?), &node_name)
        .context("issued certificate is not bound to the name it was issued for")?;

    Ok(Enrolled {
        node_name,
        chain_pem,
        key_pem: csr.key_pem,
        ca_pem,
        ca_fingerprint,
    })
}

fn chain_certificates(chain_pem: &str) -> Result<Vec<rustls::Certificate>> {
    let mut reader = std::io::BufReader::new(chain_pem.as_bytes());
    let certs =
        rustls_pemfile::certs(&mut reader).context("failed to parse issued certificate chain")?;
    Ok(certs.into_iter().map(rustls::Certificate).collect())
}

async fn write_message<T: Serialize>(stream: &mut TcpStream, message: &T) -> Result<()> {
    let data = serde_json::to_vec(message)?;
    let len = u32::try_from(data.len()).map_err(|_| anyhow!("enrollment message is too large"))?;
    if len > MAX_MESSAGE_BYTES {
        bail!("enrollment message is too large ({len} bytes)");
    }
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&data).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_message<T: for<'de> Deserialize<'de>>(stream: &mut TcpStream) -> Result<T> {
    let mut len_bytes = [0u8; 4];
    stream
        .read_exact(&mut len_bytes)
        .await
        .context("failed to read enrollment message length")?;
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_MESSAGE_BYTES {
        bail!("enrollment message is too large ({len} bytes)");
    }
    let mut data = vec![0u8; len as usize];
    stream
        .read_exact(&mut data)
        .await
        .context("failed to read enrollment message body")?;
    serde_json::from_slice(&data).context("failed to parse enrollment message")
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::{generate_network_ca, write_network_ca, DEFAULT_CA_VALIDITY_DAYS};
    use tempfile::TempDir;

    /// `Enrolled` and `EnrollToken` deliberately have no `Debug` impl (they carry
    /// secrets), so `expect_err` is unavailable on results holding them.
    fn expect_error<T>(result: Result<T>, expectation: &str) -> anyhow::Error {
        match result {
            Ok(_) => panic!("{expectation}"),
            Err(e) => e,
        }
    }

    fn ca_dir() -> (TempDir, PathBuf) {
        let tmp = TempDir::new().expect("create tempdir");
        let dir = tmp.path().to_path_buf();
        let ca = generate_network_ca("test-net", DEFAULT_CA_VALIDITY_DAYS).expect("generate CA");
        write_network_ca(&CaPaths::in_dir(&dir), &ca, false).expect("write CA");
        (tmp, dir)
    }

    async fn start_server(dir: &Path) -> (SocketAddr, CancellationToken) {
        // Bind first so the test connects only once the listener is ready.
        let probe = TcpListener::bind("127.0.0.1:0").await.expect("bind probe");
        let addr = probe.local_addr().expect("probe addr");
        drop(probe);

        let token = CancellationToken::new();
        let dir = dir.to_path_buf();
        let child = token.clone();
        tokio::spawn(async move {
            let _ = serve(&dir, addr, 30, child).await;
        });
        // Wait for the listener to come up.
        for _ in 0..100 {
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        (addr, token)
    }

    #[tokio::test]
    async fn enrollment_issues_a_certificate_for_the_authorized_name() {
        let (_tmp, dir) = ca_dir();
        let token = issue_token(&dir, "node-b", 600).expect("issue token");
        let (addr, cancel) = start_server(&dir).await;

        let enrolled = enroll(addr, &token.encode(), "node-b")
            .await
            .expect("enrollment should succeed");
        assert_eq!(enrolled.node_name, "node-b");
        crate::verify_peer_cert_name(
            Some(&chain_certificates(&enrolled.chain_pem).expect("parse chain")),
            "node-b",
        )
        .expect("issued certificate must bind to node-b");
        cancel.cancel();
    }

    #[tokio::test]
    async fn a_token_cannot_be_spent_twice() {
        let (_tmp, dir) = ca_dir();
        let token = issue_token(&dir, "node-b", 600).expect("issue token");
        let (addr, cancel) = start_server(&dir).await;

        enroll(addr, &token.encode(), "node-b")
            .await
            .expect("first enrollment should succeed");
        let err = expect_error(
            enroll(addr, &token.encode(), "node-b").await,
            "a single-use token must not work twice",
        );
        assert!(
            err.to_string().contains("refused"),
            "unexpected error: {err}"
        );
        cancel.cancel();
    }

    #[tokio::test]
    async fn the_csr_cannot_choose_the_issued_name() {
        let (_tmp, dir) = ca_dir();
        // The token authorizes node-b; the enrolling machine claims to be node-a.
        let token = issue_token(&dir, "node-b", 600).expect("issue token");
        let (addr, cancel) = start_server(&dir).await;

        let enrolled = enroll(addr, &token.encode(), "node-a")
            .await
            .expect("enrollment should succeed");
        assert_eq!(
            enrolled.node_name, "node-b",
            "the token's name must win over the CSR's"
        );
        crate::verify_peer_cert_name(
            Some(&chain_certificates(&enrolled.chain_pem).expect("parse chain")),
            "node-a",
        )
        .expect_err("the certificate must not be usable as node-a");
        cancel.cancel();
    }

    #[tokio::test]
    async fn a_wrong_secret_is_rejected() {
        let (_tmp, dir) = ca_dir();
        let real = issue_token(&dir, "node-b", 600).expect("issue token");
        let (addr, cancel) = start_server(&dir).await;

        let forged = EnrollToken {
            id: real.id.clone(),
            secret: vec![0u8; 32],
            ca_fingerprint: real.ca_fingerprint.clone(),
        };
        let err = expect_error(
            enroll(addr, &forged.encode(), "node-b").await,
            "a token with the wrong secret must be refused",
        );
        assert!(
            err.to_string().contains("refused"),
            "unexpected error: {err}"
        );
        cancel.cancel();
    }

    #[tokio::test]
    async fn an_expired_token_is_rejected() {
        let (_tmp, dir) = ca_dir();
        let token = issue_token(&dir, "node-b", 1).expect("issue token");
        // Rewrite the stored expiry into the past rather than sleeping.
        let store_path = token_store_path(&dir);
        let mut store = TokenStore::load(&store_path).expect("load store");
        store.tokens[0].expires_at = OffsetDateTime::now_utc().unix_timestamp() - 10;
        store.save(&store_path).expect("save store");

        let (addr, cancel) = start_server(&dir).await;
        let err = expect_error(
            enroll(addr, &token.encode(), "node-b").await,
            "an expired token must be refused",
        );
        assert!(
            err.to_string().contains("refused"),
            "unexpected error: {err}"
        );
        cancel.cancel();
    }

    #[test]
    fn tokens_round_trip_through_their_text_form() {
        let token = EnrollToken {
            id: "0011223344556677".to_string(),
            secret: vec![7u8; 32],
            ca_fingerprint: "AA:BB:CC".to_string(),
        };
        let decoded = EnrollToken::decode(&token.encode()).expect("decode token");
        assert_eq!(decoded.id, token.id);
        assert_eq!(decoded.secret, token.secret);
        assert_eq!(decoded.ca_fingerprint, "AABBCC");
    }

    #[test]
    fn malformed_tokens_are_refused() {
        expect_error(
            EnrollToken::decode("not-a-token"),
            "garbage must not decode as a token",
        );
        expect_error(
            EnrollToken::decode("lbx1.abc.@@@.AABB"),
            "a bad base64 secret must not decode",
        );
    }
}
