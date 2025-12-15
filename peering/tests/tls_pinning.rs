use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use models::{AppConfig, ShareConfig};
use sha2::{Digest, Sha256};
use utilities::{FileSystem, VirtualFileSystem};

fn fp(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    digest
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

#[test]
fn pinning_blocks_auto_generation() {
    let fs: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());
    let cfg = AppConfig {
        pc_name: "pc".to_string(),
        instance_id: "inst".to_string(),
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000),
        plain_listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5002),
        use_tls_for_peers: true,
        discovery_port: 5001,
        aggregation_window_ms: 10,
        db_path: PathBuf::from("db"),
        log_path: PathBuf::from("log"),
        tls_cert_path: PathBuf::from("cert.pem"),
        tls_key_path: PathBuf::from("key.pem"),
        tls_ca_cert_path: PathBuf::from("trust.pem"),
        tls_pinned_ca_fingerprints: vec!["AA".to_string()],
        remote_share_root: PathBuf::from("remote"),
        shares: vec![ShareConfig {
            name: "s".to_string(),
            root_path: PathBuf::from("/share"),
            recursive: true,
            ignore_patterns: Vec::new(),
            max_file_size_bytes: None,
        }],
    };

    let res = peering::tls::TlsComponents::from_config(&cfg, fs.as_ref());
    assert!(res.is_err());
    let err = res.err().unwrap().to_string();
    assert!(err.contains("pinning is enabled"));
}

#[test]
fn pinning_allows_matching_ca() {
    let fs: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());
    let materials = peering::tls::generate_tls_materials("pc").unwrap();

    fs.write(PathBuf::from("cert.pem").as_path(), materials.cert_chain_pem.as_bytes())
        .unwrap();
    fs.write(PathBuf::from("key.pem").as_path(), materials.key_pem.as_bytes())
        .unwrap();
    fs.write(PathBuf::from("trust.pem").as_path(), materials.ca_pem.as_bytes())
        .unwrap();

    let ca_der = {
        let bytes = fs.read(PathBuf::from("trust.pem").as_path()).unwrap();
        let mut reader = std::io::BufReader::new(std::io::Cursor::new(bytes));
        rustls_pemfile::certs(&mut reader).unwrap().pop().unwrap()
    };
    let ca_fp = fp(&ca_der);

    let cfg = AppConfig {
        pc_name: "pc".to_string(),
        instance_id: "inst".to_string(),
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000),
        plain_listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5002),
        use_tls_for_peers: true,
        discovery_port: 5001,
        aggregation_window_ms: 10,
        db_path: PathBuf::from("db"),
        log_path: PathBuf::from("log"),
        tls_cert_path: PathBuf::from("cert.pem"),
        tls_key_path: PathBuf::from("key.pem"),
        tls_ca_cert_path: PathBuf::from("trust.pem"),
        tls_pinned_ca_fingerprints: vec![ca_fp],
        remote_share_root: PathBuf::from("remote"),
        shares: vec![ShareConfig {
            name: "s".to_string(),
            root_path: PathBuf::from("/share"),
            recursive: true,
            ignore_patterns: Vec::new(),
            max_file_size_bytes: None,
        }],
    };

    peering::tls::TlsComponents::from_config(&cfg, fs.as_ref()).unwrap();
}
