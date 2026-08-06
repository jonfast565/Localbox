use localbox_models::{AppConfig, ApplicationState, PeerPolicy, ShareConfig, TransferMode};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

fn cfg() -> AppConfig {
    AppConfig {
        pc_name: "pc".into(),
        instance_id: "i".into(),
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        plain_listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2),
        use_tls_for_peers: true,
        discovery_port: 3,
        aggregation_window_ms: 10,
        db_path: PathBuf::from("db"),
        log_path: PathBuf::from("log"),
        tls_cert_path: PathBuf::from("c"),
        tls_key_path: PathBuf::from("k"),
        tls_ca_cert_path: PathBuf::from("ca"),
        tls_pinned_ca_fingerprints: vec![],
        tls_peer_fingerprints: Default::default(),
        tls_insecure_shared_cert: false,
        remote_share_root: PathBuf::from("r"),
        shares: vec![ShareConfig {
            name: "docs".into(),
            root_path: PathBuf::from("/docs"),
            recursive: true,
            ignore_patterns: vec![],
            max_file_size_bytes: None,
            sync: TransferMode::Manual,
            pull: TransferMode::Auto,
            request_handling: None,
        }],
        app_state: ApplicationState::MirrorHost,
        request_handling: TransferMode::Manual,
        peer_policies: vec![PeerPolicy {
            peer: "bob".into(),
            share: Some("docs".into()),
            sync: Some(TransferMode::Auto),
            pull: None,
            request_handling: Some(TransferMode::Auto),
        }],
        control_socket: PathBuf::from("sock"),
    }
}

#[test]
fn peer_policy_overrides_share_sync() {
    let c = cfg();
    assert_eq!(
        c.resolve_sync_mode("docs", None),
        TransferMode::Manual
    );
    assert_eq!(
        c.resolve_sync_mode("docs", Some("bob@1")),
        TransferMode::Auto
    );
    assert_eq!(
        c.resolve_pull_mode("docs", None),
        TransferMode::Auto
    );
    assert_eq!(
        c.resolve_request_handling("docs", Some("bob")),
        TransferMode::Auto
    );
}
