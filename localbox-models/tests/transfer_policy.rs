use localbox_models::{
    AppConfig, ApplicationState, ConflictPolicy, PeerPolicy, ShareConfig, TransferMode,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

fn cfg() -> AppConfig {
    AppConfig {
        pc_name: "pc".into(),
        instance_id: "i".into(),
            display_name: String::new(),
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        plain_listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2),
        use_tls_for_peers: true,
        discovery_port: 3,
        discovery_send_ports: Vec::new(),
            dht_port: 5003,
            utp_port: 5004,
            enable_dht: false,
        enable_utp: false,
            bootstrap_peers: Vec::new(),
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
            sync_allow: vec![],
            max_file_size_bytes: None,
            sync: TransferMode::Manual,
            pull: TransferMode::Auto,
            request_handling: None,
            conflict: ConflictPolicy::LastWriteWins,
        }],
        app_state: ApplicationState::MirrorHost,
        request_handling: TransferMode::Manual,
        peer_policies: vec![PeerPolicy {
            peer: "bob".into(),
            share: Some("docs".into()),
            sync: Some(TransferMode::Auto),
            pull: None,
            request_handling: Some(TransferMode::Auto),
            conflict: None,
            sync_allow: None,
            ignore_patterns: None,
            allow_push: None,
            allow_pull: None,
            allow_request: None,
        }],
        quarantined_peers: vec![],
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

#[test]
fn acl_and_conflict_resolvers() {
    let mut c = cfg();
    c.shares[0].conflict = localbox_models::ConflictPolicy::KeepBoth;
    c.shares[0].sync_allow = vec!["public/*".into()];
    c.peer_policies[0].allow_push = Some(false);
    c.peer_policies[0].allow_pull = Some(false);
    c.peer_policies[0].conflict = Some(localbox_models::ConflictPolicy::OwnerWins);
    c.peer_policies[0].sync_allow = Some(vec!["other/*".into()]);

    assert_eq!(
        c.resolve_conflict_policy("docs", None),
        localbox_models::ConflictPolicy::KeepBoth
    );
    assert_eq!(
        c.resolve_conflict_policy("docs", Some("bob")),
        localbox_models::ConflictPolicy::OwnerWins
    );
    assert!(!c.resolve_allow_push("docs", "bob"));
    assert!(!c.resolve_allow_pull("docs", "bob@1"));
    assert!(c.resolve_allow_request("docs", "bob"));
    assert_eq!(c.resolve_sync_allow("docs", Some("bob")), vec!["other/*"]);
    assert_eq!(c.resolve_sync_allow("docs", None), vec!["public/*"]);
}
