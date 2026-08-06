use localbox_models as models;
use models::{
    peer_key, peer_thread_id, share_thread_id, AdvertisedShare, AppConfig, ApplicationState,
    BatchAck, ConflictPolicy, HelloMessage, ShareConfig, ShareId, WireMessage,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

#[test]
fn share_id_is_deterministic() {
    let a1 = ShareId::new("shareA", "pc-one");
    let a2 = ShareId::new("shareA", "pc-one");
    assert_eq!(a1, a2);
}

#[test]
fn share_id_changes_with_inputs() {
    let a = ShareId::new("shareA", "pc-one");
    let b = ShareId::new("shareB", "pc-one");
    let c = ShareId::new("shareA", "pc-two");
    assert_ne!(a, b);
    assert_ne!(a, c);
}

#[test]
fn wire_message_json_round_trip() {
    let msg = WireMessage::Hello(HelloMessage {
        protocol_version: models::WIRE_PROTOCOL_VERSION,
        pc_name: "pc-one".to_string(),
        instance_id: "inst".to_string(),
        display_name: String::new(),
        app_state: String::new(),
        listen_port: 5000,
        plain_port: 5002,
        use_tls_for_peers: true,
        utp_port: 5004,
        shares: vec![AdvertisedShare::new("shareA"), AdvertisedShare::new("shareB")],
        accepts_remote_shares: true,
    });
    let bytes = serde_json::to_vec(&msg).unwrap();
    let decoded: WireMessage = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        serde_json::to_value(&msg).unwrap(),
        serde_json::to_value(&decoded).unwrap()
    );

    let ack = WireMessage::BatchAck(BatchAck {
        protocol_version: models::WIRE_PROTOCOL_VERSION,
        share_id: ShareId::new("shareA", "pc-one"),
        upto_seq: 123,
        batch_id: None,
    });
    let bytes = serde_json::to_vec(&ack).unwrap();
    let decoded: WireMessage = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        serde_json::to_value(&ack).unwrap(),
        serde_json::to_value(&decoded).unwrap()
    );
}

#[test]
fn dht_and_utp_toggles_default_to_lan_only() {
    let mut cfg = AppConfig {
        pc_name: "pc".into(),
        instance_id: "i".into(),
            display_name: String::new(),
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000),
        plain_listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5002),
        use_tls_for_peers: true,
        discovery_port: 5001,
        dht_port: 5003,
        utp_port: 5004,
        enable_dht: false,
        enable_utp: false,
        bootstrap_peers: Vec::new(),
        aggregation_window_ms: 200,
        db_path: PathBuf::from("db.sqlite"),
        log_path: PathBuf::from("app.log"),
        tls_cert_path: PathBuf::from("cert.pem"),
        tls_key_path: PathBuf::from("key.pem"),
        tls_ca_cert_path: PathBuf::from("ca.pem"),
        tls_pinned_ca_fingerprints: Vec::new(),
        tls_peer_fingerprints: Default::default(),
        tls_insecure_shared_cert: false,
        remote_share_root: PathBuf::from("remote"),
        shares: Vec::new(),
        app_state: ApplicationState::MirrorHost,
        request_handling: Default::default(),
        peer_policies: Vec::new(),
        quarantined_peers: Vec::new(),
        control_socket: PathBuf::from("localbox.sock"),
    };
    assert!(!cfg.dht_enabled());
    assert!(!cfg.utp_enabled());
    assert_eq!(cfg.advertised_utp_port(), 0);

    cfg.enable_utp = true;
    assert!(cfg.utp_enabled());
    assert_eq!(cfg.advertised_utp_port(), 5004);

    cfg.enable_dht = true;
    assert!(cfg.dht_enabled());
}

#[test]
fn app_config_json_round_trip() {
    let cfg = AppConfig {
        pc_name: "pc-one".to_string(),
        instance_id: "inst-one".to_string(),
            display_name: String::new(),
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000),
        plain_listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5002),
        use_tls_for_peers: true,
        discovery_port: 5001,
        dht_port: 5003,
        utp_port: 5004,
        enable_dht: false,
        enable_utp: false,
        bootstrap_peers: Vec::new(),
        aggregation_window_ms: 200,
        db_path: PathBuf::from("db.sqlite"),
        log_path: PathBuf::from("app.log"),
        tls_cert_path: PathBuf::from("cert.pem"),
        tls_key_path: PathBuf::from("key.pem"),
        tls_ca_cert_path: PathBuf::from("ca.pem"),
        tls_pinned_ca_fingerprints: Vec::new(),
        tls_peer_fingerprints: std::collections::HashMap::new(),
            tls_insecure_shared_cert: false,
        remote_share_root: PathBuf::from("remote"),
        shares: vec![ShareConfig {
            name: "shareA".to_string(),
            root_path: PathBuf::from("/share"),
            recursive: true,
            ignore_patterns: Vec::new(),
            sync_allow: Vec::new(),
            max_file_size_bytes: None,
            sync: Default::default(),
            pull: Default::default(),
            request_handling: None,
            conflict: ConflictPolicy::LastWriteWins,
        }],
        app_state: ApplicationState::MirrorHost,
        request_handling: Default::default(),
        peer_policies: Vec::new(),
        quarantined_peers: Vec::new(),
        control_socket: std::path::PathBuf::from("localbox.sock"),
    };
    let bytes = serde_json::to_vec(&cfg).unwrap();
    let decoded: AppConfig = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(cfg.pc_name, decoded.pc_name);
    assert_eq!(cfg.instance_id, decoded.instance_id);
    assert_eq!(cfg.listen_addr, decoded.listen_addr);
    assert_eq!(cfg.plain_listen_addr, decoded.plain_listen_addr);
    assert_eq!(cfg.use_tls_for_peers, decoded.use_tls_for_peers);
    assert_eq!(cfg.discovery_port, decoded.discovery_port);
    assert_eq!(cfg.aggregation_window_ms, decoded.aggregation_window_ms);
    assert_eq!(cfg.db_path, decoded.db_path);
    assert_eq!(cfg.remote_share_root, decoded.remote_share_root);
    assert_eq!(cfg.shares.len(), decoded.shares.len());
    assert_eq!(cfg.shares[0].name, decoded.shares[0].name);
    assert_eq!(cfg.shares[0].root_path, decoded.shares[0].root_path);
    assert_eq!(cfg.shares[0].recursive, decoded.shares[0].recursive);
    assert_eq!(cfg.app_state, decoded.app_state);
}

#[test]
fn peer_thread_id_is_deterministic_and_order_independent() {
    let a = peer_key("alice", "1");
    let b = peer_key("bob", "2");
    let t1 = peer_thread_id(&a, &b);
    let t2 = peer_thread_id(&b, &a);
    assert_eq!(t1, t2);
    assert_ne!(t1, peer_thread_id(&a, &peer_key("carol", "1")));
}

#[test]
fn share_thread_id_is_deterministic() {
    assert_eq!(share_thread_id("docs"), share_thread_id("docs"));
    assert_ne!(share_thread_id("docs"), share_thread_id("pics"));
}
