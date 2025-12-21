use localbox_models as models;
use models::{
    AppConfig, ApplicationState, BatchAck, HelloMessage, ShareConfig, ShareId, WireMessage,
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
        listen_port: 5000,
        plain_port: 5002,
        use_tls_for_peers: true,
        shares: vec!["shareA".to_string(), "shareB".to_string()],
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
    });
    let bytes = serde_json::to_vec(&ack).unwrap();
    let decoded: WireMessage = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        serde_json::to_value(&ack).unwrap(),
        serde_json::to_value(&decoded).unwrap()
    );
}

#[test]
fn app_config_json_round_trip() {
    let cfg = AppConfig {
        pc_name: "pc-one".to_string(),
        instance_id: "inst-one".to_string(),
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000),
        plain_listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5002),
        use_tls_for_peers: true,
        discovery_port: 5001,
        aggregation_window_ms: 200,
        db_path: PathBuf::from("db.sqlite"),
        log_path: PathBuf::from("app.log"),
        tls_cert_path: PathBuf::from("cert.pem"),
        tls_key_path: PathBuf::from("key.pem"),
        tls_ca_cert_path: PathBuf::from("ca.pem"),
        tls_pinned_ca_fingerprints: Vec::new(),
        tls_peer_fingerprints: std::collections::HashMap::new(),
        remote_share_root: PathBuf::from("remote"),
        shares: vec![ShareConfig {
            name: "shareA".to_string(),
            root_path: PathBuf::from("/share"),
            recursive: true,
            ignore_patterns: Vec::new(),
            max_file_size_bytes: None,
        }],
        app_state: ApplicationState::MirrorHost,
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
