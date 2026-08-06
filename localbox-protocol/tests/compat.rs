use models::{BatchAck, BatchManifest, HelloMessage, ShareId, WireMessage};
use localbox_protocol as protocol;
use protocol::{parse_batch_manifest, parse_wire_message};

#[test]
fn parses_legacy_wire_message_without_protocol_version() {
    // Legacy JSON shape (before `protocol_version` fields existed).
    let json =
        r#"{"Hello":{"pc_name":"pc","instance_id":"inst","listen_port":5000,"shares":["s"]}}"#;
    let msg = parse_wire_message(json.as_bytes()).unwrap();
    match msg {
        WireMessage::Hello(h) => assert_eq!(h.protocol_version, models::WIRE_PROTOCOL_VERSION),
        _ => panic!("expected Hello"),
    }
}

#[test]
fn rejects_future_wire_protocol_versions() {
    let json = r#"{"BatchAck":{"protocol_version":999,"share_id":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"upto_seq":1}}"#;
    let err = parse_wire_message(json.as_bytes()).unwrap_err().to_string();
    assert!(err.contains("unsupported wire protocol version"));
}

#[test]
fn parses_legacy_batch_manifest_without_protocol_version() {
    let share_id = ShareId::new("shareA", "pc-one");
    // Legacy manifest JSON (no protocol_version field).
    let share_id_json = serde_json::to_string(&share_id).unwrap();
    let json = format!(
        r#"{{"batch_id":"b1","share_id":{},"from_node":"pc-one","created_at":1,"changes":[]}}"#,
        share_id_json
    );
    let parsed = parse_batch_manifest(&json).unwrap();
    assert_eq!(parsed.protocol_version, models::WIRE_PROTOCOL_VERSION);
}

#[test]
fn serde_round_trip_includes_protocol_version() {
    let hello = WireMessage::Hello(HelloMessage {
        protocol_version: models::WIRE_PROTOCOL_VERSION,
        pc_name: "pc".to_string(),
        instance_id: "inst".to_string(),
        listen_port: 1,
        plain_port: 0,
        use_tls_for_peers: true,
        utp_port: 0,
        shares: vec!["s".to_string()],
        accepts_remote_shares: true,
    });
    let bytes = serde_json::to_vec(&hello).unwrap();
    let parsed = parse_wire_message(&bytes).unwrap();
    assert_eq!(
        serde_json::to_value(&parsed).unwrap(),
        serde_json::to_value(&hello).unwrap()
    );

    let ack = WireMessage::BatchAck(BatchAck {
        protocol_version: models::WIRE_PROTOCOL_VERSION,
        share_id: ShareId::new("shareA", "pc-one"),
        upto_seq: 1,
        batch_id: None,
    });
    let bytes = serde_json::to_vec(&ack).unwrap();
    let parsed = parse_wire_message(&bytes).unwrap();
    assert_eq!(
        serde_json::to_value(&parsed).unwrap(),
        serde_json::to_value(&ack).unwrap()
    );

    let manifest = BatchManifest {
        protocol_version: models::WIRE_PROTOCOL_VERSION,
        batch_id: "b1".to_string(),
        share_id: ShareId::new("shareA", "pc-one"),
        from_node: "pc-one".to_string(),
        created_at: 1,
        basis: models::BatchBasis::Snapshot,
        journal_from_seq: 0,
        journal_to_seq: 0,
        changes: vec![],
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let parsed = parse_batch_manifest(&json).unwrap();
    assert_eq!(parsed.protocol_version, models::WIRE_PROTOCOL_VERSION);
}

#[test]
fn batch_basis_round_trips_json_and_proto() {
    use localbox_protocol::{decode_wire_message_proto, encode_wire_message_proto};

    let journal = BatchManifest {
        protocol_version: models::WIRE_PROTOCOL_VERSION,
        batch_id: "b-journal".to_string(),
        share_id: ShareId::new("shareA", "pc-one"),
        from_node: "pc-one".to_string(),
        created_at: 7,
        basis: models::BatchBasis::Journal,
        journal_from_seq: 3,
        journal_to_seq: 9,
        changes: vec![],
    };

    // JSON
    let json = serde_json::to_string(&journal).unwrap();
    let parsed = parse_batch_manifest(&json).unwrap();
    assert_eq!(parsed.basis, models::BatchBasis::Journal);
    assert_eq!((parsed.journal_from_seq, parsed.journal_to_seq), (3, 9));

    // Protobuf
    let bytes = encode_wire_message_proto(&WireMessage::Batch(journal.clone())).unwrap();
    match decode_wire_message_proto(&bytes).unwrap() {
        WireMessage::Batch(b) => {
            assert_eq!(b.basis, models::BatchBasis::Journal);
            assert_eq!((b.journal_from_seq, b.journal_to_seq), (3, 9));
        }
        other => panic!("expected batch, got {other:?}"),
    }

    // A snapshot batch round-trips as snapshot, with no range.
    let snapshot = BatchManifest {
        basis: models::BatchBasis::Snapshot,
        journal_from_seq: 0,
        journal_to_seq: 0,
        ..journal
    };
    let bytes = encode_wire_message_proto(&WireMessage::Batch(snapshot)).unwrap();
    match decode_wire_message_proto(&bytes).unwrap() {
        WireMessage::Batch(b) => assert_eq!(b.basis, models::BatchBasis::Snapshot),
        other => panic!("expected batch, got {other:?}"),
    }
}

#[test]
fn batch_without_basis_field_reads_as_snapshot() {
    // A manifest serialized before `basis` existed must decode to the
    // conservative reading: no journal positions, so no watermark may move.
    let json = r#"{
        "protocol_version": 4,
        "batch_id": "legacy",
        "share_id": [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "from_node": "pc-one",
        "created_at": 1,
        "changes": []
    }"#;
    let parsed = parse_batch_manifest(json).unwrap();
    assert_eq!(parsed.basis, models::BatchBasis::Snapshot);
    assert_eq!(parsed.journal_to_seq, 0);
}
