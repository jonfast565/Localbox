use models::{BatchAck, BatchManifest, ChangeKind, FileChange, FileMeta, HelloMessage, ShareId, WireMessage};
use protocol::{
    decode_file_chunk_proto, decode_wire_message_proto, encode_file_chunk_proto, encode_wire_message_proto,
    parse_batch_manifest, parse_discovery_message, parse_wire_message, DiscoveryMessage, FileChunk,
};

#[test]
fn parse_discovery_messages() {
    let d = parse_discovery_message("DISCOVER v1 pc_name=pc1 instance_id=i1 tcp_port=5000 shares=a,b,c")
        .expect("discover should parse");
    assert_eq!(
        d,
        DiscoveryMessage::Discover {
            pc_name: "pc1".to_string(),
            instance_id: "i1".to_string(),
            tcp_port: 5000,
            shares: vec!["a".to_string(), "b".to_string(), "c".to_string()],
        }
    );

    let h = parse_discovery_message("HERE v1 pc_name=pc2 instance_id=i2 tcp_port=6000 shares=")
        .expect("here should parse");
    assert_eq!(
        h,
        DiscoveryMessage::Here {
            pc_name: "pc2".to_string(),
            instance_id: "i2".to_string(),
            tcp_port: 6000,
            shares: vec![],
        }
    );

    assert!(parse_discovery_message("NOPE v1").is_none());
}

#[test]
fn wire_message_json_parse_round_trip() {
    let msg = WireMessage::Hello(HelloMessage {
        pc_name: "pc".to_string(),
        instance_id: "inst".to_string(),
        listen_port: 1,
        shares: vec!["s".to_string()],
    });
    let json = serde_json::to_vec(&msg).unwrap();
    let parsed = parse_wire_message(&json).unwrap();
    assert_eq!(
        serde_json::to_value(&parsed).unwrap(),
        serde_json::to_value(&msg).unwrap()
    );
}

#[test]
fn batch_manifest_json_parse() {
    let share_id = ShareId::new("shareA", "pc-one");
    let manifest = BatchManifest {
        batch_id: "b1".to_string(),
        share_id,
        from_node: "pc-one".to_string(),
        created_at: 123,
        changes: vec![FileChange {
            seq: 1,
            share_id,
            path: "a.txt".to_string(),
            kind: ChangeKind::Modify,
            meta: Some(FileMeta {
                path: "a.txt".to_string(),
                size: 1,
                mtime: 1,
                hash: [9u8; 32],
                version: 1,
                deleted: false,
            }),
        }],
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let parsed = parse_batch_manifest(&json).unwrap();
    assert_eq!(parsed.batch_id, "b1");
    assert_eq!(parsed.share_id, share_id);
    assert_eq!(parsed.changes.len(), 1);
    assert_eq!(parsed.changes[0].path, "a.txt");
}

#[test]
fn proto_wire_message_round_trip() {
    let hello = WireMessage::Hello(HelloMessage {
        pc_name: "pc".to_string(),
        instance_id: "inst".to_string(),
        listen_port: 5000,
        shares: vec!["a".to_string()],
    });
    let bytes = encode_wire_message_proto(&hello).unwrap();
    let decoded = decode_wire_message_proto(&bytes).unwrap();
    assert_eq!(
        serde_json::to_value(&decoded).unwrap(),
        serde_json::to_value(&hello).unwrap()
    );

    let ack = WireMessage::BatchAck(BatchAck {
        share_id: ShareId::new("shareA", "pc-one"),
        upto_seq: 42,
    });
    let bytes = encode_wire_message_proto(&ack).unwrap();
    let decoded = decode_wire_message_proto(&bytes).unwrap();
    assert_eq!(
        serde_json::to_value(&decoded).unwrap(),
        serde_json::to_value(&ack).unwrap()
    );
}

#[test]
fn proto_file_chunk_round_trip() {
    let share_id = ShareId::new("shareA", "pc-one").0;
    let chunk = FileChunk {
        share_id,
        path: "a.txt".to_string(),
        offset: 0,
        data: b"hello".to_vec(),
        eof: false,
    };
    let bytes = encode_file_chunk_proto(&chunk).unwrap();
    let decoded = decode_file_chunk_proto(&bytes).unwrap();
    assert_eq!(decoded, chunk);
}
