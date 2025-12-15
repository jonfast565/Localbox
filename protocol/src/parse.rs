use anyhow::Result;
use models::{BatchAck, BatchManifest, ChangeKind, FileChange, FileChunk, FileMeta, WireMessage};
use prost::Message;

use crate::proto::{
    wire_envelope::Msg as ProtoMsg, BatchAck as ProtoBatchAck, BatchManifest as ProtoBatch,
    ChangeKind as ProtoChange, FileChange as ProtoFileChange, FileChunk as ProtoFileChunk,
    FileMeta as ProtoFileMeta, Hello as ProtoHello, WireEnvelope,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryMessage {
    Discover {
        pc_name: String,
        instance_id: String,
        tls_port: u16,
        plain_port: u16,
        use_tls_for_peers: bool,
        shares: Vec<String>,
    },
    Here {
        pc_name: String,
        instance_id: String,
        tls_port: u16,
        plain_port: u16,
        use_tls_for_peers: bool,
        shares: Vec<String>,
    },
}

pub fn parse_discovery_message(msg: &str) -> Option<DiscoveryMessage> {
    if msg.starts_with("DISCOVER v1") {
        parse_key_values(msg, 2).and_then(|kv| {
            let pc_name = kv.get("pc_name")?.to_string();
            let instance_id = kv.get("instance_id")?.to_string();
            let tls_port = kv
                .get("tls_port")
                .or_else(|| kv.get("tcp_port"))
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(0);
            let plain_port = kv
                .get("plain_port")
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(0);
            let use_tls_for_peers = kv
                .get("use_tls")
                .or_else(|| kv.get("use_tls_for_peers"))
                .and_then(|v| v.parse::<bool>().ok())
                .unwrap_or(true);
            let shares = kv
                .get("shares")
                .map(|s| split_shares(s))
                .unwrap_or_default();
            Some(DiscoveryMessage::Discover {
                pc_name,
                instance_id,
                tls_port,
                plain_port,
                use_tls_for_peers,
                shares,
            })
        })
    } else if msg.starts_with("HERE v1") {
        parse_key_values(msg, 2).and_then(|kv| {
            let pc_name = kv.get("pc_name")?.to_string();
            let instance_id = kv.get("instance_id")?.to_string();
            let tls_port = kv
                .get("tls_port")
                .or_else(|| kv.get("tcp_port"))
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(0);
            let plain_port = kv
                .get("plain_port")
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(0);
            let use_tls_for_peers = kv
                .get("use_tls")
                .or_else(|| kv.get("use_tls_for_peers"))
                .and_then(|v| v.parse::<bool>().ok())
                .unwrap_or(true);
            let shares = kv
                .get("shares")
                .map(|s| split_shares(s))
                .unwrap_or_default();
            Some(DiscoveryMessage::Here {
                pc_name,
                instance_id,
                tls_port,
                plain_port,
                use_tls_for_peers,
                shares,
            })
        })
    } else {
        None
    }
}

pub fn parse_wire_message(bytes: &[u8]) -> Result<WireMessage> {
    let msg: WireMessage = serde_json::from_slice(bytes)?;
    let v = models::wire::wire_message_protocol_version(&msg);
    if v > models::WIRE_PROTOCOL_VERSION {
        anyhow::bail!(
            "unsupported wire protocol version {} (max supported {})",
            v,
            models::WIRE_PROTOCOL_VERSION
        );
    }
    Ok(msg)
}

pub fn parse_batch_manifest(json: &str) -> Result<BatchManifest> {
    let manifest: BatchManifest = serde_json::from_str(json)?;
    if manifest.protocol_version > models::WIRE_PROTOCOL_VERSION {
        anyhow::bail!(
            "unsupported wire protocol version {} (max supported {})",
            manifest.protocol_version,
            models::WIRE_PROTOCOL_VERSION
        );
    }
    Ok(manifest)
}

pub fn encode_wire_message_proto(msg: &WireMessage) -> Result<Vec<u8>> {
    let envelope = match msg {
        WireMessage::Hello(h) => WireEnvelope {
            msg: Some(ProtoMsg::Hello(ProtoHello {
                pc_name: h.pc_name.clone(),
                instance_id: h.instance_id.clone(),
                listen_port: h.listen_port as u32,
                plain_port: h.plain_port as u32,
                use_tls_for_peers: h.use_tls_for_peers,
                shares: h.shares.clone(),
            })),
        },
        WireMessage::Batch(b) => WireEnvelope {
            msg: Some(ProtoMsg::Batch(batch_to_proto(b))),
        },
        WireMessage::BatchAck(a) => WireEnvelope {
            msg: Some(ProtoMsg::BatchAck(ProtoBatchAck {
                share_id: a.share_id.0.to_vec(),
                upto_seq: a.upto_seq,
            })),
        },
        WireMessage::FileChunk(chunk) => WireEnvelope {
            msg: Some(ProtoMsg::FileChunk(ProtoFileChunk {
                share_id: chunk.share_id.0.to_vec(),
                path: chunk.path.clone(),
                offset: chunk.offset,
                data: chunk.data.clone(),
                eof: chunk.eof,
            })),
        },
    };
    Ok(envelope.encode_to_vec())
}

pub fn decode_wire_message_proto(bytes: &[u8]) -> Result<WireMessage> {
    let env = WireEnvelope::decode(bytes)?;
    match env.msg {
        Some(ProtoMsg::Hello(h)) => Ok(WireMessage::Hello(models::HelloMessage {
            protocol_version: models::WIRE_PROTOCOL_VERSION,
            pc_name: h.pc_name,
            instance_id: h.instance_id,
            listen_port: h.listen_port as u16,
            plain_port: h.plain_port as u16,
            use_tls_for_peers: if h.use_tls_for_peers {
                true
            } else {
                // Default to true if sender never set the field (http_port=0 is a hint).
                h.plain_port == 0
            },
            shares: h.shares,
        })),
        Some(ProtoMsg::Batch(b)) => Ok(WireMessage::Batch(batch_from_proto(&b)?)),
        Some(ProtoMsg::BatchAck(a)) => Ok(WireMessage::BatchAck(BatchAck {
            protocol_version: models::WIRE_PROTOCOL_VERSION,
            share_id: models::ShareId(proto_share_id_to_array(&a.share_id)?),
            upto_seq: a.upto_seq,
        })),
        Some(ProtoMsg::FileChunk(fc)) => Ok(WireMessage::FileChunk(FileChunk {
            share_id: models::ShareId(proto_share_id_to_array(&fc.share_id)?),
            path: fc.path,
            offset: fc.offset,
            data: fc.data,
            eof: fc.eof,
        })),
        None => anyhow::bail!("empty wire envelope"),
    }
}

pub fn encode_file_chunk_proto(chunk: &FileChunk) -> Result<Vec<u8>> {
    let proto = ProtoFileChunk {
        share_id: chunk.share_id.0.to_vec(),
        path: chunk.path.clone(),
        offset: chunk.offset,
        data: chunk.data.clone(),
        eof: chunk.eof,
    };
    let env = WireEnvelope {
        msg: Some(ProtoMsg::FileChunk(proto)),
    };
    Ok(env.encode_to_vec())
}

pub fn decode_file_chunk_proto(bytes: &[u8]) -> Result<FileChunk> {
    let env = WireEnvelope::decode(bytes)?;
    match env.msg {
        Some(ProtoMsg::FileChunk(fc)) => Ok(FileChunk {
            share_id: models::ShareId(proto_share_id_to_array(&fc.share_id)?),
            path: fc.path,
            offset: fc.offset,
            data: fc.data,
            eof: fc.eof,
        }),
        _ => anyhow::bail!("expected file_chunk in envelope"),
    }
}

fn batch_to_proto(batch: &BatchManifest) -> ProtoBatch {
    ProtoBatch {
        batch_id: batch.batch_id.clone(),
        share_id: batch.share_id.0.to_vec(),
        from_node: batch.from_node.clone(),
        created_at: batch.created_at,
        changes: batch.changes.iter().map(change_to_proto).collect(),
    }
}

fn batch_from_proto(pb: &ProtoBatch) -> Result<BatchManifest> {
    Ok(BatchManifest {
        protocol_version: models::WIRE_PROTOCOL_VERSION,
        batch_id: pb.batch_id.clone(),
        share_id: models::ShareId(proto_share_id_to_array(&pb.share_id)?),
        from_node: pb.from_node.clone(),
        created_at: pb.created_at,
        changes: pb
            .changes
            .iter()
            .map(change_from_proto)
            .collect::<Result<_>>()?,
    })
}

fn change_to_proto(ch: &FileChange) -> ProtoFileChange {
    ProtoFileChange {
        seq: ch.seq,
        share_id: ch.share_id.0.to_vec(),
        path: ch.path.clone(),
        kind: change_kind_to_proto(&ch.kind) as i32,
        meta: ch.meta.as_ref().map(meta_to_proto),
    }
}

fn change_from_proto(pb: &ProtoFileChange) -> Result<FileChange> {
    Ok(FileChange {
        seq: pb.seq,
        share_id: models::ShareId(proto_share_id_to_array(&pb.share_id)?),
        path: pb.path.clone(),
        kind: change_kind_from_proto(pb.kind),
        meta: pb.meta.as_ref().map(meta_from_proto).transpose()?,
    })
}

fn meta_to_proto(meta: &FileMeta) -> ProtoFileMeta {
    ProtoFileMeta {
        path: meta.path.clone(),
        size: meta.size,
        mtime: meta.mtime,
        hash: meta.hash.to_vec(),
        version: meta.version,
        deleted: meta.deleted,
    }
}

fn meta_from_proto(pb: &ProtoFileMeta) -> Result<FileMeta> {
    let mut hash = [0u8; 32];
    let copy_len = pb.hash.len().min(32);
    hash[..copy_len].copy_from_slice(&pb.hash[..copy_len]);
    Ok(FileMeta {
        path: pb.path.clone(),
        size: pb.size,
        mtime: pb.mtime,
        hash,
        version: pb.version,
        deleted: pb.deleted,
    })
}

fn change_kind_to_proto(kind: &ChangeKind) -> ProtoChange {
    match kind {
        ChangeKind::Create => ProtoChange::Create,
        ChangeKind::Modify => ProtoChange::Modify,
        ChangeKind::Delete => ProtoChange::Delete,
    }
}

fn change_kind_from_proto(val: i32) -> ChangeKind {
    match ProtoChange::try_from(val).unwrap_or(ProtoChange::Modify) {
        ProtoChange::Create => ChangeKind::Create,
        ProtoChange::Modify => ChangeKind::Modify,
        ProtoChange::Delete => ChangeKind::Delete,
    }
}

fn proto_share_id_to_array(bytes: &[u8]) -> Result<[u8; 16]> {
    if bytes.len() != 16 {
        anyhow::bail!("expected 16-byte share_id, got {}", bytes.len());
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

fn parse_key_values(msg: &str, skip: usize) -> Option<std::collections::HashMap<String, String>> {
    let mut map = std::collections::HashMap::new();
    for part in msg.split_whitespace().skip(skip) {
        if let Some((k, v)) = part.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    Some(map)
}

fn split_shares(s: &str) -> Vec<String> {
    s.split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}
