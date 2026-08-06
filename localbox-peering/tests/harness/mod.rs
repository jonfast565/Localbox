//! Two-node virtual-network harness for the journal-vs-push tests.
//!
//! Everything runs over `VirtualNet` / `VirtualFileSystem`, so a whole
//! replication exchange happens in-process with no sockets or temp files.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use db::{Db, JournalOrigin};
use localbox_peering as peering;
use models::{
    AppConfig, ApplicationState, ChangeKind, ConflictPolicy, FileChange, FileMeta, JournalEntry,
    ShareConfig, ShareContext,
};
use peering::PeerManager;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use utilities::{
    disk_utilities::build_remote_share_root, FileSystem, Net, VirtualFileSystem, VirtualNet,
};

pub const SHARE: &str = "shareA";

pub struct TwoNodes {
    pub db1: Arc<Mutex<Db>>,
    pub db2: Arc<Mutex<Db>>,
    pub fs1: Arc<dyn FileSystem>,
    pub fs2: Arc<dyn FileSystem>,
    pub share1: ShareContext,
    pub net_tx1: mpsc::Sender<String>,
    net_tx2: mpsc::Sender<String>,
    remote_root: PathBuf,
    tok1: CancellationToken,
    tok2: CancellationToken,
    t1: tokio::task::JoinHandle<()>,
    t2: tokio::task::JoinHandle<()>,
}

impl TwoNodes {
    /// Bring up node1 (owner of `shareA`) and node2 (its mirror) and wait for
    /// them to discover each other.
    pub async fn start(tag: &str, listen_base: u16, discovery_port: u16) -> Self {
        let net: Arc<dyn Net> = Arc::new(VirtualNet::default());
        let fs1: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());
        let fs2: Arc<dyn FileSystem> = Arc::new(VirtualFileSystem::new());

        let tls1 = TlsPaths::new(
            &format!("{tag}-cert1.pem"),
            &format!("{tag}-key1.pem"),
            &format!("{tag}-ca.pem"),
        );
        let tls2 = TlsPaths::new(
            &format!("{tag}-cert2.pem"),
            &format!("{tag}-key2.pem"),
            &format!("{tag}-ca.pem"),
        );
        let mat = generate_shared_tls(&["pc-one", "pc-two", "localhost"]);
        write_shared_tls(fs1.as_ref(), &tls1, &mat);
        write_shared_tls(fs2.as_ref(), &tls2, &mat);

        let cfg1 = test_config("pc-one", "inst-one", listen_base, discovery_port, &tls1);
        let cfg2 = test_config("pc-two", "inst-two", listen_base + 1, discovery_port, &tls2);

        let db1 = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        let db2 = Arc::new(Mutex::new(Db::open_in_memory().unwrap()));
        let shares1 = db1.lock().await.load_shares(&cfg1).unwrap();
        let shares2 = db2.lock().await.load_shares(&cfg2).unwrap();

        let (net_tx1, net_rx1) = mpsc::channel(16);
        let (net_tx2, net_rx2) = mpsc::channel(16);

        let pm1 = PeerManager::new(
            cfg1.clone(),
            db1.clone(),
            net_tx1.clone(),
            shares1.clone(),
            fs1.clone(),
            net.clone(),
        )
        .unwrap();
        let pm2 = PeerManager::new(
            cfg2.clone(),
            db2.clone(),
            net_tx2.clone(),
            shares2.clone(),
            fs2.clone(),
            net.clone(),
        )
        .unwrap();

        let tok1 = CancellationToken::new();
        let tok2 = CancellationToken::new();
        let (r1, r2) = (tok1.clone(), tok2.clone());
        let t1 = tokio::spawn(async move { pm1.run(net_rx1, r1).await.unwrap() });
        let t2 = tokio::spawn(async move { pm2.run(net_rx2, r2).await.unwrap() });

        tokio::time::sleep(Duration::from_millis(500)).await;

        let remote_root = build_remote_share_root(
            &cfg2.remote_share_root,
            &cfg1.pc_name,
            &cfg1.instance_id,
            SHARE,
        );

        Self {
            db1,
            db2,
            fs1,
            fs2,
            share1: shares1[0].clone(),
            net_tx1,
            net_tx2,
            remote_root,
            tok1,
            tok2,
            t1,
            t2,
        }
    }

    /// Append a change to node1's journal. Returns the seq the journal assigned
    /// — seqs are locally allocated, so callers take the value rather than pick it.
    pub async fn journal_on_1(
        &self,
        path: &str,
        kind: ChangeKind,
        contents: Option<&[u8]>,
    ) -> i64 {
        let meta = self.stage(path, &kind, contents, 1);
        let change = FileChange {
            seq: 0,
            share_id: self.share1.share_id,
            path: path.to_string(),
            kind: kind.clone(),
            meta: if matches!(kind, ChangeKind::Delete) {
                None
            } else {
                Some(meta.clone())
            },
        };
        let db = self.db1.lock().await;
        if !matches!(kind, ChangeKind::Delete) {
            db.upsert_file_meta(self.share1.id, &meta).unwrap();
        }
        db.append_journal_entry(
            self.share1.id,
            &change,
            OffsetDateTime::now_utc().unix_timestamp(),
            JournalOrigin::Local,
        )
        .unwrap()
        .expect("journal append must insert")
    }

    /// Materialize a real SyncCatchup over an existing range of node1's journal.
    /// `from_seq` exclusive, `to_seq` inclusive.
    pub async fn sync_1(&self, from_seq: i64, to_seq: i64) {
        let batch_ids = {
            let db = self.db1.lock().await;
            db.create_and_materialize_intent(
                models::IntentKind::SyncCatchup,
                models::IntentOrigin::AutoSync,
                &self.share1.share_name,
                self.share1.share_id,
                None,
                models::IntentBasis::JournalRange { from_seq, to_seq },
                None,
                "pc-one",
            )
            .unwrap()
            .1
        };
        for b in batch_ids {
            let _ = self.net_tx1.try_send(b);
        }
    }

    /// Manual push of one path from node1's *index* — never journaled, so the
    /// resulting batch carries no journal positions.
    pub async fn push_from_1(&self, path: &str, contents: &[u8]) {
        self.push_from_1_with_version(path, contents, 1).await
    }

    pub async fn push_from_1_with_version(&self, path: &str, contents: &[u8], version: i64) {
        let meta = self.stage(path, &ChangeKind::Modify, Some(contents), version);
        let batch_ids = {
            let db = self.db1.lock().await;
            db.upsert_file_meta(self.share1.id, &meta).unwrap();
            db.create_and_materialize_intent(
                models::IntentKind::SnapshotPush,
                models::IntentOrigin::User,
                &self.share1.share_name,
                self.share1.share_id,
                None,
                models::IntentBasis::Snapshot {
                    paths: vec![path.to_string()],
                },
                None,
                "pc-one",
            )
            .unwrap()
            .1
        };
        for b in batch_ids {
            let _ = self.net_tx1.try_send(b);
        }
    }

    fn stage(
        &self,
        path: &str,
        kind: &ChangeKind,
        contents: Option<&[u8]>,
        version: i64,
    ) -> FileMeta {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if matches!(kind, ChangeKind::Delete) {
            return FileMeta {
                path: path.to_string(),
                size: 0,
                mtime: now,
                hash: [0u8; 32],
                version,
                deleted: true,
            };
        }
        let data = contents.unwrap_or(b"default");
        let full = self.share1.root_path.join(path);
        if let Some(parent) = full.parent() {
            let _ = self.fs1.create_dir_all(parent);
        }
        let _ = self.fs1.write(&full, data);
        FileMeta {
            path: path.to_string(),
            size: data.len() as u64,
            mtime: now,
            hash: hash_bytes(data),
            version,
            deleted: false,
        }
    }

    /// Block until `rel` shows up on node2's mirror with the expected contents.
    pub async fn wait_mirrored(&self, rel: &str, expected: &[u8]) {
        let target = self.remote_root.join(rel);
        for _ in 0..60 {
            if let Ok(bytes) = self.fs2.read(&target) {
                if bytes == expected {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        panic!(
            "{} never materialized on the mirror with the expected contents",
            target.display()
        );
    }

    async fn mirror_share_row(&self) -> i64 {
        for _ in 0..40 {
            if let Ok(id) = self
                .db2
                .lock()
                .await
                .get_share_row_id_by_share_id(&self.share1.share_id)
            {
                return id;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        panic!("mirror share row never registered");
    }

    /// node2's journal for the mirrored share, in local-seq order.
    pub async fn mirror_journal(&self) -> Vec<JournalEntry> {
        let row = self.mirror_share_row().await;
        self.db2
            .lock()
            .await
            .list_journal_since(row, 0, 500)
            .unwrap()
    }

    /// How far of node1's journal node2 believes it has taken in.
    pub async fn node2_inbound_watermark(&self) -> i64 {
        let row = self.mirror_share_row().await;
        let db = self.db2.lock().await;
        let peer = db.list_peers().unwrap();
        let Some(p) = peer.first() else { return 0 };
        db.inbound_watermark(p.id, row).unwrap()
    }

    /// node1's outbound watermark for the peer it is syncing to.
    pub async fn node1_acked_watermark(&self) -> i64 {
        let db = self.db1.lock().await;
        let peers = db.list_peers().unwrap();
        let Some(p) = peers.first() else { return 0 };
        db.get_peer_progress(p.id, self.share1.id).unwrap().1
    }

    pub async fn node1_journal_max(&self) -> i64 {
        self.db1
            .lock()
            .await
            .max_journal_seq(self.share1.id)
            .unwrap()
    }

    pub async fn node1_meta_version(&self, path: &str) -> i64 {
        self.db1
            .lock()
            .await
            .get_file_meta(self.share1.id, path)
            .unwrap()
            .expect("sender meta")
            .version
    }

    pub async fn node2_meta_version(&self, path: &str) -> i64 {
        let row = self.mirror_share_row().await;
        self.db2
            .lock()
            .await
            .get_file_meta(row, path)
            .unwrap()
            .expect("mirror meta")
            .version
    }

    pub async fn shutdown(&mut self) {
        self.tok1.cancel();
        self.tok2.cancel();
        let _ = (&mut self.t1).await;
        let _ = (&mut self.t2).await;
    }
}

pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn test_config(
    pc_name: &str,
    instance_id: &str,
    listen_port: u16,
    discovery_port: u16,
    tls: &TlsPaths,
) -> AppConfig {
    AppConfig {
        pc_name: pc_name.to_string(),
        instance_id: instance_id.to_string(),
        listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port),
        plain_listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port + 1000),
        use_tls_for_peers: true,
        discovery_port,
        aggregation_window_ms: 100,
        db_path: PathBuf::from(""),
        log_path: PathBuf::from(""),
        tls_cert_path: tls.cert.clone(),
        tls_key_path: tls.key.clone(),
        tls_ca_cert_path: tls.ca.clone(),
        tls_pinned_ca_fingerprints: Vec::new(),
        tls_peer_fingerprints: std::collections::HashMap::new(),
        tls_insecure_shared_cert: false,
        remote_share_root: PathBuf::from("remote"),
        shares: vec![ShareConfig {
            name: SHARE.to_string(),
            root_path: PathBuf::from("/virtual"),
            recursive: true,
            ignore_patterns: Vec::new(),
            sync_allow: Vec::new(),
            max_file_size_bytes: None,
            // Journal sync is driven explicitly by the tests, not by policy.
            sync: Default::default(),
            pull: Default::default(),
            request_handling: None,
            conflict: ConflictPolicy::LastWriteWins,
        }],
        app_state: ApplicationState::MirrorHost,
        request_handling: Default::default(),
        peer_policies: Vec::new(),
        quarantined_peers: Vec::new(),
        control_socket: PathBuf::from("localbox.sock"),
    }
}

struct TlsPaths {
    cert: PathBuf,
    key: PathBuf,
    ca: PathBuf,
}

impl TlsPaths {
    fn new(cert: &str, key: &str, ca: &str) -> Self {
        Self {
            cert: PathBuf::from(cert),
            key: PathBuf::from(key),
            ca: PathBuf::from(ca),
        }
    }
}

struct TlsMaterial {
    ca_pem: String,
    cert_pem: String,
    key_pem: String,
}

fn generate_shared_tls(names: &[&str]) -> TlsMaterial {
    let cert =
        rcgen::generate_simple_self_signed(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap();
    let ca_pem = cert.serialize_pem().unwrap();
    let cert_pem = ca_pem.clone();
    let key_pem = cert.serialize_private_key_pem();
    TlsMaterial {
        ca_pem,
        cert_pem,
        key_pem,
    }
}

fn write_shared_tls(fs: &dyn FileSystem, paths: &TlsPaths, mat: &TlsMaterial) {
    let _ = fs.write(&paths.cert, mat.cert_pem.as_bytes());
    let _ = fs.write(&paths.key, mat.key_pem.as_bytes());
    let _ = fs.write(&paths.ca, mat.ca_pem.as_bytes());
}

