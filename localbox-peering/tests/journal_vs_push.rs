//! End-to-end coverage for the boundary between the two ways bytes reach a peer:
//! continuous **journal sync** (`SyncCatchup` over a `JournalRange`) and a
//! **manual push** (`SnapshotPush` over a `Snapshot` of the file index).
//!
//! They share a table, a queue and a status enum, and they used to share a seq
//! namespace too. These tests pin the separation that keeps them from
//! contaminating each other.

mod harness;

use std::time::Duration;

use harness::*;
use models::ChangeKind;

/// Manual push and journal catchup, interleaved against the same share and peer.
///
/// Before the namespaces were separated this was the failing case: the snapshot
/// push minted receiver-local seqs, which inflated the watermark that inbound
/// journal changes were checked against, so step (c) was silently dropped as a
/// "replay" while still being acked as delivered.
#[tokio::test(flavor = "current_thread")]
async fn manual_push_and_journal_catchup_interleave_on_same_share_and_peer() {
    let mut net = TwoNodes::start("interleave", 6301, 7301).await;

    // (a) A journaled change syncs across.
    let a_seq = net.journal_on_1("a.txt", ChangeKind::Modify, Some(b"aaa")).await;
    net.sync_1(0, a_seq).await;
    net.wait_mirrored("a.txt", b"aaa").await;

    // (b) A manual push of a file that is only in the index, never journaled.
    net.push_from_1("b.txt", b"bbb").await;
    net.wait_mirrored("b.txt", b"bbb").await;

    // (c) Another journaled change. This is the one that used to vanish.
    let c_seq = net.journal_on_1("c.txt", ChangeKind::Modify, Some(b"ccc")).await;
    net.sync_1(a_seq, c_seq).await;
    net.wait_mirrored("c.txt", b"ccc").await;

    // The mirror's journal: local seqs stay contiguous, origin seqs keep the
    // sender's numbering, and the push sits between them carrying no position.
    let entries = net.mirror_journal().await;
    let paths: Vec<String> = entries.iter().map(|e| e.change.path.clone()).collect();
    let local: Vec<i64> = entries.iter().map(|e| e.change.seq).collect();
    let origin: Vec<i64> = entries.iter().map(|e| e.origin_seq).collect();

    assert_eq!(paths, vec!["a.txt", "b.txt", "c.txt"]);
    assert_eq!(local, vec![1, 2, 3], "local seqs must be contiguous");
    assert_eq!(
        origin,
        vec![a_seq, 0, c_seq],
        "journal entries keep the sender's seq; the push carries 0"
    );

    net.shutdown().await;
}

/// After a manual push, journal sync must keep flowing. This is the regression
/// for the permanent stall: the receiver used to ack a local seq, the sender
/// assigned it into its own namespace, and `to_seq <= from_seq` then skipped
/// every subsequent catchup forever.
#[tokio::test(flavor = "current_thread")]
async fn sync_does_not_stall_after_manual_push() {
    let mut net = TwoNodes::start("stall", 6302, 7302).await;

    // A manual push of several files, so a naive receiver would mint local seqs
    // well above anything in the sender's journal.
    for (name, body) in [("p1.txt", &b"111"[..]), ("p2.txt", b"222"), ("p3.txt", b"333")] {
        net.push_from_1(name, body).await;
        net.wait_mirrored(name, body).await;
    }

    // Now journal a change and sync it.
    let seq = net.journal_on_1("later.txt", ChangeKind::Modify, Some(b"later")).await;
    net.sync_1(0, seq).await;
    net.wait_mirrored("later.txt", b"later").await;

    // The sender's outbound watermark must stay within its own journal.
    let acked = net.node1_acked_watermark().await;
    let journal_max = net.node1_journal_max().await;
    assert!(
        acked <= journal_max,
        "outbound watermark {acked} escaped the sender's journal (max {journal_max})"
    );

    net.shutdown().await;
}

/// A snapshot push carries no journal position, so it must leave the receiver's
/// inbound watermark alone -- otherwise the next `TransferRequest` asks for
/// history the peer will then skip. Pins the README's "peer_progress advances
/// only for SyncCatchup".
#[tokio::test(flavor = "current_thread")]
async fn snapshot_push_never_advances_receiver_inbound_watermark() {
    let mut net = TwoNodes::start("watermark", 6303, 7303).await;

    net.push_from_1("only.txt", b"only").await;
    net.wait_mirrored("only.txt", b"only").await;

    assert_eq!(
        net.node2_inbound_watermark().await,
        0,
        "a snapshot push must not move the inbound watermark"
    );

    // A journal sync does move it, to the range it declared.
    let seq = net.journal_on_1("j.txt", ChangeKind::Modify, Some(b"j")).await;
    net.sync_1(0, seq).await;
    net.wait_mirrored("j.txt", b"j").await;
    assert_eq!(net.node2_inbound_watermark().await, seq);

    net.shutdown().await;
}

/// A push must not overwrite `FileMeta.version` with a receiver-local number:
/// `version` is the conflict-resolution key, so inflating it would shadow
/// genuine later updates to the same path.
#[tokio::test(flavor = "current_thread")]
async fn snapshot_push_does_not_inflate_file_meta_version() {
    let mut net = TwoNodes::start("version", 6304, 7304).await;

    net.push_from_1("doc.txt", b"v1").await;
    net.wait_mirrored("doc.txt", b"v1").await;

    let sender_version = net.node1_meta_version("doc.txt").await;
    let mirror_version = net.node2_meta_version("doc.txt").await;
    assert_eq!(
        mirror_version, sender_version,
        "mirror must keep the sender's index version, not a local seq"
    );

    // A genuine later update still wins.
    net.push_from_1_with_version("doc.txt", b"v2", sender_version + 1).await;
    net.wait_mirrored("doc.txt", b"v2").await;

    net.shutdown().await;
}

/// Re-delivering the same journal range is a no-op, not a duplicate or an error.
/// The partial unique index over (share, origin_peer, origin_seq) is what makes
/// this durable across restarts and out-of-order delivery.
#[tokio::test(flavor = "current_thread")]
async fn redelivered_journal_range_is_idempotent() {
    let mut net = TwoNodes::start("redeliver", 6305, 7305).await;

    let seq = net.journal_on_1("x.txt", ChangeKind::Modify, Some(b"xxx")).await;
    net.sync_1(0, seq).await;
    net.wait_mirrored("x.txt", b"xxx").await;
    assert_eq!(net.mirror_journal().await.len(), 1);

    // Ship the identical range again, as a bootstrap intent racing a catchup would.
    net.sync_1(0, seq).await;
    tokio::time::sleep(Duration::from_millis(600)).await;

    assert_eq!(
        net.mirror_journal().await.len(),
        1,
        "re-delivered journal entry must not duplicate"
    );

    net.shutdown().await;
}
