use localbox_db::Db;
use models::{
    format_chat_thread_title, peer_thread_id, ChatMessageRecord, ThreadKind,
};

#[test]
fn chat_inbox_persists_and_marks_read() {
    let db = Db::open_in_memory().unwrap();
    let tid = peer_thread_id("a@1", "b@2");
    db.ensure_chat_thread(&tid, ThreadKind::Peer, Some("b@2"), None, "b@2", 100)
        .unwrap();
    db.insert_chat_message(
        &ChatMessageRecord {
            id: "m1".into(),
            thread_id: tid.clone(),
            from_peer: "b@2".into(),
            body: "hello".into(),
            attachment_share: None,
            attachment_path: None,
            created_at: 100,
            direction: "in".into(),
            status: "received".into(),
        },
        true,
    )
    .unwrap();
    let inbox = db.list_inbox().unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].unread_count, 1);
    db.mark_thread_read(&tid).unwrap();
    let inbox = db.list_inbox().unwrap();
    assert_eq!(inbox[0].unread_count, 0);
    let msgs = db.list_thread_messages(&tid, 10).unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].body, "hello");
}

#[test]
fn chat_thread_remembers_peer_and_share() {
    let db = Db::open_in_memory().unwrap();
    let tid = peer_thread_id("a@1", "b@2");
    db.ensure_chat_thread(&tid, ThreadKind::Peer, Some("b@2"), None, "Bob", 100)
        .unwrap();
    db.ensure_chat_thread(&tid, ThreadKind::Peer, Some("b@2"), Some("docs"), "Bob", 110)
        .unwrap();
    let inbox = db.list_inbox().unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].peer_key.as_deref(), Some("b@2"));
    assert_eq!(inbox[0].share_name.as_deref(), Some("docs"));
    // Inbound without share must not wipe the remembered share.
    db.ensure_chat_thread(&tid, ThreadKind::Peer, Some("b@2"), None, "Bob", 120)
        .unwrap();
    let inbox = db.list_inbox().unwrap();
    assert_eq!(inbox[0].share_name.as_deref(), Some("docs"));
}

#[test]
fn chat_thread_titles_are_slack_like_and_custom_rename_sticks() {
    let db = Db::open_in_memory().unwrap();
    let tid = peer_thread_id("a@1", "b@2");
    let title = format_chat_thread_title(ThreadKind::Peer, Some("Bob"), None);
    db.ensure_chat_thread(&tid, ThreadKind::Peer, Some("b@2"), None, &title, 100)
        .unwrap();
    assert_eq!(db.list_inbox().unwrap()[0].title, "Bob");

    let with_share = format_chat_thread_title(ThreadKind::Peer, Some("Bob"), Some("docs"));
    db.ensure_chat_thread(
        &tid,
        ThreadKind::Peer,
        Some("b@2"),
        Some("docs"),
        &with_share,
        110,
    )
    .unwrap();
    assert_eq!(db.list_inbox().unwrap()[0].title, "Bob · #docs");

    assert!(db.rename_chat_thread(&tid, "Project chat").unwrap());
    assert_eq!(db.list_inbox().unwrap()[0].title, "Project chat");
    assert!(db.list_inbox().unwrap()[0].title_custom);

    assert_eq!(
        db.refresh_chat_thread_titles_for_peer("b@2", "Bob Desk")
            .unwrap(),
        0
    );
    assert_eq!(db.list_inbox().unwrap()[0].title, "Project chat");
}

#[test]
fn format_chat_thread_title_helpers() {
    assert_eq!(
        format_chat_thread_title(ThreadKind::Share, None, Some("docs")),
        "#docs"
    );
    assert_eq!(
        format_chat_thread_title(ThreadKind::Peer, Some("Alice"), Some("docs")),
        "Alice · #docs"
    );
}

#[test]
fn delete_chat_message_and_thread() {
    let db = Db::open_in_memory().unwrap();
    let tid = peer_thread_id("a@1", "b@2");
    db.ensure_chat_thread(&tid, ThreadKind::Peer, Some("b@2"), None, "Bob", 100)
        .unwrap();
    db.insert_chat_message(
        &ChatMessageRecord {
            id: "m1".into(),
            thread_id: tid.clone(),
            from_peer: "b@2".into(),
            body: "hello".into(),
            attachment_share: None,
            attachment_path: None,
            created_at: 100,
            direction: "in".into(),
            status: "received".into(),
        },
        true,
    )
    .unwrap();
    db.insert_chat_message(
        &ChatMessageRecord {
            id: "m2".into(),
            thread_id: tid.clone(),
            from_peer: "a@1".into(),
            body: "hi".into(),
            attachment_share: None,
            attachment_path: None,
            created_at: 110,
            direction: "out".into(),
            status: "sent".into(),
        },
        false,
    )
    .unwrap();

    assert!(db.delete_chat_message("m1").unwrap());
    assert!(!db.delete_chat_message("m1").unwrap());
    assert_eq!(db.list_thread_messages(&tid, 10).unwrap().len(), 1);

    assert!(db.delete_chat_thread(&tid).unwrap());
    assert!(db.list_inbox().unwrap().is_empty());
    assert!(db.list_thread_messages(&tid, 10).unwrap().is_empty());
}

#[test]
fn self_keyed_peer_threads_are_repointed_at_the_counterpart() {
    let db = Db::open_in_memory().unwrap();
    let tid = peer_thread_id("a@1", "b@2");
    // How inbound chat used to land on b@2: the sender's `peer_key` addresses us, so
    // the thread named itself and the GUI had no one to reply to.
    db.ensure_chat_thread(&tid, ThreadKind::Peer, Some("b@2"), None, "b@2", 100)
        .unwrap();
    db.insert_chat_message(
        &ChatMessageRecord {
            id: "m1".into(),
            thread_id: tid.clone(),
            from_peer: "a@1".into(),
            body: "hello".into(),
            attachment_share: None,
            attachment_path: None,
            created_at: 100,
            direction: "in".into(),
            status: "received".into(),
        },
        true,
    )
    .unwrap();

    assert_eq!(db.repair_self_keyed_peer_threads("b@2").unwrap(), 1);
    let inbox = db.list_inbox().unwrap();
    assert_eq!(inbox[0].peer_key.as_deref(), Some("a@1"));
    assert_eq!(inbox[0].title, "a@1");

    // Idempotent, and healthy threads are left alone.
    assert_eq!(db.repair_self_keyed_peer_threads("b@2").unwrap(), 0);
}

#[test]
fn repair_keeps_custom_titles_and_skips_threads_with_no_inbound() {
    let db = Db::open_in_memory().unwrap();
    let tid = peer_thread_id("a@1", "b@2");
    db.ensure_chat_thread(&tid, ThreadKind::Peer, Some("b@2"), None, "b@2", 100)
        .unwrap();
    // Nothing inbound to recover the counterpart from: leave it untouched.
    assert_eq!(db.repair_self_keyed_peer_threads("b@2").unwrap(), 0);
    assert_eq!(
        db.list_inbox().unwrap()[0].peer_key.as_deref(),
        Some("b@2")
    );

    db.rename_chat_thread(&tid, "My name for it").unwrap();
    db.insert_chat_message(
        &ChatMessageRecord {
            id: "m1".into(),
            thread_id: tid.clone(),
            from_peer: "a@1".into(),
            body: "hello".into(),
            attachment_share: None,
            attachment_path: None,
            created_at: 100,
            direction: "in".into(),
            status: "received".into(),
        },
        true,
    )
    .unwrap();
    assert_eq!(db.repair_self_keyed_peer_threads("b@2").unwrap(), 1);
    let inbox = db.list_inbox().unwrap();
    assert_eq!(inbox[0].peer_key.as_deref(), Some("a@1"));
    assert_eq!(inbox[0].title, "My name for it");
}
