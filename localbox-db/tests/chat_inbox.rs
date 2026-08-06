use localbox_db::Db;
use models::{
    peer_thread_id, ChatMessageRecord, ThreadKind,
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
