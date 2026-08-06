use localbox_models::{peer_key, peer_thread_id, share_thread_id, TransferMode};

#[test]
fn peer_thread_id_is_symmetric() {
    let a = peer_key("pc-a", "1");
    let b = peer_key("pc-b", "2");
    assert_eq!(peer_thread_id(&a, &b), peer_thread_id(&b, &a));
    assert_ne!(peer_thread_id(&a, &b), peer_thread_id(&a, &a));
}

#[test]
fn share_thread_id_is_deterministic() {
    assert_eq!(share_thread_id("docs"), share_thread_id("docs"));
    assert_ne!(share_thread_id("docs"), share_thread_id("pics"));
}

#[test]
fn transfer_mode_defaults_manual() {
    assert_eq!(TransferMode::default(), TransferMode::Manual);
    assert!(!TransferMode::Manual.is_auto());
    assert!(TransferMode::Auto.is_auto());
}
