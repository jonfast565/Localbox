//! Covers the parser the live REPL actually uses (`shell::parse_repl_to_request`),
//! reached from both the in-process shell and the attached `localbox shell`.

use localbox_core::service::ControlRequest;
use localbox_core::shell::parse_repl_to_request;

#[test]
fn parses_push_and_chat() {
    let req = parse_repl_to_request("push --share docs --peer bob --path a.txt").unwrap();
    match req {
        ControlRequest::Push { share, peer, path } => {
            assert_eq!(share, "docs");
            assert_eq!(peer.as_deref(), Some("bob"));
            assert_eq!(path.as_deref(), Some("a.txt"));
        }
        _ => panic!("expected push"),
    }

    let req = parse_repl_to_request("chat send --peer bob --message \"hi there\"").unwrap();
    match req {
        ControlRequest::ChatSend { peer, message, .. } => {
            assert_eq!(peer.as_deref(), Some("bob"));
            assert_eq!(message.as_deref(), Some("hi there"));
        }
        _ => panic!("expected chat send"),
    }
}

#[test]
fn push_requires_a_share() {
    assert!(parse_repl_to_request("push --peer bob").is_err());
}

#[test]
fn parses_share_add_and_list() {
    let req = parse_repl_to_request("share add --name docs --path /tmp/docs").unwrap();
    match req {
        ControlRequest::ShareAdd {
            name,
            path,
            recursive,
        } => {
            assert_eq!(name, "docs");
            assert_eq!(path, "/tmp/docs");
            assert!(recursive);
        }
        _ => panic!("expected share add"),
    }

    let req = parse_repl_to_request("shares").unwrap();
    assert!(matches!(req, ControlRequest::ShareList));
    let req = parse_repl_to_request("share list").unwrap();
    assert!(matches!(req, ControlRequest::ShareList));
}
