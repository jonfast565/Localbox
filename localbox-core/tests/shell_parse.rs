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
fn parses_chat_rename() {
    let req = parse_repl_to_request("chat rename --thread abc --title \"Project chat\"").unwrap();
    match req {
        ControlRequest::ChatRename { thread, title } => {
            assert_eq!(thread, "abc");
            assert_eq!(title, "Project chat");
        }
        _ => panic!("expected chat rename"),
    }
}

#[test]
fn parses_chat_delete() {
    let req = parse_repl_to_request("chat delete --thread abc").unwrap();
    match req {
        ControlRequest::ChatDeleteThread { thread } => assert_eq!(thread, "abc"),
        _ => panic!("expected chat delete thread"),
    }

    let req = parse_repl_to_request("chat delete-message --message mid").unwrap();
    match req {
        ControlRequest::ChatDeleteMessage { message } => assert_eq!(message, "mid"),
        _ => panic!("expected chat delete message"),
    }
}

#[test]
fn push_requires_a_share() {
    assert!(parse_repl_to_request("push --peer bob").is_err());
}

#[test]
fn parses_shutdown_and_stop() {
    assert!(matches!(
        parse_repl_to_request("shutdown").unwrap(),
        ControlRequest::Shutdown
    ));
    assert!(matches!(
        parse_repl_to_request("stop").unwrap(),
        ControlRequest::Shutdown
    ));
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

#[test]
fn parses_logs_tail() {
    let req = parse_repl_to_request("logs").unwrap();
    assert!(matches!(req, ControlRequest::Logs { limit: None }));
    let req = parse_repl_to_request("logs --limit 50").unwrap();
    match req {
        ControlRequest::Logs { limit: Some(50) } => {}
        other => panic!("unexpected {other:?}"),
    }
}


#[test]
fn logs_request_serde_round_trip() {
    let req = ControlRequest::Logs { limit: Some(100) };
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains(r#""cmd":"logs""#), "got {json}");
    let back: ControlRequest = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, ControlRequest::Logs { limit: Some(100) }));
}
