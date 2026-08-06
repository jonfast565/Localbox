use localbox_core::service::parse_shell_line;

#[test]
fn parses_push_and_chat() {
    let req = parse_shell_line("push --share docs --peer bob --path a.txt")
        .unwrap()
        .unwrap();
    match req {
        localbox_core::service::ControlRequest::Push { share, peer, path } => {
            assert_eq!(share, "docs");
            assert_eq!(peer.as_deref(), Some("bob"));
            assert_eq!(path.as_deref(), Some("a.txt"));
        }
        _ => panic!("expected push"),
    }

    let req = parse_shell_line("chat send --peer bob --message \"hi there\"")
        .unwrap()
        .unwrap();
    match req {
        localbox_core::service::ControlRequest::ChatSend {
            peer,
            message,
            ..
        } => {
            assert_eq!(peer.as_deref(), Some("bob"));
            assert_eq!(message.as_deref(), Some("hi there"));
        }
        _ => panic!("expected chat send"),
    }
}
