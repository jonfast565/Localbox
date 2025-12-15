use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use utilities::{Net, VirtualNet};

#[tokio::test]
async fn udp_broadcast_delivers_to_all_sockets_on_port() {
    let net = VirtualNet::default();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9000);

    let sock1 = net.bind_udp(addr).await.unwrap();
    let sock2 = net.bind_udp(addr).await.unwrap();

    let payload = b"hello-broadcast";
    let broadcast_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), 9000);
    sock1.send_to(payload, &broadcast_addr).await.unwrap();

    let mut buf1 = [0u8; 64];
    let mut buf2 = [0u8; 64];
    let (n1, from1) = tokio::time::timeout(Duration::from_millis(200), sock1.recv_from(&mut buf1))
        .await
        .unwrap()
        .unwrap();
    let (n2, from2) = tokio::time::timeout(Duration::from_millis(200), sock2.recv_from(&mut buf2))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(&buf1[..n1], payload);
    assert_eq!(&buf2[..n2], payload);
    assert_eq!(from1.port(), 9000);
    assert_eq!(from2.port(), 9000);
    assert!(from1.ip().is_unspecified());
    assert!(from2.ip().is_unspecified());
}

#[tokio::test]
async fn udp_unicast_only_delivers_to_target_addr() {
    let net = VirtualNet::default();

    let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9001);
    let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9002);
    let sock_a = net.bind_udp(a).await.unwrap();
    let sock_b = net.bind_udp(b).await.unwrap();

    sock_a.send_to(b"hello", &b).await.unwrap();

    let mut buf = [0u8; 32];
    let (n, from) = tokio::time::timeout(Duration::from_millis(200), sock_b.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"hello");
    assert_eq!(from, a);

    let mut buf2 = [0u8; 32];
    let recv_a =
        tokio::time::timeout(Duration::from_millis(100), sock_a.recv_from(&mut buf2)).await;
    assert!(
        recv_a.is_err(),
        "sender socket should not receive unicast to a different addr"
    );
}

#[tokio::test]
async fn tcp_connect_accept_is_duplex() {
    let net: Arc<dyn Net> = Arc::new(VirtualNet::default());
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9010);
    let listener = net.bind_tcp_listener(addr).await.unwrap();

    let server_task = tokio::spawn(async move {
        let (mut server_stream, _peer_addr) = listener.accept().await.unwrap();

        let mut buf = [0u8; 5];
        server_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping!");

        server_stream.write_all(b"pong!").await.unwrap();
    });

    let mut client = net.connect_tcp(addr).await.unwrap();
    client.write_all(b"ping!").await.unwrap();
    let mut reply = [0u8; 5];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"pong!");

    server_task.await.unwrap();
}

#[tokio::test]
async fn tcp_connect_without_listener_fails() {
    let net = VirtualNet::default();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
    match net.connect_tcp(addr).await {
        Ok(_) => panic!("connect_tcp should fail without a listener"),
        Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused),
    }
}
