use irontide_utp::{UtpConfig, UtpSocket};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn utp_localhost_stream_round_trip() {
    let bind_a: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (sock_a, mut listener) = UtpSocket::bind(UtpConfig {
        bind_addr: bind_a,
        ..UtpConfig::default()
    })
    .await
    .expect("bind a");
    let addr_a = sock_a.local_addr();

    let accept = tokio::spawn(async move {
        let (mut stream, _peer) = listener.accept().await.expect("accept");
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ping");
        stream.write_all(b"pong").await.expect("write");
        stream.flush().await.ok();
    });

    let (sock_b, _listener_b) = UtpSocket::bind(UtpConfig {
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ..UtpConfig::default()
    })
    .await
    .expect("bind b");

    let mut client = sock_b.connect(addr_a).await.expect("connect");
    client.write_all(b"ping").await.expect("client write");
    client.flush().await.ok();
    let mut buf = [0u8; 4];
    client.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf, b"pong");

    accept.await.expect("accept task");
    let _ = sock_a.shutdown().await;
    let _ = sock_b.shutdown().await;
}
