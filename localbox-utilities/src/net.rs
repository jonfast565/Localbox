use async_trait::async_trait;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

pub type DynStream = Box<dyn AsyncReadWrite>;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

#[async_trait]
pub trait UdpSocketLike: Send + Sync {
    async fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> io::Result<usize>;
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn set_broadcast(&self, on: bool) -> io::Result<()>;
}

#[async_trait]
pub trait TcpListenerLike: Send + Sync {
    async fn accept(&self) -> io::Result<(DynStream, SocketAddr)>;
}

#[async_trait]
pub trait Net: Send + Sync {
    async fn bind_udp(&self, addr: SocketAddr) -> io::Result<Arc<dyn UdpSocketLike>>;
    async fn bind_tcp_listener(&self, addr: SocketAddr) -> io::Result<Arc<dyn TcpListenerLike>>;
    async fn connect_tcp(&self, addr: SocketAddr) -> io::Result<DynStream>;
}

/* Real network implementation (tokio) */

#[derive(Debug, Clone)]
pub struct RealNet;

#[async_trait]
impl Net for RealNet {
    async fn bind_udp(&self, addr: SocketAddr) -> io::Result<Arc<dyn UdpSocketLike>> {
        let sock = tokio::net::UdpSocket::bind(addr).await?;
        Ok(Arc::new(RealUdpSocket(sock)))
    }

    async fn bind_tcp_listener(&self, addr: SocketAddr) -> io::Result<Arc<dyn TcpListenerLike>> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        Ok(Arc::new(RealTcpListener(listener)))
    }

    async fn connect_tcp(&self, addr: SocketAddr) -> io::Result<DynStream> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        Ok(Box::new(stream))
    }
}

struct RealUdpSocket(tokio::net::UdpSocket);

#[async_trait]
impl UdpSocketLike for RealUdpSocket {
    async fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> io::Result<usize> {
        self.0.send_to(buf, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await
    }

    fn set_broadcast(&self, on: bool) -> io::Result<()> {
        self.0.set_broadcast(on)
    }
}

struct RealTcpListener(tokio::net::TcpListener);

#[async_trait]
impl TcpListenerLike for RealTcpListener {
    async fn accept(&self) -> io::Result<(DynStream, SocketAddr)> {
        let (stream, addr) = self.0.accept().await?;
        Ok((Box::new(stream), addr))
    }
}

/* Virtual network for tests */

#[derive(Debug, Clone, Default)]
pub struct VirtualNet {
    inner: Arc<Mutex<VirtualNetInner>>,
}

#[derive(Default, Debug)]
struct VirtualNetInner {
    udp_sockets: Vec<(SocketAddr, mpsc::Sender<(Vec<u8>, SocketAddr)>)>,
    tcp_listeners: HashMap<SocketAddr, mpsc::Sender<(DynStream, SocketAddr)>>,
}

#[async_trait]
impl Net for VirtualNet {
    async fn bind_udp(&self, addr: SocketAddr) -> io::Result<Arc<dyn UdpSocketLike>> {
        let (tx, rx) = mpsc::channel(32);
        self.inner.lock().unwrap().udp_sockets.push((addr, tx));
        Ok(Arc::new(VirtualUdpSocket {
            addr,
            rx: tokio::sync::Mutex::new(rx),
            net: self.clone(),
        }))
    }

    async fn bind_tcp_listener(&self, addr: SocketAddr) -> io::Result<Arc<dyn TcpListenerLike>> {
        let (tx, rx) = mpsc::channel(32);
        self.inner.lock().unwrap().tcp_listeners.insert(addr, tx);
        Ok(Arc::new(VirtualTcpListener {
            addr,
            rx: tokio::sync::Mutex::new(rx),
        }))
    }

    async fn connect_tcp(&self, addr: SocketAddr) -> io::Result<DynStream> {
        let listener_tx =
            {
                let inner = self.inner.lock().unwrap();
                inner.tcp_listeners.get(&addr).cloned().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::ConnectionRefused, "no listener")
                })?
            };

        let (client, server) = tokio::io::duplex(64 * 1024);
        let client_stream: DynStream = Box::new(client);
        let server_stream: DynStream = Box::new(server);
        listener_tx
            .send((
                server_stream,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            ))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::ConnectionAborted, "listener dropped"))?;
        Ok(client_stream)
    }
}

struct VirtualUdpSocket {
    addr: SocketAddr,
    rx: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    net: VirtualNet,
}

#[async_trait]
impl UdpSocketLike for VirtualUdpSocket {
    async fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> io::Result<usize> {
        let packet = (buf.to_vec(), self.addr);

        let mut senders = Vec::new();
        {
            let inner = self.net.inner.lock().unwrap();
            match addr.ip() {
                IpAddr::V4(ip) if ip.is_broadcast() || ip == Ipv4Addr::new(255, 255, 255, 255) => {
                    for (_target, tx) in inner
                        .udp_sockets
                        .iter()
                        .filter(|(a, _)| a.port() == addr.port())
                    {
                        senders.push(tx.clone());
                    }
                }
                _ => {
                    for (_target, tx) in inner.udp_sockets.iter().filter(|(a, _)| a == addr) {
                        senders.push(tx.clone());
                    }
                }
            };
        }

        for tx in senders {
            let _ = tx.send(packet.clone()).await;
        }
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut rx = self.rx.lock().await;
        let (data, from) = rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "socket closed"))?;
        let len = data.len().min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);
        Ok((len, from))
    }

    fn set_broadcast(&self, _on: bool) -> io::Result<()> {
        Ok(())
    }
}

struct VirtualTcpListener {
    addr: SocketAddr,
    rx: tokio::sync::Mutex<mpsc::Receiver<(DynStream, SocketAddr)>>,
}

#[async_trait]
impl TcpListenerLike for VirtualTcpListener {
    async fn accept(&self) -> io::Result<(DynStream, SocketAddr)> {
        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some(v) => Ok(v),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("listener {} closed", self.addr),
            )),
        }
    }
}
