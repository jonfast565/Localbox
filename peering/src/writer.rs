use anyhow::Result;
use models::WireMessage;
use protocol::parse_wire_message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use utilities::DynStream;

pub type ServerTls = ServerTlsStream<DynStream>;
pub type ClientTls = ClientTlsStream<DynStream>;

pub enum PeerWriter {
    Server(WriteHalf<ServerTls>),
    Client(WriteHalf<ClientTls>),
}

impl PeerWriter {
    pub async fn send(&mut self, msg: &WireMessage) -> Result<()> {
        match self {
            PeerWriter::Server(w) => send_framed_message(w, msg).await,
            PeerWriter::Client(w) => send_framed_message(w, msg).await,
        }
    }
}

pub async fn send_framed_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &WireMessage,
) -> Result<()> {
    let bytes = serde_json::to_vec(msg)?;
    let len = bytes.len() as u32;
    let mut header = len.to_be_bytes().to_vec();
    header.extend_from_slice(&bytes);
    writer.write_all(&header).await?;
    Ok(())
}

pub async fn recv_framed_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<WireMessage>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Ok(None);
        }
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    parse_wire_message(&buf).map(Some)
}
