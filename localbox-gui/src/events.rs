//! Long-lived control-plane event subscription for the GUI.

use anyhow::{Context, Result};
use iced::futures::{SinkExt, Stream};
use iced::stream;
use localbox_core::ControlEvent;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::client::{ControlRequest, ControlResponse};

/// Stream of inbound [`ControlEvent`]s (reconnects on failure).
pub fn subscription(socket: PathBuf) -> impl Stream<Item = ControlEvent> {
    stream::channel(64, move |mut output| {
        let socket = socket.clone();
        async move {
            loop {
                match connect_and_pump(&socket, &mut output).await {
                    Ok(()) => {
                        eprintln!("localbox-gui: control event stream ended; reconnecting");
                    }
                    Err(e) => {
                        eprintln!("localbox-gui: control event stream: {e:#}");
                    }
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    })
}

async fn connect_and_pump<S>(socket: &Path, output: &mut S) -> Result<()>
where
    S: SinkExt<ControlEvent> + Unpin,
{
    #[cfg(unix)]
    {
        use tokio::net::UnixStream;
        let stream = UnixStream::connect(socket)
            .await
            .with_context(|| format!("connect {}", socket.display()))?;
        pump_stream(stream, output).await
    }

    #[cfg(windows)]
    {
        use localbox_core::control::windows_pipe_name;
        use tokio::net::windows::named_pipe::ClientOptions;
        let pipe_name = windows_pipe_name(socket);
        let stream = ClientOptions::new()
            .open(&pipe_name)
            .with_context(|| format!("connect {pipe_name}"))?;
        pump_stream(stream, output).await
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (socket, output);
        anyhow::bail!("unsupported platform")
    }
}

async fn pump_stream<T, S>(stream: T, output: &mut S) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
    S: SinkExt<ControlEvent> + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let req = ControlRequest::Subscribe {
        topics: Vec::new(),
    };
    let mut bytes = serde_json::to_vec(&req)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;

    let mut lines = BufReader::new(reader).lines();
    let Some(ack_line) = lines.next_line().await? else {
        anyhow::bail!("subscribe closed before ack");
    };
    let ack: ControlResponse = serde_json::from_str(&ack_line)
        .with_context(|| format!("subscribe ack: {ack_line}"))?;
    if !ack.ok {
        anyhow::bail!("subscribe rejected: {}", ack.message);
    }

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        if line.contains("\"ok\":") && !line.contains("\"event\":") {
            continue;
        }
        match serde_json::from_str::<ControlEvent>(&line) {
            Ok(event) => {
                if output.send(event).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                eprintln!("localbox-gui: bad control event line: {e}; {line}");
            }
        }
    }
    Ok(())
}

/// Sender to the notification worker; started on first use.
///
/// Notifications must not be sent from the UI thread. On macOS the backend
/// waits for delivery confirmation by pumping the main run loop, which re-enters
/// winit's event handler while `App::update` is still on the stack; that panic
/// crosses an Objective-C block boundary and aborts the process. Off the main
/// thread the same code waits on a condvar instead.
fn notifier() -> &'static Mutex<Sender<(String, String)>> {
    static TX: OnceLock<Mutex<Sender<(String, String)>>> = OnceLock::new();
    TX.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<(String, String)>();
        std::thread::Builder::new()
            .name("localbox-notify".to_string())
            .spawn(move || {
                // Claim the backend's one-shot application slot before the first
                // `show()`. Left unset, mac-notification-sys resolves the sentinel
                // name "use_default" through AppleScript, which fails and makes
                // Launch Services pop an app-chooser dialog at the user. Swap this
                // for our own identifier once the GUI ships as a real .app; the
                // bundle only decides which icon the notification wears.
                #[cfg(target_os = "macos")]
                let _ = notify_rust::set_application("com.apple.Terminal");

                for (title, body) in rx {
                    let _ = notify_rust::Notification::new()
                        .summary(&title)
                        .body(&body)
                        .appname("LocalBox")
                        .timeout(notify_rust::Timeout::Milliseconds(5000))
                        .show();
                }
            })
            .expect("spawn notification thread");
        Mutex::new(tx)
    })
}

pub fn show_os_notification(event: &ControlEvent) {
    let payload = (event.title().to_string(), event.body());
    if let Ok(tx) = notifier().lock() {
        let _ = tx.send(payload);
    }
}
