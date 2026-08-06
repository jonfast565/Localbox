//! Interactive REPL for Localbox (in-process or attached to control socket).
//!
//! Uses rustyline for line editing/history. Engine logs are routed through an
//! ExternalPrinter so they scroll above a sticky `localbox>` prompt.

use anyhow::{anyhow, Result};
use db::Db;
use models::{AppConfig, TransferProgressRegistry};
use peering::PeerCommand;
use rustyline::error::ReadlineError;
use rustyline::{DefaultEditor, ExternalPrinter};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self as std_mpsc, SyncSender};
use std::sync::Arc;
use std::thread;
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::info;
use utilities::set_console_log_bridge;

use crate::control::send_control_request;
use crate::service::{ControlRequest, ControlResponse, ControlService, ShareHooks};

enum ReplEvent {
    Line { line: String, done: SyncSender<()> },
    Eof,
}

pub async fn run_inprocess_shell(
    cfg: AppConfig,
    db: Arc<Mutex<Db>>,
    net_tx: mpsc::Sender<String>,
    cmd_tx: mpsc::Sender<PeerCommand>,
    progress: Arc<TransferProgressRegistry>,
    share_hooks: Option<ShareHooks>,
    token: CancellationToken,
) -> Result<()> {
    info!("Interactive shell (in-process). Type 'help' or 'quit'.");
    let service = ControlService {
        cfg,
        db,
        net_tx,
        peer_cmd_tx: cmd_tx,
        progress,
        share_hooks,
        token: token.clone(),
    };
    run_repl_loop(
        "localbox interactive shell. Logs scroll above; type help or quit.",
        token.clone(),
        move |line| {
            let service = service.clone();
            let token = token.clone();
            async move {
                if matches!(line.as_str(), "quit" | "exit" | "q") {
                    token.cancel();
                    return true;
                }
                if line == "help" || line == "?" {
                    print_help();
                    return false;
                }
                match parse_repl_to_request(&line) {
                    Ok(req) => {
                        let shutting_down = matches!(req, ControlRequest::Shutdown);
                        let resp = service.handle(req).await;
                        print_resp(&resp);
                        if shutting_down {
                            return true;
                        }
                    }
                    Err(e) => eprintln!("error: {e}"),
                }
                false
            }
        },
    )
    .await
}

pub async fn run_attached_shell(socket: PathBuf) -> Result<()> {
    if !socket.exists() {
        return Err(anyhow!(
            "control socket {} not found; start `localbox run` or `localbox run --interactive` first",
            socket.display()
        ));
    }
    let banner = format!(
        "localbox shell attached to {}. Logs scroll above; type help or quit.",
        socket.display()
    );
    let token = CancellationToken::new();
    run_repl_loop(&banner, token.clone(), move |line| {
        let socket = socket.clone();
        let token = token.clone();
        async move {
            if matches!(line.as_str(), "quit" | "exit" | "q") {
                token.cancel();
                return true;
            }
            if line == "help" || line == "?" {
                print_help();
                return false;
            }
            match parse_repl_to_request(&line) {
                Ok(req) => {
                    let shutting_down = matches!(req, ControlRequest::Shutdown);
                    match send_control_request(&socket, &req).await {
                        Ok(resp) => print_resp(&resp),
                        Err(e) => eprintln!("error: {e}"),
                    }
                    if shutting_down {
                        token.cancel();
                        return true;
                    }
                }
                Err(e) => eprintln!("error: {e}"),
            }
            false
        }
    })
    .await
}

async fn run_repl_loop<F, Fut>(banner: &str, token: CancellationToken, mut on_line: F) -> Result<()>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let (log_tx, log_rx) = std_mpsc::channel::<String>();
    set_console_log_bridge(Some(log_tx));

    let (event_tx, mut event_rx) = mpsc::channel::<ReplEvent>(8);
    let banner = banner.to_string();
    let readline_token = token.clone();

    let readline_thread = thread::spawn(move || -> Result<()> {
        let mut rl = DefaultEditor::new()?;
        let mut printer = rl.create_external_printer()?;
        let _ = printer.print(format!("{banner}\n"));

        let printer_thread = thread::spawn(move || {
            while let Ok(chunk) = log_rx.recv() {
                for line in chunk.split_inclusive('\n') {
                    if line.is_empty() {
                        continue;
                    }
                    let _ = printer.print(line.to_string());
                }
            }
        });

        let result = (|| -> Result<()> {
            loop {
                if readline_token.is_cancelled() {
                    break;
                }
                match rl.readline("localbox> ") {
                    Ok(line) => {
                        let trimmed = line.trim().to_string();
                        if trimmed.is_empty() {
                            continue;
                        }
                        let _ = rl.add_history_entry(trimmed.as_str());
                        let (done_tx, done_rx) = std_mpsc::sync_channel(0);
                        if event_tx
                            .blocking_send(ReplEvent::Line {
                                line: trimmed,
                                done: done_tx,
                            })
                            .is_err()
                        {
                            break;
                        }
                        let _ = done_rx.recv();
                        if readline_token.is_cancelled() {
                            break;
                        }
                    }
                    Err(ReadlineError::Interrupted) => continue,
                    Err(ReadlineError::Eof) => {
                        let _ = event_tx.blocking_send(ReplEvent::Eof);
                        break;
                    }
                    Err(e) => return Err(anyhow!("readline error: {e}")),
                }
            }
            Ok(())
        })();

        // Drop the console bridge so the printer thread can exit (channel closes).
        set_console_log_bridge(None);
        drop(event_tx);
        let _ = printer_thread.join();
        result
    });

    while let Some(ev) = event_rx.recv().await {
        match ev {
            ReplEvent::Eof => {
                token.cancel();
                break;
            }
            ReplEvent::Line { line, done } => {
                let quit = on_line(line).await;
                let _ = done.send(());
                if quit {
                    break;
                }
            }
        }
    }

    set_console_log_bridge(None);
    token.cancel();
    match readline_thread.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(anyhow!("readline thread panicked")),
    }
}

fn print_help() {
    println!(
        "Commands:\n\
         \x20 status | peers | shares | pending | intents [--all] [--limit N]\n\
         \x20 share list | share add --name NAME --path DIR [--recursive true|false]\n\
         \x20 intent show --id ID\n\
         \x20 push --share NAME [--peer KEY] [--path REL]\n\
         \x20 pull|request --share NAME --peer KEY [--path REL]\n\
         \x20 reply --id ID accept|decline\n\
         \x20 chat inbox | chat show --thread ID | chat read --thread ID\n\
         \x20 chat send --peer KEY|--share NAME --message TEXT\n\
         \x20 chat send --peer KEY --file REL --share-dest NAME\n\
         \x20 shutdown | stop  — stop the daemon (control-plane Shutdown)\n\
         \x20 quit | exit | q  — leave this shell / disconnect (does not stop a remote daemon)"
    );
}

fn print_resp(resp: &ControlResponse) {
    if resp.ok {
        println!("{}", resp.message);
        if let Some(data) = &resp.data {
            println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
        }
    } else {
        eprintln!("error: {}", resp.message);
    }
}

pub fn parse_repl_to_request(line: &str) -> Result<ControlRequest> {
    let parts = shell_split(line);
    if parts.is_empty() {
        return Err(anyhow!("empty command"));
    }
    match parts[0].as_str() {
        "status" | "ping" => Ok(ControlRequest::Status),
        "shutdown" | "stop" => Ok(ControlRequest::Shutdown),
        "peers" => Ok(ControlRequest::Status), // status includes peer count; use Pending for lists via inbox-like
        "shares" => Ok(ControlRequest::ShareList),
        "share" => {
            let sub = parts
                .get(1)
                .map(|s| s.as_str())
                .ok_or_else(|| anyhow!("usage: share list | share add --name NAME --path DIR"))?;
            match sub {
                "list" | "ls" => Ok(ControlRequest::ShareList),
                "add" => {
                    let args = parse_flags(&parts[2..])?;
                    let name = required(&args, "name").or_else(|_| required(&args, "share"))?;
                    let path = required(&args, "path").or_else(|_| required(&args, "root"))?;
                    let recursive = args
                        .get("recursive")
                        .map(|v| v != "false" && v != "0")
                        .unwrap_or(true);
                    Ok(ControlRequest::ShareAdd {
                        name,
                        path,
                        recursive,
                    })
                }
                other => Err(anyhow!("unknown share subcommand '{other}'")),
            }
        }
        "pending" | "pending_requests" => Ok(ControlRequest::PendingRequests),
        "intents" => {
            let args = parse_flags(&parts[1..])?;
            Ok(ControlRequest::Intents {
                all: args.contains_key("all"),
                limit: args.get("limit").and_then(|s| s.parse().ok()),
            })
        }
        "intent" => {
            let args = parse_flags(&parts[1..])?;
            let id = args
                .get("id")
                .cloned()
                .or_else(|| parts.get(2).cloned())
                .ok_or_else(|| anyhow!("usage: intent show --id ID"))?;
            Ok(ControlRequest::IntentShow { id })
        }
        "push" => {
            let args = parse_flags(&parts[1..])?;
            Ok(ControlRequest::Push {
                share: required(&args, "share")?,
                peer: args.get("peer").cloned(),
                path: args.get("path").cloned(),
            })
        }
        "pull" => {
            let args = parse_flags(&parts[1..])?;
            Ok(ControlRequest::Pull {
                share: required(&args, "share")?,
                peer: required(&args, "peer")?,
                path: args.get("path").cloned(),
            })
        }
        "request" => {
            let args = parse_flags(&parts[1..])?;
            Ok(ControlRequest::Request {
                share: required(&args, "share")?,
                peer: required(&args, "peer")?,
                path: args.get("path").cloned(),
            })
        }
        "reply" => {
            let args = parse_flags(&parts[1..])?;
            let id = args
                .get("id")
                .cloned()
                .or_else(|| args.get("request_id").cloned())
                .or_else(|| parts.get(1).filter(|p| !p.starts_with('-')).cloned())
                .ok_or_else(|| anyhow!("reply requires --id"))?;
            let action = args
                .get("action")
                .cloned()
                .or_else(|| {
                    parts
                        .iter()
                        .find(|p| *p == "accept" || *p == "decline")
                        .cloned()
                })
                .unwrap_or_else(|| "accept".into());
            Ok(ControlRequest::Reply {
                id,
                accept: action == "accept",
                reason: args.get("reason").cloned(),
            })
        }
        "chat" => {
            let sub = parts
                .get(1)
                .map(|s| s.as_str())
                .ok_or_else(|| anyhow!("chat requires subcommand"))?;
            match sub {
                "inbox" | "threads" => Ok(ControlRequest::ChatInbox),
                "show" => {
                    let args = parse_flags(&parts[2..])?;
                    Ok(ControlRequest::ChatShow {
                        thread: required(&args, "thread")
                            .or_else(|_| required(&args, "thread_id"))?,
                        limit: args.get("limit").and_then(|s| s.parse().ok()),
                    })
                }
                "read" => {
                    let args = parse_flags(&parts[2..])?;
                    Ok(ControlRequest::ChatRead {
                        thread: required(&args, "thread")
                            .or_else(|_| required(&args, "thread_id"))?,
                    })
                }
                "send" => {
                    let args = parse_flags(&parts[2..])?;
                    Ok(ControlRequest::ChatSend {
                        peer: args.get("peer").cloned(),
                        share: args.get("share").cloned(),
                        thread: args
                            .get("thread")
                            .cloned()
                            .or_else(|| args.get("thread_id").cloned()),
                        message: args.get("message").cloned(),
                        file: args.get("file").cloned(),
                        share_dest: args
                            .get("share-dest")
                            .cloned()
                            .or_else(|| args.get("share_dest").cloned()),
                    })
                }
                other => Err(anyhow!("unknown chat subcommand '{other}'")),
            }
        }
        other => Err(anyhow!("unknown command '{other}'")),
    }
}

fn shell_split(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for ch in line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn parse_flags(parts: &[String]) -> Result<std::collections::HashMap<String, String>> {
    let mut map = std::collections::HashMap::new();
    let mut i = 0;
    while i < parts.len() {
        let p = &parts[i];
        if let Some(key) = p.strip_prefix("--") {
            if let Some((k, v)) = key.split_once('=') {
                map.insert(k.to_string(), v.to_string());
            } else if i + 1 < parts.len() && !parts[i + 1].starts_with("--") {
                map.insert(key.to_string(), parts[i + 1].clone());
                i += 1;
            } else {
                map.insert(key.to_string(), "true".into());
            }
        }
        i += 1;
    }
    Ok(map)
}

fn required(args: &std::collections::HashMap<String, String>, key: &str) -> Result<String> {
    args.get(key)
        .cloned()
        .ok_or_else(|| anyhow!("missing --{key}"))
}

#[allow(dead_code)]
pub async fn call_via_socket(socket: &Path, req: &ControlRequest) -> Result<ControlResponse> {
    send_control_request(socket, req).await
}
