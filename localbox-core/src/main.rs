use clap::Parser;
use comfy_table::{presets::ASCII_FULL_CONDENSED, Table};
use localbox_core::config::{
    init_config_template, set_quarantined_peer_in_config, validate_app_config, BootstrapCommand,
    ChatCommand, Cli, Command, ConfigCliCommand, PeerCliCommand, ShareCliCommand, StatusSection,
    DEFAULT_CONFIG_PATH,
};
use localbox_core::control::send_control_request;
use localbox_core::integrity;
use localbox_core::monitoring;
use localbox_core::service::ControlRequest;
use localbox_core::shell::run_attached_shell;
use localbox_core::Engine;
use peering::PeerCommand;
use serde_json::json;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use tls::{self, bootstrap, workflow};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use utilities::{copy_file_atomic, write_file_atomic, RealFileSystem};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Command::Run(run_args) => {
            let cfg = cli.resolve_app_config_with_overrides(run_args)?;
            validate_app_config(&cfg)?;
            let engine = Engine::new(cfg)?;
            if run_args.interactive {
                let (cmd_tx, cmd_rx) = mpsc::channel::<PeerCommand>(256);
                let token = CancellationToken::new();
                engine
                    .run_with_peer_commands(token, cmd_tx, cmd_rx, true)
                    .await
            } else {
                engine.run().await
            }
        }
        Command::Shell(args) | Command::Interactive(args) => {
            let sock = resolve_control_socket(&cli, args.socket.clone())?;
            run_attached_shell(sock).await
        }
        Command::Stop(args) => {
            let sock = resolve_control_socket(&cli, args.socket.clone())?;
            let resp = send_control_request(&sock, &ControlRequest::Shutdown).await?;
            print_control_resp(&resp);
            if resp.ok {
                Ok(())
            } else {
                Err(anyhow::anyhow!(resp.message))
            }
        }
        Command::Push(args) => {
            let sock = resolve_control_socket(&cli, args.socket.clone())?;
            let resp = send_control_request(
                &sock,
                &ControlRequest::Push {
                    share: args.share.clone(),
                    peer: args.peer.clone(),
                    path: args.path.clone(),
                },
            )
            .await?;
            print_control_resp(&resp);
            if resp.ok {
                Ok(())
            } else {
                Err(anyhow::anyhow!(resp.message))
            }
        }
        Command::Pull(args) | Command::Request(args) => {
            let sock = resolve_control_socket(&cli, args.socket.clone())?;
            let resp = send_control_request(
                &sock,
                &ControlRequest::Request {
                    share: args.share.clone(),
                    peer: args.peer.clone(),
                    path: args.path.clone(),
                },
            )
            .await?;
            print_control_resp(&resp);
            if resp.ok {
                Ok(())
            } else {
                Err(anyhow::anyhow!(resp.message))
            }
        }
        Command::Reply(args) => {
            let sock = resolve_control_socket(&cli, args.socket.clone())?;
            let accept = args.action == "accept";
            let resp = send_control_request(
                &sock,
                &ControlRequest::Reply {
                    id: args.id.clone(),
                    accept,
                    reason: args.reason.clone(),
                },
            )
            .await?;
            print_control_resp(&resp);
            if resp.ok {
                Ok(())
            } else {
                Err(anyhow::anyhow!(resp.message))
            }
        }
        Command::Intents(args) => {
            let sock = resolve_control_socket(&cli, args.socket.clone())?;
            let req = if let Some(id) = &args.id {
                ControlRequest::IntentShow { id: id.clone() }
            } else {
                ControlRequest::Intents {
                    all: args.all,
                    limit: args.limit,
                }
            };
            let resp = send_control_request(&sock, &req).await?;
            print_control_resp(&resp);
            if resp.ok {
                Ok(())
            } else {
                Err(anyhow::anyhow!(resp.message))
            }
        }
        Command::Chat(args) => handle_chat_command(&cli, args).await,
        Command::Init(args) => {
            let path = cli
                .config
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("config.toml"));
            init_config_template(&path, args.force)?;
            println!("Wrote {}", path.display());
            Ok(())
        }
        Command::Validate(_) => {
            let cfg = cli.resolve_app_config()?;
            validate_app_config(&cfg)?;
            println!("OK");
            Ok(())
        }
        Command::Audit(args) => {
            let cfg = cli.resolve_app_config_allow_empty_shares()?;
            let db = db::Db::open(&cfg.db_path)?;
            let fs = RealFileSystem::new();
            let report = integrity::audit_disk(&db, &fs, args.share.as_deref())?;
            if report.checked == 0 {
                println!("No files to verify");
                return Ok(());
            }
            if report.issues.is_empty() {
                println!("Verified {} file(s); no issues found", report.checked);
            } else {
                println!(
                    "Verified {} file(s); {} issue(s) detected:",
                    report.checked,
                    report.issues.len()
                );
                for issue in &report.issues {
                    match &issue.kind {
                        integrity::IntegrityIssueKind::Missing => {
                            println!(" - [{}] {} (missing)", issue.share, issue.path);
                        }
                        integrity::IntegrityIssueKind::HashMismatch { expected, actual } => {
                            println!(
                                " - [{}] {} (hash mismatch expected {}, got {})",
                                issue.share, issue.path, expected, actual
                            );
                        }
                        integrity::IntegrityIssueKind::IoError(e) => {
                            println!(" - [{}] {} (io error: {})", issue.share, issue.path, e);
                        }
                    }
                }
            }
            Ok(())
        }
        Command::Monitor(args) => {
            let cfg = cli.resolve_app_config_allow_empty_shares()?;
            let opts = monitoring::MonitorOptions {
                interval_secs: args.interval_secs,
                iterations: args.iterations,
                queue_threshold: args.queue_threshold,
                stale_peer_seconds: args.stale_peer_seconds,
                json: args.json,
                exit_on_alert: args.exit_on_alert,
            };
            monitoring::run_monitor(&cfg, &opts)
        }
        Command::Status(args) => {
            let cfg = cli.resolve_app_config_allow_empty_shares()?;
            let db = db::Db::open(&cfg.db_path)?;
            let now = time::OffsetDateTime::now_utc().unix_timestamp();

            let peers = db.list_peers()?;
            let shares = db.list_shares_table()?;
            let progress = db.list_peer_progress_table()?;
            let peer_count = peers.len();
            let share_count = shares.len();
            let progress_count = progress.len();
            let queue_depth = db.outbound_queue_depth()?;
            let queue_due = db.outbound_queue_due_now(now)?;
            let journal_entries = db.journal_entry_count()?;
            let db_filename = cfg
                .db_path
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| "".into());

            if args.json {
                let db_json = || -> serde_json::Value {
                    json!({
                        "path": cfg.db_path.to_string_lossy(),
                        "filename": db_filename.clone(),
                        "table_counts": {
                            "peers": peer_count,
                            "shares": share_count,
                            "peer_progress": progress_count,
                        },
                    })
                };
                let peers_json = || -> Vec<serde_json::Value> {
                    peers
                        .iter()
                        .map(|p| {
                            json!({
                                "id": p.id,
                                "pc_name": p.pc_name,
                                "instance_id": p.instance_id,
                                "last_ip": p.last_ip,
                                "last_port": p.last_port,
                                "last_tls_port": p.last_tls_port,
                                "last_plain_port": p.last_plain_port,
                                "last_seen": p.last_seen,
                                "state": p.state,
                                "prefer_tls": p.prefer_tls,
                                "last_insecure_seen": p.last_insecure_seen,
                                "quarantined": p.quarantined,
                            })
                        })
                        .collect()
                };
                let shares_json = || -> Vec<serde_json::Value> {
                    shares
                        .iter()
                        .map(|s| {
                            json!({
                                "id": s.id,
                                "share_name": s.share_name,
                                "pc_name": s.pc_name,
                                "root_path": s.root_path,
                                "recursive": s.recursive,
                            })
                        })
                        .collect()
                };
                let progress_json = || -> Vec<serde_json::Value> {
                    progress
                        .iter()
                        .map(|r| {
                            json!({
                                "peer_id": r.peer_id,
                                "peer_pc_name": r.peer_pc_name,
                                "peer_instance_id": r.peer_instance_id,
                                "share_row_id": r.share_row_id,
                                "share_name": r.share_name,
                                "share_pc_name": r.share_pc_name,
                                "last_seq_sent": r.last_seq_sent,
                                "last_seq_acked": r.last_seq_acked,
                            })
                        })
                        .collect()
                };
                match args.section {
                    None => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "db": db_json(),
                                "metrics": {
                                    "outbound_queue_depth": queue_depth,
                                    "outbound_queue_due_now": queue_due,
                                    "journal_entries": journal_entries,
                                },
                                "peers": peers_json(),
                                "shares": shares_json(),
                                "peer_progress": progress_json(),
                            }))?
                        );
                    }
                    Some(StatusSection::Db) => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({ "db": db_json() }))?
                        );
                    }
                    Some(StatusSection::Queue) => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "queue": {
                                    "outbound_queue_depth": queue_depth,
                                    "outbound_queue_due_now": queue_due,
                                },
                            }))?
                        );
                    }
                    Some(StatusSection::Metrics) => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "metrics": {
                                    "journal_entries": journal_entries,
                                },
                            }))?
                        );
                    }
                    Some(StatusSection::Peers) => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({ "peers": peers_json() }))?
                        );
                    }
                    Some(StatusSection::Shares) => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({ "shares": shares_json() }))?
                        );
                    }
                    Some(StatusSection::PeerProgress) => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(
                                &json!({ "peer_progress": progress_json() })
                            )?
                        );
                    }
                }
                return Ok(());
            }

            let default_sections = [
                StatusSection::Db,
                StatusSection::Queue,
                StatusSection::Metrics,
                StatusSection::Peers,
                StatusSection::Shares,
                StatusSection::PeerProgress,
            ];
            let sections: Vec<StatusSection> = match args.section {
                Some(section) => vec![section],
                None => default_sections.to_vec(),
            };

            let mut first_section = true;
            for section in sections {
                if !first_section {
                    println!();
                }
                first_section = false;

                match section {
                    StatusSection::Db => {
                        println!("DB status:");
                        let mut db_table = Table::new();
                        db_table.load_preset(ASCII_FULL_CONDENSED);
                        db_table.set_header(vec!["db_path", "filename"]);
                        db_table
                            .add_row(vec![cfg.db_path.display().to_string(), db_filename.clone()]);
                        println!("{db_table}");

                        let mut count_table = Table::new();
                        count_table.load_preset(ASCII_FULL_CONDENSED);
                        count_table.set_header(vec!["table", "rowcount"]);
                        count_table.add_row(vec!["peers".to_string(), peer_count.to_string()]);
                        count_table.add_row(vec!["shares".to_string(), share_count.to_string()]);
                        count_table.add_row(vec![
                            "peer_progress".to_string(),
                            progress_count.to_string(),
                        ]);
                        println!("{count_table}");
                    }
                    StatusSection::Queue => {
                        println!("Queue status:");
                        let mut queue_table = Table::new();
                        queue_table.load_preset(ASCII_FULL_CONDENSED);
                        queue_table.set_header(vec!["depth", "due_now"]);
                        queue_table.add_row(vec![queue_depth.to_string(), queue_due.to_string()]);
                        println!("{queue_table}");
                    }
                    StatusSection::Metrics => {
                        println!("Metrics status:");
                        let mut metrics_table = Table::new();
                        metrics_table.load_preset(ASCII_FULL_CONDENSED);
                        metrics_table.set_header(vec!["journal_entries"]);
                        metrics_table.add_row(vec![journal_entries.to_string()]);
                        println!("{metrics_table}");
                    }
                    StatusSection::Peers => {
                        println!("Peers ({}):", peers.len());
                        if peers.is_empty() {
                            println!("  (none)");
                        } else {
                            let mut peer_table = Table::new();
                            peer_table.load_preset(ASCII_FULL_CONDENSED);
                            peer_table.set_header(vec![
                                "id",
                                "peer",
                                "ip",
                                "tls_port",
                                "plain_port",
                                "last_seen",
                                "state",
                                "prefer_tls",
                                "last_insecure_seen",
                                "quarantined",
                            ]);
                            for p in &peers {
                                peer_table.add_row(vec![
                                    p.id.to_string(),
                                    format!("{}@{}", p.pc_name, p.instance_id),
                                    p.last_ip.clone(),
                                    p.last_tls_port.to_string(),
                                    p.last_plain_port.to_string(),
                                    p.last_seen.to_string(),
                                    p.state.clone(),
                                    p.prefer_tls.to_string(),
                                    p.last_insecure_seen.to_string(),
                                    p.quarantined.to_string(),
                                ]);
                            }
                            println!("{peer_table}");
                        }
                    }
                    StatusSection::Shares => {
                        println!("Shares ({}):", shares.len());
                        if shares.is_empty() {
                            println!("  (none)");
                        } else {
                            let mut share_table = Table::new();
                            share_table.load_preset(ASCII_FULL_CONDENSED);
                            share_table.set_header(vec!["id", "share", "root_path", "recursive"]);
                            for s in &shares {
                                share_table.add_row(vec![
                                    s.id.to_string(),
                                    format!("{}@{}", s.share_name, s.pc_name),
                                    s.root_path.clone(),
                                    s.recursive.to_string(),
                                ]);
                            }
                            println!("{share_table}");
                        }
                    }
                    StatusSection::PeerProgress => {
                        println!("Peer progress ({}):", progress.len());
                        if progress.is_empty() {
                            println!("  (none)");
                        } else {
                            let mut progress_table = Table::new();
                            progress_table.load_preset(ASCII_FULL_CONDENSED);
                            progress_table.set_header(vec![
                                "peer_id",
                                "peer",
                                "share_id",
                                "share",
                                "last_seq_sent",
                                "last_seq_acked",
                            ]);
                            for r in &progress {
                                progress_table.add_row(vec![
                                    r.peer_id.to_string(),
                                    format!("{}@{}", r.peer_pc_name, r.peer_instance_id),
                                    r.share_row_id.to_string(),
                                    format!("{}@{}", r.share_name, r.share_pc_name),
                                    r.last_seq_sent.to_string(),
                                    r.last_seq_acked.to_string(),
                                ]);
                            }
                            println!("{progress_table}");
                        }
                    }
                }
            }
            Ok(())
        }
        Command::Share(args) => match &args.command {
            ShareCliCommand::List { socket } => {
                let sock = resolve_control_socket(&cli, socket.clone())?;
                let resp = send_control_request(&sock, &ControlRequest::ShareList).await?;
                print_control_resp(&resp);
                if resp.ok {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(resp.message))
                }
            }
            ShareCliCommand::Add {
                name,
                path,
                recursive,
                socket,
            } => {
                let sock = resolve_control_socket(&cli, socket.clone())?;
                let resp = send_control_request(
                    &sock,
                    &ControlRequest::ShareAdd {
                        name: name.clone(),
                        path: path.display().to_string(),
                        recursive: *recursive,
                    },
                )
                .await?;
                print_control_resp(&resp);
                if resp.ok {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(resp.message))
                }
            }
        },
        Command::Config(args) => match &args.command {
            ConfigCliCommand::List { socket } => {
                let sock = resolve_control_socket(&cli, socket.clone())?;
                let resp = send_control_request(&sock, &ControlRequest::ConfigList).await?;
                print_control_resp(&resp);
                if resp.ok {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(resp.message))
                }
            }
            ConfigCliCommand::Get { key, socket } => {
                let sock = resolve_control_socket(&cli, socket.clone())?;
                let resp = send_control_request(
                    &sock,
                    &ControlRequest::ConfigGet { key: key.clone() },
                )
                .await?;
                print_control_resp(&resp);
                if resp.ok {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(resp.message))
                }
            }
            ConfigCliCommand::Set {
                key,
                value,
                socket,
            } => {
                let sock = resolve_control_socket(&cli, socket.clone())?;
                let value = localbox_core::settings::parse_value_literal(value)?;
                let resp = send_control_request(
                    &sock,
                    &ControlRequest::ConfigSet {
                        key: key.clone(),
                        value,
                    },
                )
                .await?;
                print_control_resp(&resp);
                if resp.ok {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(resp.message))
                }
            }
            ConfigCliCommand::Unset { key, socket } => {
                let sock = resolve_control_socket(&cli, socket.clone())?;
                let resp = send_control_request(
                    &sock,
                    &ControlRequest::ConfigUnset { key: key.clone() },
                )
                .await?;
                print_control_resp(&resp);
                if resp.ok {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(resp.message))
                }
            }
        },
        Command::Peer(args) => {
            let cfg = cli.resolve_app_config_allow_empty_shares()?;
            let db = db::Db::open(&cfg.db_path)?;
            let config_path = cli
                .config
                .clone()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
            match &args.command {
                PeerCliCommand::List => {
                    let peers = db.list_peers()?;
                    if peers.is_empty() {
                        println!("(no peers)");
                    } else {
                        let mut peer_table = Table::new();
                        peer_table.load_preset(ASCII_FULL_CONDENSED);
                        peer_table.set_header(vec![
                            "id",
                            "peer",
                            "ip",
                            "state",
                            "last_seen",
                            "quarantined",
                        ]);
                        for p in &peers {
                            peer_table.add_row(vec![
                                p.id.to_string(),
                                format!("{}@{}", p.pc_name, p.instance_id),
                                p.last_ip.clone(),
                                p.state.clone(),
                                p.last_seen.to_string(),
                                p.quarantined.to_string(),
                            ]);
                        }
                        println!("{peer_table}");
                    }
                    Ok(())
                }
                PeerCliCommand::Quarantine { peer } => {
                    if !db.set_peer_quarantined(peer, true)? {
                        anyhow::bail!("peer '{peer}' not found in DB");
                    }
                    if set_quarantined_peer_in_config(&config_path, peer, true)? {
                        println!(
                            "quarantined {peer} (DB + {})",
                            config_path.display()
                        );
                    } else {
                        println!(
                            "quarantined {peer} in DB (already listed in {})",
                            config_path.display()
                        );
                    }
                    Ok(())
                }
                PeerCliCommand::Unquarantine { peer } => {
                    if !db.set_peer_quarantined(peer, false)? {
                        anyhow::bail!("peer '{peer}' not found in DB");
                    }
                    if set_quarantined_peer_in_config(&config_path, peer, false)? {
                        println!(
                            "unquarantined {peer} (DB + {})",
                            config_path.display()
                        );
                    } else {
                        println!(
                            "unquarantined {peer} in DB (was not listed in {})",
                            config_path.display()
                        );
                    }
                    Ok(())
                }
            }
        }
        Command::Ca(args) => {
            use localbox_core::config::CaCommand;
            match &args.command {
                CaCommand::Init(init) => {
                    let paths = tls::CaPaths::in_dir(&init.dir);
                    std::fs::create_dir_all(&init.dir)?;
                    let ca = tls::generate_network_ca(&init.name, init.lifetime)?;
                    tls::ca::write_network_ca(&paths, &ca, init.force)?;
                    println!("Created network CA in {}", init.dir.display());
                    println!("  cert: {}", paths.cert_path.display());
                    println!("  key:  {} (keep this on this machine only)", paths.key_path.display());
                    println!("  fingerprint: {}", ca.fingerprint);
                    println!();
                    println!("Pin this root on every node:");
                    println!("  tls_pinned_ca_fingerprints = [\"{}\"]", ca.fingerprint);
                    Ok(())
                }
                CaCommand::Show(show) => {
                    let paths = tls::CaPaths::in_dir(&show.dir);
                    let (_, fingerprint) = tls::ca::read_ca_cert(&paths)?;
                    println!("cert:        {}", paths.cert_path.display());
                    println!("fingerprint: {fingerprint}");
                    println!(
                        "key present: {}",
                        if paths.key_path.exists() { "yes" } else { "no" }
                    );
                    Ok(())
                }
                CaCommand::Request(req) => {
                    let cfg = cli.resolve_app_config_allow_empty_shares()?;
                    let name = req.name.clone().unwrap_or_else(|| cfg.pc_name.clone());
                    for path in [&req.csr_out, &req.key_out] {
                        if path.exists() && !req.force {
                            anyhow::bail!(
                                "{} already exists (pass --force to overwrite)",
                                path.display()
                            );
                        }
                    }
                    let csr = tls::generate_node_csr(&name)?;
                    write_file_atomic(&req.csr_out, csr.csr_pem.as_bytes())?;
                    if req.key_out.exists() {
                        std::fs::remove_file(&req.key_out)?;
                    }
                    utilities::write_secret_file_atomic(&req.key_out, csr.key_pem.as_bytes())?;
                    println!("Generated a certificate request for '{name}'");
                    println!("  csr: {}", req.csr_out.display());
                    println!("  key: {} (never send this anywhere)", req.key_out.display());
                    println!();
                    println!("Send only the CSR to the CA machine, then run there:");
                    println!(
                        "  localbox ca sign --csr <csr> --name {name} --out {name}.chain.pem"
                    );
                    Ok(())
                }
                CaCommand::Sign(sign) => {
                    if sign.out.exists() && !sign.force {
                        anyhow::bail!(
                            "{} already exists (pass --force to overwrite)",
                            sign.out.display()
                        );
                    }
                    let paths = tls::CaPaths::in_dir(&sign.dir);
                    let signer = tls::load_ca_signer(&paths)?;
                    let csr_pem = std::fs::read_to_string(&sign.csr)
                        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", sign.csr.display()))?;
                    let chain =
                        tls::sign_node_csr(&signer, &csr_pem, &sign.name, sign.lifetime)?;
                    write_file_atomic(&sign.out, chain.as_bytes())?;
                    println!(
                        "Signed a {} certificate for '{}' -> {}",
                        sign.lifetime,
                        sign.name,
                        sign.out.display()
                    );
                    println!("Issued by root {}", signer.fingerprint);
                    Ok(())
                }
                CaCommand::Token(token) => {
                    let issued = tls::issue_token(&token.dir, &token.name, token.ttl_secs)?;
                    println!(
                        "Enrollment token for '{}' (valid {}s, single use):",
                        token.name, token.ttl_secs
                    );
                    println!();
                    println!("  {}", issued.encode());
                    println!();
                    println!("On {}, run:", token.name);
                    println!(
                        "  localbox enroll --server <this-host>:{} --token <token> --pin",
                        tls::DEFAULT_ENROLL_PORT
                    );
                    Ok(())
                }
                CaCommand::Serve(serve) => {
                    let listen = serve.listen.unwrap_or_else(|| {
                        SocketAddr::new(
                            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                            tls::DEFAULT_ENROLL_PORT,
                        )
                    });
                    let cancel = tokio_util::sync::CancellationToken::new();
                    let shutdown = cancel.clone();
                    tokio::spawn(async move {
                        if tokio::signal::ctrl_c().await.is_ok() {
                            shutdown.cancel();
                        }
                    });
                    println!("Serving enrollment on {listen} (Ctrl-C to stop)");
                    tls::enroll::serve(&serve.dir, listen, serve.lifetime, cancel).await
                }
                CaCommand::ProvisionShared(shared) => {
                    let paths = tls::CaPaths::in_dir(&shared.dir);
                    let signer = tls::load_ca_signer(&paths)?;
                    let bundle =
                        tls::ca::issue_shared_bundle(&signer, &shared.name, shared.lifetime)?;

                    std::fs::create_dir_all(&shared.out_dir)?;
                    let chain_out = shared.out_dir.join("shared.chain.pem");
                    let key_out = shared.out_dir.join("shared.key.pem");
                    let ca_out = shared.out_dir.join("ca.cert.pem");
                    for path in [&chain_out, &key_out, &ca_out] {
                        if path.exists() && !shared.force {
                            anyhow::bail!(
                                "{} already exists (pass --force to overwrite)",
                                path.display()
                            );
                        }
                    }
                    write_file_atomic(&chain_out, bundle.chain_pem.as_bytes())?;
                    if key_out.exists() {
                        std::fs::remove_file(&key_out)?;
                    }
                    utilities::write_secret_file_atomic(&key_out, bundle.key_pem.as_bytes())?;
                    write_file_atomic(&ca_out, bundle.ca_pem.as_bytes())?;

                    println!("Wrote a shared bundle to {}", shared.out_dir.display());
                    println!("  chain: {}", chain_out.display());
                    println!("  key:   {}", key_out.display());
                    println!("  ca:    {} ({})", ca_out.display(), bundle.ca_fingerprint);
                    println!();
                    println!("WARNING: every node given this bundle presents the same certificate.");
                    println!("Peers cannot tell each other apart, and anyone who obtains it can act");
                    println!("as any node. Prefer `localbox ca token` + `localbox enroll` instead.");
                    println!();
                    println!("On each node, copy the bundle over and run:");
                    println!(
                        "  localbox ca install --chain shared.chain.pem --key shared.key.pem --pin"
                    );
                    println!("then set in config.toml:");
                    println!("  tls_insecure_shared_cert = true");
                    Ok(())
                }
                CaCommand::Install(install) => {
                    let cfg = cli.resolve_app_config_allow_empty_shares()?;
                    let chain = std::fs::read_to_string(&install.chain).map_err(|e| {
                        anyhow::anyhow!("failed to read {}: {e}", install.chain.display())
                    })?;
                    let key = std::fs::read_to_string(&install.key).map_err(|e| {
                        anyhow::anyhow!("failed to read {}: {e}", install.key.display())
                    })?;
                    let ca_pem = tls::ca::ca_pem_from_chain(&chain)?;
                    let result = tls::install_node_materials(&cfg, &chain, &key, &ca_pem)?;
                    println!("Installed certificate for this node");
                    println!(
                        "  leaf: {} ({})",
                        cfg.tls_cert_path.display(),
                        result.leaf_fingerprint
                    );
                    println!("  key:  {}", cfg.tls_key_path.display());
                    println!(
                        "  trust store: {} ({} CA cert(s) added)",
                        cfg.tls_ca_cert_path.display(),
                        result.ca_certs_added
                    );
                    if install.pin {
                        let config_path = cli
                            .config
                            .clone()
                            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
                        if tls::ca::pin_ca_in_config(&config_path, &result.ca_fingerprint)? {
                            println!(
                                "  pinned root {} in {}",
                                result.ca_fingerprint,
                                config_path.display()
                            );
                        } else {
                            println!("  root {} was already pinned", result.ca_fingerprint);
                        }
                    }
                    Ok(())
                }
            }
        }
        Command::Enroll(args) => {
            let cfg = cli.resolve_app_config_allow_empty_shares()?;
            let server = args
                .server
                .to_socket_addrs()
                .map_err(|e| anyhow::anyhow!("could not resolve {}: {e}", args.server))?
                .next()
                .ok_or_else(|| anyhow::anyhow!("{} resolved to no addresses", args.server))?;

            let enrolled = tls::enroll::enroll(server, &args.token, &cfg.pc_name).await?;
            if enrolled.node_name != cfg.pc_name && !args.force {
                anyhow::bail!(
                    "the token issued a certificate for '{}' but this machine is '{}'; peers \
                     identify each other by hostname, so this certificate would be rejected. \
                     Re-issue with `localbox ca token --name {}` (or pass --force).",
                    enrolled.node_name,
                    cfg.pc_name,
                    cfg.pc_name
                );
            }

            let result = tls::install_node_materials(
                &cfg,
                &enrolled.chain_pem,
                &enrolled.key_pem,
                &enrolled.ca_pem,
            )?;
            println!("Enrolled as '{}'", enrolled.node_name);
            println!(
                "  leaf: {} ({})",
                cfg.tls_cert_path.display(),
                result.leaf_fingerprint
            );
            println!("  key:  {}", cfg.tls_key_path.display());
            println!(
                "  trust store: {} ({} CA cert(s) added)",
                cfg.tls_ca_cert_path.display(),
                result.ca_certs_added
            );
            if args.pin {
                let config_path = cli
                    .config
                    .clone()
                    .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
                if tls::ca::pin_ca_in_config(&config_path, &enrolled.ca_fingerprint)? {
                    println!(
                        "  pinned root {} in {}",
                        enrolled.ca_fingerprint,
                        config_path.display()
                    );
                } else {
                    println!("  root {} was already pinned", enrolled.ca_fingerprint);
                }
            } else {
                println!();
                println!(
                    "Tip: re-run with --pin to restrict trust to this root ({}).",
                    enrolled.ca_fingerprint
                );
            }
            Ok(())
        }
        Command::Bootstrap(args) => {
            let cfg = cli.resolve_app_config_allow_empty_shares()?;
            match &args.command {
                BootstrapCommand::Invite(invite) => {
                    bootstrap::issue_invite(&cfg, &invite.peer, &invite.out, invite.force)?;
                    println!("Wrote invite to {}", invite.out.display());
                    Ok(())
                }
                BootstrapCommand::Accept(accept) => {
                    let config_path = cli
                        .config
                        .clone()
                        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
                    let result =
                        bootstrap::accept_invite(&cfg, &config_path, &accept.file, accept.force)?;
                    println!(
                        "Verified invite from {} (fingerprint {}). Token: {}",
                        result.peer_name, result.fingerprint, result.token
                    );
                    println!("Imported {} CA cert(s)", result.ca_certs_added);
                    if result.config_updated {
                        println!(
                            "Updated tls_peer_fingerprints entry for {} in {}",
                            result.peer_name,
                            config_path.display()
                        );
                    } else {
                        println!(
                            "tls_peer_fingerprints already contained {}",
                            result.peer_name
                        );
                    }
                    Ok(())
                }
                BootstrapCommand::Join(join) => {
                    let config_path = cli
                        .config
                        .clone()
                        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
                    if let Some(incoming) = &join.incoming {
                        let result =
                            bootstrap::accept_invite(&cfg, &config_path, incoming, join.force)?;
                        println!(
                            "Verified invite from {} (fingerprint {}). Token: {}",
                            result.peer_name, result.fingerprint, result.token
                        );
                        println!("Imported {} CA cert(s)", result.ca_certs_added);
                        if result.config_updated {
                            println!(
                                "Updated tls_peer_fingerprints entry for {} in {}",
                                result.peer_name,
                                config_path.display()
                            );
                        } else {
                            println!(
                                "tls_peer_fingerprints already contained {}",
                                result.peer_name
                            );
                        }
                    } else {
                        println!("No incoming invite supplied; skipping acceptance step");
                    }
                    bootstrap::issue_invite(&cfg, &join.peer, &join.out, join.force)?;
                    println!(
                        "Wrote response invite for {} to {}",
                        join.peer,
                        join.out.display()
                    );
                    println!(
                        "Send this file back to the peer to complete the bootstrap round trip."
                    );
                    Ok(())
                }
            }
        }
        Command::Tls(tls) => {
            let cfg = cli.resolve_app_config_allow_empty_shares()?;
            match &tls.command {
                localbox_core::config::TlsCommand::Ensure => {
                    let fs = RealFileSystem::new();
                    let _ = tls::TlsComponents::from_config(&cfg, &fs)?;
                    println!("leaf:  {}", cfg.tls_cert_path.display());
                    println!("trust: {}", cfg.tls_ca_cert_path.display());
                    for fp in workflow::fingerprints_for_pem_file(&cfg.tls_cert_path)? {
                        println!("leaf-fp {}", fp.fingerprint);
                    }
                    for fp in workflow::fingerprints_for_pem_file(&cfg.tls_ca_cert_path)? {
                        println!("ca-fp   {}", fp.fingerprint);
                    }
                    Ok(())
                }
                localbox_core::config::TlsCommand::List => {
                    let fps = workflow::read_trust_store_fingerprints(&cfg.tls_ca_cert_path)?;
                    if fps.is_empty() {
                        println!("(empty)");
                    } else {
                        for fp in fps {
                            println!("{fp}");
                        }
                    }
                    Ok(())
                }
                localbox_core::config::TlsCommand::Fingerprint(args) => {
                    let file = args.file.as_deref();
                    let mut printed_any = false;
                    let want_leaf = args.leaf || (!args.leaf && !args.ca);
                    let want_ca = args.ca || (!args.leaf && !args.ca);

                    if let Some(path) = file {
                        let fps = workflow::fingerprints_for_pem_file(path)?;
                        for fp in fps {
                            println!("{}", fp.fingerprint);
                            printed_any = true;
                        }
                    } else {
                        if want_leaf {
                            let fps = workflow::fingerprints_for_pem_file(&cfg.tls_cert_path)?;
                            for fp in fps {
                                println!("leaf {}", fp.fingerprint);
                                printed_any = true;
                            }
                        }
                        if want_ca {
                            let fps = workflow::fingerprints_for_pem_file(&cfg.tls_ca_cert_path)?;
                            for fp in fps {
                                println!("ca   {}", fp.fingerprint);
                                printed_any = true;
                            }
                        }
                    }

                    if !printed_any {
                        println!("(no certs)");
                    }
                    Ok(())
                }
                localbox_core::config::TlsCommand::ExportCa(args) => {
                    workflow::export_ca_from_chain_pem(&cfg.tls_cert_path, &args.out)?;
                    println!("Wrote {}", args.out.display());
                    Ok(())
                }
                localbox_core::config::TlsCommand::ImportCa(args) => {
                    let added =
                        workflow::import_ca_into_trust_store(&cfg.tls_ca_cert_path, &args.r#in)?;
                    println!(
                        "Added {added} certificate(s) to {}",
                        cfg.tls_ca_cert_path.display()
                    );
                    Ok(())
                }
                localbox_core::config::TlsCommand::Rotate(args) => {
                    let fs = RealFileSystem::new();
                    let materials = tls::generate_tls_materials(&cfg.pc_name)?;
                    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
                    let suffix = format!(".bak-{ts}");
                    if args.backup {
                        let _ = workflow::backup_file(&cfg.tls_cert_path, &suffix)?;
                        let _ = workflow::backup_file(&cfg.tls_key_path, &suffix)?;
                        let _ = workflow::backup_file(&cfg.tls_ca_cert_path, &suffix)?;
                    }
                    tls::persist_tls_materials(&cfg, &materials, &fs)?;
                    if let Some(out) = &args.export_ca {
                        write_file_atomic(out, format!("{}\n", materials.ca_pem).as_bytes())?;
                        println!("Wrote {}", out.display());
                    }
                    println!("Rotated TLS materials");
                    Ok(())
                }
                localbox_core::config::TlsCommand::Provision(args) => {
                    let fs = RealFileSystem::new();
                    let _ = tls::TlsComponents::from_config(&cfg, &fs)?;
                    std::fs::create_dir_all(&args.out_dir)?;
                    let leaf_out = args.out_dir.join("leaf.cert.pem");
                    let key_out = args.out_dir.join("leaf.key.pem");
                    let ca_out = args.out_dir.join("ca.bundle.pem");
                    copy_file_atomic(&cfg.tls_cert_path, &leaf_out, args.force)?;
                    copy_file_atomic(&cfg.tls_key_path, &key_out, args.force)?;
                    copy_file_atomic(&cfg.tls_ca_cert_path, &ca_out, args.force)?;

                    if let Some(extra_ca) = &args.export_ca {
                        copy_file_atomic(&cfg.tls_ca_cert_path, extra_ca, args.force)?;
                    }

                    let leaf_fps = workflow::fingerprints_for_pem_file(&cfg.tls_cert_path)?;
                    let mut fp_text = String::new();
                    for fp in &leaf_fps {
                        fp_text.push_str(&format!("leaf {}\n", fp.fingerprint));
                    }
                    for fp in workflow::fingerprints_for_pem_file(&cfg.tls_ca_cert_path)? {
                        fp_text.push_str(&format!("ca   {}\n", fp.fingerprint));
                    }
                    let fp_out = args.out_dir.join("fingerprints.txt");
                    if fp_out.exists() && !args.force {
                        anyhow::bail!(
                            "{} already exists (pass --force to overwrite)",
                            fp_out.display()
                        );
                    }
                    write_file_atomic(&fp_out, fp_text.as_bytes())?;

                    let mut snippet = String::from("[tls_peer_fingerprints]\n");
                    snippet.push_str(&format!("\"{}\" = [\n", cfg.pc_name));
                    for fp in &leaf_fps {
                        snippet.push_str(&format!("  \"{}\",\n", fp.fingerprint));
                    }
                    snippet.push_str("]\n");
                    let snippet_out = args.out_dir.join("peer-snippet.toml");
                    if snippet_out.exists() && !args.force {
                        anyhow::bail!(
                            "{} already exists (pass --force to overwrite)",
                            snippet_out.display()
                        );
                    }
                    write_file_atomic(&snippet_out, snippet.as_bytes())?;

                    println!("Wrote TLS bundle to {}", args.out_dir.display());
                    println!("  - leaf cert  -> {}", leaf_out.display());
                    println!("  - leaf key   -> {}", key_out.display());
                    println!("  - CA bundle  -> {}", ca_out.display());
                    println!("  - fingerprints -> {}", fp_out.display());
                    println!("  - config snippet -> {}", snippet_out.display());
                    if let Some(extra_ca) = &args.export_ca {
                        println!("  - exported CA -> {}", extra_ca.display());
                    }
                    println!("Distribute the CA + snippet to peers so they can pin this node.");
                    Ok(())
                }
            }
        }
    }
}

fn resolve_control_socket(cli: &Cli, override_sock: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(p) = override_sock {
        return Ok(p);
    }
    let cfg = cli.resolve_app_config_allow_empty_shares()?;
    Ok(cfg.control_socket)
}

fn print_control_resp(resp: &localbox_core::service::ControlResponse) {
    if resp.ok {
        println!("{}", resp.message);
        if let Some(data) = &resp.data {
            println!("{}", serde_json::to_string_pretty(data).unwrap_or_default());
        }
    } else {
        eprintln!("error: {}", resp.message);
    }
}

async fn handle_chat_command(
    cli: &Cli,
    args: &localbox_core::config::ChatArgs,
) -> anyhow::Result<()> {
    match &args.command {
        ChatCommand::Send(a) => {
            let sock = resolve_control_socket(cli, a.socket.clone())?;
            let resp = send_control_request(
                &sock,
                &ControlRequest::ChatSend {
                    peer: a.peer.clone(),
                    share: a.share.clone(),
                    thread: a.thread.clone(),
                    message: a.message.clone(),
                    file: a.file.clone(),
                    share_dest: a.share_dest.clone(),
                },
            )
            .await?;
            print_control_resp(&resp);
            if resp.ok {
                Ok(())
            } else {
                Err(anyhow::anyhow!(resp.message))
            }
        }
        ChatCommand::Inbox(a) | ChatCommand::Threads(a) => {
            let sock = resolve_control_socket(cli, a.socket.clone())?;
            let resp = send_control_request(&sock, &ControlRequest::ChatInbox).await?;
            print_control_resp(&resp);
            if resp.ok {
                Ok(())
            } else {
                Err(anyhow::anyhow!(resp.message))
            }
        }
        ChatCommand::Show(a) => {
            let sock = resolve_control_socket(cli, a.socket.clone())?;
            let resp = send_control_request(
                &sock,
                &ControlRequest::ChatShow {
                    thread: a.thread.clone(),
                    limit: a.limit,
                },
            )
            .await?;
            print_control_resp(&resp);
            if resp.ok {
                Ok(())
            } else {
                Err(anyhow::anyhow!(resp.message))
            }
        }
        ChatCommand::Read(a) => {
            let sock = resolve_control_socket(cli, a.socket.clone())?;
            let resp = send_control_request(
                &sock,
                &ControlRequest::ChatRead {
                    thread: a.thread.clone(),
                },
            )
            .await?;
            print_control_resp(&resp);
            if resp.ok {
                Ok(())
            } else {
                Err(anyhow::anyhow!(resp.message))
            }
        }
    }
}
