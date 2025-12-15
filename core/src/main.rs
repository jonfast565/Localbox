use clap::Parser;
use localbox::config::{init_config_template, validate_app_config, Cli, Command};
use localbox::Engine;
use utilities::RealFileSystem;
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Some(Command::Init(args)) => {
            let path = cli
                .config
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("config.toml"));
            init_config_template(&path, args.force)?;
            println!("Wrote {}", path.display());
            Ok(())
        }
        Some(Command::Validate(_)) => {
            let cfg = cli.resolve_app_config()?;
            validate_app_config(&cfg)?;
            println!("OK");
            Ok(())
        }
        Some(Command::Status(args)) => {
            let cfg = cli.resolve_app_config_allow_empty_shares()?;
            let db = db::Db::open(&cfg.db_path)?;
            let now = time::OffsetDateTime::now_utc().unix_timestamp();

            let peers = db.list_peers()?;
            let shares = db.list_shares_table()?;
            let progress = db.list_peer_progress_table()?;
            let queue_depth = db.outbound_queue_depth()?;
            let queue_due = db.outbound_queue_due_now(now)?;
            let change_log_total = db.change_log_total()?;

            if args.json {
                let peers_json = peers
                    .into_iter()
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
                        })
                    })
                    .collect::<Vec<_>>();
                let shares_json = shares
                    .into_iter()
                    .map(|s| {
                        json!({
                            "id": s.id,
                            "share_name": s.share_name,
                            "pc_name": s.pc_name,
                            "root_path": s.root_path,
                            "recursive": s.recursive,
                        })
                    })
                    .collect::<Vec<_>>();
                let progress_json = progress
                    .into_iter()
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
                    .collect::<Vec<_>>();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "db_path": cfg.db_path.to_string_lossy(),
                        "metrics": {
                            "outbound_queue_depth": queue_depth,
                            "outbound_queue_due_now": queue_due,
                            "change_log_total": change_log_total,
                        },
                        "peers": peers_json,
                        "shares": shares_json,
                        "peer_progress": progress_json,
                    }))?
                );
                return Ok(());
            }

            println!("DB: {}", cfg.db_path.display());
            println!("Queue: depth={} due_now={}", queue_depth, queue_due);
            println!("Metrics: change_log_total={}", change_log_total);
            println!();
            println!("Peers ({}):", peers.len());
            for p in peers {
                println!(
                    "  #{:<3} {}@{} ip={} tls_port={} plain_port={} last_seen={} state={} prefer_tls={} last_insecure_seen={}",
                    p.id,
                    p.pc_name,
                    p.instance_id,
                    p.last_ip,
                    p.last_tls_port,
                    p.last_plain_port,
                    p.last_seen,
                    p.state,
                    p.prefer_tls,
                    p.last_insecure_seen
                );
            }
            println!();
            println!("Shares ({}):", shares.len());
            for s in shares {
                println!(
                    "  #{:<3} {}@{} root={} recursive={}",
                    s.id, s.share_name, s.pc_name, s.root_path, s.recursive
                );
            }
            println!();
            println!("Peer progress ({}):", progress.len());
            for r in progress {
                println!(
                    "  peer #{:<3} {}@{} -> share #{:<3} {}@{} sent={} acked={}",
                    r.peer_id,
                    r.peer_pc_name,
                    r.peer_instance_id,
                    r.share_row_id,
                    r.share_name,
                    r.share_pc_name,
                    r.last_seq_sent,
                    r.last_seq_acked
                );
            }
            Ok(())
        }
        Some(Command::Tls(tls)) => {
            let cfg = cli.resolve_app_config_allow_empty_shares()?;
            match &tls.command {
                localbox::config::TlsCommand::Ensure => {
                    let fs = RealFileSystem::new();
                    let _ = peering::tls::TlsComponents::from_config(&cfg, &fs)?;
                    println!("leaf:  {}", cfg.tls_cert_path.display());
                    println!("trust: {}", cfg.tls_ca_cert_path.display());
                    for fp in localbox::tls_workflow::fingerprints_for_pem_file(&cfg.tls_cert_path)? {
                        println!("leaf-fp {}", fp.fingerprint);
                    }
                    for fp in localbox::tls_workflow::fingerprints_for_pem_file(&cfg.tls_ca_cert_path)? {
                        println!("ca-fp   {}", fp.fingerprint);
                    }
                    Ok(())
                }
                localbox::config::TlsCommand::List => {
                    let fps = localbox::tls_workflow::read_trust_store_fingerprints(&cfg.tls_ca_cert_path)?;
                    if fps.is_empty() {
                        println!("(empty)");
                    } else {
                        for fp in fps {
                            println!("{fp}");
                        }
                    }
                    Ok(())
                }
                localbox::config::TlsCommand::Fingerprint(args) => {
                    let file = args.file.as_deref();
                    let mut printed_any = false;
                    let want_leaf = args.leaf || (!args.leaf && !args.ca);
                    let want_ca = args.ca || (!args.leaf && !args.ca);

                    if let Some(path) = file {
                        let fps = localbox::tls_workflow::fingerprints_for_pem_file(path)?;
                        for fp in fps {
                            println!("{}", fp.fingerprint);
                            printed_any = true;
                        }
                    } else {
                        if want_leaf {
                            let fps = localbox::tls_workflow::fingerprints_for_pem_file(&cfg.tls_cert_path)?;
                            for fp in fps {
                                println!("leaf {}", fp.fingerprint);
                                printed_any = true;
                            }
                        }
                        if want_ca {
                            let fps = localbox::tls_workflow::fingerprints_for_pem_file(&cfg.tls_ca_cert_path)?;
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
                localbox::config::TlsCommand::ExportCa(args) => {
                    localbox::tls_workflow::export_ca_from_chain_pem(&cfg.tls_cert_path, &args.out)?;
                    println!("Wrote {}", args.out.display());
                    Ok(())
                }
                localbox::config::TlsCommand::ImportCa(args) => {
                    let added = localbox::tls_workflow::import_ca_into_trust_store(
                        &cfg.tls_ca_cert_path,
                        &args.r#in,
                    )?;
                    println!("Added {added} certificate(s) to {}", cfg.tls_ca_cert_path.display());
                    Ok(())
                }
                localbox::config::TlsCommand::Rotate(args) => {
                    let fs = RealFileSystem::new();
                    let materials = peering::tls::generate_tls_materials(&cfg.pc_name)?;
                    let ts = time::OffsetDateTime::now_utc().unix_timestamp();
                    let suffix = format!(".bak-{ts}");
                    if args.backup {
                        let _ = localbox::tls_workflow::backup_file(&cfg.tls_cert_path, &suffix)?;
                        let _ = localbox::tls_workflow::backup_file(&cfg.tls_key_path, &suffix)?;
                        let _ = localbox::tls_workflow::backup_file(&cfg.tls_ca_cert_path, &suffix)?;
                    }
                    peering::tls::persist_tls_materials(&cfg, &materials, &fs)?;
                    if let Some(out) = &args.export_ca {
                        std::fs::write(out, format!("{}\n", materials.ca_pem))?;
                        println!("Wrote {}", out.display());
                    }
                    println!("Rotated TLS materials");
                    Ok(())
                }
            }
        }
        None => {
            let cfg = cli.resolve_app_config()?;
            validate_app_config(&cfg)?;
            let engine = Engine::new(cfg)?;
            engine.run().await
        }
    }
}
