use clap::Parser;
use localbox::config::{init_config_template, validate_app_config, Cli, Command};
use localbox::Engine;

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
        None => {
            let cfg = cli.resolve_app_config()?;
            validate_app_config(&cfg)?;
            let engine = Engine::new(cfg)?;
            engine.run().await
        }
    }
}
