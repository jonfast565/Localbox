use clap::Parser;
use localbox::config::CliConfig;
use localbox::Engine;
use models::AppConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg: AppConfig = CliConfig::parse().into_app_config();

    let engine = Engine::new(cfg)?;
    engine.run().await
}
