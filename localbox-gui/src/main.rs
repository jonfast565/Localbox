mod app;
mod client;
mod theme;

use clap::Parser;
use iced::Size;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "localbox-gui", about = "Localbox desktop control UI")]
struct Args {
    /// Path to the Localbox control Unix socket
    #[arg(long, default_value = "localbox.sock")]
    socket: PathBuf,
}

fn main() -> iced::Result {
    let args = Args::parse();
    iced::application(app::App::title, app::App::update, app::App::view)
        .theme(app::App::theme)
        .window_size(Size::new(960.0, 640.0))
        .run_with(move || app::App::new(args.socket.clone()))
}
