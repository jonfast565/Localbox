mod app;
mod client;
mod events;
mod prefs;
mod runtime;
mod theme;

use clap::Parser;
use iced::Size;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use runtime::{
    default_control_socket, ensure_runtime, resolve_socket, stop_runtime, EnsureOpts, RuntimeHandle,
    RuntimeMode,
};

#[derive(Debug, Parser)]
#[command(name = "localbox-gui", about = "Localbox desktop control UI")]
struct Args {
    /// Path to the Localbox control Unix socket / named pipe
    #[arg(long, default_value_os_t = default_control_socket())]
    socket: PathBuf,

    /// TOML config passed to a spawned runtime; also supplies `control_socket` when `--socket` is default
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Path to the `localbox-core` binary (else `$LOCALBOX_CORE`, sibling of this exe, or PATH)
    #[arg(long, value_name = "PATH")]
    core: Option<PathBuf>,

    /// Never spawn a runtime; only attach to an already-running daemon
    #[arg(long)]
    no_runtime: bool,
}

fn main() -> iced::Result {
    let args = Args::parse();
    let socket_was_default = args.socket == default_control_socket();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let socket = match resolve_socket(args.socket.clone(), socket_was_default, args.config.as_deref())
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("localbox-gui: {e:#}");
            std::process::exit(1);
        }
    };

    let ensure_opts = EnsureOpts {
        socket: socket.clone(),
        config: args.config.clone(),
        core: args.core.clone(),
        no_runtime: args.no_runtime,
    };

    let handle = match rt.block_on(ensure_runtime(EnsureOpts {
        socket: socket.clone(),
        config: args.config.clone(),
        core: args.core.clone(),
        no_runtime: args.no_runtime,
    })) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("localbox-gui: {e:#}");
            std::process::exit(1);
        }
    };

    let runtime: Arc<Mutex<Option<RuntimeHandle>>> = Arc::new(Mutex::new(Some(handle)));
    let runtime_for_app = Arc::clone(&runtime);
    let result = iced::application(app::App::title, app::App::update, app::App::view)
        .theme(app::App::theme)
        .subscription(app::App::subscription)
        .window_size(Size::new(780.0, 620.0))
        .run_with(move || app::App::new(socket, ensure_opts, runtime_for_app));

    // Window close / process exit: stop a GUI-spawned child runtime.
    // Attached daemons are left running.
    if let Some(mut handle) = runtime
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
    {
        if handle.mode == RuntimeMode::Managed {
            let _ = rt.block_on(stop_runtime(&mut handle));
        }
    }
    result
}
