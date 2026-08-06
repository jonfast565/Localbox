//! Control-plane client for the Localbox GUI (Unix socket or Windows named pipe).

pub use localbox_core::control::send_control_request as send_request;
pub use localbox_core::service::{ControlRequest, ControlResponse};
