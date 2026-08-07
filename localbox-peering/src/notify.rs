//! Shared progress + control-event fan-out for peer connection tasks.

use models::{ControlEvent, TransferProgressRegistry};
use std::sync::Arc;
use tokio::sync::broadcast;

/// Cloned into every inbound/outbound peer task.
#[derive(Clone)]
pub struct PeerNotify {
    pub progress: Arc<TransferProgressRegistry>,
    events: broadcast::Sender<ControlEvent>,
}

impl PeerNotify {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(256);
        Self {
            progress: TransferProgressRegistry::new(),
            events,
        }
    }

    pub fn from_parts(
        progress: Arc<TransferProgressRegistry>,
        events: broadcast::Sender<ControlEvent>,
    ) -> Self {
        Self { progress, events }
    }

    pub fn emit(&self, event: ControlEvent) {
        let _ = self.events.send(event);
    }

    pub fn event_sender(&self) -> broadcast::Sender<ControlEvent> {
        self.events.clone()
    }
}

impl Default for PeerNotify {
    fn default() -> Self {
        Self::new()
    }
}
