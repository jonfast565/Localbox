use iced::widget::pane_grid::{self, PaneGrid};
use iced::widget::scrollable::AbsoluteOffset;
use iced::widget::{
    button, column, container, progress_bar, row, scrollable, text, text_input, Column, Space,
};
use iced::{event, time, window, Alignment, Element, Event, Length, Padding, Subscription, Task,
    Theme};
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::theme::Colors;
use localbox_core::ControlEvent;
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;

use crate::client::{self, ControlRequest, ControlResponse};
use crate::events as control_events;
use crate::prefs::{self, GuiPrefs, DEFAULT_LOG_TAIL_LINES};
use crate::runtime::{
    restart_runtime, stop_managed_sync, stop_runtime, EnsureOpts, RuntimeHandle, RuntimeMode,
};
use crate::theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChatPane {
    Inbox,
    Thread,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusPane {
    Shares,
    Peers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransfersPane {
    Pending,
    Intents,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Status,
    Transfers,
    Chat,
    Logs,
    Settings,
}

#[derive(Debug, Clone)]
pub enum Message {
    Tab(Tab),
    Refresh,
    StatusLoaded(Result<ControlResponse, String>),
    InboxLoaded(Result<ControlResponse, String>),
    PendingLoaded(Result<ControlResponse, String>),
    IntentsLoaded(Result<ControlResponse, String>),
    PeersLoaded(Result<ControlResponse, String>),
    SharesLoaded(Result<ControlResponse, String>),
    SettingsLoaded(Result<ControlResponse, String>),
    LogsLoaded(Result<ControlResponse, String>),
    ThreadLoaded(Result<ControlResponse, String>),
    ActionDone(Result<ControlResponse, String>),
    NewShareNameInput(String),
    NewSharePathInput(String),
    AddShare,
    ConfigKeyInput(String),
    ConfigValueInput(String),
    ConfigSet,
    ConfigUnset,
    ConfigRefresh,
    SelectPeer(String),
    SelectShare(String),
    PathInput(String),
    Push,
    Pull,
    Request,
    ReplyAccept(String),
    ReplyDecline(String),
    SelectChatPeer(String),
    SelectChatShare(String),
    ChatBodyInput(String),
    ChatSend,
    ChatSent(Result<ControlResponse, String>),
    NewChat,
    SelectThread(String),
    StartRenameChat,
    ChatTitleInput(String),
    SaveChatTitle,
    CancelRenameChat,
    DeleteChatThread,
    DeleteChatMessage(String),
    MarkRead,
    QuarantinePeer(String),
    UnquarantinePeer(String),
    LogTailInput(String),
    SaveLogTail,
    ChatPanesResized(pane_grid::ResizeEvent),
    StatusPanesResized(pane_grid::ResizeEvent),
    TransfersPanesResized(pane_grid::ResizeEvent),
    StartRuntime,
    StopRuntime,
    RuntimeStarted(Result<(String, bool), String>),
    RuntimeStopped(Result<String, String>),
    ClearFlash,
    SyncSystemTheme,
    Tick,
    /// Last window closed — stop a managed child runtime if we own one.
    WindowClosed,
    WindowFocused(bool),
    ControlEventArrived(ControlEvent),
    DismissToast(u64),
}

#[derive(Debug, Clone)]
struct Toast {
    id: u64,
    title: String,
    body: String,
    created: Instant,
}

#[derive(Debug, Clone, Deserialize)]
struct StatusSnapshot {
    peers: u64,
    shares: u64,
    queue_depth: u64,
    #[allow(dead_code)]
    pending_requests: u64,
    #[allow(dead_code)]
    active_intents: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct ShareInfo {
    #[allow(dead_code)]
    id: i64,
    share_name: String,
    #[allow(dead_code)]
    #[serde(default)]
    pc_name: String,
    root_path: String,
    #[serde(default)]
    recursive: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct AdvertisedShareInfo {
    name: String,
    #[serde(default = "default_true_bool")]
    #[allow(dead_code)]
    recursive: bool,
    #[serde(default)]
    sync: String,
    #[serde(default)]
    pull: String,
}

fn default_true_bool() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
struct PeerInfo {
    id: i64,
    pc_name: String,
    instance_id: String,
    #[serde(default)]
    display_name: String,
    #[serde(default)]
    app_state: String,
    last_ip: String,
    last_port: i64,
    #[serde(default)]
    last_tls_port: i64,
    last_seen: i64,
    state: String,
    #[serde(default)]
    quarantined: bool,
    #[serde(default)]
    shares: Vec<AdvertisedShareInfo>,
}

impl PeerInfo {
    fn peer_key(&self) -> String {
        format!("{}@{}", self.pc_name, self.instance_id)
    }

    fn label(&self) -> String {
        let trimmed = self.display_name.trim();
        if trimmed.is_empty() {
            self.pc_name.clone()
        } else {
            trimmed.to_string()
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct SettingRow {
    key: String,
    value: Value,
    source: String,
    #[serde(default)]
    restart_required: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct PendingRequest {
    request_id: String,
    share_name: String,
    #[serde(default)]
    paths: Vec<String>,
    from_pc: String,
    from_instance: String,
    #[serde(default)]
    direction: String,
    #[serde(default)]
    status: String,
    created_at: i64,
}

#[derive(Debug, Clone)]
struct IntentRow {
    id: String,
    kind: String,
    status: String,
    share: String,
    pending_batches: i64,
    bytes_done: u64,
    bytes_total: u64,
    files_done: u64,
    files_total: u64,
    last_error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ThreadInfo {
    id: String,
    #[serde(default)]
    kind: String,
    peer_key: Option<String>,
    share_name: Option<String>,
    title: String,
    #[serde(default)]
    title_custom: bool,
    #[serde(default)]
    updated_at: i64,
    #[serde(default)]
    unread_count: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct ChatMsg {
    id: String,
    from_peer: String,
    body: String,
    attachment_share: Option<String>,
    attachment_path: Option<String>,
    created_at: i64,
    direction: String,
    #[serde(default)]
    status: String,
}

pub struct App {
    socket: PathBuf,
    ensure_opts: EnsureOpts,
    runtime: Arc<Mutex<Option<RuntimeHandle>>>,
    runtime_label: String,
    managed_runtime: bool,
    runtime_busy: bool,
    dark: bool,
    tab: Tab,
    connected: bool,
    flash: Option<(bool, String)>,
    status: Option<StatusSnapshot>,
    peers: Vec<PeerInfo>,
    local_shares: Vec<ShareInfo>,
    new_share_name: String,
    new_share_path: String,
    config_key: String,
    config_value: String,
    settings: Vec<SettingRow>,
    pending: Vec<PendingRequest>,
    intents: Vec<IntentRow>,
    threads: Vec<ThreadInfo>,
    messages: Vec<ChatMsg>,
    share: String,
    peer: String,
    path: String,
    chat_peer: String,
    chat_share: String,
    chat_body: String,
    selected_thread: Option<String>,
    editing_chat_title: bool,
    chat_title_draft: String,
    /// After a successful send, bind the inbox thread for this peer once it appears.
    bind_chat_peer_after_inbox: Option<String>,
    log_lines: Vec<String>,
    log_path: String,
    log_truncated: bool,
    log_total_lines: usize,
    log_tail_lines: usize,
    log_tail_input: String,
    prefs_path: PathBuf,
    chat_split_ratio: f32,
    status_split_ratio: f32,
    transfers_split_ratio: f32,
    chat_panes: pane_grid::State<ChatPane>,
    status_panes: pane_grid::State<StatusPane>,
    transfers_panes: pane_grid::State<TransfersPane>,
    split_prefs_dirty: bool,
    /// When true, load errors from periodic polls do not spam the flash banner.
    background_refresh: bool,
    window_focused: bool,
    toasts: VecDeque<Toast>,
    next_toast_id: u64,
    /// Dedupe keys for push + poll-fallback notifications.
    seen_notify_keys: HashSet<String>,
}

impl App {
    pub fn new(
        socket: PathBuf,
        ensure_opts: EnsureOpts,
        runtime: Arc<Mutex<Option<RuntimeHandle>>>,
    ) -> (Self, Task<Message>) {
        let (runtime_label, managed_runtime) = {
            let guard = runtime.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(h) => (h.label().to_string(), h.mode == RuntimeMode::Managed),
                None => ("stopped".into(), false),
            }
        };
        let prefs_path = prefs::prefs_path_for_socket(&socket);
        let prefs = GuiPrefs::load(&prefs_path);
        let log_tail_lines = GuiPrefs::clamp_log_tail_lines(prefs.log_tail_lines);
        let chat_split_ratio = GuiPrefs::clamp_split_ratio(prefs.chat_split_ratio);
        let status_split_ratio = GuiPrefs::clamp_split_ratio(prefs.status_split_ratio);
        let transfers_split_ratio = GuiPrefs::clamp_split_ratio(prefs.transfers_split_ratio);
        let app = Self {
            socket,
            ensure_opts,
            runtime,
            runtime_label,
            managed_runtime,
            runtime_busy: false,
            dark: theme::system_is_dark(),
            tab: Tab::Status,
            connected: false,
            flash: None,
            status: None,
            peers: Vec::new(),
            local_shares: Vec::new(),
            new_share_name: String::new(),
            new_share_path: String::new(),
            config_key: String::new(),
            config_value: String::new(),
            settings: Vec::new(),
            pending: Vec::new(),
            intents: Vec::new(),
            threads: Vec::new(),
            messages: Vec::new(),
            share: String::new(),
            peer: String::new(),
            path: String::new(),
            chat_peer: String::new(),
            chat_share: String::new(),
            chat_body: String::new(),
            selected_thread: None,
            editing_chat_title: false,
            chat_title_draft: String::new(),
            bind_chat_peer_after_inbox: None,
            log_lines: Vec::new(),
            log_path: String::new(),
            log_truncated: false,
            log_total_lines: 0,
            log_tail_lines,
            log_tail_input: log_tail_lines.to_string(),
            prefs_path,
            chat_split_ratio,
            status_split_ratio,
            transfers_split_ratio,
            chat_panes: two_pane_state(
                pane_grid::Axis::Vertical,
                chat_split_ratio,
                ChatPane::Inbox,
                ChatPane::Thread,
            ),
            status_panes: two_pane_state(
                pane_grid::Axis::Horizontal,
                status_split_ratio,
                StatusPane::Shares,
                StatusPane::Peers,
            ),
            transfers_panes: two_pane_state(
                pane_grid::Axis::Vertical,
                transfers_split_ratio,
                TransfersPane::Pending,
                TransfersPane::Intents,
            ),
            split_prefs_dirty: false,
            background_refresh: false,
            window_focused: true,
            toasts: VecDeque::new(),
            next_toast_id: 1,
            seen_notify_keys: HashSet::new(),
        };
        (app, Task::done(Message::Refresh))
    }

    fn notify_event(&mut self, event: ControlEvent, from_poll: bool) {
        let key = event.dedupe_key();
        if !self.seen_notify_keys.insert(key) {
            return;
        }
        // Cap memory for long sessions.
        if self.seen_notify_keys.len() > 2000 {
            self.seen_notify_keys.clear();
        }
        let title = event.title().to_string();
        let body = event.body();
        let id = self.next_toast_id;
        self.next_toast_id = self.next_toast_id.saturating_add(1);
        self.toasts.push_back(Toast {
            id,
            title,
            body,
            created: Instant::now(),
        });
        while self.toasts.len() > 5 {
            self.toasts.pop_front();
        }
        if !self.window_focused {
            control_events::show_os_notification(&event);
        }
        let _ = from_poll;
    }

    fn prune_toasts(&mut self) {
        let ttl = Duration::from_secs(8);
        self.toasts
            .retain(|t| t.created.elapsed() < ttl);
    }

    pub fn title(&self) -> String {
        format!("LocalBox — {}", self.socket.display())
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Tab(t) => {
                self.tab = t;
                self.background_refresh = false;
                Task::done(Message::Refresh)
            }
            Message::Refresh => {
                self.background_refresh = false;
                self.refresh_tasks()
            }
            Message::StatusLoaded(res) => {
                self.apply_result(res, |app, resp| {
                    app.status = parse_status(&resp);
                });
                Task::none()
            }
            Message::InboxLoaded(res) => {
                let prev_threads = self.threads.clone();
                self.apply_result(res, |app, resp| {
                    app.threads = parse_vec(&resp);
                });
                if self.background_refresh {
                    poll_notify_chat_threads(self, &prev_threads);
                }
                if let Some(peer) = self.bind_chat_peer_after_inbox.take() {
                    if let Some(thread) = find_thread_for_peer(self, &peer).cloned() {
                        apply_thread_to_composer(self, &thread);
                        self.selected_thread = Some(thread.id);
                        self.messages.clear();
                        return Task::done(Message::Refresh);
                    }
                }
                Task::none()
            }
            Message::PendingLoaded(res) => {
                let prev_pending: HashSet<String> =
                    self.pending.iter().map(|p| p.request_id.clone()).collect();
                self.apply_result(res, |app, resp| {
                    app.pending = parse_vec(&resp);
                });
                if self.background_refresh {
                    poll_notify_pending(self, &prev_pending);
                }
                Task::none()
            }
            Message::IntentsLoaded(res) => {
                let prev_progress: HashSet<(String, u64, u64)> = self
                    .intents
                    .iter()
                    .map(|i| (i.id.clone(), i.files_done, i.bytes_done))
                    .collect();
                self.apply_result(res, |app, resp| {
                    app.intents = parse_intent_rows(&resp);
                });
                if self.background_refresh {
                    poll_notify_intents(self, &prev_progress);
                }
                Task::none()
            }
            Message::PeersLoaded(res) => {
                self.apply_result(res, |app, resp| {
                    app.peers = parse_vec(&resp);
                });
                Task::none()
            }
            Message::SharesLoaded(res) => {
                self.apply_result(res, |app, resp| {
                    app.local_shares = parse_vec(&resp);
                });
                Task::none()
            }
            Message::SettingsLoaded(res) => {
                self.apply_result(res, |app, resp| {
                    app.settings = parse_vec(&resp);
                });
                Task::none()
            }
            Message::LogsLoaded(res) => {
                match &res {
                    Ok(resp)
                        if !resp.ok
                            && resp.message.contains("unknown variant")
                            && resp.message.contains("logs") =>
                    {
                        self.connected = true;
                        if !self.background_refresh {
                            self.flash = Some((
                                false,
                                "Runtime is too old for Logs — Stop, then Start (or restart `localbox run`) to load the new binary.".into(),
                            ));
                        }
                        return Task::none();
                    }
                    Err(e) if e.contains("unknown variant") && e.contains("logs") => {
                        if !self.background_refresh {
                            self.flash = Some((
                                false,
                                "Runtime is too old for Logs — Stop, then Start (or restart `localbox run`) to load the new binary.".into(),
                            ));
                        }
                        return Task::none();
                    }
                    _ => {}
                }
                let prev_len = self.log_lines.len();
                let prev_last = self.log_lines.last().cloned();
                self.apply_result(res, |app, resp| {
                    if let Some(data) = &resp.data {
                        app.log_path = data
                            .get("path")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        app.log_truncated = data
                            .get("truncated")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        app.log_total_lines = data
                            .get("total_lines")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as usize;
                        app.log_lines = data
                            .get("lines")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();
                    }
                });
                let grew = self.log_lines.len() > prev_len
                    || self.log_lines.last() != prev_last.as_ref();
                if grew {
                    scrollable::scroll_to(
                        scrollable::Id::new("engine-logs"),
                        AbsoluteOffset { x: 0.0, y: f32::MAX },
                    )
                } else {
                    Task::none()
                }
            }
            Message::ThreadLoaded(res) => {
                let prev_len = self.messages.len();
                let prev_last = self.messages.last().map(|m| m.id.clone());
                self.apply_result(res, |app, resp| {
                    app.messages = parse_vec(&resp);
                });
                let grew = self.messages.len() > prev_len
                    || self.messages.last().map(|m| &m.id) != prev_last.as_ref();
                if grew && self.selected_thread.is_some() {
                    scrollable::scroll_to(
                        scrollable::Id::new("chat-messages"),
                        AbsoluteOffset { x: 0.0, y: f32::MAX },
                    )
                } else {
                    Task::none()
                }
            }
            Message::ActionDone(res) => {
                match res {
                    Ok(resp) => {
                        self.connected = true;
                        if resp.ok && resp.message.starts_with("added share") {
                            self.new_share_name.clear();
                            self.new_share_path.clear();
                        }
                        if resp.ok
                            && (resp.message.starts_with("set ") || resp.message.starts_with("unset "))
                        {
                            self.config_value.clear();
                        }
                        if resp.ok && resp.message.starts_with("deleted thread ") {
                            self.selected_thread = None;
                            self.messages.clear();
                            self.chat_peer.clear();
                            self.chat_share.clear();
                            self.editing_chat_title = false;
                            self.chat_title_draft.clear();
                        }
                        if !resp.ok {
                            if let Some(msg) = stale_runtime_message(&resp.message) {
                                self.flash = Some((false, msg));
                                return Task::done(Message::Refresh);
                            }
                        }
                        self.flash = Some((resp.ok, resp.message));
                    }
                    Err(e) => {
                        self.connected = false;
                        self.flash = Some((false, disconnect_message(&e, self.managed_runtime)));
                    }
                }
                Task::done(Message::Refresh)
            }
            Message::NewShareNameInput(s) => {
                self.new_share_name = s;
                Task::none()
            }
            Message::NewSharePathInput(s) => {
                self.new_share_path = s;
                Task::none()
            }
            Message::AddShare => {
                let name = self.new_share_name.trim().to_string();
                let path = self.new_share_path.trim().to_string();
                if name.is_empty() || path.is_empty() {
                    self.flash = Some((false, "share name and path are required".into()));
                    return Task::none();
                }
                self.transfer_action(ControlRequest::ShareAdd {
                    name,
                    path,
                    recursive: true,
                })
            }
            Message::ConfigKeyInput(s) => {
                self.config_key = s;
                Task::none()
            }
            Message::ConfigValueInput(s) => {
                self.config_value = s;
                Task::none()
            }
            Message::ConfigRefresh => {
                self.tab = Tab::Settings;
                Task::done(Message::Refresh)
            }
            Message::ConfigSet => {
                let key = self.config_key.trim().to_string();
                let raw = self.config_value.trim().to_string();
                if key.is_empty() || raw.is_empty() {
                    self.flash = Some((false, "key and value are required".into()));
                    return Task::none();
                }
                let value = match localbox_core::settings::parse_value_literal(&raw) {
                    Ok(v) => v,
                    Err(e) => {
                        self.flash = Some((false, e.to_string()));
                        return Task::none();
                    }
                };
                self.transfer_action(ControlRequest::ConfigSet { key, value })
            }
            Message::ConfigUnset => {
                let key = self.config_key.trim().to_string();
                if key.is_empty() {
                    self.flash = Some((false, "key is required".into()));
                    return Task::none();
                }
                self.transfer_action(ControlRequest::ConfigUnset { key })
            }
            Message::SelectPeer(s) => {
                self.peer = s;
                Task::none()
            }
            Message::SelectShare(s) => {
                self.share = s;
                Task::none()
            }
            Message::PathInput(s) => {
                self.path = s;
                Task::none()
            }
            Message::Push => self.transfer_action(ControlRequest::Push {
                share: self.share.clone(),
                peer: nonempty(&self.peer),
                path: nonempty(&self.path),
            }),
            Message::Pull => self.transfer_action(ControlRequest::Pull {
                share: self.share.clone(),
                peer: self.peer.clone(),
                path: nonempty(&self.path),
            }),
            Message::Request => self.transfer_action(ControlRequest::Request {
                share: self.share.clone(),
                peer: self.peer.clone(),
                path: nonempty(&self.path),
            }),
            Message::ReplyAccept(id) => self.transfer_action(ControlRequest::Reply {
                id,
                accept: true,
                reason: None,
            }),
            Message::ReplyDecline(id) => self.transfer_action(ControlRequest::Reply {
                id,
                accept: false,
                reason: Some("declined from GUI".into()),
            }),
            Message::SelectChatPeer(s) => {
                self.chat_peer = s;
                self.editing_chat_title = false;
                self.chat_title_draft.clear();
                if let Some(thread) = find_thread_for_peer(self, &self.chat_peer).cloned() {
                    apply_thread_to_composer(self, &thread);
                    self.selected_thread = Some(thread.id);
                    self.messages.clear();
                    Task::done(Message::Refresh)
                } else {
                    // New DM to this peer — keep optional share the user already picked.
                    self.selected_thread = None;
                    self.messages.clear();
                    Task::none()
                }
            }
            Message::SelectChatShare(s) => {
                self.chat_share = s;
                Task::none()
            }
            Message::ChatBodyInput(s) => {
                self.chat_body = s;
                Task::none()
            }
            Message::NewChat => {
                self.selected_thread = None;
                self.messages.clear();
                self.chat_peer.clear();
                self.chat_share.clear();
                self.chat_body.clear();
                self.editing_chat_title = false;
                self.chat_title_draft.clear();
                Task::none()
            }
            Message::ChatSend => {
                if self.chat_peer.trim().is_empty() {
                    self.flash = Some((false, "select a peer in To to send a chat message".into()));
                    return Task::none();
                }
                if self.chat_body.trim().is_empty() {
                    return Task::none();
                }
                // Keep an explicit thread id only for peer DMs; share-thread ids
                // must not override a peer-targeted send.
                let thread = self.selected_thread.clone().filter(|id| {
                    self.threads
                        .iter()
                        .any(|t| &t.id == id && t.kind != "share")
                });
                let req = ControlRequest::ChatSend {
                    peer: nonempty(&self.chat_peer),
                    share: nonempty(&self.chat_share),
                    thread,
                    message: nonempty(&self.chat_body),
                    file: None,
                    share_dest: None,
                };
                self.chat_body.clear();
                let sock = self.socket.clone();
                Task::perform(
                    async move {
                        client::send_request(&sock, &req)
                            .await
                            .map_err(|e| e.to_string())
                    },
                    Message::ChatSent,
                )
            }
            Message::ChatSent(res) => match res {
                Ok(resp) if resp.ok => {
                    self.connected = true;
                    self.bind_chat_peer_after_inbox = Some(self.chat_peer.clone());
                    self.background_refresh = true;
                    Task::batch([
                        self.refresh_tasks(),
                        scrollable::scroll_to(
                            scrollable::Id::new("chat-messages"),
                            AbsoluteOffset { x: 0.0, y: f32::MAX },
                        ),
                    ])
                }
                Ok(resp) => {
                    self.connected = true;
                    self.flash = Some((false, resp.message));
                    Task::none()
                }
                Err(e) => {
                    self.connected = false;
                    self.flash = Some((false, disconnect_message(&e, self.managed_runtime)));
                    Task::none()
                }
            }
            Message::SelectThread(id) => {
                if let Some(thread) = self.threads.iter().find(|t| t.id == id).cloned() {
                    apply_thread_to_composer(self, &thread);
                }
                self.selected_thread = Some(id);
                self.messages.clear();
                self.editing_chat_title = false;
                self.chat_title_draft.clear();
                Task::done(Message::Refresh)
            }
            Message::StartRenameChat => {
                if let Some(thread) = self
                    .selected_thread
                    .as_ref()
                    .and_then(|id| self.threads.iter().find(|t| &t.id == id))
                {
                    self.chat_title_draft = thread.title.clone();
                    self.editing_chat_title = true;
                }
                Task::none()
            }
            Message::ChatTitleInput(s) => {
                self.chat_title_draft = s;
                Task::none()
            }
            Message::CancelRenameChat => {
                self.editing_chat_title = false;
                self.chat_title_draft.clear();
                Task::none()
            }
            Message::SaveChatTitle => {
                let Some(thread) = self.selected_thread.clone() else {
                    return Task::none();
                };
                let title = self.chat_title_draft.trim().to_string();
                if title.is_empty() {
                    return Task::none();
                }
                self.editing_chat_title = false;
                self.transfer_action(ControlRequest::ChatRename { thread, title })
            }
            Message::DeleteChatThread => {
                if let Some(thread) = self.selected_thread.clone() {
                    self.transfer_action(ControlRequest::ChatDeleteThread { thread })
                } else {
                    Task::none()
                }
            }
            Message::DeleteChatMessage(message) => {
                self.transfer_action(ControlRequest::ChatDeleteMessage { message })
            }
            Message::MarkRead => {
                if let Some(tid) = self.selected_thread.clone() {
                    self.transfer_action(ControlRequest::ChatRead { thread: tid })
                } else {
                    Task::none()
                }
            }
            Message::QuarantinePeer(peer) => {
                self.transfer_action(ControlRequest::PeerQuarantine { peer })
            }
            Message::UnquarantinePeer(peer) => {
                self.transfer_action(ControlRequest::PeerUnquarantine { peer })
            }
            Message::StartRuntime => {
                if self.runtime_busy || self.connected {
                    return Task::none();
                }
                if self.ensure_opts.no_runtime {
                    self.flash = Some((
                        false,
                        "cannot start runtime with --no-runtime".into(),
                    ));
                    return Task::none();
                }
                self.runtime_busy = true;
                let opts = self.ensure_opts.clone();
                let slot = Arc::clone(&self.runtime);
                Task::perform(
                    async move {
                        // Drop any previous handle (kills a managed child) before attach/spawn.
                        {
                            let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
                            guard.take();
                        }
                        // Replace any daemon still on the socket so Start picks up a newly
                        // built localbox-core instead of re-attaching to a stale process.
                        let handle = restart_runtime(opts).await.map_err(|e| e.to_string())?;
                        let label = handle.label().to_string();
                        let managed = handle.mode == RuntimeMode::Managed;
                        let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
                        *guard = Some(handle);
                        Ok((label, managed))
                    },
                    Message::RuntimeStarted,
                )
            }
            Message::StopRuntime => {
                if self.runtime_busy {
                    return Task::none();
                }
                let has_handle = self
                    .runtime
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .is_some();
                if !has_handle && !self.connected {
                    return Task::none();
                }
                self.runtime_busy = true;
                let slot = Arc::clone(&self.runtime);
                let socket = self.socket.clone();
                let was_managed = self.managed_runtime;
                Task::perform(
                    async move {
                        let taken = {
                            let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
                            guard.take()
                        };
                        if let Some(mut handle) = taken {
                            let msg = stop_runtime(&mut handle).await.map_err(|e| e.to_string())?;
                            Ok(msg.to_string())
                        } else if was_managed {
                            Err("no managed runtime to stop".into())
                        } else {
                            let resp = client::send_request(&socket, &ControlRequest::Shutdown)
                                .await
                                .map_err(|e| e.to_string())?;
                            if resp.ok {
                                Ok(resp.message)
                            } else {
                                Err(resp.message)
                            }
                        }
                    },
                    Message::RuntimeStopped,
                )
            }
            Message::RuntimeStarted(res) => {
                self.runtime_busy = false;
                match res {
                    Ok((label, managed)) => {
                        self.runtime_label = label;
                        self.managed_runtime = managed;
                        self.connected = true;
                        self.flash =
                            Some((true, format!("runtime {} ready", self.runtime_label)));
                        Task::done(Message::Refresh)
                    }
                    Err(e) => {
                        self.runtime_label = "stopped".into();
                        self.managed_runtime = false;
                        self.connected = false;
                        self.flash = Some((false, e));
                        Task::none()
                    }
                }
            }
            Message::RuntimeStopped(res) => {
                self.runtime_busy = false;
                self.runtime_label = "stopped".into();
                self.managed_runtime = false;
                self.connected = false;
                self.status = None;
                match res {
                    Ok(msg) => {
                        self.flash = Some((true, msg));
                    }
                    Err(e) => {
                        self.flash = Some((false, e));
                    }
                }
                Task::none()
            }
            Message::ClearFlash => {
                self.flash = None;
                Task::none()
            }
            Message::LogTailInput(s) => {
                self.log_tail_input = s;
                Task::none()
            }
            Message::SaveLogTail => {
                let parsed = self.log_tail_input.trim().parse::<usize>().ok();
                let Some(n) = parsed else {
                    self.flash = Some((false, "log line limit must be a number".into()));
                    return Task::none();
                };
                let n = GuiPrefs::clamp_log_tail_lines(n);
                self.log_tail_lines = n;
                self.log_tail_input = n.to_string();
                match self.persist_prefs() {
                    Ok(()) => {
                        self.flash = Some((
                            true,
                            format!("log window set to {n} lines (saved to UI prefs)"),
                        ));
                        if self.tab == Tab::Logs {
                            Task::done(Message::Refresh)
                        } else {
                            Task::none()
                        }
                    }
                    Err(e) => {
                        self.flash = Some((false, format!("failed to save UI prefs: {e}")));
                        Task::none()
                    }
                }
            }
            Message::ChatPanesResized(event) => {
                self.chat_panes.resize(event.split, event.ratio);
                self.chat_split_ratio = GuiPrefs::clamp_split_ratio(event.ratio);
                self.split_prefs_dirty = true;
                Task::none()
            }
            Message::StatusPanesResized(event) => {
                self.status_panes.resize(event.split, event.ratio);
                self.status_split_ratio = GuiPrefs::clamp_split_ratio(event.ratio);
                self.split_prefs_dirty = true;
                Task::none()
            }
            Message::TransfersPanesResized(event) => {
                self.transfers_panes.resize(event.split, event.ratio);
                self.transfers_split_ratio = GuiPrefs::clamp_split_ratio(event.ratio);
                self.split_prefs_dirty = true;
                Task::none()
            }
            Message::Tick => {
                self.prune_toasts();
                if self.split_prefs_dirty {
                    if self.persist_prefs().is_ok() {
                        self.split_prefs_dirty = false;
                    }
                }
                // Keep live tabs fresh (peers, transfers, chat, logs). Skip Settings
                // so editing config fields is not disrupted by list reloads.
                if self.runtime_busy || matches!(self.tab, Tab::Settings) {
                    Task::none()
                } else {
                    self.background_refresh = true;
                    self.refresh_tasks()
                }
            }
            Message::SyncSystemTheme => {
                let dark = theme::system_is_dark();
                if self.dark != dark {
                    self.dark = dark;
                }
                Task::none()
            }
            Message::WindowFocused(focused) => {
                self.window_focused = focused;
                Task::none()
            }
            Message::ControlEventArrived(event) => {
                self.notify_event(event, false);
                self.background_refresh = true;
                self.refresh_tasks()
            }
            Message::DismissToast(id) => {
                self.toasts.retain(|t| t.id != id);
                Task::none()
            }
            Message::WindowClosed => {
                // Tear down a GUI-spawned child immediately on window close.
                let mut guard = self.runtime.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(mut handle) = guard.take() {
                    if handle.mode == RuntimeMode::Managed {
                        stop_managed_sync(&mut handle);
                        self.managed_runtime = false;
                        self.connected = false;
                        self.runtime_label = "stopped".into();
                    } else {
                        // Keep attached handle for main()'s post-run cleanup path.
                        *guard = Some(handle);
                    }
                }
                Task::none()
            }
        }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
            time::every(Duration::from_secs(2)).map(|_| Message::SyncSystemTheme),
            time::every(Duration::from_secs(2)).map(|_| Message::Tick),
            window::close_events().map(|_| Message::WindowClosed),
            event::listen_with(|event, _status, _id| match event {
                Event::Window(window::Event::Focused) => Some(Message::WindowFocused(true)),
                Event::Window(window::Event::Unfocused) => Some(Message::WindowFocused(false)),
                _ => None,
            }),
            Subscription::run_with_id(
                self.socket.clone(),
                control_events::subscription(self.socket.clone()),
            )
            .map(Message::ControlEventArrived),
        ])
    }

    fn colors(&self) -> &'static Colors {
        theme::palette(self.dark)
    }

    fn persist_prefs(&self) -> std::io::Result<()> {
        GuiPrefs {
            log_tail_lines: self.log_tail_lines,
            chat_split_ratio: self.chat_split_ratio,
            status_split_ratio: self.status_split_ratio,
            transfers_split_ratio: self.transfers_split_ratio,
        }
        .save(&self.prefs_path)
    }

    fn refresh_tasks(&self) -> Task<Message> {
        let sock = self.socket.clone();
        match self.tab {
            Tab::Status => {
                let sock2 = self.socket.clone();
                let sock3 = self.socket.clone();
                Task::batch([
                    Task::perform(
                        async move {
                            client::send_request(&sock, &ControlRequest::Status)
                                .await
                                .map_err(|e| e.to_string())
                        },
                        Message::StatusLoaded,
                    ),
                    Task::perform(
                        async move {
                            client::send_request(&sock2, &ControlRequest::PeerList)
                                .await
                                .map_err(|e| e.to_string())
                        },
                        Message::PeersLoaded,
                    ),
                    Task::perform(
                        async move {
                            client::send_request(&sock3, &ControlRequest::ShareList)
                                .await
                                .map_err(|e| e.to_string())
                        },
                        Message::SharesLoaded,
                    ),
                ])
            }
            Tab::Transfers => {
                let sock2 = self.socket.clone();
                let sock3 = self.socket.clone();
                let sock4 = self.socket.clone();
                Task::batch([
                    Task::perform(
                        async move {
                            client::send_request(&sock, &ControlRequest::PendingRequests)
                                .await
                                .map_err(|e| e.to_string())
                        },
                        Message::PendingLoaded,
                    ),
                    Task::perform(
                        async move {
                            client::send_request(
                                &sock3,
                                &ControlRequest::Intents {
                                    all: false,
                                    limit: Some(100),
                                },
                            )
                            .await
                            .map_err(|e| e.to_string())
                        },
                        Message::IntentsLoaded,
                    ),
                    Task::perform(
                        async move {
                            client::send_request(&sock2, &ControlRequest::Status)
                                .await
                                .map_err(|e| e.to_string())
                        },
                        Message::StatusLoaded,
                    ),
                    Task::perform(
                        async move {
                            client::send_request(&sock4, &ControlRequest::PeerList)
                                .await
                                .map_err(|e| e.to_string())
                        },
                        Message::PeersLoaded,
                    ),
                ])
            }
            Tab::Chat => {
                let sock2 = self.socket.clone();
                let sock3 = self.socket.clone();
                let sock4 = self.socket.clone();
                let thread = self.selected_thread.clone();
                let mut tasks = vec![
                    Task::perform(
                        async move {
                            client::send_request(&sock, &ControlRequest::ChatInbox)
                                .await
                                .map_err(|e| e.to_string())
                        },
                        Message::InboxLoaded,
                    ),
                    Task::perform(
                        async move {
                            client::send_request(&sock3, &ControlRequest::PeerList)
                                .await
                                .map_err(|e| e.to_string())
                        },
                        Message::PeersLoaded,
                    ),
                    Task::perform(
                        async move {
                            client::send_request(&sock4, &ControlRequest::ShareList)
                                .await
                                .map_err(|e| e.to_string())
                        },
                        Message::SharesLoaded,
                    ),
                ];
                if let Some(tid) = thread {
                    tasks.push(Task::perform(
                        async move {
                            client::send_request(
                                &sock2,
                                &ControlRequest::ChatShow {
                                    thread: tid,
                                    limit: Some(100),
                                },
                            )
                            .await
                            .map_err(|e| e.to_string())
                        },
                        Message::ThreadLoaded,
                    ));
                }
                Task::batch(tasks)
            }
            Tab::Logs => {
                let limit = self.log_tail_lines;
                Task::perform(
                    async move {
                        client::send_request(&sock, &ControlRequest::Logs { limit: Some(limit) })
                            .await
                            .map_err(|e| e.to_string())
                    },
                    Message::LogsLoaded,
                )
            }
            Tab::Settings => Task::perform(
                async move {
                    client::send_request(&sock, &ControlRequest::ConfigList)
                        .await
                        .map_err(|e| e.to_string())
                },
                Message::SettingsLoaded,
            ),
        }
    }

    fn transfer_action(&self, req: ControlRequest) -> Task<Message> {
        let sock = self.socket.clone();
        Task::perform(
            async move {
                client::send_request(&sock, &req)
                    .await
                    .map_err(|e| e.to_string())
            },
            Message::ActionDone,
        )
    }

    fn apply_result(
        &mut self,
        res: Result<ControlResponse, String>,
        on_ok: impl FnOnce(&mut Self, ControlResponse),
    ) {
        let quiet = self.background_refresh;
        match res {
            Ok(resp) => {
                self.connected = true;
                if resp.ok {
                    on_ok(self, resp);
                } else if !quiet {
                    self.flash = Some((false, resp.message));
                }
            }
            Err(e) => {
                let was_connected = self.connected;
                self.connected = false;
                if !quiet || was_connected {
                    self.flash = Some((false, disconnect_message(&e, self.managed_runtime)));
                }
            }
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let c = self.colors();
        let has_handle = self
            .runtime
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some();
        let can_start =
            !self.connected && !has_handle && !self.runtime_busy && !self.ensure_opts.no_runtime;
        let can_stop =
            (self.connected || self.managed_runtime || has_handle) && !self.runtime_busy;
        let mut runtime_controls = row![].spacing(6).align_y(Alignment::Center);
        if can_start {
            runtime_controls = runtime_controls.push(styled_button(
                "Start",
                Message::StartRuntime,
                theme::btn_secondary,
            ));
        }
        if can_stop {
            runtime_controls = runtime_controls.push(styled_button(
                "Stop",
                Message::StopRuntime,
                theme::btn_secondary,
            ));
        }

        let header = row![
            column![
                text("LocalBox").size(26).color(c.accent),
                text(format!(
                    "{} · runtime {}",
                    self.socket.display(),
                    self.runtime_label
                ))
                .size(12)
                .color(c.muted),
            ]
            .spacing(2),
            Space::with_width(Length::Fill),
            connection_badge(self.connected, c),
            runtime_controls,
            styled_button("Refresh", Message::Refresh, theme::btn_secondary),
        ]
        .spacing(12)
        .align_y(Alignment::Center);

        let tabs = container(
            row![
                tab_btn("Status", Tab::Status, self.tab),
                tab_btn("Transfers", Tab::Transfers, self.tab),
                tab_btn("Chat", Tab::Chat, self.tab),
                tab_btn("Logs", Tab::Logs, self.tab),
                tab_btn("Settings", Tab::Settings, self.tab),
            ]
            .spacing(6),
        )
        .padding(6)
        .style(theme::tab_bar_style);

        let flash = self.flash.as_ref().map(|(ok, msg)| {
            let color = if *ok { c.ok } else { c.danger };
            container(
                row![
                    text(msg).size(13).color(color),
                    Space::with_width(Length::Fill),
                    button(text("Dismiss").size(12))
                        .padding([4, 8])
                        .style(theme::btn_ghost)
                        .on_press(Message::ClearFlash),
                ]
                .align_y(Alignment::Center),
            )
            .padding([10, 14])
            .width(Length::Fill)
            .style(theme::badge_style(color))
        });

        let mut toast_col: Column<'_, Message> = column![].spacing(6);
        for toast in self.toasts.iter().rev().take(3) {
            toast_col = toast_col.push(
                container(
                    row![
                        column![
                            text(&toast.title).size(13).color(c.text),
                            text(&toast.body).size(12).color(c.muted),
                        ]
                        .spacing(2)
                        .width(Length::Fill),
                        button(text("Dismiss").size(11))
                            .padding([4, 8])
                            .style(theme::btn_ghost)
                            .on_press(Message::DismissToast(toast.id)),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                )
                .padding([10, 14])
                .width(Length::Fill)
                .style(theme::card_style),
            );
        }

        let body: Element<'_, Message> = match self.tab {
            Tab::Status => status_view(self),
            Tab::Transfers => transfers_view(self),
            Tab::Chat => chat_view(self),
            Tab::Logs => logs_view(self),
            Tab::Settings => settings_view(self),
        };

        let mut content = column![header, tabs].spacing(10);
        if let Some(banner) = flash {
            content = content.push(banner);
        }
        if !self.toasts.is_empty() {
            content = content.push(toast_col);
        }
        content = content.push(body);

        container(content.padding(12).width(Length::Fill).height(Length::Fill))
            .width(Length::Fill)
            .height(Length::Fill)
            .style(theme::root_style)
            .into()
    }

    pub fn theme(&self) -> Theme {
        if self.dark {
            Theme::Dark
        } else {
            Theme::Light
        }
    }
}

fn status_view(app: &App) -> Element<'_, Message> {
    let c = app.colors();
    let metrics = if let Some(s) = &app.status {
        row![
            metric_card("Peers", s.peers.to_string(), c),
            metric_card("Shares", s.shares.to_string(), c),
            metric_card("Queue", s.queue_depth.to_string(), c),
        ]
        .spacing(8)
        .width(Length::Fill)
    } else {
        row![text("Waiting for status…").size(14).color(c.muted)].width(Length::Fill)
    };

    let add_share = panel_sized(
        column![
            section_title("Add share", c),
            labeled_input("Name", &app.new_share_name, Message::NewShareNameInput, c),
            labeled_input("Path", &app.new_share_path, Message::NewSharePathInput, c),
            styled_button("Add share", Message::AddShare, theme::btn_primary),
        ]
        .spacing(8),
        Length::Fill,
        Length::Shrink,
    );

    let panes = PaneGrid::new(&app.status_panes, |_pane, kind, _maximized| {
        let body = match kind {
            StatusPane::Shares => status_shares_body(app),
            StatusPane::Peers => status_peers_body(app),
        };
        resizable_pane(body)
    })
    .width(Length::Fill)
    .height(Length::Fill)
    .spacing(10)
    .on_resize(8, Message::StatusPanesResized)
    .style(theme::pane_grid_style);

    column![
        section_title("Overview", c),
        metrics,
        add_share,
        panes,
    ]
    .spacing(10)
    .height(Length::Fill)
    .into()
}

fn transfers_view(app: &App) -> Element<'_, Message> {
    let c = app.colors();
    let form = panel_sized(
        column![
            section_title("Manual transfer", c),
            picker_row(
                "Peer",
                &app.peer,
                peer_picker_options(app),
                Message::SelectPeer,
                c,
            ),
            picker_row(
                "Share",
                &app.share,
                share_picker_options(app),
                Message::SelectShare,
                c,
            ),
            labeled_input("Path", &app.path, Message::PathInput, c),
            row![
                styled_button("Push", Message::Push, theme::btn_primary),
                styled_button("Pull", Message::Pull, theme::btn_secondary),
                styled_button("Request", Message::Request, theme::btn_secondary),
            ]
            .spacing(8),
        ]
        .spacing(12),
        Length::Fill,
        Length::Shrink,
    );

    let panes = PaneGrid::new(&app.transfers_panes, |_pane, kind, _maximized| {
        let body = match kind {
            TransfersPane::Pending => transfers_pending_body(app),
            TransfersPane::Intents => transfers_intents_body(app),
        };
        resizable_pane(body)
    })
    .width(Length::Fill)
    .height(Length::Fill)
    .spacing(12)
    .on_resize(8, Message::TransfersPanesResized)
    .style(theme::pane_grid_style);

    column![form, panes]
        .spacing(12)
        .height(Length::Fill)
        .into()
}

fn chat_view(app: &App) -> Element<'_, Message> {
    PaneGrid::new(&app.chat_panes, |_pane, kind, _maximized| {
        let body = match kind {
            ChatPane::Inbox => chat_inbox_body(app),
            ChatPane::Thread => chat_thread_body(app),
        };
        resizable_pane(body)
    })
    .width(Length::Fill)
    .height(Length::Fill)
    .spacing(12)
    .on_resize(8, Message::ChatPanesResized)
    .style(theme::pane_grid_style)
    .into()
}

fn two_pane_state<T: Copy>(
    axis: pane_grid::Axis,
    ratio: f32,
    a: T,
    b: T,
) -> pane_grid::State<T> {
    pane_grid::State::with_configuration(pane_grid::Configuration::Split {
        axis,
        ratio: GuiPrefs::clamp_split_ratio(ratio),
        a: Box::new(pane_grid::Configuration::Pane(a)),
        b: Box::new(pane_grid::Configuration::Pane(b)),
    })
}

fn resizable_pane(body: Element<'_, Message>) -> pane_grid::Content<'_, Message> {
    pane_grid::Content::new(
        container(body)
            .padding(16)
            .width(Length::Fill)
            .height(Length::Fill),
    )
    .style(theme::panel_style)
}

fn status_shares_body(app: &App) -> Element<'_, Message> {
    let c = app.colors();
    let mut shares_col: Column<'_, Message> = column![section_title("Shares", c)].spacing(6);
    if app.local_shares.is_empty() {
        shares_col = shares_col.push(empty_state("No local shares yet.", c));
    } else {
        for share in &app.local_shares {
            shares_col = shares_col.push(
                container(
                    column![
                        text(&share.share_name).size(14).color(c.text),
                        text(format!(
                            "{}{}",
                            share.root_path,
                            if share.recursive { " · recursive" } else { "" }
                        ))
                        .size(11)
                        .color(c.muted),
                    ]
                    .spacing(2),
                )
                .padding(10)
                .width(Length::Fill)
                .style(theme::card_style),
            );
        }
    }
    scrollable(shares_col).height(Length::Fill).into()
}

fn status_peers_body(app: &App) -> Element<'_, Message> {
    let c = app.colors();
    let mut peers_col: Column<'_, Message> = column![section_title("Peers", c)].spacing(8);
    if app.peers.is_empty() {
        peers_col = peers_col.push(empty_state("No peers discovered yet.", c));
    } else {
        for peer in &app.peers {
            peers_col = peers_col.push(peer_card(peer, c));
        }
    }
    scrollable(peers_col).height(Length::Fill).into()
}

fn transfers_pending_body(app: &App) -> Element<'_, Message> {
    let c = app.colors();
    let mut pending_col: Column<'_, Message> =
        column![section_title("Pending inbound requests", c)].spacing(8);
    if app.pending.is_empty() {
        pending_col = pending_col.push(empty_state("No pending requests.", c));
    } else {
        for req in &app.pending {
            pending_col = pending_col.push(pending_card(req, c));
        }
    }
    scrollable(pending_col).height(Length::Fill).into()
}

fn transfers_intents_body(app: &App) -> Element<'_, Message> {
    let c = app.colors();
    let mut intents_col: Column<'_, Message> =
        column![section_title("Active transfer intents", c)].spacing(8);
    if app.intents.is_empty() {
        intents_col = intents_col.push(empty_state("No active intents.", c));
    } else {
        for intent in &app.intents {
            intents_col = intents_col.push(intent_card(intent, c));
        }
    }
    scrollable(intents_col).height(Length::Fill).into()
}

fn chat_inbox_body(app: &App) -> Element<'_, Message> {
    let c = app.colors();
    let mut inbox_col: Column<'_, Message> = column![
        row![
            section_title("Messages", c),
            Space::with_width(Length::Fill),
            styled_button("New message", Message::NewChat, theme::btn_ghost),
        ]
        .align_y(Alignment::Center),
    ]
    .spacing(6);
    if app.threads.is_empty() {
        inbox_col = inbox_col.push(empty_state("No conversations yet.", c));
    } else {
        for thread in &app.threads {
            let selected = app.selected_thread.as_deref() == Some(thread.id.as_str());
            inbox_col = inbox_col.push(thread_item(thread, selected, c));
        }
    }
    scrollable(inbox_col).height(Length::Fill).into()
}

fn chat_thread_body(app: &App) -> Element<'_, Message> {
    let c = app.colors();
    let composing_new = app.selected_thread.is_none();
    let selected = app
        .selected_thread
        .as_ref()
        .and_then(|id| app.threads.iter().find(|t| &t.id == id));

    let header: Element<'_, Message> = if composing_new {
        column![
            text("New message").size(18).color(c.text),
            text("Choose who to message, then write below.")
                .size(12)
                .color(c.muted),
        ]
        .spacing(4)
        .into()
    } else if app.editing_chat_title {
        let placeholder = if selected.map(|t| t.title_custom).unwrap_or(false) {
            "Custom name"
        } else {
            "Conversation name"
        };
        column![
            text("Rename conversation").size(12).color(c.muted),
            row![
                text_input(placeholder, &app.chat_title_draft)
                    .on_input(Message::ChatTitleInput)
                    .on_submit(Message::SaveChatTitle)
                    .padding(8)
                    .width(Length::Fill)
                    .style(theme::input_style),
                styled_button("Save", Message::SaveChatTitle, theme::btn_primary),
                styled_button("Cancel", Message::CancelRenameChat, theme::btn_ghost),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        ]
        .spacing(6)
        .into()
    } else {
        let title = selected
            .map(|t| t.title.as_str())
            .unwrap_or("Conversation");
        let subtitle = selected
            .map(thread_subtitle)
            .unwrap_or_default();
        let mut actions = row![].spacing(8).align_y(Alignment::Center);
        actions = actions.push(styled_button(
            "Rename",
            Message::StartRenameChat,
            theme::btn_ghost,
        ));
        actions = actions.push(styled_button(
            "Mark read",
            Message::MarkRead,
            theme::btn_ghost,
        ));
        actions = actions.push(styled_button(
            "Delete",
            Message::DeleteChatThread,
            theme::btn_danger,
        ));
        column![
            row![
                text(title).size(18).color(c.text),
                Space::with_width(Length::Fill),
                actions,
            ]
            .align_y(Alignment::Center),
            text(subtitle).size(12).color(c.muted),
        ]
        .spacing(4)
        .into()
    };

    let mut body_col: Column<'_, Message> = column![header].spacing(10);

    if composing_new {
        let to_summary = chat_to_summary(app);
        body_col = body_col.push(
            container(
                column![
                    text("To").size(12).color(c.muted),
                    picker_row(
                        "Peer",
                        &app.chat_peer,
                        peer_picker_options(app),
                        Message::SelectChatPeer,
                        c,
                    ),
                    picker_row(
                        "Share (optional)",
                        &app.chat_share,
                        share_picker_options(app),
                        Message::SelectChatShare,
                        c,
                    ),
                    text(to_summary).size(12).color(c.muted),
                ]
                .spacing(8),
            )
            .padding(12)
            .width(Length::Fill)
            .style(theme::card_style),
        );
    }

    let mut messages_col: Column<'_, Message> = column![].spacing(8);
    if composing_new && app.chat_peer.trim().is_empty() {
        messages_col = messages_col.push(empty_state(
            "Pick a peer under To to start a DM, or open a conversation from the sidebar.",
            c,
        ));
    } else if composing_new {
        messages_col = messages_col.push(empty_state(
            "Send a message to start this conversation.",
            c,
        ));
    } else if app.messages.is_empty() {
        messages_col = messages_col.push(empty_state("No messages yet. Say hello.", c));
    } else {
        for msg in &app.messages {
            messages_col = messages_col.push(message_bubble(msg, app, c));
        }
    }

    // Nothing to send to until the user picks a peer or opens an existing thread.
    let can_compose = !app.chat_peer.trim().is_empty() || app.selected_thread.is_some();
    let placeholder = if can_compose {
        "Message…"
    } else {
        "Select a peer or conversation first"
    };
    let mut input = text_input(placeholder, &app.chat_body)
        .padding(10)
        .width(Length::Fill)
        .style(theme::input_style);
    if can_compose {
        input = input
            .on_input(Message::ChatBodyInput)
            .on_submit(Message::ChatSend);
    }
    let composer = row![
        input,
        styled_button_maybe(
            "Send",
            can_compose.then_some(Message::ChatSend),
            theme::btn_primary,
        ),
    ]
    .spacing(8)
    .align_y(Alignment::Center);

    body_col = body_col
        .push(
            scrollable(messages_col)
                .id(scrollable::Id::new("chat-messages"))
                .anchor_bottom()
                .height(Length::Fill),
        )
        .push(composer);

    body_col
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn chat_to_summary(app: &App) -> String {
    let peer = app.chat_peer.trim();
    let share = app.chat_share.trim();
    match (peer.is_empty(), share.is_empty()) {
        (true, _) => "Choose a peer to message.".into(),
        (false, true) => {
            if app.selected_thread.is_some() {
                format!("Opening conversation with {peer}")
            } else {
                format!("New conversation with {peer}")
            }
        }
        (false, false) => {
            if app.selected_thread.is_some() {
                format!("Opening conversation with {peer} · #{share}")
            } else {
                format!("New conversation with {peer} · #{share}")
            }
        }
    }
}

fn thread_subtitle(thread: &ThreadInfo) -> String {
    match (thread.kind.as_str(), &thread.peer_key, &thread.share_name) {
        ("share", _, Some(s)) => format!("#{s}"),
        (_, Some(p), Some(s)) => format!("{p} · #{s}"),
        (_, Some(p), None) => p.clone(),
        (_, None, Some(s)) => format!("#{s}"),
        _ => thread.kind.clone(),
    }
}

fn apply_thread_to_composer(app: &mut App, thread: &ThreadInfo) {
    match thread.kind.as_str() {
        "share" => {
            app.chat_peer.clear();
            app.chat_share = thread
                .share_name
                .clone()
                .unwrap_or_else(|| thread.title.clone());
        }
        _ => {
            app.chat_peer = thread.peer_key.clone().unwrap_or_default();
            app.chat_share = thread.share_name.clone().unwrap_or_default();
        }
    }
}

fn find_thread_for_peer<'a>(app: &'a App, peer_key: &str) -> Option<&'a ThreadInfo> {
    let peer_key = peer_key.trim();
    if peer_key.is_empty() {
        return None;
    }
    app.threads.iter().find(|t| {
        t.kind != "share" && t.peer_key.as_deref() == Some(peer_key)
    })
}

fn peer_display_label(app: &App, peer_key: &str) -> String {
    let peer_key = peer_key.trim();
    if let Some(peer) = app.peers.iter().find(|p| p.peer_key() == peer_key) {
        return peer.label();
    }
    peer_key
        .split_once('@')
        .map(|(pc, _)| pc.to_string())
        .unwrap_or_else(|| peer_key.to_string())
}

fn logs_view(app: &App) -> Element<'_, Message> {
    let c = app.colors();
    let meta = if app.log_path.is_empty() {
        "Waiting for log tail…".to_string()
    } else if app.log_truncated {
        format!(
            "{} · showing last {} of {} lines",
            app.log_path, app.log_tail_lines, app.log_total_lines
        )
    } else {
        format!(
            "{} · {} line{}",
            app.log_path,
            app.log_total_lines,
            if app.log_total_lines == 1 { "" } else { "s" }
        )
    };

    let mut lines_col: Column<'_, Message> = column![].spacing(2);
    if app.log_lines.is_empty() {
        lines_col = lines_col.push(empty_state("No log lines yet.", c));
    } else {
        for line in &app.log_lines {
            lines_col = lines_col.push(
                text(line.clone())
                    .size(12)
                    .font(iced::Font::MONOSPACE)
                    .color(c.text),
            );
        }
    }

    column![
        row![
            column![
                section_title("Engine logs", c),
                text(meta).size(12).color(c.muted),
            ]
            .spacing(4)
            .width(Length::Fill),
            row![
                labeled_input("Lines", &app.log_tail_input, Message::LogTailInput, c),
                styled_button("Apply", Message::SaveLogTail, theme::btn_secondary),
            ]
            .spacing(8)
            .align_y(Alignment::End),
        ]
        .spacing(12)
        .align_y(Alignment::End),
        panel(
            scrollable(lines_col)
                .id(scrollable::Id::new("engine-logs"))
                .anchor_bottom()
                .height(Length::Fill),
            Length::Fill,
        ),
    ]
    .spacing(10)
    .height(Length::Fill)
    .into()
}

fn settings_view(app: &App) -> Element<'_, Message> {
    let c = app.colors();
    let ui_prefs = column![
        section_title("UI preferences", c),
        text(format!(
            "Stored in {} (GUI only; not sent to the engine).",
            app.prefs_path.display()
        ))
        .size(12)
        .color(c.muted),
        row![
            labeled_input(
                "Log tail lines",
                &app.log_tail_input,
                Message::LogTailInput,
                c,
            ),
            styled_button("Save", Message::SaveLogTail, theme::btn_primary),
        ]
        .spacing(8)
        .align_y(Alignment::End),
        text(format!(
            "Rolling window for the Logs tab (default {DEFAULT_LOG_TAIL_LINES}; min {}; max {}).",
            prefs::MIN_LOG_TAIL_LINES,
            prefs::MAX_LOG_TAIL_LINES
        ))
        .size(12)
        .color(c.muted),
    ]
    .spacing(8);

    let editor = column![
        section_title("Override setting", c),
        text("Saved values override config.toml; unset falls back to the file/defaults. CLI flags still win for the current process.")
            .size(12)
            .color(c.muted),
        row![
            labeled_input("Key", &app.config_key, Message::ConfigKeyInput, c),
            labeled_input("Value", &app.config_value, Message::ConfigValueInput, c),
        ]
        .spacing(8),
        row![
            styled_button("Set", Message::ConfigSet, theme::btn_primary),
            styled_button("Unset", Message::ConfigUnset, theme::btn_secondary),
            styled_button("Refresh", Message::ConfigRefresh, theme::btn_ghost),
        ]
        .spacing(8),
    ]
    .spacing(10);

    let mut list: Column<'_, Message> = column![section_title("Effective settings", c)].spacing(6);
    if app.settings.is_empty() {
        list = list.push(empty_state("Connect to a running daemon to load settings.", c));
    } else {
        for row in &app.settings {
            list = list.push(setting_row(row, c));
        }
    }

    column![
        panel(ui_prefs, Length::Shrink),
        panel(editor, Length::Shrink),
        panel(scrollable(list).height(Length::Fill), Length::Fill),
    ]
    .spacing(12)
    .height(Length::Fill)
    .into()
}

fn setting_row<'a>(row: &'a SettingRow, c: &'a Colors) -> Element<'a, Message> {
    let value = match &row.value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let mut meta = row.source.clone();
    if row.restart_required {
        meta.push_str(" · restart");
    }
    container(
        column![
            row![
                text(&row.key).size(14).color(c.text),
                Space::with_width(Length::Fill),
                text(meta).size(11).color(c.muted),
            ]
            .align_y(Alignment::Center),
            text(value).size(12).color(c.muted),
        ]
        .spacing(4),
    )
    .padding(12)
    .width(Length::Fill)
    .style(theme::card_style)
    .into()
}

fn peer_card<'a>(peer: &'a PeerInfo, c: &'a Colors) -> Element<'a, Message> {
    let key = peer.peer_key();
    let endpoint = if peer.last_tls_port > 0 {
        format!(
            "{}:{} (tls {})",
            peer.last_ip, peer.last_port, peer.last_tls_port
        )
    } else {
        format!("{}:{}", peer.last_ip, peer.last_port)
    };
    let seen = format_ts(peer.last_seen);
    let q_btn = if peer.quarantined {
        styled_button(
            "Unquarantine",
            Message::UnquarantinePeer(key.clone()),
            theme::btn_secondary,
        )
    } else {
        styled_button(
            "Quarantine",
            Message::QuarantinePeer(key.clone()),
            theme::btn_danger,
        )
    };

    let label = peer.label();
    let mut title = row![
        text(label).size(15).color(c.text),
        status_pill(&peer.state, c),
    ]
    .spacing(8)
    .align_y(Alignment::Center);
    if !peer.app_state.is_empty() {
        title = title.push(status_pill(&peer.app_state, c));
    }
    if peer.quarantined {
        title = title.push(status_pill("quarantined", c));
    }

    let shares_line = if peer.shares.is_empty() {
        "No advertised shares".to_string()
    } else {
        peer.shares
            .iter()
            .map(|s| {
                format!(
                    "{} (sync={}, pull={})",
                    s.name,
                    if s.sync.is_empty() { "manual" } else { &s.sync },
                    if s.pull.is_empty() { "manual" } else { &s.pull },
                )
            })
            .collect::<Vec<_>>()
            .join(" · ")
    };

    container(
        row![
            column![
                title,
                text(format!(
                    "{} · #{} · instance {}",
                    peer.pc_name, peer.id, peer.instance_id
                ))
                .size(12)
                .color(c.muted),
                text(format!("{endpoint} · last seen {seen}"))
                    .size(12)
                    .color(c.muted),
                text(shares_line).size(12).color(c.muted),
            ]
            .spacing(4)
            .width(Length::Fill),
            q_btn,
        ]
        .spacing(12)
        .align_y(Alignment::Center),
    )
    .padding(14)
    .width(Length::Fill)
    .style(theme::card_style)
    .into()
}

fn pending_card<'a>(req: &'a PendingRequest, c: &'a Colors) -> Element<'a, Message> {
    let from = format!("{}@{}", req.from_pc, req.from_instance);
    let paths = if req.paths.is_empty() {
        "entire share".into()
    } else {
        req.paths.join(", ")
    };
    container(
        column![
            row![
                text(&req.share_name).size(15).color(c.text),
                Space::with_width(Length::Fill),
                status_pill(&req.status, c),
            ]
            .align_y(Alignment::Center),
            text(format!("{} · from {from}", req.direction))
                .size(12)
                .color(c.muted),
            text(format!("paths: {paths}")).size(12).color(c.muted),
            text(format!(
                "id {} · {}",
                short_id(&req.request_id),
                format_ts(req.created_at)
            ))
            .size(11)
            .color(c.muted),
            row![
                styled_button(
                    "Accept",
                    Message::ReplyAccept(req.request_id.clone()),
                    theme::btn_primary,
                ),
                styled_button(
                    "Decline",
                    Message::ReplyDecline(req.request_id.clone()),
                    theme::btn_danger,
                ),
            ]
            .spacing(8),
        ]
        .spacing(6),
    )
    .padding(14)
    .width(Length::Fill)
    .style(theme::card_style)
    .into()
}

fn intent_card<'a>(intent: &'a IntentRow, c: &'a Colors) -> Element<'a, Message> {
    let frac = if intent.bytes_total > 0 {
        intent.bytes_done as f32 / intent.bytes_total as f32
    } else if intent.pending_batches == 0 {
        1.0
    } else {
        0.0
    };
    let bytes = format!(
        "{} / {}",
        format_bytes(intent.bytes_done),
        format_bytes(intent.bytes_total)
    );
    let files = if intent.files_total > 0 {
        format!("{} / {} files", intent.files_done, intent.files_total)
    } else {
        format!("{} batches pending", intent.pending_batches)
    };

    let mut col = column![
        row![
            text(format!("{} · {}", short_id(&intent.id), intent.kind))
                .size(14)
                .color(c.text),
            Space::with_width(Length::Fill),
            status_pill(&intent.status, c),
        ]
        .align_y(Alignment::Center),
        text(format!("share {}", intent.share))
            .size(12)
            .color(c.muted),
        progress_bar(0.0..=1.0, frac)
            .height(8)
            .style(theme::progress_style),
        row![
            text(bytes).size(12).color(c.muted),
            Space::with_width(Length::Fill),
            text(files).size(12).color(c.muted),
        ],
    ]
    .spacing(6);

    if let Some(err) = &intent.last_error {
        col = col.push(text(err).size(12).color(c.danger));
    }

    container(col)
        .padding(14)
        .width(Length::Fill)
        .style(theme::card_style)
        .into()
}

fn thread_item<'a>(thread: &'a ThreadInfo, selected: bool, c: &'a Colors) -> Element<'a, Message> {
    let subtitle = thread_subtitle(thread);
    let unread = if thread.unread_count > 0 {
        format!(" ({})", thread.unread_count)
    } else {
        String::new()
    };
    let updated = format_ts(thread.updated_at);

    button(
        column![
            text(format!("{}{unread}", thread.title))
                .size(14)
                .color(if selected { c.text } else { c.muted }),
            text(format!("{subtitle} · {updated}"))
                .size(11)
                .color(c.muted),
        ]
        .spacing(2)
        .width(Length::Fill),
    )
    .padding(10)
    .width(Length::Fill)
    .style(theme::btn_list_item(selected))
    .on_press(Message::SelectThread(thread.id.clone()))
    .into()
}

fn message_bubble<'a>(msg: &'a ChatMsg, app: &'a App, c: &'a Colors) -> Element<'a, Message> {
    let outgoing = msg.direction == "out";
    let align = if outgoing {
        Alignment::End
    } else {
        Alignment::Start
    };
    let from_label = peer_display_label(app, &msg.from_peer);
    let mut body = column![
        text(from_label).size(11).color(c.muted),
        text(&msg.body).size(14).color(c.text),
    ]
    .spacing(4);

    if let (Some(share), Some(path)) = (&msg.attachment_share, &msg.attachment_path) {
        body = body.push(
            text(format!("attachment {share}:{path}"))
                .size(12)
                .color(c.accent),
        );
    }

    let meta = if outgoing {
        format!("{} · {}", format_ts(msg.created_at), chat_delivery_label(&msg.status))
    } else {
        format_ts(msg.created_at)
    };
    body = body.push(
        row![
            text(meta).size(10).color(c.muted),
            Space::with_width(Length::Fill),
            button(text("Delete").size(10).color(c.danger))
                .padding(Padding::from([2, 6]))
                .style(theme::btn_ghost)
                .on_press(Message::DeleteChatMessage(msg.id.clone())),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    );

    let bubble = container(body)
        .padding([10, 12])
        .max_width(480)
        .style(theme::bubble_style(outgoing));

    column![bubble]
        .width(Length::Fill)
        .align_x(align)
        .into()
}

fn chat_delivery_label(status: &str) -> &'static str {
    match status {
        "acked" | "delivered" => "Delivered",
        "read" => "Read",
        "failed" | "error" => "Failed",
        _ => "Sent",
    }
}

fn metric_card<'a>(label: &'a str, value: String, c: &'a Colors) -> Element<'a, Message> {
    container(
        column![
            text(label).size(12).color(c.muted),
            text(value).size(24).color(c.text),
        ]
        .spacing(4),
    )
    .padding(16)
    .width(Length::Fill)
    .style(theme::metric_style)
    .into()
}

fn section_title<'a>(label: &'a str, c: &'a Colors) -> Element<'a, Message> {
    text(label).size(16).color(c.text).into()
}

fn empty_state<'a>(label: &'a str, c: &'a Colors) -> Element<'a, Message> {
    container(text(label).size(13).color(c.muted))
        .padding(16)
        .width(Length::Fill)
        .style(theme::card_style)
        .into()
}

fn panel<'a>(
    content: impl Into<Element<'a, Message>>,
    width: Length,
) -> Element<'a, Message> {
    panel_sized(content, width, Length::Fill)
}

fn panel_sized<'a>(
    content: impl Into<Element<'a, Message>>,
    width: Length,
    height: Length,
) -> Element<'a, Message> {
    container(content)
        .padding(16)
        .width(width)
        .height(height)
        .style(theme::panel_style)
        .into()
}

fn status_pill<'a>(label: &'a str, c: &'a Colors) -> Element<'a, Message> {
    let color = theme::status_color(c, label);
    container(text(label).size(11).color(color))
        .padding(Padding::from([3, 8]))
        .style(theme::badge_style(color))
        .into()
}

fn connection_badge(ok: bool, c: &Colors) -> Element<'static, Message> {
    let (label, color) = if ok {
        ("Connected", c.ok)
    } else {
        ("Offline", c.danger)
    };
    container(text(label).size(12).color(color))
        .padding(Padding::from([5, 12]))
        .style(theme::badge_style(color))
        .into()
}

fn labeled_input<'a>(
    label: &'a str,
    value: &str,
    on_input: impl Fn(String) -> Message + 'a,
    c: &Colors,
) -> Element<'a, Message> {
    column![
        text(label).size(12).color(c.muted),
        text_input(label, value)
            .on_input(on_input)
            .padding(9)
            .style(theme::input_style),
    ]
    .spacing(4)
    .width(Length::Fill)
    .into()
}

fn peer_picker_options(app: &App) -> Vec<(String, String)> {
    app.peers
        .iter()
        .map(|p| (p.peer_key(), p.label()))
        .collect()
}

fn share_picker_options(app: &App) -> Vec<(String, String)> {
    let mut names: Vec<String> = app
        .local_shares
        .iter()
        .map(|s| s.share_name.clone())
        .collect();
    for peer in &app.peers {
        for share in &peer.shares {
            if !names.iter().any(|n| n == &share.name) {
                names.push(share.name.clone());
            }
        }
    }
    names.sort();
    names.into_iter().map(|n| (n.clone(), n)).collect()
}

fn picker_row<'a>(
    label: &'a str,
    selected: &str,
    options: Vec<(String, String)>,
    on_pick: impl Fn(String) -> Message + Copy + 'a,
    c: &'a Colors,
) -> Element<'a, Message> {
    let mut chips = row![].spacing(6);
    if options.is_empty() {
        chips = chips.push(text("None discovered yet").size(12).color(c.muted));
    } else {
        for (value, caption) in options {
            let active = selected == value;
            chips = chips.push(picker_chip(caption, value, active, on_pick, c));
        }
    }
    column![
        text(label).size(12).color(c.muted),
        text(if selected.is_empty() {
            "(none selected)".into()
        } else {
            selected.to_string()
        })
        .size(12)
        .color(c.text),
        scrollable(chips).direction(scrollable::Direction::Horizontal(
            scrollable::Scrollbar::new(),
        )),
    ]
    .spacing(4)
    .width(Length::Fill)
    .into()
}

fn picker_chip<'a>(
    caption: String,
    value: String,
    active: bool,
    on_pick: impl Fn(String) -> Message + 'a,
    _c: &'a Colors,
) -> Element<'a, Message> {
    let style = if active {
        theme::btn_primary
    } else {
        theme::btn_ghost
    };
    button(text(caption).size(12))
        .padding(Padding::from([6, 10]))
        .style(style)
        .on_press(on_pick(value))
        .into()
}

fn tab_btn(label: &str, tab: Tab, active: Tab) -> Element<'_, Message> {
    button(text(label).size(14))
        .padding([8, 14])
        .style(theme::btn_tab(tab == active))
        .on_press(Message::Tab(tab))
        .into()
}

fn styled_button<'a>(
    label: &'a str,
    msg: Message,
    style: impl Fn(&Theme, button::Status) -> button::Style + 'a,
) -> Element<'a, Message> {
    styled_button_maybe(label, Some(msg), style)
}

/// Same as [`styled_button`] but renders disabled when `msg` is `None`.
fn styled_button_maybe<'a>(
    label: &'a str,
    msg: Option<Message>,
    style: impl Fn(&Theme, button::Status) -> button::Style + 'a,
) -> Element<'a, Message> {
    button(text(label).size(13))
        .padding([8, 14])
        .style(style)
        .on_press_maybe(msg)
        .into()
}

fn parse_status(resp: &ControlResponse) -> Option<StatusSnapshot> {
    resp.data
        .as_ref()
        .and_then(|d| serde_json::from_value(d.clone()).ok())
}

fn parse_vec<T: for<'de> Deserialize<'de>>(resp: &ControlResponse) -> Vec<T> {
    resp.data
        .as_ref()
        .and_then(|d| serde_json::from_value::<Vec<T>>(d.clone()).ok())
        .unwrap_or_default()
}

fn parse_intent_rows(resp: &ControlResponse) -> Vec<IntentRow> {
    let Some(arr) = resp.data.as_ref().and_then(|d| d.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .map(|item| {
            let id = str_field(item, "id", "?");
            let kind = value_as_string(item.get("kind")).unwrap_or_else(|| "?".into());
            let status = value_as_string(item.get("status")).unwrap_or_else(|| "?".into());
            let share = str_field(item, "share_name", "?");
            let pending_batches = item
                .get("pending_batches")
                .and_then(|x| x.as_i64())
                .unwrap_or(0);
            let last_error = item
                .get("last_error")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string());
            let (bytes_done, bytes_total, files_done, files_total) = item
                .get("progress")
                .and_then(|p| p.as_array())
                .map(|progress| {
                    let mut bytes_done = 0u64;
                    let mut bytes_total = 0u64;
                    let mut files_done = 0u64;
                    let mut files_total = 0u64;
                    for e in progress {
                        bytes_done += e.get("bytes_done").and_then(|x| x.as_u64()).unwrap_or(0);
                        bytes_total += e.get("bytes_total").and_then(|x| x.as_u64()).unwrap_or(0);
                        files_done += e.get("files_done").and_then(|x| x.as_u64()).unwrap_or(0);
                        files_total += e.get("files_total").and_then(|x| x.as_u64()).unwrap_or(0);
                    }
                    (bytes_done, bytes_total, files_done, files_total)
                })
                .unwrap_or((0, 0, 0, 0));
            IntentRow {
                id,
                kind,
                status,
                share,
                pending_batches,
                bytes_done,
                bytes_total,
                files_done,
                files_total,
                last_error,
            }
        })
        .collect()
}

fn str_field(v: &Value, key: &str, fallback: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or(fallback)
        .to_string()
}

fn value_as_string(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Object(obj) => obj
            .get("type")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string())
            .or_else(|| Some(v?.to_string())),
        other => Some(other.to_string().trim_matches('"').to_string()),
    }
}

fn short_id(id: &str) -> String {
    if id.len() > 8 {
        id[..8].to_string()
    } else {
        id.to_string()
    }
}

fn format_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let n = n as f64;
    if n >= GB {
        format!("{:.1} GB", n / GB)
    } else if n >= MB {
        format!("{:.1} MB", n / MB)
    } else if n >= KB {
        format!("{:.1} KB", n / KB)
    } else {
        format!("{n:.0} B")
    }
}

fn format_ts(ts: i64) -> String {
    if ts <= 0 {
        return "—".into();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(ts);
    let delta = (now - ts).max(0);
    if delta < 60 {
        format!("{delta}s ago")
    } else if delta < 3600 {
        format!("{}m ago", delta / 60)
    } else if delta < 86400 {
        format!("{}h ago", delta / 3600)
    } else {
        format!("{}d ago", delta / 86400)
    }
}

fn nonempty(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

fn disconnect_message(err: &str, managed: bool) -> String {
    if managed {
        format!("Disconnected from managed runtime: {err}")
    } else {
        format!("Disconnected: {err}")
    }
}

fn poll_notify_chat_threads(app: &mut App, prev: &[ThreadInfo]) {
    for thread in &app.threads.clone() {
        if thread.unread_count <= 0 {
            continue;
        }
        if app.selected_thread.as_deref() == Some(thread.id.as_str()) {
            continue;
        }
        let prev_unread = prev
            .iter()
            .find(|t| t.id == thread.id)
            .map(|t| t.unread_count)
            .unwrap_or(0);
        if thread.unread_count <= prev_unread {
            continue;
        }
        let from = thread
            .peer_key
            .clone()
            .unwrap_or_else(|| thread.title.clone());
        app.notify_event(
            ControlEvent::ChatReceived {
                thread_id: thread.id.clone(),
                message_id: format!("poll:{}:{}", thread.id, thread.updated_at),
                from_peer: from,
                preview: thread.title.clone(),
            },
            true,
        );
    }
}

fn poll_notify_pending(app: &mut App, prev_ids: &HashSet<String>) {
    for req in app.pending.clone() {
        if prev_ids.contains(&req.request_id) {
            continue;
        }
        app.notify_event(
            ControlEvent::TransferRequestPending {
                request_id: req.request_id.clone(),
                share_name: req.share_name.clone(),
                from_peer: format!("{}@{}", req.from_pc, req.from_instance),
                direction: if req.direction.is_empty() {
                    "in".into()
                } else {
                    req.direction.clone()
                },
            },
            true,
        );
    }
}

fn poll_notify_intents(app: &mut App, prev: &HashSet<(String, u64, u64)>) {
    for intent in app.intents.clone() {
        let key = (intent.id.clone(), intent.files_done, intent.bytes_done);
        if prev.contains(&key) {
            continue;
        }
        let grew = prev
            .iter()
            .find(|(id, _, _)| id == &intent.id)
            .map(|(_, files, bytes)| intent.files_done > *files || intent.bytes_done > *bytes)
            .unwrap_or(intent.files_done > 0 || intent.bytes_done > 0);
        if !grew {
            continue;
        }
        app.notify_event(
            ControlEvent::BatchReceived {
                batch_id: format!("poll-intent:{}:{}:{}", intent.id, intent.files_done, intent.bytes_done),
                share_name: intent.share.clone(),
                from_peer: intent.kind.clone(),
                change_count: intent.files_done as usize,
            },
            true,
        );
    }
}

/// Serde rejects new control cmds when the running daemon binary is older than the GUI.
fn stale_runtime_message(err: &str) -> Option<String> {
    let lower = err.to_ascii_lowercase();
    let unknown = lower.contains("unknown variant")
        || lower.contains("unknown message")
        || lower.contains("invalid request");
    if !unknown {
        return None;
    }
    if lower.contains("chat_delete")
        || lower.contains("chat_rename")
        || lower.contains("\"logs\"")
        || lower.contains("`logs`")
    {
        Some(
            "Runtime is too old for this action — Stop, then Start (rebuild localbox-core if needed)."
                .into(),
        )
    } else {
        None
    }
}
