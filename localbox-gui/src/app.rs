use iced::widget::{
    button, column, container, progress_bar, row, scrollable, text, text_input, Column, Space,
};
use iced::{time, Alignment, Element, Length, Padding, Subscription, Task, Theme};
use std::time::Duration;

use crate::theme::Colors;
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;

use crate::client::{self, ControlRequest, ControlResponse};
use crate::theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Status,
    Transfers,
    Chat,
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
    ThreadLoaded(Result<ControlResponse, String>),
    ActionDone(Result<ControlResponse, String>),
    ShareInput(String),
    PeerInput(String),
    PathInput(String),
    Push,
    Pull,
    Request,
    ReplyAccept(String),
    ReplyDecline(String),
    ChatPeerInput(String),
    ChatShareInput(String),
    ChatBodyInput(String),
    ChatSend,
    SelectThread(String),
    MarkRead,
    QuarantinePeer(String),
    UnquarantinePeer(String),
    ClearFlash,
    SyncSystemTheme,
}

#[derive(Debug, Clone, Deserialize)]
struct StatusSnapshot {
    peers: u64,
    shares: u64,
    queue_depth: u64,
    pending_requests: u64,
    active_intents: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct PeerInfo {
    id: i64,
    pc_name: String,
    instance_id: String,
    last_ip: String,
    last_port: i64,
    #[serde(default)]
    last_tls_port: i64,
    last_seen: i64,
    state: String,
    #[serde(default)]
    quarantined: bool,
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
    runtime_label: String,
    managed_runtime: bool,
    dark: bool,
    tab: Tab,
    connected: bool,
    flash: Option<(bool, String)>,
    status: Option<StatusSnapshot>,
    peers: Vec<PeerInfo>,
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
}

impl App {
    pub fn new(socket: PathBuf, runtime_label: String, managed_runtime: bool) -> (Self, Task<Message>) {
        let app = Self {
            socket,
            runtime_label,
            managed_runtime,
            dark: theme::system_is_dark(),
            tab: Tab::Status,
            connected: false,
            flash: None,
            status: None,
            peers: Vec::new(),
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
        };
        (app, Task::done(Message::Refresh))
    }

    pub fn title(&self) -> String {
        format!("Localbox — {}", self.socket.display())
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Tab(t) => {
                self.tab = t;
                Task::done(Message::Refresh)
            }
            Message::Refresh => self.refresh_tasks(),
            Message::StatusLoaded(res) => {
                self.apply_result(res, |app, resp| {
                    app.status = parse_status(&resp);
                });
                Task::none()
            }
            Message::InboxLoaded(res) => {
                self.apply_result(res, |app, resp| {
                    app.threads = parse_vec(&resp);
                });
                Task::none()
            }
            Message::PendingLoaded(res) => {
                self.apply_result(res, |app, resp| {
                    app.pending = parse_vec(&resp);
                });
                Task::none()
            }
            Message::IntentsLoaded(res) => {
                self.apply_result(res, |app, resp| {
                    app.intents = parse_intent_rows(&resp);
                });
                Task::none()
            }
            Message::PeersLoaded(res) => {
                self.apply_result(res, |app, resp| {
                    app.peers = parse_vec(&resp);
                });
                Task::none()
            }
            Message::ThreadLoaded(res) => {
                self.apply_result(res, |app, resp| {
                    app.messages = parse_vec(&resp);
                });
                Task::none()
            }
            Message::ActionDone(res) => {
                match res {
                    Ok(resp) => {
                        self.connected = true;
                        self.flash = Some((resp.ok, resp.message));
                    }
            Err(e) => {
                self.connected = false;
                self.flash = Some((false, disconnect_message(&e, self.managed_runtime)));
            }
                }
                Task::done(Message::Refresh)
            }
            Message::ShareInput(s) => {
                self.share = s;
                Task::none()
            }
            Message::PeerInput(s) => {
                self.peer = s;
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
            Message::ChatPeerInput(s) => {
                self.chat_peer = s;
                Task::none()
            }
            Message::ChatShareInput(s) => {
                self.chat_share = s;
                Task::none()
            }
            Message::ChatBodyInput(s) => {
                self.chat_body = s;
                Task::none()
            }
            Message::ChatSend => {
                let req = ControlRequest::ChatSend {
                    peer: nonempty(&self.chat_peer),
                    share: nonempty(&self.chat_share),
                    thread: self.selected_thread.clone(),
                    message: nonempty(&self.chat_body),
                    file: None,
                    share_dest: None,
                };
                self.chat_body.clear();
                self.transfer_action(req)
            }
            Message::SelectThread(id) => {
                if let Some(thread) = self.threads.iter().find(|t| t.id == id) {
                    if let Some(pk) = &thread.peer_key {
                        self.chat_peer = pk.clone();
                    }
                    if let Some(sn) = &thread.share_name {
                        self.chat_share = sn.clone();
                    }
                }
                self.selected_thread = Some(id);
                self.messages.clear();
                Task::done(Message::Refresh)
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
            Message::ClearFlash => {
                self.flash = None;
                Task::none()
            }
            Message::SyncSystemTheme => {
                let dark = theme::system_is_dark();
                if self.dark != dark {
                    self.dark = dark;
                }
                Task::none()
            }
        }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        time::every(Duration::from_secs(2)).map(|_| Message::SyncSystemTheme)
    }

    fn colors(&self) -> &'static Colors {
        theme::palette(self.dark)
    }

    fn refresh_tasks(&self) -> Task<Message> {
        let sock = self.socket.clone();
        match self.tab {
            Tab::Status => {
                let sock2 = self.socket.clone();
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
                ])
            }
            Tab::Transfers => {
                let sock2 = self.socket.clone();
                let sock3 = self.socket.clone();
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
                ])
            }
            Tab::Chat => {
                let sock2 = self.socket.clone();
                let thread = self.selected_thread.clone();
                let mut tasks = vec![Task::perform(
                    async move {
                        client::send_request(&sock, &ControlRequest::ChatInbox)
                            .await
                            .map_err(|e| e.to_string())
                    },
                    Message::InboxLoaded,
                )];
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
        match res {
            Ok(resp) => {
                self.connected = true;
                if resp.ok {
                    on_ok(self, resp);
                } else {
                    self.flash = Some((false, resp.message));
                }
            }
            Err(e) => {
                self.connected = false;
                self.flash = Some((false, disconnect_message(&e, self.managed_runtime)));
            }
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let c = self.colors();
        let header = row![
            column![
                text("Localbox").size(26).color(c.accent),
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
            styled_button("Refresh", Message::Refresh, theme::btn_secondary),
        ]
        .spacing(12)
        .align_y(Alignment::Center);

        let tabs = container(
            row![
                tab_btn("Status", Tab::Status, self.tab),
                tab_btn("Transfers", Tab::Transfers, self.tab),
                tab_btn("Chat", Tab::Chat, self.tab),
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

        let body: Element<'_, Message> = match self.tab {
            Tab::Status => status_view(self),
            Tab::Transfers => transfers_view(self),
            Tab::Chat => chat_view(self),
        };

        let mut content = column![header, tabs].spacing(10);
        if let Some(banner) = flash {
            content = content.push(banner);
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
            metric_card("Pending", s.pending_requests.to_string(), c),
            metric_card("Intents", s.active_intents.to_string(), c),
        ]
        .spacing(12)
        .width(Length::Fill)
    } else {
        row![text("Waiting for status…").size(14).color(c.muted)].width(Length::Fill)
    };

    let mut peers_col: Column<'_, Message> = column![section_title("Peers", c)].spacing(8);
    if app.peers.is_empty() {
        peers_col = peers_col.push(empty_state("No peers discovered yet.", c));
    } else {
        for peer in &app.peers {
            peers_col = peers_col.push(peer_card(peer, c));
        }
    }

    column![
        section_title("Overview", c),
        metrics,
        Space::with_height(8),
        panel(scrollable(peers_col).height(Length::Fill), Length::Fill),
    ]
    .spacing(12)
    .height(Length::Fill)
    .into()
}

fn transfers_view(app: &App) -> Element<'_, Message> {
    let c = app.colors();
    let form = panel_sized(
        column![
            section_title("Manual transfer", c),
            row![
                labeled_input("Share", &app.share, Message::ShareInput, c),
                labeled_input("Peer", &app.peer, Message::PeerInput, c),
                labeled_input("Path", &app.path, Message::PathInput, c),
            ]
            .spacing(12),
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

    let mut pending_col: Column<'_, Message> =
        column![section_title("Pending inbound requests", c)].spacing(8);
    if app.pending.is_empty() {
        pending_col = pending_col.push(empty_state("No pending requests.", c));
    } else {
        for req in &app.pending {
            pending_col = pending_col.push(pending_card(req, c));
        }
    }

    let mut intents_col: Column<'_, Message> =
        column![section_title("Active transfer intents", c)].spacing(8);
    if app.intents.is_empty() {
        intents_col = intents_col.push(empty_state("No active intents.", c));
    } else {
        for intent in &app.intents {
            intents_col = intents_col.push(intent_card(intent, c));
        }
    }

    column![
        form,
        row![
            panel(
                scrollable(pending_col).height(Length::Fill),
                Length::FillPortion(1),
            ),
            panel(
                scrollable(intents_col).height(Length::Fill),
                Length::FillPortion(1),
            ),
        ]
        .spacing(12)
        .height(Length::Fill),
    ]
    .spacing(12)
    .height(Length::Fill)
    .into()
}

fn chat_view(app: &App) -> Element<'_, Message> {
    let c = app.colors();
    let mut inbox_col: Column<'_, Message> = column![section_title("Inbox", c)].spacing(6);
    if app.threads.is_empty() {
        inbox_col = inbox_col.push(empty_state("No conversations yet.", c));
    } else {
        for thread in &app.threads {
            let selected = app.selected_thread.as_deref() == Some(thread.id.as_str());
            inbox_col = inbox_col.push(thread_item(thread, selected, c));
        }
    }

    let title = app
        .selected_thread
        .as_ref()
        .and_then(|id| app.threads.iter().find(|t| &t.id == id))
        .map(|t| t.title.clone())
        .unwrap_or_else(|| "Select a thread".into());

    let mut messages_col: Column<'_, Message> = column![].spacing(8);
    if app.selected_thread.is_none() {
        messages_col = messages_col.push(empty_state("Choose a thread from the inbox.", c));
    } else if app.messages.is_empty() {
        messages_col = messages_col.push(empty_state("No messages in this thread.", c));
    } else {
        for msg in &app.messages {
            messages_col = messages_col.push(message_bubble(msg, c));
        }
    }

    let composer = column![
        row![
            labeled_input("Peer", &app.chat_peer, Message::ChatPeerInput, c),
            labeled_input("Share", &app.chat_share, Message::ChatShareInput, c),
        ]
        .spacing(8),
        row![
            text_input("Write a message…", &app.chat_body)
                .on_input(Message::ChatBodyInput)
                .padding(10)
                .width(Length::Fill)
                .style(theme::input_style),
            styled_button("Send", Message::ChatSend, theme::btn_primary),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    ]
    .spacing(8);

    let thread_pane = column![
        row![
            text(title).size(16).color(c.text),
            Space::with_width(Length::Fill),
            styled_button("Mark read", Message::MarkRead, theme::btn_ghost),
        ]
        .align_y(Alignment::Center),
        scrollable(messages_col).height(Length::Fill),
        composer,
    ]
    .spacing(10)
    .width(Length::Fill)
    .height(Length::Fill);

    row![
        panel(scrollable(inbox_col).height(Length::Fill), Length::Fixed(120.0)),
        panel(thread_pane, Length::Fill),
    ]
    .spacing(12)
    .height(Length::Fill)
    .into()
}

fn peer_card<'a>(peer: &'a PeerInfo, c: &'a Colors) -> Element<'a, Message> {
    let key = format!("{}@{}", peer.pc_name, peer.instance_id);
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

    let mut title = row![
        text(&peer.pc_name).size(15).color(c.text),
        status_pill(&peer.state, c),
    ]
    .spacing(8)
    .align_y(Alignment::Center);
    if peer.quarantined {
        title = title.push(status_pill("quarantined", c));
    }

    container(
        row![
            column![
                title,
                text(format!("#{} · instance {}", peer.id, peer.instance_id))
                    .size(12)
                    .color(c.muted),
                text(format!("{endpoint} · last seen {seen}"))
                    .size(12)
                    .color(c.muted),
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
    let subtitle = match (&thread.peer_key, &thread.share_name) {
        (Some(p), Some(s)) => format!("{p} · {s}"),
        (Some(p), None) => p.clone(),
        (None, Some(s)) => format!("share {s}"),
        _ => thread.kind.clone(),
    };
    let unread = if thread.unread_count > 0 {
        format!(" · {}", thread.unread_count)
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

fn message_bubble<'a>(msg: &'a ChatMsg, c: &'a Colors) -> Element<'a, Message> {
    let outgoing = msg.direction == "out";
    let align = if outgoing {
        Alignment::End
    } else {
        Alignment::Start
    };
    let mut body = column![
        text(&msg.from_peer).size(11).color(c.muted),
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

    body = body.push(
        text(format!(
            "{} · {} · {}",
            short_id(&msg.id),
            format_ts(msg.created_at),
            msg.status
        ))
        .size(10)
        .color(c.muted),
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
    button(text(label).size(13))
        .padding([8, 14])
        .style(style)
        .on_press(msg)
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
