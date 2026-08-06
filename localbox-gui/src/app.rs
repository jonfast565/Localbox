use iced::widget::{
    button, column, container, row, scrollable, text, text_input, Column, Space,
};
use iced::{Alignment, Background, Border, Color, Element, Length, Task, Theme};
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
    ThreadLoaded(Result<ControlResponse, String>),
    ActionDone(Result<ControlResponse, String>),
    ShareInput(String),
    PeerInput(String),
    PathInput(String),
    Push,
    Pull,
    Request,
    ReplyIdInput(String),
    ReplyAccept,
    ReplyDecline,
    ChatPeerInput(String),
    ChatShareInput(String),
    ChatBodyInput(String),
    ChatSend,
    SelectThread(String),
    MarkRead,
}

pub struct App {
    socket: PathBuf,
    tab: Tab,
    connected: bool,
    status_text: String,
    log: String,
    share: String,
    peer: String,
    path: String,
    reply_id: String,
    chat_peer: String,
    chat_share: String,
    chat_body: String,
    inbox_json: String,
    thread_json: String,
    pending_json: String,
    intents_json: String,
    selected_thread: Option<String>,
}

impl App {
    pub fn new(socket: PathBuf) -> (Self, Task<Message>) {
        let app = Self {
            socket,
            tab: Tab::Status,
            connected: false,
            status_text: "Connecting…".into(),
            log: String::new(),
            share: String::new(),
            peer: String::new(),
            path: String::new(),
            reply_id: String::new(),
            chat_peer: String::new(),
            chat_share: String::new(),
            chat_body: String::new(),
            inbox_json: String::new(),
            thread_json: String::new(),
            pending_json: String::new(),
            intents_json: String::new(),
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
            Message::Refresh => {
                let sock = self.socket.clone();
                match self.tab {
                    Tab::Status => Task::perform(
                        async move {
                            client::send_request(&sock, &ControlRequest::Status)
                                .await
                                .map_err(|e| e.to_string())
                        },
                        Message::StatusLoaded,
                    ),
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
            Message::StatusLoaded(res) => {
                self.apply_result(res, |app, resp| {
                    app.status_text = format_status(&resp);
                });
                Task::none()
            }
            Message::InboxLoaded(res) => {
                self.apply_result(res, |app, resp| {
                    app.inbox_json = pretty_data(&resp);
                });
                Task::none()
            }
            Message::PendingLoaded(res) => {
                self.apply_result(res, |app, resp| {
                    app.pending_json = pretty_data(&resp);
                });
                Task::none()
            }
            Message::IntentsLoaded(res) => {
                self.apply_result(res, |app, resp| {
                    app.intents_json = pretty_data(&resp);
                });
                Task::none()
            }
            Message::ThreadLoaded(res) => {
                self.apply_result(res, |app, resp| {
                    app.thread_json = pretty_data(&resp);
                });
                Task::none()
            }
            Message::ActionDone(res) => {
                self.apply_result(res, |app, resp| {
                    app.log = format!("{}\n{}", resp.message, pretty_data(&resp));
                });
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
            Message::ReplyIdInput(s) => {
                self.reply_id = s;
                Task::none()
            }
            Message::ReplyAccept => self.transfer_action(ControlRequest::Reply {
                id: self.reply_id.clone(),
                accept: true,
                reason: None,
            }),
            Message::ReplyDecline => self.transfer_action(ControlRequest::Reply {
                id: self.reply_id.clone(),
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
                self.selected_thread = Some(id);
                Task::done(Message::Refresh)
            }
            Message::MarkRead => {
                if let Some(tid) = self.selected_thread.clone() {
                    self.transfer_action(ControlRequest::ChatRead { thread: tid })
                } else {
                    Task::none()
                }
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
                    self.log = format!("error: {}", resp.message);
                }
            }
            Err(e) => {
                self.connected = false;
                self.status_text = format!("Disconnected: {e}");
                self.log = e;
            }
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let header = row![
            text("Localbox").size(28).color(theme::ACCENT),
            Space::with_width(Length::Fill),
            connection_badge(self.connected),
            button(text("Refresh").size(14)).on_press(Message::Refresh),
        ]
        .spacing(12)
        .align_y(Alignment::Center);

        let tabs = row![
            tab_btn("Status", Tab::Status, self.tab),
            tab_btn("Transfers", Tab::Transfers, self.tab),
            tab_btn("Chat", Tab::Chat, self.tab),
        ]
        .spacing(8);

        let body: Element<'_, Message> = match self.tab {
            Tab::Status => column![
                text(&self.status_text).size(16).color(theme::TEXT),
                Space::with_height(8),
                text("Log").size(14).color(theme::MUTED),
                scrollable(text(&self.log).size(13).color(theme::MUTED)).height(Length::Fill),
            ]
            .spacing(8)
            .into(),
            Tab::Transfers => transfers_view(self),
            Tab::Chat => chat_view(self),
        };

        let content = column![header, tabs, body]
            .spacing(16)
            .padding(24)
            .width(Length::Fill)
            .height(Length::Fill);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(theme::BG)),
                text_color: Some(theme::TEXT),
                ..Default::default()
            })
            .into()
    }

    pub fn theme(&self) -> Theme {
        Theme::Dark
    }
}

fn transfers_view(app: &App) -> Element<'_, Message> {
    column![
        text("Manual transfer").size(18).color(theme::TEXT),
        row![
            labeled_input("Share", &app.share, Message::ShareInput),
            labeled_input("Peer", &app.peer, Message::PeerInput),
            labeled_input("Path", &app.path, Message::PathInput),
        ]
        .spacing(12),
        row![
            button(text("Push").size(14)).on_press(Message::Push),
            button(text("Pull").size(14)).on_press(Message::Pull),
            button(text("Request").size(14)).on_press(Message::Request),
        ]
        .spacing(8),
        Space::with_height(12),
        text("Pending inbound requests").size(18).color(theme::TEXT),
        scrollable(text(&app.pending_json).size(13).color(theme::MUTED)).height(120),
        row![
            labeled_input("Request id", &app.reply_id, Message::ReplyIdInput),
            button(text("Accept").size(14)).on_press(Message::ReplyAccept),
            button(text("Decline").size(14)).on_press(Message::ReplyDecline),
        ]
        .spacing(8)
        .align_y(Alignment::End),
        text("Transfer intents").size(18).color(theme::TEXT),
        scrollable(text(&app.intents_json).size(13).color(theme::MUTED)).height(160),
        text(&app.log).size(13).color(theme::MUTED),
    ]
    .spacing(10)
    .into()
}

fn chat_view(app: &App) -> Element<'_, Message> {
    let mut inbox_col: Column<'_, Message> =
        column![text("Inbox").size(18).color(theme::TEXT)].spacing(6);
    if let Some(arr) = parse_inbox_threads(&app.inbox_json) {
        for t in arr {
            let id = t
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let title = t
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or(&id)
                .to_string();
            let unread = t.get("unread_count").and_then(|v| v.as_i64()).unwrap_or(0);
            let label = if unread > 0 {
                format!("{title} ({unread})")
            } else {
                title
            };
            inbox_col = inbox_col.push(
                button(text(label).size(14)).on_press(Message::SelectThread(id)),
            );
        }
    } else {
        inbox_col = inbox_col.push(text(&app.inbox_json).size(12).color(theme::MUTED));
    }

    column![
        row![
            scrollable(inbox_col).width(220).height(Length::Fill),
            column![
                row![
                    text(
                        app.selected_thread
                            .as_deref()
                            .unwrap_or("Select a thread")
                    )
                    .size(16)
                    .color(theme::TEXT),
                    Space::with_width(Length::Fill),
                    button(text("Mark read").size(13)).on_press(Message::MarkRead),
                ],
                scrollable(text(&app.thread_json).size(13).color(theme::MUTED))
                    .height(Length::Fill),
                row![
                    labeled_input("Peer", &app.chat_peer, Message::ChatPeerInput),
                    labeled_input("Share", &app.chat_share, Message::ChatShareInput),
                ]
                .spacing(8),
                row![
                    text_input("Message…", &app.chat_body)
                        .on_input(Message::ChatBodyInput)
                        .padding(10)
                        .width(Length::Fill),
                    button(text("Send").size(14)).on_press(Message::ChatSend),
                ]
                .spacing(8),
            ]
            .spacing(8)
            .width(Length::Fill)
            .height(Length::Fill),
        ]
        .spacing(16)
        .height(Length::Fill),
        text(&app.log).size(12).color(theme::MUTED),
    ]
    .spacing(8)
    .height(Length::Fill)
    .into()
}

fn parse_inbox_threads(raw: &str) -> Option<Vec<Value>> {
    let v: Value = serde_json::from_str(raw).ok()?;
    v.as_array().cloned()
}

fn labeled_input<'a>(
    label: &'a str,
    value: &str,
    on_input: impl Fn(String) -> Message + 'a,
) -> Element<'a, Message> {
    column![
        text(label).size(12).color(theme::MUTED),
        text_input(label, value).on_input(on_input).padding(8),
    ]
    .spacing(4)
    .into()
}

fn tab_btn(label: &str, tab: Tab, active: Tab) -> Element<'_, Message> {
    let label = if tab == active {
        format!("[{label}]")
    } else {
        label.to_string()
    };
    button(text(label).size(14))
        .on_press(Message::Tab(tab))
        .into()
}

fn connection_badge(ok: bool) -> Element<'static, Message> {
    let (label, color) = if ok {
        ("Connected", theme::OK)
    } else {
        ("Offline", theme::DANGER)
    };
    container(text(label).size(12).color(color))
        .padding([4, 10])
        .style(move |_| container::Style {
            background: Some(Background::Color(theme::PANEL)),
            border: Border {
                color,
                width: 1.0,
                radius: 4.0.into(),
            },
            ..Default::default()
        })
        .into()
}

fn format_status(resp: &ControlResponse) -> String {
    if let Some(data) = &resp.data {
        format!(
            "{}\n{}",
            resp.message,
            serde_json::to_string_pretty(data).unwrap_or_default()
        )
    } else {
        resp.message.clone()
    }
}

fn pretty_data(resp: &ControlResponse) -> String {
    resp.data
        .as_ref()
        .map(|d| serde_json::to_string_pretty(d).unwrap_or_default())
        .unwrap_or_default()
}

fn nonempty(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

#[allow(dead_code)]
fn _unused_color() -> Color {
    theme::BORDER
}
