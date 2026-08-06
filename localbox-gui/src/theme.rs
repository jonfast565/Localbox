//! Visual tokens and widget styles for the Localbox GUI.

use iced::widget::{button, container, progress_bar, text_input};
use iced::{Background, Border, Color, Shadow, Theme, Vector};

pub const BG: Color = Color::from_rgb(0.07, 0.09, 0.11);
pub const SURFACE: Color = Color::from_rgb(0.11, 0.14, 0.17);
pub const SURFACE_RAISED: Color = Color::from_rgb(0.14, 0.18, 0.21);
pub const PANEL: Color = Color::from_rgb(0.12, 0.15, 0.18);
pub const BORDER: Color = Color::from_rgb(0.22, 0.27, 0.30);
pub const BORDER_STRONG: Color = Color::from_rgb(0.30, 0.36, 0.40);
pub const TEXT: Color = Color::from_rgb(0.92, 0.94, 0.95);
pub const MUTED: Color = Color::from_rgb(0.58, 0.63, 0.66);
pub const ACCENT: Color = Color::from_rgb(0.22, 0.70, 0.64);
pub const ACCENT_DIM: Color = Color::from_rgb(0.14, 0.42, 0.39);
pub const DANGER: Color = Color::from_rgb(0.82, 0.38, 0.34);
pub const DANGER_DIM: Color = Color::from_rgb(0.42, 0.18, 0.16);
pub const OK: Color = Color::from_rgb(0.48, 0.76, 0.52);
pub const WARN: Color = Color::from_rgb(0.86, 0.68, 0.32);
pub const BUBBLE_OUT: Color = Color::from_rgb(0.16, 0.36, 0.34);
pub const BUBBLE_IN: Color = Color::from_rgb(0.16, 0.19, 0.22);

fn btn(
    bg: Color,
    bg_hover: Color,
    text: Color,
    border: Color,
    status: button::Status,
) -> button::Style {
    let background = match status {
        button::Status::Pressed => Background::Color(bg_hover),
        button::Status::Hovered => Background::Color(bg_hover),
        button::Status::Disabled => Background::Color(Color {
            a: 0.45,
            ..bg
        }),
        button::Status::Active => Background::Color(bg),
    };
    button::Style {
        background: Some(background),
        text_color: if matches!(status, button::Status::Disabled) {
            Color { a: 0.5, ..text }
        } else {
            text
        },
        border: Border {
            color: border,
            width: 1.0,
            radius: 6.0.into(),
        },
        shadow: Shadow::default(),
    }
}

pub fn btn_primary(theme: &Theme, status: button::Status) -> button::Style {
    let _ = theme;
    btn(ACCENT_DIM, ACCENT, TEXT, ACCENT, status)
}

pub fn btn_secondary(theme: &Theme, status: button::Status) -> button::Style {
    let _ = theme;
    btn(SURFACE_RAISED, BORDER_STRONG, TEXT, BORDER, status)
}

pub fn btn_danger(theme: &Theme, status: button::Status) -> button::Style {
    let _ = theme;
    btn(DANGER_DIM, DANGER, TEXT, DANGER, status)
}

pub fn btn_ghost(theme: &Theme, status: button::Status) -> button::Style {
    let _ = theme;
    let bg = match status {
        button::Status::Hovered | button::Status::Pressed => SURFACE_RAISED,
        _ => Color::TRANSPARENT,
    };
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: MUTED,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: 6.0.into(),
        },
        shadow: Shadow::default(),
    }
}

pub fn btn_tab(active: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_theme, status| {
        if active {
            button::Style {
                background: Some(Background::Color(SURFACE_RAISED)),
                text_color: ACCENT,
                border: Border {
                    color: ACCENT,
                    width: 1.0,
                    radius: 6.0.into(),
                },
                shadow: Shadow::default(),
            }
        } else {
            let bg = match status {
                button::Status::Hovered | button::Status::Pressed => SURFACE,
                _ => Color::TRANSPARENT,
            };
            button::Style {
                background: Some(Background::Color(bg)),
                text_color: MUTED,
                border: Border {
                    color: Color::TRANSPARENT,
                    width: 1.0,
                    radius: 6.0.into(),
                },
                shadow: Shadow::default(),
            }
        }
    }
}

pub fn btn_list_item(selected: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_theme, status| {
        let bg = if selected {
            ACCENT_DIM
        } else {
            match status {
                button::Status::Hovered | button::Status::Pressed => SURFACE_RAISED,
                _ => Color::TRANSPARENT,
            }
        };
        button::Style {
            background: Some(Background::Color(bg)),
            text_color: if selected { TEXT } else { MUTED },
            border: Border {
                color: if selected { ACCENT } else { Color::TRANSPARENT },
                width: if selected { 1.0 } else { 0.0 },
                radius: 6.0.into(),
            },
            shadow: Shadow::default(),
        }
    }
}

pub fn input_style(theme: &Theme, status: text_input::Status) -> text_input::Style {
    let _ = theme;
    let border_color = match status {
        text_input::Status::Focused => ACCENT,
        text_input::Status::Hovered => BORDER_STRONG,
        text_input::Status::Disabled => BORDER,
        text_input::Status::Active => BORDER,
    };
    text_input::Style {
        background: Background::Color(SURFACE),
        border: Border {
            color: border_color,
            width: 1.0,
            radius: 6.0.into(),
        },
        icon: MUTED,
        placeholder: MUTED,
        value: TEXT,
        selection: ACCENT_DIM,
    }
}

pub fn panel_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(PANEL)),
        border: Border {
            color: BORDER,
            width: 1.0,
            radius: 10.0.into(),
        },
        text_color: Some(TEXT),
        shadow: Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.25),
            offset: Vector::new(0.0, 1.0),
            blur_radius: 8.0,
        },
    }
}

pub fn card_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(SURFACE)),
        border: Border {
            color: BORDER,
            width: 1.0,
            radius: 8.0.into(),
        },
        text_color: Some(TEXT),
        shadow: Shadow::default(),
    }
}

pub fn metric_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(SURFACE_RAISED)),
        border: Border {
            color: BORDER,
            width: 1.0,
            radius: 8.0.into(),
        },
        text_color: Some(TEXT),
        shadow: Shadow::default(),
    }
}

pub fn badge_style(color: Color) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(Background::Color(Color { a: 0.18, ..color })),
        border: Border {
            color,
            width: 1.0,
            radius: 999.0.into(),
        },
        text_color: Some(color),
        shadow: Shadow::default(),
    }
}

pub fn bubble_style(outgoing: bool) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(Background::Color(if outgoing { BUBBLE_OUT } else { BUBBLE_IN })),
        border: Border {
            color: if outgoing { ACCENT_DIM } else { BORDER },
            width: 1.0,
            radius: 10.0.into(),
        },
        text_color: Some(TEXT),
        shadow: Shadow::default(),
    }
}

pub fn root_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(BG)),
        text_color: Some(TEXT),
        ..Default::default()
    }
}

pub fn progress_style(theme: &Theme) -> progress_bar::Style {
    let _ = theme;
    progress_bar::Style {
        background: Background::Color(SURFACE),
        bar: Background::Color(ACCENT),
        border: Border {
            color: BORDER,
            width: 1.0,
            radius: 4.0.into(),
        },
    }
}

pub fn status_color(status: &str) -> Color {
    match status.to_ascii_lowercase().as_str() {
        "done" | "complete" | "completed" | "accepted" | "ok" | "online" | "connected" => OK,
        "failed" | "error" | "declined" | "rejected" | "offline" => DANGER,
        "in_flight" | "running" | "active" | "pending" | "queued" => WARN,
        _ => MUTED,
    }
}
