//! Visual tokens and widget styles for the Localbox GUI.

use iced::widget::{button, container, progress_bar, text_input};
use iced::{Background, Border, Color, Shadow, Theme, Vector};

#[derive(Debug, Clone, Copy)]
pub struct Colors {
    pub bg: Color,
    pub surface: Color,
    pub surface_raised: Color,
    pub panel: Color,
    pub border: Color,
    pub border_strong: Color,
    pub text: Color,
    pub muted: Color,
    pub accent: Color,
    pub accent_dim: Color,
    pub danger: Color,
    pub danger_dim: Color,
    pub ok: Color,
    pub warn: Color,
    pub bubble_out: Color,
    pub bubble_in: Color,
    pub input_bg: Color,
}

pub const LIGHT: Colors = Colors {
    bg: Color::from_rgb(0.93, 0.93, 0.93),
    surface: Color::from_rgb(0.97, 0.97, 0.97),
    surface_raised: Color::from_rgb(0.90, 0.90, 0.90),
    panel: Color::from_rgb(0.95, 0.95, 0.95),
    border: Color::from_rgb(0.72, 0.72, 0.72),
    border_strong: Color::from_rgb(0.55, 0.55, 0.55),
    text: Color::from_rgb(0.15, 0.15, 0.15),
    muted: Color::from_rgb(0.45, 0.45, 0.45),
    accent: Color::from_rgb(0.40, 0.40, 0.40),
    accent_dim: Color::from_rgb(0.78, 0.78, 0.78),
    danger: Color::from_rgb(0.70, 0.28, 0.28),
    danger_dim: Color::from_rgb(0.90, 0.78, 0.78),
    ok: Color::from_rgb(0.28, 0.55, 0.32),
    warn: Color::from_rgb(0.65, 0.50, 0.20),
    bubble_out: Color::from_rgb(0.86, 0.86, 0.86),
    bubble_in: Color::from_rgb(1.0, 1.0, 1.0),
    input_bg: Color::WHITE,
};

pub const DARK: Colors = Colors {
    bg: Color::from_rgb(0.12, 0.12, 0.12),
    surface: Color::from_rgb(0.18, 0.18, 0.18),
    surface_raised: Color::from_rgb(0.24, 0.24, 0.24),
    panel: Color::from_rgb(0.16, 0.16, 0.16),
    border: Color::from_rgb(0.35, 0.35, 0.35),
    border_strong: Color::from_rgb(0.48, 0.48, 0.48),
    text: Color::from_rgb(0.92, 0.92, 0.92),
    muted: Color::from_rgb(0.62, 0.62, 0.62),
    accent: Color::from_rgb(0.78, 0.78, 0.78),
    accent_dim: Color::from_rgb(0.32, 0.32, 0.32),
    danger: Color::from_rgb(0.85, 0.42, 0.40),
    danger_dim: Color::from_rgb(0.38, 0.18, 0.17),
    ok: Color::from_rgb(0.48, 0.72, 0.50),
    warn: Color::from_rgb(0.82, 0.66, 0.32),
    bubble_out: Color::from_rgb(0.28, 0.28, 0.28),
    bubble_in: Color::from_rgb(0.20, 0.20, 0.20),
    input_bg: Color::from_rgb(0.14, 0.14, 0.14),
};

pub fn system_is_dark() -> bool {
    matches!(dark_light::detect(), dark_light::Mode::Dark)
}

pub fn palette(dark: bool) -> &'static Colors {
    if dark {
        &DARK
    } else {
        &LIGHT
    }
}

pub fn colors(theme: &Theme) -> &'static Colors {
    palette(matches!(theme, Theme::Dark))
}

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
    let c = colors(theme);
    btn(
        c.surface_raised,
        c.border,
        c.text,
        c.border_strong,
        status,
    )
}

pub fn btn_secondary(theme: &Theme, status: button::Status) -> button::Style {
    let c = colors(theme);
    btn(c.surface, c.surface_raised, c.text, c.border, status)
}

pub fn btn_danger(theme: &Theme, status: button::Status) -> button::Style {
    let c = colors(theme);
    btn(c.danger_dim, c.danger, c.text, c.danger, status)
}

pub fn btn_ghost(theme: &Theme, status: button::Status) -> button::Style {
    let c = colors(theme);
    let bg = match status {
        button::Status::Hovered | button::Status::Pressed => c.surface_raised,
        _ => Color::TRANSPARENT,
    };
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: c.muted,
        border: Border {
            color: Color::TRANSPARENT,
            width: 0.0,
            radius: 6.0.into(),
        },
        shadow: Shadow::default(),
    }
}

pub fn btn_tab(active: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |theme, status| {
        let c = colors(theme);
        if active {
            button::Style {
                background: Some(Background::Color(c.surface)),
                text_color: c.text,
                border: Border {
                    color: c.border_strong,
                    width: 1.0,
                    radius: 6.0.into(),
                },
                shadow: Shadow::default(),
            }
        } else {
            let bg = match status {
                button::Status::Hovered | button::Status::Pressed => c.surface_raised,
                _ => Color::TRANSPARENT,
            };
            button::Style {
                background: Some(Background::Color(bg)),
                text_color: c.muted,
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
    move |theme, status| {
        let c = colors(theme);
        let bg = if selected {
            c.accent_dim
        } else {
            match status {
                button::Status::Hovered | button::Status::Pressed => c.surface_raised,
                _ => Color::TRANSPARENT,
            }
        };
        button::Style {
            background: Some(Background::Color(bg)),
            text_color: if selected { c.text } else { c.muted },
            border: Border {
                color: if selected {
                    c.border_strong
                } else {
                    Color::TRANSPARENT
                },
                width: if selected { 1.0 } else { 0.0 },
                radius: 6.0.into(),
            },
            shadow: Shadow::default(),
        }
    }
}

pub fn input_style(theme: &Theme, status: text_input::Status) -> text_input::Style {
    let c = colors(theme);
    let border_color = match status {
        text_input::Status::Focused => c.border_strong,
        text_input::Status::Hovered => c.border_strong,
        text_input::Status::Disabled => c.border,
        text_input::Status::Active => c.border,
    };
    text_input::Style {
        background: Background::Color(c.input_bg),
        border: Border {
            color: border_color,
            width: 1.0,
            radius: 6.0.into(),
        },
        icon: c.muted,
        placeholder: c.muted,
        value: c.text,
        selection: c.accent_dim,
    }
}

pub fn panel_style(theme: &Theme) -> container::Style {
    let c = colors(theme);
    container::Style {
        background: Some(Background::Color(c.panel)),
        border: Border {
            color: c.border,
            width: 1.0,
            radius: 10.0.into(),
        },
        text_color: Some(c.text),
        shadow: Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, if matches!(theme, Theme::Dark) { 0.35 } else { 0.08 }),
            offset: Vector::new(0.0, 1.0),
            blur_radius: 4.0,
        },
    }
}

pub fn card_style(theme: &Theme) -> container::Style {
    let c = colors(theme);
    container::Style {
        background: Some(Background::Color(c.surface)),
        border: Border {
            color: c.border,
            width: 1.0,
            radius: 8.0.into(),
        },
        text_color: Some(c.text),
        shadow: Shadow::default(),
    }
}

pub fn metric_style(theme: &Theme) -> container::Style {
    let c = colors(theme);
    container::Style {
        background: Some(Background::Color(c.surface_raised)),
        border: Border {
            color: c.border,
            width: 1.0,
            radius: 8.0.into(),
        },
        text_color: Some(c.text),
        shadow: Shadow::default(),
    }
}

pub fn badge_style(color: Color) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(Background::Color(Color { a: 0.12, ..color })),
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
    move |theme| {
        let c = colors(theme);
        container::Style {
            background: Some(Background::Color(if outgoing {
                c.bubble_out
            } else {
                c.bubble_in
            })),
            border: Border {
                color: c.border,
                width: 1.0,
                radius: 10.0.into(),
            },
            text_color: Some(c.text),
            shadow: Shadow::default(),
        }
    }
}

pub fn root_style(theme: &Theme) -> container::Style {
    let c = colors(theme);
    container::Style {
        background: Some(Background::Color(c.bg)),
        text_color: Some(c.text),
        ..Default::default()
    }
}

pub fn progress_style(theme: &Theme) -> progress_bar::Style {
    let c = colors(theme);
    progress_bar::Style {
        background: Background::Color(c.surface),
        bar: Background::Color(c.accent),
        border: Border {
            color: c.border,
            width: 1.0,
            radius: 4.0.into(),
        },
    }
}

pub fn status_color(c: &Colors, status: &str) -> Color {
    match status.to_ascii_lowercase().as_str() {
        "done" | "complete" | "completed" | "accepted" | "ok" | "online" | "connected" => c.ok,
        "failed" | "error" | "declined" | "rejected" | "offline" => c.danger,
        "in_flight" | "running" | "active" | "pending" | "queued" => c.warn,
        _ => c.muted,
    }
}

pub fn tab_bar_style(theme: &Theme) -> container::Style {
    let c = colors(theme);
    container::Style {
        background: Some(Background::Color(c.surface)),
        border: Border {
            color: c.border,
            width: 1.0,
            radius: 8.0.into(),
        },
        ..Default::default()
    }
}
