use iced::{
    border,
    widget::{button, container, pick_list, text_input},
    Background, Color, Shadow, Theme, Vector,
};

pub struct Colors;

impl Colors {
    // Premium Dark / Glass Palette
    pub const BACKGROUND_DARK: Color = Color::from_rgb(0.05, 0.05, 0.08); // Very dark blue-ish grey

    pub const ACCENT: Color = Color::from_rgb(0.35, 0.65, 1.0); // Brighter Blue
    pub const ACCENT_HOVER: Color = Color::from_rgb(0.45, 0.75, 1.0);

    pub const TEXT_PRIMARY: Color = Color::from_rgb(0.98, 0.98, 1.0);
    pub const TEXT_SECONDARY: Color = Color::from_rgb(0.70, 0.70, 0.80);

    pub const SUCCESS: Color = Color::from_rgb(0.3, 0.9, 0.5);
    pub const ERROR: Color = Color::from_rgb(1.0, 0.4, 0.4);

    pub const BORDER: Color = Color::from_rgba(0.4, 0.5, 0.6, 0.2);
}

// Embed the fonts
pub const FONT_BYTES: &[u8] =
    include_bytes!("../GoogleSansCode-v6.001/variable/GoogleSansCode[wght].ttf");
pub const FONT: iced::Font = iced::Font::with_name("Google Sans Code");

// Embed CJK font for Chinese support
pub const CJK_FONT_BYTES: &[u8] = include_bytes!("../assets/NotoSansSC-Regular.ttf");
pub const CJK_FONT: iced::Font = iced::Font::with_name("Noto Sans CJK SC");

// Hash code block style (Markdown-like)
pub fn hash_code_block(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.4))),
        border: border::color(Colors::BORDER).width(1.0).rounded(8.0),
        text_color: Some(Colors::ACCENT),
        ..container::Style::default()
    }
}

pub fn quick_menu_item(theme: &Theme, status: button::Status) -> button::Style {
    let palette = theme.extended_palette();
    let mut style = button::text(theme, status);
    style.text_color = palette.background.base.text;
    style.border = border::rounded(10.0).width(1.0).color(match status {
        button::Status::Hovered => Color::from_rgba(1.0, 1.0, 1.0, 0.24),
        button::Status::Pressed => Color::from_rgba(1.0, 1.0, 1.0, 0.30),
        button::Status::Disabled => Color::from_rgba(1.0, 1.0, 1.0, 0.06),
        _ => Color::from_rgba(1.0, 1.0, 1.0, 0.12),
    });
    style.background = match status {
        button::Status::Hovered => Some(Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.12))),
        button::Status::Pressed => Some(Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.18))),
        button::Status::Disabled => Some(Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.04))),
        _ => Some(Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.06))),
    };
    style.shadow = match status {
        button::Status::Hovered => Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.16),
            offset: Vector::new(0.0, 2.0),
            blur_radius: 7.0,
        },
        button::Status::Pressed => Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.18),
            offset: Vector::new(0.0, 1.0),
            blur_radius: 3.0,
        },
        _ => Shadow::default(),
    };
    style
}

pub fn quick_menu_card(progress: f32) -> impl Fn(&Theme) -> container::Style {
    move |_theme: &Theme| {
        let p = progress.clamp(0.0, 1.0);
        container::Style {
            background: Some(Background::Color(Color::from_rgba(
                0.18,
                0.19,
                0.23,
                0.68 + 0.18 * p,
            ))),
            border: border::rounded(12.0)
                .width(1.0 + 0.35 * p)
                .color(Color::from_rgba(1.0, 1.0, 1.0, 0.14 + 0.18 * p)),
            shadow: Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, 0.28 + 0.16 * p),
                offset: Vector::new(0.0, 7.0 + 3.0 * p),
                blur_radius: 16.0 + 9.0 * p,
            },
            ..Default::default()
        }
    }
}

pub fn container_drop_zone(active: bool) -> container::Style {
    let (border_color, bg_color) = if active {
        (Colors::ACCENT, Color::from_rgba(0.35, 0.65, 1.0, 0.15))
    } else {
        (
            Color::from_rgba(0.5, 0.5, 0.6, 0.3),
            Color::from_rgba(1.0, 1.0, 1.0, 0.02),
        )
    };

    container::Style {
        background: Some(Background::Color(bg_color)),
        border: border::color(border_color).width(2.0).rounded(16.0),
        text_color: Some(Colors::TEXT_SECONDARY),
        ..container::Style::default()
    }
}

pub fn text_input_style(_theme: &Theme, status: text_input::Status) -> text_input::Style {
    let (border_color, bg) = match status {
        text_input::Status::Active | text_input::Status::Focused { .. } => {
            (Colors::ACCENT, Color::from_rgba(1.0, 1.0, 1.0, 0.05))
        }
        text_input::Status::Hovered => {
            (Colors::ACCENT_HOVER, Color::from_rgba(1.0, 1.0, 1.0, 0.08))
        }
        text_input::Status::Disabled => (Colors::BORDER, Color::TRANSPARENT),
    };

    text_input::Style {
        background: Background::Color(bg),
        border: border::color(border_color).width(1.0).rounded(8.0),
        icon: Colors::TEXT_SECONDARY,
        placeholder: Colors::TEXT_SECONDARY,
        value: Colors::TEXT_PRIMARY,
        selection: Color::from_rgba(0.35, 0.65, 1.0, 0.3),
    }
}

pub fn pick_list_style_with_motion(
    _theme: &Theme,
    status: pick_list::Status,
    motion: f32,
) -> pick_list::Style {
    let p = motion.clamp(0.0, 1.0);
    let (bg, border_color, handle_color) = match status {
        pick_list::Status::Active => (
            Color::from_rgba(0.17, 0.18, 0.22, 0.62),
            Color::from_rgba(0.96, 0.98, 1.0, 0.20 + 0.07 * p),
            Color::from_rgba(0.82, 0.87, 0.94, 0.84),
        ),
        pick_list::Status::Hovered => (
            Color::from_rgba(0.20, 0.21, 0.25, 0.70),
            Color::from_rgba(0.84, 0.90, 1.0, 0.34 + 0.16 * p),
            Color::from_rgba(0.88, 0.92, 0.98, 0.92),
        ),
        pick_list::Status::Opened { .. } => (
            Color::from_rgba(0.22, 0.23, 0.27, 0.78),
            Color::from_rgba(0.88, 0.94, 1.0, 0.48 + 0.20 * p),
            Color::from_rgba(0.94, 0.97, 1.0, 0.98),
        ),
    };

    pick_list::Style {
        text_color: Colors::TEXT_PRIMARY,
        placeholder_color: Colors::TEXT_SECONDARY,
        handle_color,
        background: Background::Color(bg),
        border: border::color(border_color).width(1.4).rounded(10.0),
    }
}

pub fn pick_list_menu_style_with_motion(
    _theme: &Theme,
    motion: f32,
) -> iced::widget::overlay::menu::Style {
    let p = motion.clamp(0.0, 1.0);
    iced::widget::overlay::menu::Style {
        text_color: Colors::TEXT_PRIMARY,
        background: Background::Color(Color::from_rgba(0.18, 0.19, 0.23, 0.84 + 0.08 * p)),
        border: border::color(Color::from_rgba(1.0, 1.0, 1.0, 0.18 + 0.14 * p))
            .width(1.0)
            .rounded(11.0),
        shadow: Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.32 + 0.14 * p),
            offset: Vector::new(0.0, 8.0 + 2.0 * p),
            blur_radius: 18.0 + 8.0 * p,
        },
        selected_text_color: Color::from_rgba(0.92, 0.96, 1.0, 1.0),
        selected_background: Background::Color(Color::from_rgba(0.64, 0.72, 0.90, 0.18 + 0.12 * p)),
    }
}
