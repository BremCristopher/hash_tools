use iced::{border, widget::{container, button, text_input, pick_list}, Background, Color, Shadow, Theme, Vector};

pub struct Colors;

impl Colors {
    // Premium Dark / Glass Palette
    pub const BACKGROUND_DARK: Color = Color::from_rgb(0.05, 0.05, 0.08); // Very dark blue-ish grey
    pub const SURFACE_DARK: Color = Color::from_rgba(0.12, 0.12, 0.18, 0.8); // Semi-transparent
    
    pub const ACCENT: Color = Color::from_rgb(0.35, 0.65, 1.0); // Brighter Blue
    pub const ACCENT_HOVER: Color = Color::from_rgb(0.45, 0.75, 1.0);
    
    pub const TEXT_PRIMARY: Color = Color::from_rgb(0.98, 0.98, 1.0);
    pub const TEXT_SECONDARY: Color = Color::from_rgb(0.70, 0.70, 0.80);
    
    pub const SUCCESS: Color = Color::from_rgb(0.3, 0.9, 0.5);
    pub const ERROR: Color = Color::from_rgb(1.0, 0.4, 0.4);
    
    pub const BORDER: Color = Color::from_rgba(0.4, 0.5, 0.6, 0.2);
    pub const BORDER_ACCENT: Color = Color::from_rgba(0.35, 0.65, 1.0, 0.5);
}

// Embed the fonts
pub const FONT_BYTES: &[u8] = include_bytes!("../GoogleSansCode-v6.001/variable/GoogleSansCode[wght].ttf");
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

pub fn container_card(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Colors::SURFACE_DARK)),
        border: border::color(Colors::BORDER).width(1.0).rounded(16.0),
        text_color: Some(Colors::TEXT_PRIMARY),
        shadow: Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.5),
            offset: Vector::new(0.0, 8.0),
            blur_radius: 20.0,
        },
        ..container::Style::default()
    }
}

pub fn container_drop_zone(active: bool) -> container::Style {
    let (border_color, bg_color) = if active {
        (Colors::ACCENT, Color::from_rgba(0.35, 0.65, 1.0, 0.15))
    } else {
        (
            Color::from_rgba(0.5, 0.5, 0.6, 0.3),
            Color::from_rgba(1.0, 1.0, 1.0, 0.02)
        )
    };
    
    container::Style {
        background: Some(Background::Color(bg_color)),
        border: border::color(border_color).width(2.0).rounded(16.0),
        text_color: Some(Colors::TEXT_SECONDARY),
        ..container::Style::default()
    }
}

pub fn button_primary(_theme: &Theme, status: button::Status) -> button::Style {
    let (bg, border_c, sh) = match status {
        button::Status::Active => (Colors::ACCENT, Colors::ACCENT, Shadow::default()),
        button::Status::Hovered => (Colors::ACCENT_HOVER, Colors::ACCENT_HOVER, Shadow {
            color: Color::from_rgba(0.35, 0.65, 1.0, 0.4),
            offset: Vector::new(0.0, 2.0),
            blur_radius: 10.0,
        }),
        button::Status::Pressed => (Colors::ACCENT, Colors::ACCENT, Shadow::default()),
        button::Status::Disabled => (Colors::BORDER, Colors::BORDER, Shadow::default()),
    };
    
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: Colors::BACKGROUND_DARK, // Contrast text on accent button
        border: border::color(border_c).rounded(8.0),
        shadow: sh,
        ..button::Style::default()
    }
}


pub fn text_input_style(_theme: &Theme, status: text_input::Status) -> text_input::Style {
    let (border_color, bg) = match status {
        text_input::Status::Active | text_input::Status::Focused => (Colors::ACCENT, Color::from_rgba(1.0, 1.0, 1.0, 0.05)),
        text_input::Status::Hovered => (Colors::ACCENT_HOVER, Color::from_rgba(1.0, 1.0, 1.0, 0.08)),
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

// Modern pick_list styling with 3D depth
pub fn pick_list_style(_theme: &Theme, status: pick_list::Status) -> pick_list::Style {
    let (bg, border_color, shadow) = match status {
        pick_list::Status::Active => (
            Color::from_rgba(0.12, 0.12, 0.16, 0.95),
            Color::from_rgba(0.5, 0.5, 0.6, 0.4),
            Shadow {
                color: Color::from_rgba(0.0, 0.0, 0.0, 0.4),
                offset: Vector::new(0.0, 2.0),
                blur_radius: 6.0,
            },
        ),
        pick_list::Status::Hovered => (
            Color::from_rgba(0.15, 0.18, 0.22, 0.98),
            Colors::ACCENT,
            Shadow {
                color: Color::from_rgba(0.35, 0.65, 1.0, 0.3),
                offset: Vector::new(0.0, 3.0),
                blur_radius: 10.0,
            },
        ),
        pick_list::Status::Opened => (
            Color::from_rgba(0.14, 0.16, 0.20, 1.0),
            Colors::ACCENT,
            Shadow {
                color: Color::from_rgba(0.35, 0.65, 1.0, 0.25),
                offset: Vector::new(0.0, 4.0),
                blur_radius: 12.0,
            },
        ),
    };

    pick_list::Style {
        text_color: Colors::TEXT_PRIMARY,
        placeholder_color: Colors::TEXT_SECONDARY,
        handle_color: Colors::ACCENT,
        background: Background::Color(bg),
        border: border::color(border_color).width(1.5).rounded(10.0),
    }
}

// Menu styling for pick_list dropdown overlay
pub fn pick_list_menu_style(_theme: &Theme) -> iced::widget::overlay::menu::Style {
    iced::widget::overlay::menu::Style {
        text_color: Colors::TEXT_PRIMARY,
        background: Background::Color(Color::from_rgba(0.08, 0.08, 0.12, 0.98)),
        border: border::color(Colors::ACCENT).width(1.0).rounded(10.0),
        selected_text_color: Colors::ACCENT,
        selected_background: Background::Color(Color::from_rgba(0.35, 0.65, 1.0, 0.2)),
    }
}
