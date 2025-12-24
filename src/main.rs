// Hide console window on Windows
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use iced::{
    widget::{button, column, container, pick_list, row, text, text_input, Space, svg, scrollable},
    Alignment, Element, Length, Subscription, Task, Theme, Background, Color,
};
use std::path::PathBuf;

mod hash_logic;
mod style;
mod icons; 

use hash_logic::{compute_hash, Algorithm};

pub fn main() -> iced::Result {
    iced::application("Hash Tools", HashApp::update, HashApp::view)
        .subscription(HashApp::subscription)
        .theme(|_| Theme::Dark)
        .window(iced::window::Settings {
            size: iced::Size::new(700.0, 480.0), // Compact default
            min_size: Some(iced::Size::new(500.0, 380.0)),
            ..iced::window::Settings::default()
        })
        .font(style::FONT_BYTES) // Load embedded custom font
        .font(style::CJK_FONT_BYTES) // Load embedded CJK font
        .run()
}



struct HashApp {
    current_file: Option<PathBuf>,
    selected_algorithm: Algorithm,
    hash_result: Option<Result<String, String>>,
    is_computing: bool,
    comparison_input: String,
    hovering_file: bool,
}

impl Default for HashApp {
    fn default() -> Self {
        Self {
            current_file: None,
            selected_algorithm: Algorithm::Sha256,
            hash_result: None,
            is_computing: false,
            comparison_input: String::new(),
            hovering_file: false,
        }
    }
}

#[derive(Debug, Clone)]
enum Message {
    FileSelected(PathBuf),
    AlgorithmChanged(Algorithm),
    HashComputed(Result<String, String>),
    InputChanged(String),
    RequestFilePick,
    FileHovered(bool),
    FileDropped(PathBuf),
    CopyHash,
    None,
}

impl HashApp {
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::RequestFilePick => {
                return Task::perform(async {
                    let file = rfd::AsyncFileDialog::new().pick_file().await;
                    file.map(|f| f.path().to_path_buf())
                }, |f| {
                    if let Some(path) = f {
                        Message::FileSelected(path)
                    } else {
                        Message::None
                    }
                });
            }
            Message::FileSelected(path) => {
                self.current_file = Some(path.clone());
                self.hash_result = None;
                self.is_computing = true;
                self.hovering_file = false;

                let algo = self.selected_algorithm;
                return Task::perform(compute_hash(path, algo), |res| Message::HashComputed(res.map_err(|e| e.to_string())));
            }
            Message::FileDropped(path) => {
                self.current_file = Some(path.clone());
                self.hash_result = None;
                self.is_computing = true;
                self.hovering_file = false;

                let algo = self.selected_algorithm;
                return Task::perform(compute_hash(path, algo), |res| Message::HashComputed(res.map_err(|e| e.to_string())));
            }
            Message::FileHovered(hovered) => {
                self.hovering_file = hovered;
            }
            Message::AlgorithmChanged(algo) => {
                self.selected_algorithm = algo;
                if let Some(path) = &self.current_file {
                    self.is_computing = true;
                    self.hash_result = None;
                    return Task::perform(compute_hash(path.clone(), algo), |res| Message::HashComputed(res.map_err(|e| e.to_string())));
                }
            }
            Message::HashComputed(result) => {
                self.is_computing = false;
                self.hash_result = Some(result);
            }
            Message::InputChanged(input) => {
                self.comparison_input = input;
            }
            Message::CopyHash => {
                if let Some(Ok(hash)) = &self.hash_result {
                    return iced::clipboard::write(hash.clone());
                }
            }
            Message::None => {}
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        // Sidebar / Top Bar
        let title = text("Hash Tools")
            .size(32)
            .color(style::Colors::TEXT_PRIMARY)
            .font(style::FONT); 
        
        let algo_pick = pick_list(
            Algorithm::all(),
            Some(self.selected_algorithm),
            Message::AlgorithmChanged
        )
        .font(style::CJK_FONT)  // Apply CJK font for Chinese in "SM3 (信创)"
        .text_size(14)
        .padding(8)
        .width(Length::Fixed(180.0))
        .style(style::pick_list_style)
        .menu_style(style::pick_list_menu_style);

        let top_bar = row![title, Space::with_width(Length::Fill), algo_pick]
            .align_y(Alignment::Center)
            .padding(20)
            .spacing(20);

        // Main Drop Zone - compact
        let drop_zone_content = if let Some(path) = &self.current_file {
             column![
                // Apply CJK font explicitly for Chinese support
                text(path.file_name().unwrap_or_default().to_string_lossy())
                    .size(16) // Smaller
                    .color(style::Colors::TEXT_PRIMARY)
                    .font(style::CJK_FONT),
                text(path.to_string_lossy())
                    .size(11) // Smaller
                    .color(style::Colors::TEXT_SECONDARY)
                    .font(style::CJK_FONT)
            ]
            .align_x(Alignment::Center)
            .spacing(6)
        } else {
             column![
                text("Drag & Drop File Here").size(18).color(style::Colors::TEXT_SECONDARY).font(style::FONT),
                text("or click to browse").size(12).color(style::Colors::TEXT_SECONDARY).font(style::FONT)
            ]
            .align_x(Alignment::Center)
            .spacing(8)
        };

        let drop_zone = button(
            container(drop_zone_content)
                .width(Length::Fill)
                .height(Length::Fixed(80.0)) // Even more compact
                .align_x(iced::alignment::Horizontal::Center)
                .align_y(iced::alignment::Vertical::Center)
                .style(move |_| style::container_drop_zone(self.hovering_file))
        )
        .on_press(Message::RequestFilePick)
        .style(button::text) 
        .padding(0)
        .width(Length::Fill);

        // Result Area
        let result_section: Element<Message> = if self.is_computing {
             container(text("Computing hash...").size(20).color(style::Colors::ACCENT).font(style::FONT))
                .width(Length::Fill)
                .padding(30)
                .align_x(iced::alignment::Horizontal::Center)
                .into()
        } else if let Some(result) = &self.hash_result {
            match result {
                Ok(hash) => {
                    let is_match = !self.comparison_input.is_empty() 
                        && hash.eq_ignore_ascii_case(self.comparison_input.trim());
                    
                    let match_indicator: Element<Message> = if self.comparison_input.is_empty() {
                        Space::with_height(0).into()
                    } else if is_match {
                        row![
                            svg(svg::Handle::from_memory(icons::CHECK_ICON))
                                .width(Length::Fixed(20.0))
                                .height(Length::Fixed(20.0)),
                            text("MATCH").color(style::Colors::SUCCESS).size(16).font(style::FONT)
                        ]
                        .align_y(Alignment::Center)
                        .spacing(6)
                        .into()
                    } else {
                        row![
                            svg(svg::Handle::from_memory(icons::X_ICON))
                                .width(Length::Fixed(20.0))
                                .height(Length::Fixed(20.0)),
                            text("MISMATCH").color(style::Colors::ERROR).size(16).font(style::FONT)
                        ]
                        .align_y(Alignment::Center)
                        .spacing(6)
                        .into()
                    };

                    let copy_btn = button(
                        svg(svg::Handle::from_memory(icons::COPY_ICON))
                            .width(Length::Fixed(14.0))
                            .height(Length::Fixed(14.0))
                            .style(|_theme, _status| {
                                svg::Style {
                                    color: Some(style::Colors::TEXT_PRIMARY),
                                }
                            })
                    )
                    .on_press(Message::CopyHash)
                    .style(|_theme, status| {
                        button::Style {
                            background: Some(Background::Color(match status {
                                button::Status::Hovered => Color::from_rgba(1.0, 1.0, 1.0, 0.1),
                                _ => Color::TRANSPARENT,
                            })),
                            text_color: style::Colors::TEXT_PRIMARY,
                            border: iced::border::rounded(4.0),
                            ..button::Style::default()
                        }
                    })
                    .padding(4);

                    // Hash in code-block style with copy button inside
                    let hash_block = container(
                        row![
                            container(
                                text(hash)
                                    .size(14)  // Smaller size for long hashes
                                    .color(style::Colors::ACCENT)
                                    .font(style::FONT)
                                    .wrapping(iced::widget::text::Wrapping::Glyph)
                            ).width(Length::FillPortion(9)),  // Hash takes 90%
                            container(copy_btn)
                                .width(Length::FillPortion(1))  // Button takes 10%
                                .align_x(iced::alignment::Horizontal::Right)
                        ]
                        .align_y(Alignment::Center)
                        .spacing(8)
                    )
                    .padding(12)
                    .width(Length::Fill)
                    .style(style::hash_code_block);

                    column![
                        text("Calculated Hash:").color(style::Colors::TEXT_SECONDARY).font(style::FONT).size(14),
                        hash_block,
                        Space::with_height(12),
                        text("Compare with:").color(style::Colors::TEXT_SECONDARY).font(style::FONT).size(14),
                        text_input("Paste hash here...", &self.comparison_input)
                            .on_input(Message::InputChanged)
                            .padding(10)
                            .font(style::FONT)
                            .style(style::text_input_style),
                        Space::with_height(8),
                        match_indicator
                    ]
                    .spacing(8)
                    .into()
                },
                Err(e) => {
                     column![
                        text("Error computing hash:").color(style::Colors::ERROR).font(style::FONT),
                        text(e.to_string()).color(style::Colors::TEXT_SECONDARY).font(style::FONT)
                    ].spacing(10)
                    .into()
                }
            }
        } else {
            Space::with_height(0).into()
        };

        let content = column![
            top_bar,
            container(drop_zone).padding(10), // Reduced padding
            container(result_section).padding(10) 
        ]
        .spacing(10);

        container(scrollable(content))
            .width(Length::Fill)
            .height(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(style::Colors::BACKGROUND_DARK)),
                ..Default::default()
            })
            .into()
    }

    fn subscription(&self) -> Subscription<Message> {
        iced::event::listen_with(|event, status, _id| {
            if let iced::event::Status::Captured = status {
                return None;
            }

            match event {
                iced::Event::Window(iced::window::Event::FileHovered(_)) => {
                    Some(Message::FileHovered(true))
                }
                iced::Event::Window(iced::window::Event::FileDropped(path)) => {
                    Some(Message::FileDropped(path))
                }
                iced::Event::Window(iced::window::Event::FilesHoveredLeft) => {
                    Some(Message::FileHovered(false))
                }
                _ => None,
            }
        })
    }
}
