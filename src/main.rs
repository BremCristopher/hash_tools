// Hide console window on Windows
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use iced::{
    time::{Duration, Instant},
    widget::{
        button, column, container, pick_list, row, scrollable, svg, text, text_input, Space, Stack,
    },
    Alignment, Background, Color, Element, Length, Subscription, Task, Theme,
};
use std::path::{Path, PathBuf};

mod hash_logic;
mod icons;
mod pdf_signature;
mod style;

use hash_logic::{compute_hash, Algorithm};
use pdf_signature::{get_all_signature_hashes, SignatureInfo};
use rayon::prelude::*;
use serde::Serialize;
use tera::{Context, Tera};

/// Data structure for template rendering
#[derive(Serialize)]
struct SignatureData {
    index: usize,
    signer_name: String,
    algorithm: String,
    sign_date: String,
    doc_hash: String,
    sig_hash: String,
    md_hash: Option<String>,
    calc_hash: String,
    embed_hash: String,
    is_valid: bool,
    hash_valid: bool,
    signature_verification_supported: bool,
    error: Option<String>,
    oid_diagnostics: Option<OidDiagnosticsData>,
    certificate: Option<CertificateData>,
}

#[derive(Serialize)]
struct OidDiagnosticsData {
    content_type: String,
    digest_algorithms: Vec<String>,
    signature_algorithm: Option<String>,
}

#[derive(Serialize)]
struct CertificateData {
    subject: String,
    issuer: String,
    serial_number: String,
    signature_algorithm: String,
}

/// Format PDF date string from "D:20251209181854+08'00'" to "2025-12-09 18:18:54 (UTC+08:00)"
fn format_pdf_date(pdf_date: &str) -> String {
    // PDF date format: D:YYYYMMDDHHmmss+HH'mm' or D:YYYYMMDDHHmmss-HH'mm' or D:YYYYMMDDHHmmssZ
    let date_str = pdf_date.trim_start_matches("D:");

    if date_str.len() < 14 {
        return pdf_date.to_string(); // Return as-is if format unknown
    }

    // Parse date components
    let year = &date_str[0..4];
    let month = &date_str[4..6];
    let day = &date_str[6..8];
    let hour = &date_str[8..10];
    let minute = &date_str[10..12];
    let second = &date_str[12..14];

    // Parse timezone if present
    let timezone = if date_str.len() > 14 {
        let tz_part = &date_str[14..];
        // Convert +08'00' or -05'30' to (UTC+08:00) format
        if tz_part.starts_with('+') || tz_part.starts_with('-') {
            let sign = &tz_part[0..1];
            let tz_clean = tz_part[1..].replace('\'', ":");
            // Remove trailing colon if present
            let tz_clean = tz_clean.trim_end_matches(':');
            format!(" (UTC{}{})", sign, tz_clean)
        } else if tz_part.starts_with('Z') {
            " (UTC)".to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    format!(
        "{}-{}-{} {}:{}:{}{}",
        year, month, day, hour, minute, second, timezone
    )
}

/// Export diagnostics report for PDF signatures to HTML file
fn export_diagnostics_report(
    pdf_path: &PathBuf,
    signatures: &[(SignatureInfo, String)],
) -> Result<PathBuf, String> {
    let report_path = pdf_path.with_extension("diagnostics.html");

    // Build template inline (embedded for portability)
    let template_str = include_str!("../templates/diagnostics_report.html");
    let mut tera = Tera::default();
    tera.add_raw_template("report.html", template_str)
        .map_err(|e| format!("Failed to parse template: {}", e))?;

    // Build context
    let mut context = Context::new();
    context.insert("file_path", &pdf_path.display().to_string());
    context.insert(
        "generated_at",
        &chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
    );

    // Process each signature
    let mut sig_data_list: Vec<SignatureData> = Vec::new();

    for (i, (sig_info, doc_hash)) in signatures.iter().enumerate() {
        // Get verification result
        let verification = sig_info.verify_signature(pdf_path);

        // Get OID diagnostics
        let oid_diagnostics =
            sig_info
                .extract_signature_diagnostics()
                .ok()
                .map(|d| OidDiagnosticsData {
                    content_type: d.content_type,
                    digest_algorithms: d.digest_algorithms,
                    signature_algorithm: d.signers.first().map(|s| s.signature_algorithm.clone()),
                });

        // Get certificate info
        let certificate = sig_info.extract_signature_diagnostics().ok().and_then(|d| {
            d.certificates.first().map(|c| CertificateData {
                subject: c.subject.clone(),
                issuer: c.issuer.clone(),
                serial_number: c.serial_number.clone(),
                signature_algorithm: c.signature_algorithm.clone(),
            })
        });

        let sig_data = SignatureData {
            index: i + 1,
            signer_name: sig_info.get_display_name(),
            algorithm: format!("{:?}", sig_info.algorithm),
            sign_date: sig_info
                .sign_date
                .as_ref()
                .map(|d| format_pdf_date(d))
                .unwrap_or_else(|| "Unknown".to_string()),
            doc_hash: doc_hash.clone(),
            sig_hash: sig_info.calculate_signature_block_hash(hash_logic::Algorithm::Sm3),
            md_hash: sig_info.extract_message_digest().ok(),
            calc_hash: verification.calculated_hash.clone(),
            embed_hash: verification.embedded_hash.clone(),
            is_valid: verification.is_valid,
            hash_valid: verification.hash_valid,
            signature_verification_supported: verification.signature_verification_supported,
            error: verification.error.clone(),
            oid_diagnostics,
            certificate,
        };

        sig_data_list.push(sig_data);
    }

    context.insert("signatures", &sig_data_list);

    // Calculate and add whole file hash (SHA-256)
    let file_hash = match std::fs::read(pdf_path) {
        Ok(data) => {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(&data);
            format!("{:x}", hash)
        }
        Err(_) => "Unable to calculate".to_string(),
    };
    context.insert("file_hash", &file_hash);

    // Render template
    let html = tera
        .render("report.html", &context)
        .map_err(|e| format!("Failed to render template: {}", e))?;

    // Write to file
    std::fs::write(&report_path, html).map_err(|e| format!("Failed to write report: {}", e))?;

    Ok(report_path)
}

pub fn main() -> iced::Result {
    // Load window icon from embedded PNG
    let icon = load_window_icon();

    iced::application(init, update, view)
        .title(title)
        .subscription(subscription)
        .theme(theme)
        .window(iced::window::Settings {
            size: iced::Size::new(700.0, 480.0), // Compact default
            min_size: Some(iced::Size::new(500.0, 380.0)),
            icon,
            ..iced::window::Settings::default()
        })
        .font(style::FONT_BYTES) // Load embedded custom font
        .font(style::CJK_FONT_BYTES) // Load embedded CJK font
        .run()
}

fn init() -> (HashApp, Task<Message>) {
    (HashApp::default(), Task::none())
}

fn update(state: &mut HashApp, message: Message) -> Task<Message> {
    state.update(message)
}

fn view<'a>(state: &'a HashApp) -> Element<'a, Message> {
    state.view()
}

fn subscription(state: &HashApp) -> Subscription<Message> {
    state.subscription()
}

fn theme(_state: &HashApp) -> Theme {
    Theme::Dark
}

fn title(_state: &HashApp) -> String {
    "Hash Tools".to_string()
}

fn animate_scalar(value: &mut f32, target: f32, dt: f32, speed_up: f32, speed_down: f32) {
    let clamped_target = target.clamp(0.0, 1.0);
    let speed = if clamped_target > *value {
        speed_up
    } else {
        speed_down
    };
    let step = speed * dt;
    if (*value - clamped_target).abs() <= step {
        *value = clamped_target;
    } else if *value < clamped_target {
        *value += step;
    } else {
        *value -= step;
    }
    *value = (*value).clamp(0.0, 1.0);
}

fn ease_out_cubic(t: f32) -> f32 {
    let x = t.clamp(0.0, 1.0);
    1.0 - (1.0 - x).powi(3)
}

/// Load window icon from embedded PNG for runtime display (taskbar, title bar)
fn load_window_icon() -> Option<iced::window::Icon> {
    // Embed the icon PNG at compile time
    let icon_bytes = include_bytes!("../assets/icon.png");

    // Decode PNG to RGBA
    let img = image::load_from_memory(icon_bytes).ok()?;
    let rgba = img.to_rgba8();
    let (width, height) = rgba.dimensions();

    // Create iced icon from RGBA pixels
    iced::window::icon::from_rgba(rgba.into_raw(), width, height).ok()
}

/// Override option for PDF signature hash algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PdfHashOverride {
    #[default]
    Auto,
    ForceSha256,
    ForceSm3,
    ForceSm3WithSm2, // SM3(Z || M) for SM3withSM2 signatures
    ForceSha1,
}

impl PdfHashOverride {
    pub const ALL: [PdfHashOverride; 5] = [
        Self::Auto,
        Self::ForceSha256,
        Self::ForceSm3,
        Self::ForceSm3WithSm2,
        Self::ForceSha1,
    ];
}

impl std::fmt::Display for PdfHashOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "Auto"),
            Self::ForceSha256 => write!(f, "SHA-256"),
            Self::ForceSm3 => write!(f, "SM3"),
            Self::ForceSm3WithSm2 => write!(f, "SM3(Z||M)"),
            Self::ForceSha1 => write!(f, "SHA-1"),
        }
    }
}

#[derive(Debug, Clone)]
struct SignatureDetailRow {
    index: usize,
    signer: String,
    algorithm: String,
    sign_date: String,
    verify_icon: String,
    verify_text: String,
    verify_color: Color,
    doc_hash: String,
    sig_hash: String,
    zm_hash: String,
    md_hash: String,
    oid_text: String,
    oid_is_error: bool,
    cert_text: Option<String>,
    verify_detail_text: String,
    verify_detail_copy_text: String,
    verify_detail_color: Color,
}

fn signature_block_algorithm(
    sig_info: &SignatureInfo,
    override_algo: PdfHashOverride,
) -> Algorithm {
    match override_algo {
        PdfHashOverride::Auto => sig_info.algorithm.hash_algorithm(),
        PdfHashOverride::ForceSha256 => hash_logic::Algorithm::Sha256,
        PdfHashOverride::ForceSm3 => hash_logic::Algorithm::Sm3,
        PdfHashOverride::ForceSm3WithSm2 => hash_logic::Algorithm::Sm3,
        PdfHashOverride::ForceSha1 => hash_logic::Algorithm::Sha1,
    }
}

fn build_signature_details(
    pdf_path: &Path,
    signatures: &[(SignatureInfo, String)],
    override_algo: PdfHashOverride,
) -> Vec<SignatureDetailRow> {
    signatures
        .par_iter()
        .enumerate()
        .map(|(idx, (sig_info, doc_hash))| {
            let signer = sig_info.get_display_name();
            let sign_date = sig_info.sign_date.as_deref().unwrap_or("N/A").to_string();
            let verification = sig_info.verify_signature(pdf_path);
            let (verify_icon, verify_color, verify_text) = if verification.is_valid {
                ("[OK]", Color::from_rgb(0.3, 0.9, 0.3), "Valid")
            } else if verification.hash_valid {
                ("[~]", Color::from_rgb(1.0, 0.8, 0.2), "Hash OK")
            } else {
                ("[X]", Color::from_rgb(0.9, 0.3, 0.3), "Invalid")
            };

            let sig_hash = sig_info
                .calculate_signature_block_hash(signature_block_algorithm(sig_info, override_algo));

            let zm_hash = sig_info
                .calculate_sm3_with_sm2_hash(&sig_info.signature_contents)
                .unwrap_or_else(|e| format!("Error: {}", e));

            let md_hash = sig_info
                .extract_message_digest()
                .unwrap_or_else(|e| format!("Error: {}", e));

            let diag = sig_info.extract_signature_diagnostics();
            let (oid_text, oid_is_error, cert_text) = match diag {
                Ok(diagnostics) => {
                    let mut diag_text = format!(
                        "Alg: {}",
                        diagnostics
                            .signers
                            .first()
                            .map(|s| s.signature_algorithm.as_str())
                            .unwrap_or("?")
                    );
                    if let Some(signer_diag) = diagnostics.signers.first() {
                        diag_text.push_str(&format!(" | Digest: {}", signer_diag.digest_algorithm));
                        if !signer_diag.signed_attributes.is_empty() {
                            let attr_oids: Vec<_> = signer_diag
                                .signed_attributes
                                .iter()
                                .map(|(oid, _)| oid.split(" (").next().unwrap_or(oid))
                                .collect();
                            diag_text.push_str(&format!(" | Attrs: {}", attr_oids.join(", ")));
                        }
                    }

                    let cert = diagnostics.certificates.first().map(|cert| {
                        format!(
                            "Subject: {} | Issuer: {} | Serial: {}...",
                            cert.subject,
                            cert.issuer,
                            &cert.serial_number[..cert.serial_number.len().min(16)]
                        )
                    });
                    (diag_text, false, cert)
                }
                Err(e) => (format!("OID: Error - {}", e), true, None),
            };

            let calc_preview = if verification.calculated_hash.is_empty() {
                "empty".to_string()
            } else if verification.calculated_hash.len() > 16 {
                format!("{}...", &verification.calculated_hash[..16])
            } else {
                verification.calculated_hash.clone()
            };

            let embed_preview = if verification.embedded_hash.is_empty() {
                "empty".to_string()
            } else if verification.embedded_hash.len() > 16 {
                format!("{}...", &verification.embedded_hash[..16])
            } else {
                verification.embedded_hash.clone()
            };

            let verify_error_preview = verification
                .error
                .as_ref()
                .map(|e| format!(" | Err: {}", if e.len() > 50 { &e[..50] } else { e }))
                .unwrap_or_default();

            let verify_detail_text = format!(
                "Hash: {} | Sig: {} | Calc: {} | Embed: {}{}",
                if verification.hash_valid { "OK" } else { "X" },
                if !verification.signature_verification_supported {
                    "N/A"
                } else if verification.signature_valid {
                    "OK"
                } else {
                    "X"
                },
                calc_preview,
                embed_preview,
                verify_error_preview
            );

            let verify_detail_copy_text = format!(
                "Hash: {} | Sig: {} | Calc: {} | Embed: {}{}",
                if verification.hash_valid { "OK" } else { "X" },
                if !verification.signature_verification_supported {
                    "N/A"
                } else if verification.signature_valid {
                    "OK"
                } else {
                    "X"
                },
                verification.calculated_hash,
                verification.embedded_hash,
                verification
                    .error
                    .as_ref()
                    .map(|e| format!(" | Err: {}", e))
                    .unwrap_or_default()
            );

            let verify_detail_color = if verification.is_valid {
                Color::from_rgb(0.3, 0.9, 0.3)
            } else if verification.hash_valid {
                Color::from_rgb(1.0, 0.8, 0.2)
            } else {
                Color::from_rgb(0.9, 0.4, 0.4)
            };

            SignatureDetailRow {
                index: idx + 1,
                signer,
                algorithm: sig_info.algorithm.display_name(),
                sign_date,
                verify_icon: verify_icon.to_string(),
                verify_text: verify_text.to_string(),
                verify_color,
                doc_hash: doc_hash.clone(),
                sig_hash,
                zm_hash,
                md_hash,
                oid_text,
                oid_is_error,
                cert_text,
                verify_detail_text,
                verify_detail_copy_text,
                verify_detail_color,
            }
        })
        .collect()
}

fn extract_pdf_signatures_task(path: PathBuf, algo: Algorithm) -> Task<Message> {
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || {
                get_all_signature_hashes(&path, algo).map_err(|e| e.to_string())
            })
            .await
            .unwrap_or_else(|e| Err(format!("Task join error: {}", e)))
        },
        Message::PdfSignaturesExtracted,
    )
}

fn extract_pdf_signatures_with_override_task(
    path: PathBuf,
    override_algo: PdfHashOverride,
) -> Task<Message> {
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || {
                pdf_signature::get_all_signature_hashes_with_override(&path, override_algo)
                    .map_err(|e| e.to_string())
            })
            .await
            .unwrap_or_else(|e| Err(format!("Task join error: {}", e)))
        },
        Message::PdfSignaturesExtracted,
    )
}

fn build_signature_details_task(
    path: PathBuf,
    signatures: Vec<(SignatureInfo, String)>,
    override_algo: PdfHashOverride,
) -> Task<Message> {
    Task::perform(
        async move {
            tokio::task::spawn_blocking(move || {
                Ok::<Vec<SignatureDetailRow>, String>(build_signature_details(
                    &path,
                    &signatures,
                    override_algo,
                ))
            })
            .await
            .unwrap_or_else(|e| Err(format!("Task join error: {}", e)))
        },
        Message::PdfSignatureDetailsBuilt,
    )
}

#[derive(Debug, Clone)]
struct MotionState {
    menu: f32,
    signature_panel: f32,
    toast: f32,
    phase: f32,
    last_tick: Option<Instant>,
}

impl Default for MotionState {
    fn default() -> Self {
        Self {
            menu: 0.0,
            signature_panel: 0.0,
            toast: 0.0,
            phase: 0.0,
            last_tick: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ToastKind {
    Info,
    Success,
    Error,
}

#[derive(Debug, Clone)]
struct ToastState {
    text: String,
    kind: ToastKind,
    seconds_left: f32,
}

struct HashApp {
    current_file: Option<PathBuf>,
    selected_algorithm: Algorithm,
    hash_result: Option<Result<String, String>>,
    is_computing: bool,
    comparison_input: String,
    hovering_file: bool,
    // PDF signature support
    pdf_signatures: Option<Result<Vec<(SignatureInfo, String)>, String>>,
    pdf_signature_details: Option<Result<Vec<SignatureDetailRow>, String>>,
    show_pdf_signatures: bool,
    show_quick_menu: bool,
    pdf_hash_override: PdfHashOverride,
    pdf_signatures_loading: bool,
    pdf_signature_details_loading: bool,
    toast: Option<ToastState>,
    motion: MotionState,
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
            pdf_signatures: None,
            pdf_signature_details: None,
            show_pdf_signatures: false,
            show_quick_menu: false,
            pdf_hash_override: PdfHashOverride::Auto,
            pdf_signatures_loading: false,
            pdf_signature_details_loading: false,
            toast: None,
            motion: MotionState::default(),
        }
    }
}

#[derive(Debug, Clone)]
enum Message {
    AnimationTick(Instant),
    FileSelected(PathBuf),
    AlgorithmChanged(Algorithm),
    HashComputed(Result<String, String>),
    InputChanged(String),
    RequestFilePick,
    FileHovered(bool),
    FileDropped(PathBuf),
    CopyHash,
    CopyPdfSignatureHash(String),
    ToggleQuickMenu,
    CloseOverlays,
    TogglePdfSignatures,
    PdfSignaturesExtracted(Result<Vec<(SignatureInfo, String)>, String>),
    PdfSignatureDetailsBuilt(Result<Vec<SignatureDetailRow>, String>),
    PdfHashOverrideChanged(PdfHashOverride),
    ExportDiagnostics,
    ExportComplete(Result<PathBuf, String>),
    None,
}

impl HashApp {
    fn show_toast(&mut self, text: impl Into<String>, kind: ToastKind) {
        self.toast = Some(ToastState {
            text: text.into(),
            kind,
            seconds_left: 2.4,
        });
    }
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::AnimationTick(now) => {
                let dt = self
                    .motion
                    .last_tick
                    .map(|previous| (now - previous).as_secs_f32().clamp(1.0 / 240.0, 0.05))
                    .unwrap_or(1.0 / 60.0);
                self.motion.last_tick = Some(now);
                self.motion.phase = (self.motion.phase + dt).fract();

                let menu_target = if self.show_quick_menu { 1.0 } else { 0.0 };
                let sig_panel_target = if self.show_pdf_signatures { 1.0 } else { 0.0 };

                animate_scalar(&mut self.motion.menu, menu_target, dt, 11.0, 9.5);
                animate_scalar(
                    &mut self.motion.signature_panel,
                    sig_panel_target,
                    dt,
                    8.5,
                    10.5,
                );

                if let Some(toast) = &mut self.toast {
                    toast.seconds_left -= dt;
                    if toast.seconds_left <= -0.25 {
                        self.toast = None;
                    }
                }
                let toast_target = self
                    .toast
                    .as_ref()
                    .map(|t| {
                        if t.seconds_left > 0.20 {
                            1.0
                        } else if t.seconds_left > 0.0 {
                            (t.seconds_left / 0.20).max(0.0)
                        } else {
                            0.0
                        }
                    })
                    .unwrap_or(0.0);
                animate_scalar(&mut self.motion.toast, toast_target, dt, 11.0, 9.0);
            }
            Message::RequestFilePick => {
                self.show_quick_menu = false;
                return Task::perform(
                    async {
                        let file = rfd::AsyncFileDialog::new().pick_file().await;
                        file.map(|f| f.path().to_path_buf())
                    },
                    |f| {
                        if let Some(path) = f {
                            Message::FileSelected(path)
                        } else {
                            Message::None
                        }
                    },
                );
            }
            Message::FileSelected(path) => {
                self.current_file = Some(path.clone());
                self.hash_result = None;
                self.is_computing = true;
                self.hovering_file = false;
                self.pdf_signatures = None;
                self.pdf_signature_details = None;
                self.show_pdf_signatures = false;
                self.show_quick_menu = false;
                self.pdf_signature_details_loading = false;

                let algo = self.selected_algorithm;
                let path_for_pdf = path.clone();

                // Start hash computation
                let hash_task = Task::perform(compute_hash(path, algo), |res| {
                    Message::HashComputed(res.map_err(|e| e.to_string()))
                });

                // If PDF, also extract signatures
                if path_for_pdf
                    .extension()
                    .map(|e| e.eq_ignore_ascii_case("pdf"))
                    .unwrap_or(false)
                {
                    self.pdf_signatures_loading = true; // Show loading indicator
                    let pdf_task = extract_pdf_signatures_task(path_for_pdf, algo);
                    return Task::batch([hash_task, pdf_task]);
                }
                self.pdf_signatures_loading = false;
                return hash_task;
            }
            Message::FileDropped(path) => {
                self.current_file = Some(path.clone());
                self.hash_result = None;
                self.is_computing = true;
                self.hovering_file = false;
                self.pdf_signatures = None;
                self.pdf_signature_details = None;
                self.show_pdf_signatures = false;
                self.show_quick_menu = false;
                self.pdf_signature_details_loading = false;

                let algo = self.selected_algorithm;
                let path_for_pdf = path.clone();

                let hash_task = Task::perform(compute_hash(path, algo), |res| {
                    Message::HashComputed(res.map_err(|e| e.to_string()))
                });

                if path_for_pdf
                    .extension()
                    .map(|e| e.eq_ignore_ascii_case("pdf"))
                    .unwrap_or(false)
                {
                    self.pdf_signatures_loading = true; // Show loading indicator
                    let pdf_task = extract_pdf_signatures_task(path_for_pdf, algo);
                    return Task::batch([hash_task, pdf_task]);
                }
                self.pdf_signatures_loading = false;
                return hash_task;
            }
            Message::FileHovered(hovered) => {
                self.hovering_file = hovered;
            }
            Message::AlgorithmChanged(algo) => {
                self.selected_algorithm = algo;
                self.show_quick_menu = false;
                if let Some(path) = &self.current_file {
                    self.is_computing = true;
                    self.hash_result = None;
                    self.pdf_signatures = None;
                    self.pdf_signature_details = None;
                    self.pdf_signature_details_loading = false;

                    let path_clone = path.clone();
                    let path_for_pdf = path.clone();

                    let hash_task = Task::perform(compute_hash(path_clone, algo), |res| {
                        Message::HashComputed(res.map_err(|e| e.to_string()))
                    });

                    if path_for_pdf
                        .extension()
                        .map(|e| e.eq_ignore_ascii_case("pdf"))
                        .unwrap_or(false)
                    {
                        self.pdf_signatures_loading = true;
                        let pdf_task = extract_pdf_signatures_task(path_for_pdf, algo);
                        return Task::batch([hash_task, pdf_task]);
                    }
                    self.pdf_signatures_loading = false;
                    return hash_task;
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
                self.show_quick_menu = false;
                if let Some(Ok(hash)) = &self.hash_result {
                    let hash_to_copy = hash.clone();
                    self.show_toast("Hash copied", ToastKind::Success);
                    return iced::clipboard::write(hash_to_copy);
                }
            }
            Message::CopyPdfSignatureHash(hash) => {
                self.show_quick_menu = false;
                self.show_toast("Value copied", ToastKind::Info);
                return iced::clipboard::write(hash);
            }
            Message::ToggleQuickMenu => {
                self.show_quick_menu = !self.show_quick_menu;
            }
            Message::CloseOverlays => {
                self.show_quick_menu = false;
            }
            Message::TogglePdfSignatures => {
                self.show_quick_menu = false;
                self.show_pdf_signatures = !self.show_pdf_signatures;
                // Start loading if opening and no signatures loaded yet
                if self.show_pdf_signatures && self.pdf_signatures.is_none() {
                    if let Some(path) = &self.current_file {
                        if path
                            .extension()
                            .map(|e| e.eq_ignore_ascii_case("pdf"))
                            .unwrap_or(false)
                        {
                            self.pdf_signatures_loading = true;
                            let path_clone = path.clone();
                            let override_copy = self.pdf_hash_override;
                            return extract_pdf_signatures_with_override_task(
                                path_clone,
                                override_copy,
                            );
                        }
                    }
                }
                // If signatures are already extracted but details cache is missing, compute it now.
                if self.show_pdf_signatures
                    && !self.pdf_signature_details_loading
                    && self.pdf_signature_details.is_none()
                {
                    if let (Some(path), Some(Ok(signatures))) =
                        (&self.current_file, &self.pdf_signatures)
                    {
                        self.pdf_signature_details_loading = true;
                        return build_signature_details_task(
                            path.clone(),
                            signatures.clone(),
                            self.pdf_hash_override,
                        );
                    }
                }
            }
            Message::PdfSignaturesExtracted(result) => {
                self.pdf_signatures_loading = false;
                self.pdf_signature_details = None;
                match result {
                    Ok(signatures) => {
                        let for_state = signatures.clone();
                        self.pdf_signatures = Some(Ok(for_state));
                        if let Some(path) = &self.current_file {
                            if !signatures.is_empty() {
                                self.pdf_signature_details_loading = true;
                                return build_signature_details_task(
                                    path.clone(),
                                    signatures,
                                    self.pdf_hash_override,
                                );
                            }
                        }
                        self.pdf_signature_details_loading = false;
                    }
                    Err(e) => {
                        self.pdf_signatures = Some(Err(e));
                        self.pdf_signature_details_loading = false;
                    }
                }
            }
            Message::PdfSignatureDetailsBuilt(result) => {
                self.pdf_signature_details_loading = false;
                self.pdf_signature_details = Some(result);
            }
            Message::PdfHashOverrideChanged(override_algo) => {
                self.show_quick_menu = false;
                self.pdf_hash_override = override_algo;
                self.pdf_signature_details = None;
                self.pdf_signature_details_loading = false;
                // Recalculate PDF signature hashes with new algorithm
                if let Some(path) = &self.current_file {
                    if path
                        .extension()
                        .map(|e| e.eq_ignore_ascii_case("pdf"))
                        .unwrap_or(false)
                    {
                        self.pdf_signatures_loading = true;
                        let path_clone = path.clone();
                        return extract_pdf_signatures_with_override_task(
                            path_clone,
                            override_algo,
                        );
                    }
                }
            }
            Message::ExportDiagnostics => {
                self.show_quick_menu = false;
                self.show_toast("Exporting diagnostics report...", ToastKind::Info);
                // Export diagnostics report
                if let (Some(path), Some(Ok(sigs))) = (&self.current_file, &self.pdf_signatures) {
                    let path_clone = path.clone();
                    let sigs_clone = sigs.clone();
                    return Task::perform(
                        async move { export_diagnostics_report(&path_clone, &sigs_clone) },
                        Message::ExportComplete,
                    );
                }
            }
            Message::ExportComplete(result) => {
                match result {
                    Ok(path) => {
                        self.show_toast(
                            format!(
                                "Report exported: {}",
                                path.file_name().unwrap_or_default().to_string_lossy()
                            ),
                            ToastKind::Success,
                        );
                        // Open file location or show message
                        let _ = std::process::Command::new("open")
                            .arg("-R")
                            .arg(&path)
                            .spawn();
                    }
                    Err(e) => {
                        self.show_toast(format!("Export failed: {}", e), ToastKind::Error);
                    }
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
        let ambient_motion = (self.motion.phase * std::f32::consts::TAU).sin() * 0.5 + 0.5;
        let menu_progress = ease_out_cubic(self.motion.menu);
        let signature_reveal = ease_out_cubic(self.motion.signature_panel);
        let menu_pulse = ambient_motion * menu_progress;
        let pick_list_motion = (0.26 + 0.30 * ambient_motion).clamp(0.0, 1.0);

        let algo_pick = pick_list(
            Algorithm::all(),
            Some(self.selected_algorithm),
            Message::AlgorithmChanged,
        )
        .font(style::CJK_FONT) // Apply CJK font for Chinese in "SM3 (信创)"
        .text_size(14)
        .padding([7, 10])
        .width(Length::Fixed(188.0))
        .style(move |theme, status| {
            style::pick_list_style_with_motion(theme, status, pick_list_motion)
        })
        .menu_style(move |theme| style::pick_list_menu_style_with_motion(theme, pick_list_motion));
        let quick_menu_button = button(
            svg(svg::Handle::from_memory(icons::MENU_ICON))
                .width(Length::Fixed(16.0))
                .height(Length::Fixed(16.0))
                .style(|_theme, _status| svg::Style {
                    color: Some(style::Colors::TEXT_PRIMARY),
                }),
        )
        .width(Length::Fixed(42.0))
        .on_press(Message::ToggleQuickMenu)
        .style(move |_theme, status| button::Style {
            background: Some(Background::Color(match status {
                button::Status::Hovered => {
                    Color::from_rgba(1.0, 1.0, 1.0, 0.11 + 0.05 * menu_pulse)
                }
                button::Status::Pressed => Color::from_rgba(1.0, 1.0, 1.0, 0.16),
                button::Status::Disabled => Color::from_rgba(1.0, 1.0, 1.0, 0.04),
                _ => Color::from_rgba(1.0, 1.0, 1.0, 0.06),
            })),
            text_color: style::Colors::TEXT_PRIMARY,
            border: iced::border::rounded(10.0)
                .width(1.0)
                .color(Color::from_rgba(1.0, 1.0, 1.0, 0.16 + 0.16 * menu_progress)),
            ..button::Style::default()
        })
        .padding([7, 9]);

        let top_bar = row![
            title,
            Space::new().width(Length::Fill),
            algo_pick,
            quick_menu_button
        ]
        .align_y(Alignment::Center)
        .padding(20)
        .spacing(12);

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
                text("Drag & Drop File Here")
                    .size(18)
                    .color(style::Colors::TEXT_SECONDARY)
                    .font(style::FONT),
                text("or click to browse")
                    .size(12)
                    .color(style::Colors::TEXT_SECONDARY)
                    .font(style::FONT)
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
                .style(move |_| style::container_drop_zone(self.hovering_file)),
        )
        .on_press(Message::RequestFilePick)
        .style(button::text)
        .padding(0)
        .width(Length::Fill);

        // Result Area
        let result_section: Element<Message> = if self.is_computing {
            container(
                text("Computing hash...")
                    .size(20)
                    .color(style::Colors::ACCENT)
                    .font(style::FONT),
            )
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
                        Space::new().height(0).into()
                    } else if is_match {
                        row![
                            svg(svg::Handle::from_memory(icons::CHECK_ICON))
                                .width(Length::Fixed(20.0))
                                .height(Length::Fixed(20.0)),
                            text("MATCH")
                                .color(style::Colors::SUCCESS)
                                .size(16)
                                .font(style::FONT)
                        ]
                        .align_y(Alignment::Center)
                        .spacing(6)
                        .into()
                    } else {
                        row![
                            svg(svg::Handle::from_memory(icons::X_ICON))
                                .width(Length::Fixed(20.0))
                                .height(Length::Fixed(20.0)),
                            text("MISMATCH")
                                .color(style::Colors::ERROR)
                                .size(16)
                                .font(style::FONT)
                        ]
                        .align_y(Alignment::Center)
                        .spacing(6)
                        .into()
                    };

                    let copy_btn = button(
                        svg(svg::Handle::from_memory(icons::COPY_ICON))
                            .width(Length::Fixed(14.0))
                            .height(Length::Fixed(14.0))
                            .style(|_theme, _status| svg::Style {
                                color: Some(style::Colors::TEXT_PRIMARY),
                            }),
                    )
                    .on_press(Message::CopyHash)
                    .style(|_theme, status| button::Style {
                        background: Some(Background::Color(match status {
                            button::Status::Hovered => Color::from_rgba(1.0, 1.0, 1.0, 0.1),
                            _ => Color::TRANSPARENT,
                        })),
                        text_color: style::Colors::TEXT_PRIMARY,
                        border: iced::border::rounded(4.0),
                        ..button::Style::default()
                    })
                    .padding(4);

                    // Hash in code-block style with copy button inside
                    let hash_block = container(
                        row![
                            container(
                                text(hash)
                                    .size(14) // Smaller size for long hashes
                                    .color(style::Colors::ACCENT)
                                    .font(style::FONT)
                                    .wrapping(iced::widget::text::Wrapping::Glyph)
                            )
                            .width(Length::FillPortion(9)), // Hash takes 90%
                            container(copy_btn)
                                .width(Length::FillPortion(1)) // Button takes 10%
                                .align_x(iced::alignment::Horizontal::Right)
                        ]
                        .align_y(Alignment::Center)
                        .spacing(8),
                    )
                    .padding(12)
                    .width(Length::Fill)
                    .style(style::hash_code_block);

                    column![
                        text("Calculated Hash:")
                            .color(style::Colors::TEXT_SECONDARY)
                            .font(style::FONT)
                            .size(14),
                        hash_block,
                        Space::new().height(12),
                        text("Compare with:")
                            .color(style::Colors::TEXT_SECONDARY)
                            .font(style::FONT)
                            .size(14),
                        text_input("Paste hash here...", &self.comparison_input)
                            .on_input(Message::InputChanged)
                            .padding(10)
                            .font(style::FONT)
                            .style(style::text_input_style),
                        Space::new().height(8),
                        match_indicator
                    ]
                    .spacing(8)
                    .into()
                }
                Err(e) => column![
                    text("Error computing hash:")
                        .color(style::Colors::ERROR)
                        .font(style::FONT),
                    text(e.to_string())
                        .color(style::Colors::TEXT_SECONDARY)
                        .font(style::FONT)
                ]
                .spacing(10)
                .into(),
            }
        } else {
            Space::new().height(0).into()
        };

        // PDF Signature Section (only for PDFs with signatures or loading)
        let pdf_sig_section: Element<Message> = if self.pdf_signatures_loading {
            // Show loading indicator with expandable section style
            container(column![row![
                text("⏳ PDF Signatures")
                    .size(13)
                    .color(style::Colors::ACCENT)
                    .font(style::FONT),
                Space::new().width(8),
                text("正在分析签名...")
                    .size(11)
                    .color(style::Colors::TEXT_SECONDARY)
                    .font(style::CJK_FONT),
            ]
            .align_y(Alignment::Center)])
            .padding(8)
            .into()
        } else if let Some(ref sig_result) = self.pdf_signatures {
            match sig_result {
                Ok(signatures) if !signatures.is_empty() => {
                    let toggle_text = if self.show_pdf_signatures {
                        format!("▼ PDF Signatures ({})", signatures.len())
                    } else {
                        format!("▶ PDF Signatures ({})", signatures.len())
                    };

                    let toggle_btn = button(
                        text(toggle_text)
                            .size(13)
                            .color(style::Colors::ACCENT)
                            .font(style::FONT),
                    )
                    .on_press(Message::TogglePdfSignatures)
                    .style(button::text)
                    .padding(4);

                    // Algorithm override picker
                    let algo_picker = pick_list(
                        PdfHashOverride::ALL.as_slice(),
                        Some(self.pdf_hash_override),
                        Message::PdfHashOverrideChanged,
                    )
                    .font(style::CJK_FONT)
                    .text_size(11)
                    .padding(4)
                    .width(Length::Fixed(90.0))
                    .style(move |theme, status| {
                        let picker_motion = (0.20 + 0.55 * signature_reveal).clamp(0.0, 1.0);
                        style::pick_list_style_with_motion(theme, status, picker_motion)
                    })
                    .menu_style(move |theme| {
                        let picker_motion = (0.20 + 0.55 * signature_reveal).clamp(0.0, 1.0);
                        style::pick_list_menu_style_with_motion(theme, picker_motion)
                    });

                    let header_row = row![
                        toggle_btn,
                        Space::new().width(Length::Fill),
                        button(
                            text("Export")
                                .size(10)
                                .color(Color::from_rgb(0.5, 0.8, 0.5))
                        )
                        .on_press(Message::ExportDiagnostics)
                        .style(button::text)
                        .padding(4),
                        text("Hash:")
                            .size(11)
                            .color(style::Colors::TEXT_SECONDARY)
                            .font(style::FONT),
                        algo_picker
                    ]
                    .align_y(Alignment::Center)
                    .spacing(6);

                    let sig_content: Element<Message> = if self.show_pdf_signatures
                        || self.motion.signature_panel > 0.02
                    {
                        if self.pdf_signature_details_loading {
                            container(
                                text("正在准备签名详情...")
                                    .size(11)
                                    .color(style::Colors::TEXT_SECONDARY)
                                    .font(style::CJK_FONT),
                            )
                            .padding(6)
                            .into()
                        } else if let Some(detail_result) = &self.pdf_signature_details {
                            match detail_result {
                                Ok(detail_rows) => {
                                    let mut sig_rows: Vec<Element<Message>> = Vec::new();

                                    for sig in detail_rows {
                                        let doc_copy_btn = button(
                                            svg(svg::Handle::from_memory(icons::COPY_ICON))
                                                .width(Length::Fixed(10.0))
                                                .height(Length::Fixed(10.0))
                                                .style(|_theme, _status| svg::Style {
                                                    color: Some(style::Colors::TEXT_SECONDARY),
                                                }),
                                        )
                                        .on_press(Message::CopyPdfSignatureHash(
                                            sig.doc_hash.clone(),
                                        ))
                                        .style(button::text)
                                        .padding(2);

                                        let sig_copy_btn = button(
                                            svg(svg::Handle::from_memory(icons::COPY_ICON))
                                                .width(Length::Fixed(10.0))
                                                .height(Length::Fixed(10.0))
                                                .style(|_theme, _status| svg::Style {
                                                    color: Some(style::Colors::ACCENT),
                                                }),
                                        )
                                        .on_press(Message::CopyPdfSignatureHash(
                                            sig.sig_hash.clone(),
                                        ))
                                        .style(button::text)
                                        .padding(2);

                                        let zm_copy_btn = button(
                                            svg(svg::Handle::from_memory(icons::COPY_ICON))
                                                .width(Length::Fixed(10.0))
                                                .height(Length::Fixed(10.0))
                                                .style(|_theme, _status| svg::Style {
                                                    color: Some(Color::from_rgb(0.4, 0.9, 0.4)),
                                                }),
                                        )
                                        .on_press(Message::CopyPdfSignatureHash(
                                            sig.zm_hash.clone(),
                                        ))
                                        .style(button::text)
                                        .padding(2);

                                        let md_copy_btn = button(
                                            svg(svg::Handle::from_memory(icons::COPY_ICON))
                                                .width(Length::Fixed(10.0))
                                                .height(Length::Fixed(10.0))
                                                .style(|_theme, _status| svg::Style {
                                                    color: Some(Color::from_rgb(1.0, 0.9, 0.3)),
                                                }),
                                        )
                                        .on_press(Message::CopyPdfSignatureHash(
                                            sig.md_hash.clone(),
                                        ))
                                        .style(button::text)
                                        .padding(2);

                                        let verify_copy_btn = button(
                                            svg(svg::Handle::from_memory(icons::COPY_ICON))
                                                .width(Length::Fixed(10.0))
                                                .height(Length::Fixed(10.0))
                                                .style({
                                                    let color = sig.verify_detail_color;
                                                    move |_theme, _status| svg::Style {
                                                        color: Some(color),
                                                    }
                                                }),
                                        )
                                        .on_press(Message::CopyPdfSignatureHash(
                                            sig.verify_detail_copy_text.clone(),
                                        ))
                                        .style(button::text)
                                        .padding(2);

                                        let mut details_lines: Vec<Element<Message>> = vec![
                                            row![
                                                text(format!("{} ", sig.verify_icon))
                                                    .size(12)
                                                    .color(sig.verify_color)
                                                    .font(style::FONT),
                                                text(format!("#{} ", sig.index))
                                                    .size(11)
                                                    .color(style::Colors::ACCENT)
                                                    .font(style::FONT),
                                                text(sig.signer.clone())
                                                    .size(11)
                                                    .color(style::Colors::TEXT_PRIMARY)
                                                    .font(style::CJK_FONT),
                                                text(format!(" [{}]", sig.algorithm))
                                                    .size(11)
                                                    .color(style::Colors::ACCENT)
                                                    .font(style::FONT),
                                                text(format!(" {}", sig.verify_text))
                                                    .size(11)
                                                    .color(sig.verify_color)
                                                    .font(style::FONT),
                                                Space::new().width(Length::Fill),
                                                text(sig.sign_date.clone())
                                                    .size(10)
                                                    .color(style::Colors::TEXT_SECONDARY)
                                                    .font(style::FONT),
                                            ]
                                            .align_y(Alignment::Center)
                                            .spacing(4)
                                            .into(),
                                            row![
                                                text("Doc: ")
                                                    .size(11)
                                                    .color(style::Colors::TEXT_SECONDARY)
                                                    .font(style::FONT),
                                                text(sig.doc_hash.clone())
                                                    .size(11)
                                                    .color(style::Colors::TEXT_SECONDARY)
                                                    .font(style::FONT)
                                                    .wrapping(iced::widget::text::Wrapping::Glyph),
                                                doc_copy_btn,
                                            ]
                                            .align_y(Alignment::Center)
                                            .spacing(4)
                                            .into(),
                                            row![
                                                text("Sig: ")
                                                    .size(11)
                                                    .color(style::Colors::ACCENT)
                                                    .font(style::FONT),
                                                text(sig.sig_hash.clone())
                                                    .size(11)
                                                    .color(style::Colors::ACCENT)
                                                    .font(style::FONT)
                                                    .wrapping(iced::widget::text::Wrapping::Glyph),
                                                sig_copy_btn,
                                            ]
                                            .align_y(Alignment::Center)
                                            .spacing(4)
                                            .into(),
                                            row![
                                                text("ZM: ")
                                                    .size(11)
                                                    .color(Color::from_rgb(0.4, 0.9, 0.4))
                                                    .font(style::FONT),
                                                text(sig.zm_hash.clone())
                                                    .size(11)
                                                    .color(Color::from_rgb(0.4, 0.9, 0.4))
                                                    .font(style::FONT)
                                                    .wrapping(iced::widget::text::Wrapping::Glyph),
                                                zm_copy_btn,
                                            ]
                                            .align_y(Alignment::Center)
                                            .spacing(4)
                                            .into(),
                                            row![
                                                text("MD: ")
                                                    .size(11)
                                                    .color(Color::from_rgb(1.0, 0.9, 0.3))
                                                    .font(style::FONT),
                                                text(sig.md_hash.clone())
                                                    .size(11)
                                                    .color(Color::from_rgb(1.0, 0.9, 0.3))
                                                    .font(style::FONT)
                                                    .wrapping(iced::widget::text::Wrapping::Glyph),
                                                md_copy_btn,
                                            ]
                                            .align_y(Alignment::Center)
                                            .spacing(4)
                                            .into(),
                                            row![
                                                text("OID: ")
                                                    .size(10)
                                                    .color(if sig.oid_is_error {
                                                        Color::from_rgb(0.8, 0.4, 0.4)
                                                    } else {
                                                        Color::from_rgb(0.6, 0.6, 0.8)
                                                    })
                                                    .font(style::FONT),
                                                text(sig.oid_text.clone())
                                                    .size(10)
                                                    .color(if sig.oid_is_error {
                                                        Color::from_rgb(0.8, 0.4, 0.4)
                                                    } else {
                                                        Color::from_rgb(0.6, 0.6, 0.8)
                                                    })
                                                    .font(style::FONT)
                                                    .wrapping(iced::widget::text::Wrapping::Glyph),
                                            ]
                                            .align_y(Alignment::Center)
                                            .spacing(4)
                                            .into(),
                                        ];

                                        if let Some(cert_text) = &sig.cert_text {
                                            let cert_color = Color::from_rgb(0.6, 0.8, 0.6);
                                            let cert_copy_btn = button(
                                                svg(svg::Handle::from_memory(icons::COPY_ICON))
                                                    .width(Length::Fixed(10.0))
                                                    .height(Length::Fixed(10.0))
                                                    .style(|_theme, _status| svg::Style {
                                                        color: Some(Color::from_rgb(0.6, 0.8, 0.6)),
                                                    }),
                                            )
                                            .on_press(Message::CopyPdfSignatureHash(
                                                cert_text.clone(),
                                            ))
                                            .style(button::text)
                                            .padding(2);

                                            details_lines.push(
                                                row![
                                                    text("Cert: ")
                                                        .size(10)
                                                        .color(cert_color)
                                                        .font(style::CJK_FONT),
                                                    text(cert_text.clone())
                                                        .size(10)
                                                        .color(cert_color)
                                                        .font(style::CJK_FONT)
                                                        .wrapping(
                                                            iced::widget::text::Wrapping::Glyph
                                                        ),
                                                    cert_copy_btn,
                                                ]
                                                .align_y(Alignment::Center)
                                                .spacing(4)
                                                .into(),
                                            );
                                        }

                                        details_lines.push(
                                            row![
                                                text("Verify: ")
                                                    .size(10)
                                                    .color(sig.verify_detail_color)
                                                    .font(style::FONT),
                                                text(sig.verify_detail_text.clone())
                                                    .size(10)
                                                    .color(sig.verify_detail_color)
                                                    .font(style::FONT)
                                                    .wrapping(iced::widget::text::Wrapping::Glyph),
                                                verify_copy_btn,
                                            ]
                                            .align_y(Alignment::Center)
                                            .spacing(4)
                                            .into(),
                                        );

                                        let sig_row = container(column(details_lines).spacing(2))
                                            .padding(6)
                                            .style(|_| container::Style {
                                                background: Some(Background::Color(
                                                    Color::from_rgba(0.0, 0.0, 0.0, 0.2),
                                                )),
                                                border: iced::border::rounded(4.0),
                                                ..Default::default()
                                            });
                                        sig_rows.push(sig_row.into());
                                    }

                                    column(sig_rows).spacing(4).into()
                                }
                                Err(e) => text(format!("Signature details error: {}", e))
                                    .size(10)
                                    .color(style::Colors::TEXT_SECONDARY)
                                    .font(style::FONT)
                                    .into(),
                            }
                        } else {
                            Space::new().height(0).into()
                        }
                    } else {
                        Space::new().height(0).into()
                    };

                    let sig_content_animated = container(
                        column![
                            Space::new().height((1.0 - signature_reveal) * 8.0),
                            sig_content
                        ]
                        .spacing(0),
                    )
                    .padding(4)
                    .style(move |_| container::Style {
                        background: Some(Background::Color(Color::from_rgba(
                            0.09,
                            0.11,
                            0.17,
                            0.18 * signature_reveal,
                        ))),
                        border: iced::border::rounded(8.0)
                            .width(1.0)
                            .color(Color::from_rgba(0.35, 0.65, 1.0, 0.28 * signature_reveal)),
                        ..Default::default()
                    });

                    column![header_row, sig_content_animated].spacing(4).into()
                }
                Ok(_) => Space::new().height(0).into(), // No signatures
                Err(e) => {
                    // Only show error if it's not "no signatures"
                    if e.contains("No signatures") {
                        Space::new().height(0).into()
                    } else {
                        text(format!("PDF Error: {}", e))
                            .size(10)
                            .color(style::Colors::TEXT_SECONDARY)
                            .font(style::FONT)
                            .into()
                    }
                }
            }
        } else {
            Space::new().height(0).into()
        };

        let content = column![
            top_bar,
            container(drop_zone).padding(10),
            container(result_section).padding(10),
            container(pdf_sig_section).padding(iced::Padding::from([0, 10]))
        ]
        .spacing(10);
        let base_layer = container(scrollable(content))
            .width(Length::Fill)
            .height(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(style::Colors::BACKGROUND_DARK)),
                ..Default::default()
            });

        let mut stack = Stack::new().push(base_layer);

        if self.show_quick_menu || self.motion.menu > 0.01 {
            let scrim_alpha = 0.10 + 0.15 * menu_progress;
            let scrim_layer = button(Space::new().width(Length::Fill).height(Length::Fill))
                .on_press_maybe(self.show_quick_menu.then_some(Message::CloseOverlays))
                .style(move |_theme, _status| button::Style {
                    background: Some(Background::Color(Color::from_rgba(
                        0.03,
                        0.05,
                        0.10,
                        scrim_alpha,
                    ))),
                    ..button::Style::default()
                });
            stack = stack.push(scrim_layer);

            let menu_curve = ease_out_cubic(self.motion.menu);
            let menu_slide = (1.0 - menu_curve) * 10.0;
            let menu_scale_inset = (1.0 - menu_curve) * 1.2;
            let menu_float = (1.0 - menu_curve) * 1.8 + (ambient_motion - 0.5) * 1.2 * menu_curve;

            let has_hash = matches!(self.hash_result, Some(Ok(_)));
            let can_export =
                matches!(&self.pdf_signatures, Some(Ok(signatures)) if !signatures.is_empty());

            let mut copy_hash_btn = button(
                container(
                    text("📋 Copy Current Hash")
                        .size(12)
                        .color(style::Colors::TEXT_PRIMARY)
                        .font(style::FONT),
                )
                .width(Length::Fill)
                .align_x(iced::alignment::Horizontal::Left),
            )
            .width(Length::Fill)
            .style(style::quick_menu_item)
            .padding([6, 8]);
            if has_hash {
                copy_hash_btn = copy_hash_btn.on_press(Message::CopyHash);
            }

            let mut export_btn = button(
                container(
                    text("🧾 Export Diagnostics")
                        .size(12)
                        .color(style::Colors::TEXT_PRIMARY)
                        .font(style::FONT),
                )
                .width(Length::Fill)
                .align_x(iced::alignment::Horizontal::Left),
            )
            .width(Length::Fill)
            .style(style::quick_menu_item)
            .padding([6, 8]);
            if can_export {
                export_btn = export_btn.on_press(Message::ExportDiagnostics);
            }
            let open_file_btn = button(
                container(
                    text("📂 Open File...")
                        .size(12)
                        .color(style::Colors::TEXT_PRIMARY)
                        .font(style::FONT),
                )
                .width(Length::Fill)
                .align_x(iced::alignment::Horizontal::Left),
            )
            .width(Length::Fill)
            .on_press(Message::RequestFilePick)
            .style(style::quick_menu_item)
            .padding([6, 8]);
            let quick_menu_items = column![open_file_btn, copy_hash_btn, export_btn]
                .width(Length::Fill)
                .spacing(2);
            let bottom_divider =
                container(Space::new().width(Length::Fill).height(Length::Fixed(0.55)))
                    .width(Length::Fill)
                    .style(move |_| container::Style {
                        background: Some(Background::Color(Color::from_rgba(
                            1.0,
                            1.0,
                            1.0,
                            0.04 + 0.06 * menu_curve,
                        ))),
                        border: iced::border::rounded(99.0),
                        ..Default::default()
                    });

            let quick_menu = container(column![quick_menu_items, bottom_divider].spacing(3))
                .width(Length::Fixed(188.0 + 6.0 * menu_curve))
                .padding(iced::Padding::from([
                    6.0 + 0.9 * menu_scale_inset,
                    8.0 + 0.7 * menu_scale_inset,
                ]))
                .style(style::quick_menu_card(menu_curve));

            stack = stack.push(
                container(quick_menu)
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .align_x(iced::alignment::Horizontal::Right)
                    .align_y(iced::alignment::Vertical::Top)
                    .padding(iced::Padding::from([
                        63.0 + menu_slide + menu_float,
                        15.0 + (1.0 - menu_curve) * 2.0,
                    ])),
            );
        }

        if self.motion.toast > 0.01 {
            if let Some(toast) = &self.toast {
                let toast_progress = ease_out_cubic(self.motion.toast);
                let (accent, icon) = match toast.kind {
                    ToastKind::Info => (style::Colors::ACCENT, "ℹ"),
                    ToastKind::Success => (style::Colors::SUCCESS, "✓"),
                    ToastKind::Error => (style::Colors::ERROR, "⚠"),
                };
                let toast_offset = 12.0 + (1.0 - toast_progress) * 8.0;

                let toast_card = container(
                    row![
                        text(icon).size(12).color(accent).font(style::FONT),
                        text(toast.text.as_str())
                            .size(12)
                            .color(style::Colors::TEXT_PRIMARY)
                            .font(style::CJK_FONT)
                    ]
                    .align_y(Alignment::Center)
                    .spacing(6),
                )
                .padding([7, 12])
                .style(move |_| container::Style {
                    background: Some(Background::Color(Color::from_rgba(
                        0.08,
                        0.10,
                        0.15,
                        0.88 * toast_progress,
                    ))),
                    border: iced::border::rounded(10.0)
                        .width(1.0)
                        .color(Color::from_rgba(
                            accent.r,
                            accent.g,
                            accent.b,
                            0.72 * toast_progress,
                        )),
                    ..Default::default()
                });

                let toast_layer = container(
                    column![
                        Space::new().height(Length::Fill),
                        row![
                            Space::new().width(Length::Fill),
                            toast_card,
                            Space::new().width(Length::Fill)
                        ],
                        Space::new().height(toast_offset)
                    ]
                    .spacing(0),
                )
                .width(Length::Fill)
                .height(Length::Fill);

                stack = stack.push(toast_layer);
            }
        }

        stack.into()
    }

    fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
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
                    iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                        key,
                        modifiers,
                        ..
                    }) => {
                        if modifiers.command() || modifiers.control() {
                            match key {
                                iced::keyboard::Key::Character(ch)
                                    if ch.eq_ignore_ascii_case("o") =>
                                {
                                    Some(Message::RequestFilePick)
                                }
                                iced::keyboard::Key::Character(ch)
                                    if ch.eq_ignore_ascii_case("c") =>
                                {
                                    Some(Message::CopyHash)
                                }
                                iced::keyboard::Key::Character(ch)
                                    if ch.eq_ignore_ascii_case("e") =>
                                {
                                    Some(Message::ExportDiagnostics)
                                }
                                _ => None,
                            }
                        } else {
                            match key {
                                iced::keyboard::Key::Named(iced::keyboard::key::Named::Escape) => {
                                    Some(Message::CloseOverlays)
                                }
                                _ => None,
                            }
                        }
                    }
                    _ => None,
                }
            }),
            iced::time::every(Duration::from_millis(16)).map(Message::AnimationTick),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_report_marks_unimplemented_verification_and_escapes_fields() {
        let mut tera = Tera::default();
        tera.add_raw_template(
            "report.html",
            include_str!("../templates/diagnostics_report.html"),
        )
        .expect("add diagnostics template");

        let mut context = Context::new();
        context.insert("file_path", "<unsafe.pdf>");
        context.insert("generated_at", "2026-09-05 12:00:00");
        context.insert("file_hash", "file-hash");
        context.insert(
            "signatures",
            &vec![
                SignatureData {
                    index: 1,
                    signer_name: "<script>alert(1)</script>".to_string(),
                    algorithm: "SHA256withRSA".to_string(),
                    sign_date: "Unknown".to_string(),
                    doc_hash: "doc-hash".to_string(),
                    sig_hash: "signature-hash".to_string(),
                    md_hash: Some("embedded-hash".to_string()),
                    calc_hash: "calculated-hash".to_string(),
                    embed_hash: "embedded-hash".to_string(),
                    is_valid: false,
                    hash_valid: true,
                    signature_verification_supported: false,
                    error: Some("Cryptographic verification is unavailable".to_string()),
                    oid_diagnostics: None,
                    certificate: None,
                },
                SignatureData {
                    index: 2,
                    signer_name: "Digest mismatch".to_string(),
                    algorithm: "SHA256withRSA".to_string(),
                    sign_date: "Unknown".to_string(),
                    doc_hash: "doc-hash".to_string(),
                    sig_hash: "signature-hash".to_string(),
                    md_hash: Some("embedded-hash".to_string()),
                    calc_hash: "different-hash".to_string(),
                    embed_hash: "embedded-hash".to_string(),
                    is_valid: false,
                    hash_valid: false,
                    signature_verification_supported: false,
                    error: Some("messageDigest does not match".to_string()),
                    oid_diagnostics: None,
                    certificate: None,
                },
            ],
        );

        let html = tera
            .render("report.html", &context)
            .expect("render diagnostics");

        assert!(html.contains("Hash OK · Signature verification not implemented (N/A)"));
        assert!(html.contains("Digest mismatch · Signature verification not implemented (N/A)"));
        assert!(!html.contains("验证失败"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;&#x2F;script&gt;"));
        assert!(!html.contains("<script>alert(1)</script>"));
    }
}
