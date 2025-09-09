use crate::cli::verify_jwt_hs256_token;
use crate::combination_generator::CombinationGenerator;
use crate::jwt::{decode_jwt, encode_jwt};
use crossbeam_channel::{unbounded, Receiver, Sender, TryRecvError};
use eframe::egui;
use egui::{
    epaint, Align, Checkbox, DragValue, FontData, FontDefinitions, Label, Layout, RichText,
    TextEdit, TextStyle, TopBottomPanel,
};
use egui_extras::syntax_highlighting::{highlight, CodeTheme};
use rayon::iter::{ParallelBridge, ParallelIterator};
use std::sync::Arc;
use std::thread;

/// 主应用窗口结构体，包含所有状态
pub(crate) struct MainWindow {
    status: RunningStatus,
    user_charset: String,
    min_len: usize,
    max_len: usize,
    use_lowercase: bool,
    use_uppercase: bool,
    use_digits: bool,
    use_special: bool,
    use_user_charset: bool,
    pub(crate) jwt_playload: String,
    pub(crate) jwt_header: String,
    pub(crate) jwt_burp_token: String,
    pub(crate) jwt_singed_token: String,
    pub(crate) burped_key: String,
    pub(crate) error_type: ErrorType,
    task_handle: Option<thread::JoinHandle<Option<String>>>,
    tx: Option<Sender<String>>,
    rx: Option<Receiver<String>>,
    stop_tx: Option<Sender<()>>,
}

/// 应用程序运行状态枚举
#[derive(Debug, PartialEq, Eq, Default)]
enum RunningStatus {
    #[default]
    OK,
    Running,
    Error,
    Stopping,
    Stopped,
    Found,
}

/// 错误类型枚举
pub(crate) enum ErrorType {
    None,
    UserCharsetEmpty,
    JwtTokenEmpty,
    JwtTokenFormatError,
    UnknownAlgorithmType,
    InputJSONFormatError,
    SignJWTFailed,
}

impl Default for MainWindow {
    fn default() -> Self {
        Self {
            stop_tx: None,
            status: RunningStatus::default(),
            use_user_charset: false,
            user_charset: "".to_string(),
            min_len: 1,
            max_len: 4,
            use_lowercase: true,
            use_uppercase: true,
            use_digits: true,
            use_special: false,
            jwt_playload: "".to_string(),
            jwt_header: "".to_string(),
            jwt_burp_token: "".to_string(),
            jwt_singed_token: "".to_string(),
            burped_key: "".to_string(),
            error_type: ErrorType::None,
            task_handle: None,
            tx: None,
            rx: None,
        }
    }
}

impl MainWindow {
    fn handle_channels(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.rx {
            loop {
                match rx.try_recv() {
                    Ok(key) => {
                        self.burped_key = key;
                        ctx.request_repaint();
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.rx = None;
                        break;
                    }
                }
            }
        }

        if let Some(handle) = self.task_handle.as_mut() {
            if handle.is_finished() {
                match self.task_handle.take().unwrap().join() {
                    Ok(Some(key)) => {
                        self.burped_key = key;
                        self.status = RunningStatus::Found;
                        encode_jwt(self);
                    }
                    Ok(None) => {
                        if self.status == RunningStatus::Stopping {
                            self.status = RunningStatus::Stopped;
                        } else {
                            self.status = RunningStatus::Error;
                            self.error_type = ErrorType::None;
                        }
                    }
                    Err(_) => {
                        self.status = RunningStatus::Error;
                        self.error_type = ErrorType::None;
                    }
                }
            }
        }
    }

    fn render_central_panel(&mut self, ui: &mut egui::Ui) {
        let ui_width = ui.available_width();

        ui.horizontal(|ui| {
            ui.heading("选择字符集:");
            ui.checkbox(&mut self.use_user_charset, "自定义字符集");
            ui.add(Label::new("爆破长度:从"));
            ui.add(DragValue::new(&mut self.min_len));
            ui.add(Label::new("到"));
            ui.add(DragValue::new(&mut self.max_len));
            if self.min_len > self.max_len {
                self.min_len = self.max_len;
            }
        });

        ui.horizontal(|ui| {
            if self.use_user_charset {
                ui.add(
                    TextEdit::singleline(&mut self.user_charset).hint_text("请输入自定义字符集"),
                );
            } else {
                ui.group(|child_ui| {
                    child_ui
                        .add(Checkbox::new(&mut self.use_digits, "数字"))
                        .on_hover_text("0123456789");
                    child_ui
                        .add(Checkbox::new(&mut self.use_lowercase, "小写字母"))
                        .on_hover_text("abcdefghijklmnopqrstuvwxyz");
                    child_ui
                        .add(Checkbox::new(&mut self.use_uppercase, "大写字母"))
                        .on_hover_text("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
                    child_ui
                        .add(Checkbox::new(&mut self.use_special, "特殊字符"))
                        .on_hover_text("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~");
                });
            }
            ui.group(|chile_ui| {
                chile_ui.add(
                    TextEdit::singleline(&mut self.burped_key)
                        .desired_width(self.max_len as f32 * 10.0),
                )
            })
        });
        ui.separator();

        let mut layouter = |ui: &egui::Ui, buf: &dyn egui::TextBuffer, wrap_width: f32| {
            let mut layout_job = highlight(
                ui.ctx(),
                ui.style(),
                &CodeTheme::from_memory(ui.ctx(), ui.style()),
                buf.as_str(),
                "json".into(),
            );
            layout_job.wrap.max_width = wrap_width;
            ui.fonts(|f| f.layout_job(layout_job))
        };

        if ui
            .add(
                TextEdit::multiline(&mut self.jwt_burp_token)
                    .font(TextStyle::Monospace)
                    .code_editor()
                    .desired_rows(6)
                    .lock_focus(true)
                    .desired_width(ui_width)
                    .layouter(&mut layouter)
                    .hint_text("Please input the JWT token to be burped"),
            )
            .on_hover_text("预想要爆破的JWT字符串")
            .changed()
        {
            decode_jwt(self);
        };

        ui.horizontal(|ui| {
            if ui
                .add(
                    TextEdit::multiline(&mut self.jwt_header)
                        .font(TextStyle::Monospace)
                        .code_editor()
                        .desired_rows(6)
                        .lock_focus(true)
                        .desired_width(ui_width * 0.49)
                        .layouter(&mut layouter),
                )
                .on_hover_text("Head部分")
                .changed()
            {
                if self.status == RunningStatus::Found {
                    encode_jwt(self);
                }
            };

            if ui
                .add(
                    TextEdit::multiline(&mut self.jwt_playload)
                        .font(TextStyle::Monospace)
                        .code_editor()
                        .desired_rows(6)
                        .lock_focus(true)
                        .desired_width(ui_width * 0.49)
                        .layouter(&mut layouter),
                )
                .on_hover_text("Payload部分")
                .changed()
            {
                if self.status == RunningStatus::Found {
                    encode_jwt(self);
                }
            };
        });

        ui.add(
            TextEdit::multiline(&mut self.jwt_singed_token)
                .font(TextStyle::Monospace)
                .code_editor()
                .desired_rows(6)
                .lock_focus(true)
                .desired_width(ui_width)
                .layouter(&mut layouter),
        )
        .on_hover_text("使用爆破出来的密钥的JWT签名结果");
    }

    fn render_bottom_panel(&mut self, ui: &mut egui::Ui) {
        let status_text = match self.status {
            RunningStatus::OK => RichText::new("准备就绪").color(egui::Color32::DARK_GREEN),
            RunningStatus::Running => RichText::new("Burping...").color(egui::Color32::BLACK),
            RunningStatus::Error => {
                let error_message = match self.error_type {
                    ErrorType::None => "未知错误",
                    ErrorType::UserCharsetEmpty => "用户字符集不能为空",
                    ErrorType::JwtTokenEmpty => "预想爆破字段不能为空",
                    ErrorType::JwtTokenFormatError => "JWT格式错误",
                    ErrorType::UnknownAlgorithmType => "未知加密方式",
                    ErrorType::InputJSONFormatError => "Json格式有误",
                    ErrorType::SignJWTFailed => "JWT签名失败",
                };
                RichText::new(error_message).color(egui::Color32::RED)
            }
            RunningStatus::Stopping => RichText::new("正在停止...").color(egui::Color32::YELLOW),
            RunningStatus::Stopped => RichText::new("已经停止").color(egui::Color32::GRAY),
            RunningStatus::Found => RichText::new(format!("密钥已找到: {}", &self.burped_key))
                .color(egui::Color32::BLUE),
        };

        let ctx_clone = ui.ctx().clone();

        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
            if self.status == RunningStatus::Running || self.status == RunningStatus::Stopping {
                ui.add(egui::Spinner::new());
            }

            ui.add(Label::new(status_text));

            ui.with_layout(Layout::right_to_left(Align::RIGHT), |child_ui| {
                child_ui.horizontal(|button_ui| {
                    button_ui.add_enabled_ui(
                        !(self.status == RunningStatus::Running),
                        |start_button_ui| {
                            if start_button_ui.button("开始").clicked() {
                                self.start_bruteforce_task(ctx_clone);
                            }
                        },
                    );

                    if button_ui.button("停止").clicked() {
                        self.stop_bruteforce_task();
                    }

                    button_ui.add_enabled_ui(
                        !(self.status == RunningStatus::Running),
                        |start_button_ui| {
                            if start_button_ui.button("清空").clicked() {
                                self.clear_state();
                            }
                        },
                    );
                });
            });
        });
    }

    fn start_bruteforce_task(&mut self, ctx: egui::Context) {
        if self.jwt_burp_token.is_empty() {
            self.status = RunningStatus::Error;
            self.error_type = ErrorType::JwtTokenEmpty;
            return;
        }
        if self.use_user_charset && self.user_charset.is_empty() {
            self.status = RunningStatus::Error;
            self.error_type = ErrorType::UserCharsetEmpty;
            return;
        }
        if !self.use_user_charset
            && !self.use_digits
            && !self.use_lowercase
            && !self.use_uppercase
            && !self.use_special
        {
            self.status = RunningStatus::Error;
            self.error_type = ErrorType::UserCharsetEmpty;
            return;
        }

        let jwt_token = self.jwt_burp_token.clone();

        let (tx, rx) = unbounded::<String>();
        let (stop_tx, stop_rx) = unbounded::<()>();
        self.tx = Some(tx.clone());
        self.rx = Some(rx);
        self.stop_tx = Some(stop_tx);

        let stop_rx_arc = Arc::new(stop_rx);
        let optional_stop_rx = Some(stop_rx_arc);

        let generator = if self.use_user_charset {
            CombinationGenerator::new_with_charset(
                self.min_len,
                self.max_len,
                &*self.user_charset,
                optional_stop_rx,
            )
        } else {
            CombinationGenerator::new_with_options(
                self.min_len,
                self.max_len,
                self.use_lowercase,
                self.use_uppercase,
                self.use_digits,
                self.use_special,
                optional_stop_rx,
            )
        };

        self.task_handle = Some(thread::spawn(move || {
            let found_key = generator.par_bridge().find_any(|key| {
                let _ = tx.send(key.to_string());

                verify_jwt_hs256_token(jwt_token.as_str(), key).is_some()
            });
            ctx.request_repaint();
            found_key.map(|s| s.to_owned())
        }));
        self.status = RunningStatus::Running;
    }

    fn stop_bruteforce_task(&mut self) {
        if self.status == RunningStatus::Running {
            self.status = RunningStatus::Stopping;

            if let Some(tx) = self.stop_tx.take() {
                let _ = tx.send(());
            }
        }
    }

    fn clear_state(&mut self) {
        self.jwt_header = "".to_string();
        self.jwt_playload = "".to_string();
        self.jwt_burp_token = "".to_string();
        self.jwt_singed_token = "".to_string();
        self.burped_key = "".to_string();
        self.status = RunningStatus::OK;
        self.error_type = ErrorType::None;

        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl eframe::App for MainWindow {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_channels(ctx);

        let is_ui_enabled =
            self.status != RunningStatus::Running && self.status != RunningStatus::Stopping;

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_enabled_ui(is_ui_enabled, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    self.render_central_panel(ui);
                });
            });
        });

        TopBottomPanel::bottom("main").show(ctx, |ui| {
            self.render_bottom_panel(ui);
        });
        if self.status == RunningStatus::Stopping {
            MainWindow::stop_bruteforce_task(self)
        }
    }
}

fn load_fonts() -> FontDefinitions {
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert(
        "kaiti".to_owned(),
        Arc::from(FontData::from_owned(
            include_bytes!("assest/fonts/simkai.ttf").to_vec(),
        )),
    );
    fonts
        .families
        .get_mut(&epaint::text::FontFamily::Proportional)
        .unwrap()
        .push("kaiti".to_owned());
    fonts
}

pub fn show_gui() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 400.0])
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!("assest/icons/icon.png"))
                    .expect("Failed to load icon"),
            ),
        ..Default::default()
    };
    eframe::run_native(
        "JWT Bruteforcer",
        options,
        Box::new(|cc| {
            let fonts = load_fonts();
            cc.egui_ctx.set_fonts(fonts);
            Ok(Box::<MainWindow>::new(MainWindow::default()))
        }),
    )
}
