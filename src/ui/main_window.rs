use crate::ui::widget;
use crate::ui::widget::spinner::Spinner;
use crate::utils::combination_generator::CombinationGenerator;
use crate::utils::jwt::verify_jwt_hs256_token;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crossbeam_channel::{Receiver, Sender, TryRecvError, unbounded};
use eframe::egui;
use egui::{
    Align, CentralPanel, Checkbox, DragValue, Label, Layout, RichText, TextEdit, TopBottomPanel,
};
use egui_extras::syntax_highlighting::{CodeTheme, highlight};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rayon::iter::{ParallelBridge, ParallelIterator};
use serde_json::{Value, from_str};
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
    pub(crate) jwt_decoded_payload: String,
    pub(crate) jwt_decoded_header: String,
    pub(crate) jwt_burp_token: String,
    pub(crate) jwt_singed_token: String,

    pub(crate) burped_key_start: String,
    pub(crate) burped_key: String,
    pub(crate) burped_key_end: String,

    pub(crate) error_type: ErrorType,
    task_handle: Option<thread::JoinHandle<Option<String>>>,
    tx: Option<Sender<String>>,
    rx: Option<Receiver<String>>,
    stop_tx: Option<Sender<()>>,
    show_about_window: bool,
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
#[derive(PartialEq)]
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
            jwt_decoded_payload: "".to_string(),
            jwt_decoded_header: "".to_string(),
            jwt_burp_token: "".to_string(),
            jwt_singed_token: "".to_string(),
            burped_key_start: "".to_string(),
            burped_key: "".to_string(),
            burped_key_end: "".to_string(),
            error_type: ErrorType::None,
            task_handle: None,
            tx: None,
            rx: None,
            show_about_window: false,
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
                        if self.error_type == ErrorType::None {
                            if self.status == RunningStatus::Stopped {
                                self.status = RunningStatus::OK;
                            }
                        };
                        if (self.status == RunningStatus::Stopping) {
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
        ui.horizontal(|ui| {
            ui.heading("选择字符集:");
            ui.checkbox(&mut self.use_user_charset, "自定义字符集");
        });
        ui.horizontal(|ui| {
            if self.use_user_charset {
                ui.group(|child_ui| {
                    child_ui.add(
                        TextEdit::singleline(&mut self.user_charset)
                            .hint_text("请输入自定义字符集"),
                    )
                });
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
        });
        ui.horizontal(|ui| {
            ui.group(|chile_ui| {
                chile_ui.add(Label::new("爆破长度:从"));
                chile_ui.add(DragValue::new(&mut self.min_len));
                chile_ui.add(Label::new("到"));
                chile_ui.add(DragValue::new(&mut self.max_len));
                if self.min_len > self.max_len {
                    self.min_len = self.max_len;
                }
            });
            if (self.status == RunningStatus::OK) | (self.status == RunningStatus::Stopped) {
                ui.group(|chile_ui| {
                    chile_ui
                        .add(
                            TextEdit::singleline(&mut self.burped_key_start)
                                .desired_width(self.max_len as f32 * 10.0),
                        )
                        .on_hover_text("密钥前缀");
                    chile_ui
                        .add(
                            TextEdit::singleline(&mut self.burped_key)
                                .desired_width(self.max_len as f32 * 10.0),
                        )
                        .on_hover_text("准备爆破部分");
                    chile_ui
                        .add(
                            TextEdit::singleline(&mut self.burped_key_end)
                                .desired_width(self.max_len as f32 * 10.0),
                        )
                        .on_hover_text("密钥后缀");
                });
            } else {
                ui.label(
                    RichText::new(format!(
                        "{}{}{}",
                        self.burped_key_start, self.burped_key, self.burped_key_end
                    ))
                    .color(egui::Color32::DARK_BLUE),
                );
            }
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
        ui.group(|jwt_ui| {
            if jwt_ui
                .add(
                    egui::TextEdit::multiline(&mut self.jwt_burp_token)
                        .font(egui::TextStyle::Monospace)
                        .code_editor()
                        .desired_rows(6)
                        .lock_focus(true)
                        .desired_width(jwt_ui.available_width())
                        .layouter(&mut layouter)
                        .hint_text("Please input the JWT token to be burped"),
                )
                .on_hover_text("预想要爆破的JWT字符串")
                .changed()
            {
                decode_jwt(self);
            };

            // 使用 with_columns 方法创建两列，每列平分宽度
            jwt_ui.columns(2, |columns| {
                // 第一列
                columns[0]
                    .add(
                        egui::TextEdit::multiline(&mut self.jwt_decoded_header)
                            .font(egui::TextStyle::Monospace)
                            .code_editor()
                            .desired_rows(6)
                            .lock_focus(true)
                            .desired_width(columns[0].available_width()) // 将宽度设置为列的可用宽度
                            .layouter(&mut layouter),
                    )
                    .on_hover_text("Head部分")
                    .changed();

                // 第二列
                columns[1]
                    .add(
                        egui::TextEdit::multiline(&mut self.jwt_decoded_payload)
                            .font(egui::TextStyle::Monospace)
                            .code_editor()
                            .desired_rows(6)
                            .lock_focus(true)
                            .desired_width(columns[1].available_width()) // 将宽度设置为列的可用宽度
                            .layouter(&mut layouter),
                    )
                    .on_hover_text("Payload部分")
                    .changed();
            });

            jwt_ui
                .add(
                    egui::TextEdit::multiline(&mut self.jwt_singed_token)
                        .font(egui::TextStyle::Monospace)
                        .code_editor()
                        .desired_rows(6)
                        .lock_focus(true)
                        .desired_width(jwt_ui.available_width())
                        .layouter(&mut layouter),
                )
                .on_hover_text("使用爆破出来的密钥的JWT签名结果");
        });
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
            RunningStatus::Found => {
                let mut result = String::new(); // 创建一个可变的新字符串
                result.push_str(&self.burped_key_start); // 追加第一个字符串切片
                result.push_str(&self.burped_key); // 追加第二个字符串切片
                result.push_str(&self.burped_key_end); // 追加第三个字符串切片
                RichText::new(format!("密钥已找到: {}", result)).color(egui::Color32::BLUE)
            }
        };

        let ctx_clone = ui.ctx().clone();

        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
            if self.status == RunningStatus::Running {
                ui.add(Spinner::new().speed(2.0).clockwise(true));
            }
            if self.status == RunningStatus::Stopping {
                ui.add(widget::spinner::Spinner::new().speed(3.0).clockwise(false));
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
        let burped_key_start = self.burped_key_start.clone();
        let burped_key_end = self.burped_key_end.clone();
        self.task_handle = Some(thread::spawn(move || {
            let found_key = generator.par_bridge().find_any(|key| {
                let new_key = format!("{}{}{}", burped_key_start, key, burped_key_end);
                let _ = tx.send(key.to_string());
                verify_jwt_hs256_token(jwt_token.as_str(), new_key.as_str()).is_some()
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
        self.jwt_decoded_header = "".to_string();
        self.jwt_decoded_payload = "".to_string();
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
        TopBottomPanel::top("about").show(ctx, |ui| {
            ui.menu_button("菜单", |menu_ui| {
                if menu_ui.button("关于").clicked() {
                    self.show_about_window = true;
                    menu_ui.close(); // 关闭菜单
                }
                // menu_ui.separator();
            })
        });
        CentralPanel::default().show(ctx, |ui| {
            ui.add_enabled_ui(is_ui_enabled, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    self.render_central_panel(ui);
                });
            });
        });
        TopBottomPanel::bottom("config").show(ctx, |ui| {
            self.render_bottom_panel(ui);
        });
        if self.status == RunningStatus::Stopping {
            MainWindow::stop_bruteforce_task(self)
        }
        if self.show_about_window {
            egui::Window::new("关于")
                .open(&mut self.show_about_window)
                .resizable(false)
                .anchor(egui::Align2::LEFT_BOTTOM, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("作者: [KongJianGhost]");
                    ui.add_space(8.0);
                    ui.label("喜欢的话点个Star吧");
                    ui.add_space(8.0);
                    ui.hyperlink("https://github.com/KongJian520/JwtCracke");
                });
        }
    }
}

pub fn decode_jwt(main_window: &mut MainWindow) {
    let parts: Vec<&str> = main_window.jwt_burp_token.split('.').collect();
    if parts.len() == 3 {
        let decoded_header_result = URL_SAFE_NO_PAD.decode(parts[0]);
        let decoded_payload_result = URL_SAFE_NO_PAD.decode(parts[1]);

        if let (Ok(decoded_header_bytes), Ok(decoded_payload_bytes)) =
            (decoded_header_result, decoded_payload_result)
        {
            if let Ok(header_json) = serde_json::from_slice::<Value>(&decoded_header_bytes) {
                main_window.jwt_decoded_header = serde_json::to_string_pretty(&header_json)
                    .unwrap_or_else(|_| String::from_utf8_lossy(&decoded_header_bytes).to_string());
            } else {
                main_window.jwt_decoded_header =
                    String::from_utf8_lossy(&decoded_header_bytes).to_string();
            }

            if let Ok(payload_json) = serde_json::from_slice::<Value>(&decoded_payload_bytes) {
                main_window.jwt_decoded_payload = serde_json::to_string_pretty(&payload_json)
                    .unwrap_or_else(|_| {
                        String::from_utf8_lossy(&decoded_payload_bytes).to_string()
                    });
            } else {
                main_window.jwt_decoded_payload =
                    String::from_utf8_lossy(&decoded_payload_bytes).to_string();
            }
        } else {
            main_window.jwt_decoded_header.clear();
            main_window.jwt_decoded_payload.clear();
            main_window.error_type = ErrorType::JwtTokenFormatError;
        }
    } else {
        main_window.jwt_decoded_header.clear();
        main_window.jwt_decoded_payload.clear();
        main_window.error_type = ErrorType::JwtTokenFormatError;
    }
}

/// 使用爆破出的密钥对JWT进行签名并更新UI
/// 参数: main_window - 对MainWindow的可变引用
pub fn encode_jwt(main_window: &mut MainWindow) {
    let header_result: Result<Value, _> = from_str(&main_window.jwt_decoded_header);
    let payload_result: Result<Value, _> = from_str(&main_window.jwt_decoded_payload);

    if let (Ok(header_json), Ok(payload_json)) = (header_result, payload_result) {
        let alg_str = header_json["alg"].as_str().unwrap_or("HS256");
        let algorithm = match alg_str {
            "HS256" => Algorithm::HS256,
            "HS384" => Algorithm::HS384,
            "HS512" => Algorithm::HS512,
            _ => {
                main_window.error_type = ErrorType::UnknownAlgorithmType;
                return;
            }
        };

        let mut header = Header::new(algorithm);
        header.typ = header_json["typ"].as_str().map(String::from);
        let mut full_key = String::new();
        full_key.push_str(&main_window.burped_key_start);
        full_key.push_str(&main_window.burped_key);
        full_key.push_str(&main_window.burped_key_end);

        let encoding_key = EncodingKey::from_secret(full_key.as_bytes());

        if let Ok(token) = encode(&header, &payload_json, &encoding_key) {
            main_window.jwt_singed_token = token;
        } else {
            main_window.error_type = ErrorType::SignJWTFailed;
        }
    } else {
        main_window.error_type = ErrorType::InputJSONFormatError;
    }
}
