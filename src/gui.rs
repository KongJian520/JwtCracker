// 导入所需模块
use crate::cli::verify_jwt_hs256_token;
use crate::combination_generator::CombinationGenerator;
use crate::jwt::{decode_jwt, encode_jwt};
use base64::Engine;
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
    /// 检查并处理来自后台任务线程的消息和状态
    fn handle_channels(&mut self, ctx: &egui::Context) {
        // 如果有接收器，检查是否有新消息
        if let Some(rx) = &self.rx {
            loop {
                // 尝试非阻塞地接收消息
                match rx.try_recv() {
                    Ok(key) => {
                        // 收到新密钥，更新UI并请求重绘
                        self.burped_key = key;
                        ctx.request_repaint();
                    }
                    Err(TryRecvError::Empty) => break, // 通道为空，跳出循环
                    Err(TryRecvError::Disconnected) => {
                        // 通道已断开，说明后台线程已退出
                        self.rx = None;
                        break;
                    }
                }
            }
        }

        // 如果任务句柄存在且任务已完成
        if let Some(handle) = self.task_handle.as_mut() {
            if handle.is_finished() {
                // 等待任务完成并获取结果
                match self.task_handle.take().unwrap().join() {
                    Ok(Some(key)) => {
                        // 找到密钥，更新状态
                        self.burped_key = key;
                        self.status = RunningStatus::Found;
                        encode_jwt(self);
                    }
                    Ok(None) => {
                        // 任务因停止或未找到而结束
                        if self.status == RunningStatus::Stopping {
                            self.status = RunningStatus::Stopped;
                        } else {
                            // 未知错误或未找到密钥
                            self.status = RunningStatus::Error;
                            self.error_type = ErrorType::None;
                        }
                    }
                    Err(_) => {
                        // 线程发生恐慌
                        self.status = RunningStatus::Error;
                        self.error_type = ErrorType::None;
                    }
                }
            }
        }
    }

    /// 渲染中央面板的UI
    fn render_central_panel(&mut self, ui: &mut egui::Ui) {
        let ui_width = ui.available_width();
        // 渲染字符集选择和长度设置
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

        // 用于语法高亮的闭包
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

        // JWT输入框
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
            // 当JWT输入框内容改变时，尝试解码
            decode_jwt(self);
        };

        // Header和Payload编辑框
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

        // 签名结果显示框
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

    /// 渲染底部面板的UI，包括状态和按钮
    fn render_bottom_panel(&mut self, ui: &mut egui::Ui) {
        // 根据状态显示不同的文本和颜色
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

        // 克隆egui上下文，用于后台线程的重绘请求
        let ctx_clone = ui.ctx().clone();

        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
            // 根据状态显示旋转器
            if self.status == RunningStatus::Running || self.status == RunningStatus::Stopping {
                ui.add(egui::Spinner::new());
            }

            // 显示状态文本
            ui.add(Label::new(status_text));

            // 右对齐按钮
            ui.with_layout(Layout::right_to_left(Align::RIGHT), |child_ui| {
                child_ui.horizontal(|button_ui| {
                    // 只有当状态不是Stopping时才启用按钮
                    if self.status == RunningStatus::Stopping {
                        button_ui.set_enabled(false);
                    } else {
                        button_ui.set_enabled(true);
                    }

                    // 启动按钮
                    if button_ui.button("开始").clicked() {
                        self.start_bruteforce_task(ctx_clone);
                    }
                    // 停止按钮
                    if button_ui.button("停止").clicked() {
                        self.stop_bruteforce_task();
                    }
                    // 清空按钮
                    if button_ui.button("清空").clicked() {
                        self.clear_state();
                    }
                });
            });
        });
    }

    /// 启动后台爆破任务
    fn start_bruteforce_task(&mut self, ctx: egui::Context) {
        // 输入验证
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

        // 创建消息通道用于线程间通信
        let (tx, rx) = unbounded::<String>();
        let (stop_tx, stop_rx) = unbounded::<()>();
        self.tx = Some(tx.clone());
        self.rx = Some(rx);
        self.stop_tx = Some(stop_tx);

        // 根据UI选项创建组合生成器
        let generator = if self.use_user_charset {
            CombinationGenerator::new_with_charset(self.min_len, self.max_len, &*self.user_charset)
        } else {
            CombinationGenerator::new_with_options(
                self.min_len,
                self.max_len,
                self.use_lowercase,
                self.use_uppercase,
                self.use_digits,
                self.use_special,
            )
        };

        // 启动后台线程执行耗时任务
        self.task_handle = Some(thread::spawn(move || {
            let found_key = generator.par_bridge().find_any(|key| {
                // 检查停止信号
                if stop_rx.try_recv().is_ok() {
                    ctx.request_repaint();
                    return false;
                }
                // 发送正在尝试的密钥到主线程
                let _ = tx.send(key.to_string());
                // 验证JWT
                verify_jwt_hs256_token(jwt_token.as_str(), key).is_some()
            });
            ctx.request_repaint();
            found_key.map(|s| s.to_owned())
        }));
        self.status = RunningStatus::Running;
    }

    /// 停止后台任务
    fn stop_bruteforce_task(&mut self) {
        if self.status == RunningStatus::Running {
            self.status = RunningStatus::Stopping;
            // 发送停止信号到后台线程
            if let Some(tx) = self.stop_tx.take() {
                let _ = tx.send(());
            }
        }
    }

    /// 清空所有状态和输入
    fn clear_state(&mut self) {
        self.jwt_header = "".to_string();
        self.jwt_playload = "".to_string();
        self.jwt_burp_token = "".to_string();
        self.jwt_singed_token = "".to_string();
        self.burped_key = "".to_string();
        self.status = RunningStatus::OK;
        self.error_type = ErrorType::None;
        // 发送停止信号以确保后台线程退出
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl eframe::App for MainWindow {
    /// 主要的更新函数，负责处理状态和渲染UI
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 首先处理后台线程的消息和任务完成状态
        self.handle_channels(ctx);

        // 根据运行状态，决定是否启用中央面板的UI
        let is_ui_enabled =
            self.status != RunningStatus::Running && self.status != RunningStatus::Stopping;

        egui::CentralPanel::default().show(ctx, |ui| {
            // 使用 add_enabled_ui 方法来控制内容的启用/禁用状态，而不是 set_enabled
            ui.add_enabled_ui(is_ui_enabled, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    self.render_central_panel(ui);
                });
            });
        });

        // 渲染底部面板
        TopBottomPanel::bottom("main").show(ctx, |ui| {
            self.render_bottom_panel(ui);
        });
    }
}

/// 加载并设置自定义字体
/// 返回: FontDefinitions
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

/// 启动GUI应用程序
/// 返回: eframe::Result
pub fn show_gui() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([400.0, 400.0]),
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
