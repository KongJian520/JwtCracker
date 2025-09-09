use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use hmac::{Hmac, KeyInit, Mac};
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use rayon::current_thread_index;
use rayon::prelude::*;
use serde_json::{from_slice, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::iter::Iterator;
use std::time::{SystemTime, UNIX_EPOCH};

// 使用 clap 定义命令行参数
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 待破解的 JWT 字符串
    #[arg(short, long)]
    token: String,

    /// 密钥的最小长度
    #[arg(short = 'm', long, default_value_t = 1)]
    min_length: usize,

    /// 密钥的最大长度
    #[arg(short = 'x', long, default_value_t = 10)]
    max_length: usize,
}

fn base64url_encode<T: AsRef<[u8]>>(input: T) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

fn verify_jwt_hs256_token(token: &str, secret_key: &str) -> Option<HashMap<String, Value>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let encoded_header = parts[0];
    let encoded_payload = parts[1];
    let encoded_signature = parts[2];
    let signing_input = format!("{}.{}", encoded_header, encoded_payload);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret_key.as_bytes()).expect("HMAC-SHA256无法创建");
    mac.update(signing_input.as_bytes());
    let expected_signature_bytes = mac.finalize().into_bytes();
    let expected_signature = base64url_encode(expected_signature_bytes);
    if expected_signature != encoded_signature {
        return None;
    }
    let decoded_payload_bytes = URL_SAFE_NO_PAD.decode(encoded_payload).ok()?;
    let payload: HashMap<String, Value> = from_slice(&decoded_payload_bytes).ok()?;
    if let Some(exp_value) = payload.get("exp") {
        if let Some(exp) = exp_value.as_u64() {
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if exp < current_time {
                return None;
            }
        }
    }
    Some(payload)
}

// 惰性迭代器，它不会一次性生成所有组合
struct CombinationGenerator {
    charset: Vec<char>,
    current_length: usize,
    min_length: usize,
    max_length: usize,
    indices: Vec<usize>,
    is_new_length: bool,
}

impl CombinationGenerator {
    fn new(min_length: usize, max_length: usize) -> Self {
        let charset: Vec<char> = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            .chars()
            .collect();
        Self {
            charset,
            current_length: min_length,
            min_length,
            max_length,
            indices: Vec::new(),
            is_new_length: true,
        }
    }
}

// 核心：实现 Iterator trait，使其能够按需生成下一个组合
impl Iterator for CombinationGenerator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_length > self.max_length {
            return None;
        }

        if self.is_new_length {
            self.indices = vec![0; self.current_length];
            self.is_new_length = false;
        } else {
            let mut i = self.current_length - 1;
            loop {
                self.indices[i] += 1;
                if self.indices[i] < self.charset.len() {
                    break;
                }
                self.indices[i] = 0;
                if i == 0 {
                    self.current_length += 1;
                    self.is_new_length = true;
                    break;
                }
                i -= 1;
            }
        }

        let combination: String = self.indices.iter().map(|&i| self.charset[i]).collect();
        Some(combination)
    }
}

fn main() {
    let args = Args::parse();
    let token_to_crack = args.token.as_str();
    let min_length = args.min_length;
    let max_length = args.max_length;
    const TICK_CHARS: &[&str] = &[
        "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏",               // 经典旋转器
        " ▂▃▄▅▆▇█▇▆▅▄▃▂ ",          // 脉冲条
        "|/-\\",                    // 简单旋转
        "◐◓◑◒",                     // 圆形旋转
        "▓▒░░▒▓",                   // 填充动画
        "⠁⠂⠄⡀⢀⠠⠐⠈",                 // 点状进度
        "⣾⣽⣻⢿⡿⣟⣯⣷",                 // 扇形旋转
        "🌑🌒🌓🌔🌕🌖🌗🌘",         // 月相变化
        "⬒⬔⬓⬕",                     // 方形旋转
        "▖▘▝▗",                     // 小方块旋转
        "◢◣◤◥",                     // 斜角旋转
        "🕐🕑🕒🕓🕔🕕🕖🕗🕘🕙🕚🕛", // 时钟动画
        "⢀⣀⣄⣤⣦⣶⣷⣿⣷⣶⣦⣤⣄⣀",           // 三角形脉冲
        "♠♣♥♦",                     // 扑克牌花色
        "←↖↑↗→↘↓↙",                 // 指南针方向
        "▉▊▋▌▍▎▏▎▍▌▋▊▉",            // 细条脉冲
        "❘❙❚",                      // 竖线变化
        "☰☱☲☳☴☵☶☷",                 // 八卦符号
        "⌜⌝⌞⌟",                     // 角符号旋转
        "⦾⦿",                       // 圆圈内点变化
    ];

    // 从 tick 字符集中随机选择一个
    let mut rng = rand::rng();
    let random_tick_chars = TICK_CHARS[rng.random_range(0..TICK_CHARS.len())];
    let bar = ProgressBar::new_spinner();
    bar.set_style(
        ProgressStyle::with_template(
            "{spinner:.green}  {msg} | [{elapsed_precise}] {pos} {per_sec} ",
        )
        .unwrap()
        .tick_chars(random_tick_chars), // 应用随机 tick 字符
    );

    println!("正在尝试破解 JWT 令牌...");

    let generator = CombinationGenerator::new(min_length, max_length);

    // 核心逻辑：使用 par_bridge() 将单线程迭代器转换为并行迭代器
    // 然后直接在并行迭代器上使用 find_any()
    let found_key = generator.par_bridge().find_any(|key| {
        bar.inc(1);
        if let Some(thread_id) = current_thread_index() {
            if thread_id == 0 {
                bar.set_message(key.clone());
            }
        }
        verify_jwt_hs256_token(token_to_crack, key).is_some()
    });

    if let Some(key) = found_key {
        bar.finish_with_message("破解成功！");
        println!("\n=====================================");
        println!("找到的密钥是: {}", key);
        println!("=====================================");
    } else {
        bar.finish_with_message("未找到有效密钥。");
        println!("\n在给定的长度范围内未找到有效密钥。");
    }
}
