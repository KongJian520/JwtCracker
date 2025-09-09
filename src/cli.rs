use crate::combination_generator::CombinationGenerator;
use crate::Args;

pub(crate) use crate::jwt::verify_jwt_hs256_token;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use rayon::current_thread_index;
use rayon::iter::{ParallelBridge, ParallelIterator};
fn init_progress_bar() -> ProgressBar {
    const TICK_CHARS: &[&str] = &[
        "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏",
        " ▂▃▄▅▆▇█▇▆▅▄▃▂ ",
        "|/-\\",
        "◐◓◑◒",
        "▓▒░░▒▓",
        "⠁⠂⠄⡀⢀⠠⠐⠈",
        "⣾⣽⣻⢿⡿⣟⣯⣷",
        "🌑🌒🌓🌔🌕🌖🌗🌘",
        "⬒⬔⬓⬕",
        "▖▘▝▗",
        "◢◣◤◥",
        "🕐🕑🕒🕓🕔🕕🕖🕗🕘🕙🕚🕛",
        "⢀⣀⣄⣤⣦⣶⣷⣿⣷⣶⣦⣤⣄⣀",
        "♠♣♥♦",
        "←↖↑↗→↘↓↙",
        "▉▊▋▌▍▎▏▎▍▌▋▊▉",
        "❘❙❚",
        "☰☱☲☳☴☵☶☷",
        "⌜⌝⌞⌟",
        "⦾⦿",
    ];

    let mut rng = rand::rng();
    let random_tick_chars = TICK_CHARS[rng.random_range(0..TICK_CHARS.len())];
    let bar = ProgressBar::new_spinner();
    bar.set_style(
        ProgressStyle::with_template(
            "{spinner:.green}  {msg} | [{elapsed_precise}] {pos} {per_sec} ",
        )
        .unwrap()
        .tick_chars(random_tick_chars),
    );
    bar
}

// 核心的命令行逻辑
pub fn run_cli() {
    let args = Args::parse();
    let token_to_crack = args.token.as_str();
    let min_length = args.min_length;
    let max_length = args.max_length;

    let bar = init_progress_bar();
    println!("正在尝试破解 JWT 令牌...");

    let generator = CombinationGenerator::new(min_length, max_length, None);

    let found_key = generator.par_bridge().find_any(|key| {
        if let Some(thread_id) = current_thread_index() {
            if thread_id == 0 {
                bar.set_message(format!("尝试密钥：{}", key));
            }
        }
        bar.inc(1);
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
