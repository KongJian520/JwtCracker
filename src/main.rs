mod cli;
mod combination_generator;
mod gui;
mod jwt;

use crate::cli::run_cli;
use crate::gui::show_gui;
use clap::Parser;
use std::env;
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 待破解的 JWT 字符串
    #[arg(short, long)]
    token: String,

    /// 密钥的最小长度
    #[arg(short = 'm', long = "min", default_value_t = 1)]
    min_length: usize,

    /// 密钥的最大长度
    #[arg(short = 'x', long = "max", default_value_t = 10)]
    max_length: usize,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        run_cli();
    } else {
        show_gui().expect("Failed to start GUI");
    }
}
