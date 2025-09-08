use indicatif::{ProgressBar, ProgressStyle};
use num_bigint::{BigUint, ToBigUint};
use num_traits::identities::Zero;
use num_traits::ToPrimitive;
use rayon::prelude::*;
use std::iter::Iterator;

// 我们使用之前实现的迭代器，它负责按需生成所有组合
// （为完整性再次包含实现）
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

// 计算所有长度的组合总数，用于设置进度条的上限
fn calculate_total_combinations(min_len: u32, max_len: u32) -> BigUint {
    let mut total: BigUint = Zero::zero();
    let charset_size = 62.to_biguint().unwrap();

    for len in min_len..=max_len {
        let combinations_for_len = charset_size.pow(len);
        total += combinations_for_len;
    }
    total
}

fn main() {
    let min_length = 1;
    let max_length = 5;

    // 计算总任务数，它是一个 BigUint 类型
    let total_combinations_biguint = calculate_total_combinations(min_length, max_length);

    // 将 BigUint 转换为 u64，用于 ProgressBar。
    // 如果总数超过 u64 的最大值，我们将使用 u64::MAX
    let total_combinations_u64 = total_combinations_biguint.to_u64().unwrap_or(u64::MAX);

    // 创建一个进度条，并使用转换后的 u64 总数
    let bar = ProgressBar::new(total_combinations_u64);

    // 修改样式模板，只显示百分比和已处理数量，不显示总数
    bar.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {percent_precise}% {per_sec} {eta})",
        )
        .unwrap()
        .progress_chars("#>-"),
    );

    let generator = CombinationGenerator::new(min_length as usize, max_length as usize);

    let found_combinations: Vec<String> = generator
        .par_bridge()
        .filter(|combination| {
            bar.inc(1);
            combination.contains('a')
        })
        .collect();

    bar.finish_with_message("所有组合已生成并过滤完成！");

    println!("总共找到 {} 个符合要求的组合。", found_combinations.len());
}
