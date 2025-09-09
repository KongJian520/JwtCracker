use crossbeam_channel::Receiver;
use std::sync::Arc;

pub struct CombinationGenerator {
    charset: Vec<char>,
    current_length: usize,
    min_length: usize,
    max_length: usize,
    indices: Vec<usize>,
    is_new_length: bool,
    stop_rx: Option<Arc<Receiver<()>>>,
}

impl CombinationGenerator {
    pub fn new(min_length: usize, max_length: usize,  stop_rx: Option<Arc<Receiver<()>>>,) -> Self {
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
            stop_rx
        }
    }
    pub fn new_with_charset(
        min_length: usize,
        max_length: usize,
        charset: &str,
        stop_rx: Option<Arc<Receiver<()>>>,
    ) -> Self {
        let charset: Vec<char> = charset.chars().collect();
        Self {
            charset,
            current_length: min_length,
            min_length,
            max_length,
            indices: Vec::new(),
            is_new_length: true,
            stop_rx
        }
    }
    pub fn new_with_options(
        min_length: usize,
        max_length: usize,
        use_lowercase: bool,
        use_uppercase: bool,
        use_digits: bool,
        use_special: bool,
        stop_rx: Option<Arc<Receiver<()>>>,
    ) -> Self {
        let mut charset = String::new();
        if use_lowercase {
            charset.push_str("abcdefghijklmnopqrstuvwxyz");
        }
        if use_uppercase {
            charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
        if use_digits {
            charset.push_str("0123456789");
        }
        if use_special {
            charset.push_str("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~");
        }
        let charset: Vec<char> = charset.chars().collect();
        Self {
            charset,
            current_length: min_length,
            min_length,
            max_length,
            indices: Vec::new(),
            is_new_length: true,
            stop_rx
        }
    }
}

impl Iterator for CombinationGenerator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(rx) = &self.stop_rx {
            if rx.try_recv().is_ok() {
                return None; // 收到停止信号，返回 None 终止迭代。
            }
        }
        // 如果当前长度超过了最大长度，则停止生成
        if self.current_length > self.max_length {
            return None;
        }

        // 第一次进入当前长度的循环时，初始化索引
        if self.is_new_length {
            self.indices = vec![0; self.current_length];
            self.is_new_length = false;
        } else {
            let mut i = self.current_length - 1;
            loop {
                // 尝试递增当前位置的索引
                self.indices[i] += 1;
                // 如果索引还在字符集范围内，说明生成了一个新的组合，可以跳出循环
                if self.indices[i] < self.charset.len() {
                    break;
                }
                // 如果当前位置的索引超出了范围，重置为0，并向前一位
                self.indices[i] = 0;
                // 如果已经到了第一位（i == 0）并且需要进位，说明当前长度的所有组合都已生成
                if i == 0 {
                    self.current_length += 1;
                    self.is_new_length = true; // 标记下一个循环需要生成新长度的组合
                    break;
                }
                // 向前一位
                i -= 1;
            }
        }

        // 如果在递增后发现当前长度已经超过了最大长度，说明所有组合都已生成
        if self.current_length > self.max_length {
            return None;
        }

        // 根据当前的索引组合生成字符串
        let combination: String = self.indices.iter().map(|&i| self.charset[i]).collect();
        Some(combination)
    }
}