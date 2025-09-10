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
    pub fn new(min_length: usize, max_length: usize, stop_rx: Option<Arc<Receiver<()>>>) -> Self {
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
            stop_rx,
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
            stop_rx,
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
            stop_rx,
        }
    }
}

impl Iterator for CombinationGenerator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(rx) = &self.stop_rx {
            if rx.try_recv().is_ok() {
                return None;
            }
        }

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

        if self.current_length > self.max_length {
            return None;
        }

        let combination: String = self.indices.iter().map(|&i| self.charset[i]).collect();
        Some(combination)
    }
}
