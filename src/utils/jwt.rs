use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, from_slice};
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// 解码JWT字符串并更新UI中的Header和Payload
/// 参数: main_window - 对MainWindow的可变引用

pub fn verify_jwt_hs256_token(token: &str, secret_key: &str) -> Option<HashMap<String, Value>> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let encoded_header = parts[0];
    let encoded_payload = parts[1];
    let encoded_signature = parts[2];
    let signing_input = format!("{}.{}", encoded_header, encoded_payload);

    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret_key.as_bytes()).expect("HMAC-SHA256 实例创建失败");
    mac.update(signing_input.as_bytes());

    let expected_signature_bytes = mac.finalize().into_bytes();

    let expected_signature = URL_SAFE_NO_PAD.encode(expected_signature_bytes);
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
