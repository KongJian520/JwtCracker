use crate::gui::{ErrorType, MainWindow};
use base64::engine::general_purpose;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{from_slice, from_str, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// 解码JWT字符串并更新UI中的Header和Payload
/// 参数: main_window - 对MainWindow的可变引用
pub fn decode_jwt(main_window: &mut MainWindow) {
    let parts: Vec<&str> = main_window.jwt_burp_token.split('.').collect();
    if parts.len() == 3 {
        let decoded_header_result = general_purpose::URL_SAFE_NO_PAD.decode(parts[0]);
        let decoded_payload_result = general_purpose::URL_SAFE_NO_PAD.decode(parts[1]);

        if let (Ok(decoded_header_bytes), Ok(decoded_payload_bytes)) =
            (decoded_header_result, decoded_payload_result)
        {
            if let Ok(header_json) = serde_json::from_slice::<Value>(&decoded_header_bytes) {
                main_window.jwt_header = serde_json::to_string_pretty(&header_json)
                    .unwrap_or_else(|_| String::from_utf8_lossy(&decoded_header_bytes).to_string());
            } else {
                main_window.jwt_header = String::from_utf8_lossy(&decoded_header_bytes).to_string();
            }

            if let Ok(payload_json) = serde_json::from_slice::<Value>(&decoded_payload_bytes) {
                main_window.jwt_playload = serde_json::to_string_pretty(&payload_json)
                    .unwrap_or_else(|_| {
                        String::from_utf8_lossy(&decoded_payload_bytes).to_string()
                    });
            } else {
                main_window.jwt_playload =
                    String::from_utf8_lossy(&decoded_payload_bytes).to_string();
            }
        } else {
            main_window.jwt_header.clear();
            main_window.jwt_playload.clear();
            main_window.error_type = ErrorType::JwtTokenFormatError;
        }
    } else {
        main_window.jwt_header.clear();
        main_window.jwt_playload.clear();
        main_window.error_type = ErrorType::JwtTokenFormatError;
    }
}

/// 使用爆破出的密钥对JWT进行签名并更新UI
/// 参数: main_window - 对MainWindow的可变引用
pub fn encode_jwt(main_window: &mut MainWindow) {
    let header_result: Result<Value, _> = from_str(&main_window.jwt_header);
    let payload_result: Result<Value, _> = from_str(&main_window.jwt_playload);

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

        let encoding_key = EncodingKey::from_secret(main_window.burped_key.as_bytes());

        if let Ok(token) = encode(&header, &payload_json, &encoding_key) {
            main_window.jwt_singed_token = token;
        } else {
            main_window.error_type = ErrorType::SignJWTFailed;
        }
    } else {
        main_window.error_type = ErrorType::InputJSONFormatError;
    }
}

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
