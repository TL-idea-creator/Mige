//! TOTP（RFC 6238）与 otpauth URI 解析/生成，算法与鸿蒙版 `crypto/Totp.ets` 一致。

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::types::TotpConfig;

/// Base32 解码（忽略空格与连字符，允许小写与缺失填充）
pub fn base32_decode(input: &str) -> Vec<u8> {
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out: Vec<u8> = Vec::new();
    for ch in input.chars() {
        let value = match ch.to_ascii_uppercase() {
            'A'..='Z' => ch.to_ascii_uppercase() as u32 - 'A' as u32,
            '2'..='7' => ch as u32 - '2' as u32 + 26,
            ' ' | '-' | '=' | '\t' | '\n' => continue,
            _ => continue,
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    out
}

/// Base32 编码（带 `=` 填充），用于生成 otpauth 链接
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for byte in data {
        buffer = (buffer << 8) | *byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    while out.len() % 8 != 0 {
        out.push('=');
    }
    out
}

pub fn is_valid_base32(input: &str) -> bool {
    let cleaned: String = input.chars().filter(|c| *c != ' ' && *c != '-').collect();
    !cleaned.is_empty()
        && cleaned
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() && ('2'..='7').contains(&c))
}

pub fn period_of(cfg: &TotpConfig) -> u32 {
    if cfg.period > 0 {
        cfg.period
    } else {
        30
    }
}

pub fn counter_of(cfg: &TotpConfig, at_ms: i64) -> u64 {
    let secs = (at_ms / 1000).max(0) as u64;
    secs / period_of(cfg) as u64
}

/// 剩余有效秒数（1..period）
pub fn remaining_of(cfg: &TotpConfig, at_ms: i64) -> u32 {
    let period = period_of(cfg);
    let secs = (at_ms / 1000).max(0) as u64;
    period - (secs % period as u64) as u32
}

fn hmac_digest(algorithm: &str, key: &[u8], data: &[u8]) -> Vec<u8> {
    match algorithm.to_ascii_uppercase().as_str() {
        "SHA256" => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        "SHA512" => {
            let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(key).expect("hmac key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        _ => {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("hmac key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// 计算指定时间点的动态码；密钥为空或非法时返回空串
pub fn code_at(cfg: &TotpConfig, at_ms: i64) -> String {
    let secret = base32_decode(&cfg.secret);
    if secret.is_empty() {
        return String::new();
    }
    let counter = counter_of(cfg, at_ms).to_be_bytes();
    let digest = hmac_digest(&cfg.algorithm, &secret, &counter);
    if digest.len() < 20 {
        return String::new();
    }
    // 动态截断：取最后一个字节低 4 位作为偏移
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    if offset + 4 > digest.len() {
        return String::new();
    }
    let binary = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    let digits = if cfg.digits > 0 { cfg.digits } else { 6 };
    let modulo = 10u32.pow(digits);
    format!("{:0width$}", binary % modulo, width = digits as usize)
}

/// 解析 otpauth:// 链接
pub fn parse_otpauth(uri: &str) -> Option<TotpConfig> {
    let text = uri.trim();
    let lower = text.to_ascii_lowercase();
    if !lower.starts_with("otpauth://totp/") && !lower.starts_with("otpauth://hotp/") {
        return None;
    }
    let prefix_len = "otpauth://totp/".len();
    if text.len() <= prefix_len {
        return None;
    }
    let (label_part, query) = match text[prefix_len..].find('?') {
        Some(idx) => (&text[prefix_len..prefix_len + idx], &text[prefix_len + idx + 1..]),
        None => (&text[prefix_len..], ""),
    };
    let label = url_decode(label_part);

    let mut secret = String::new();
    let mut issuer_param = String::new();
    let mut algorithm = String::from("SHA1");
    let mut digits: u32 = 6;
    let mut period: u32 = 30;

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut kv = pair.splitn(2, '=');
        let key = kv.next().unwrap_or("").to_ascii_lowercase();
        let value = url_decode(kv.next().unwrap_or(""));
        match key.as_str() {
            "secret" => secret = value,
            "issuer" => issuer_param = value,
            "algorithm" => algorithm = value.to_ascii_uppercase(),
            "digits" => digits = value.parse().unwrap_or(6),
            "period" => period = value.parse().unwrap_or(30),
            _ => {}
        }
    }
    if secret.is_empty() {
        return None;
    }

    let mut issuer = issuer_param;
    let mut account = label.clone();
    if let Some(idx) = label.find(':') {
        let label_issuer = label[..idx].trim().to_string();
        account = label[idx + 1..].trim().to_string();
        if issuer.is_empty() {
            issuer = label_issuer;
        }
    }

    Some(TotpConfig {
        secret: secret.replace([' ', '-'], "").to_ascii_uppercase(),
        issuer,
        account,
        algorithm,
        digits: if digits == 0 { 6 } else { digits },
        period: if period == 0 { 30 } else { period },
    })
}

/// 生成 otpauth:// URI
pub fn build_otpauth(cfg: &TotpConfig) -> String {
    let issuer = if cfg.issuer.is_empty() { "密阁" } else { cfg.issuer.as_str() };
    let account = if cfg.account.is_empty() { "account" } else { cfg.account.as_str() };
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
        url_encode(issuer),
        url_encode(account),
        cfg.secret,
        url_encode(issuer),
        cfg.algorithm,
        cfg.digits,
        cfg.period
    )
}

/// 列表标题：`颁发方 · 账号`
pub fn label_of(cfg: &TotpConfig) -> String {
    if !cfg.issuer.is_empty() && !cfg.account.is_empty() {
        format!("{} · {}", cfg.issuer, cfg.account)
    } else if !cfg.issuer.is_empty() {
        cfg.issuer.clone()
    } else {
        cfg.account.clone()
    }
}

fn url_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn url_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*byte as char),
            b' ' => out.push_str("%20"),
            other => out.push_str(&format!("%{:02X}", other)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // "12345678901234567890"

    fn rfc_cfg(digits: u32) -> TotpConfig {
        TotpConfig {
            secret: RFC_SECRET.to_string(),
            issuer: "Test".into(),
            account: "rfc@example.com".into(),
            algorithm: "SHA1".into(),
            digits,
            period: 30,
        }
    }

    #[test]
    fn rfc6238_vectors_8_digits() {
        let cfg = rfc_cfg(8);
        assert_eq!(code_at(&cfg, 59_000), "94287082");
        assert_eq!(code_at(&cfg, 1_111_111_109_000), "07081804");
        assert_eq!(code_at(&cfg, 1_111_111_111_000), "14050471");
        assert_eq!(code_at(&cfg, 1_234_567_890_000), "89005924");
        assert_eq!(code_at(&cfg, 2_000_000_000_000), "69279037");
    }

    #[test]
    fn rfc6238_vectors_6_digits() {
        let cfg = rfc_cfg(6);
        assert_eq!(code_at(&cfg, 59_000), "287082");
        assert_eq!(code_at(&cfg, 1_111_111_109_000), "081804");
    }

    #[test]
    fn counter_and_remaining() {
        let cfg = rfc_cfg(6);
        assert_eq!(counter_of(&cfg, 0), 0);
        assert_eq!(counter_of(&cfg, 29_999), 0);
        assert_eq!(counter_of(&cfg, 30_000), 1);
        assert_eq!(remaining_of(&cfg, 0), 30);
        assert_eq!(remaining_of(&cfg, 1_000), 29);
        assert_eq!(remaining_of(&cfg, 29_000), 1);
        assert_eq!(remaining_of(&cfg, 30_000), 30);
    }

    #[test]
    fn parse_and_build_otpauth() {
        let cfg = parse_otpauth(
            "otpauth://totp/GitHub:me%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60",
        )
        .expect("应能解析");
        assert_eq!(cfg.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(cfg.issuer, "GitHub");
        assert_eq!(cfg.account, "me@example.com");
        assert_eq!(cfg.algorithm, "SHA256");
        assert_eq!(cfg.digits, 8);
        assert_eq!(cfg.period, 60);

        let uri = build_otpauth(&cfg);
        let again = parse_otpauth(&uri).expect("往返解析");
        assert_eq!(again.secret, cfg.secret);
        assert_eq!(again.issuer, cfg.issuer);
        assert_eq!(again.account, cfg.account);
    }

    #[test]
    fn invalid_links_rejected() {
        assert!(parse_otpauth("https://example.com").is_none());
        assert!(parse_otpauth("otpauth://totp/NoSecret?issuer=X").is_none());
        assert!(parse_otpauth("").is_none());
    }

    #[test]
    fn base32_roundtrip() {
        let raw = base32_decode("JBSWY3DPEHPK3PXP");
        assert_eq!(base32_encode(&raw).trim_end_matches('='), "JBSWY3DPEHPK3PXP");
    }
}
