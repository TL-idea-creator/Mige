//! Vaultwarden / Bitwarden 同步。
//!
//! 协议细节与鸿蒙版实现一致：
//! - 主密钥 = PBKDF2-SHA256(主密码, email 小写, kdfIterations, 32)
//! - 登录用 `masterPasswordHash` = PBKDF2-SHA256(masterKey, 主密码, 1, 32) 的 base64
//! - 拉伸密钥用 **HKDF-Expand only**（info = `enc` / `mac`），不是 extract+expand
//! - 账号密文形如 `2.<iv>|<ct>|<mac>`，AES-256-CBC + HMAC-SHA256(iv‖ct)
//! - 账号 `Key` 解密后是 64 字节原始 userKey（32 enc + 32 mac）
//! - Vaultwarden ≥1.37.4 创建条目必须带 `encryptedFor`（当前用户 UUID，取自 access token 的 sub）

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;

use crate::crypto;
use crate::types::{TotpConfig, VaultItem};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// 同步用的会话（保存在内存，不落盘）
#[derive(Debug, Clone)]
pub struct BwSession {
    pub server: String,
    pub email: String,
    pub access_token: String,
    pub refresh_token: String,
    pub kdf_iterations: u32,
    /// 64 字节：前 32 enc，后 32 mac
    pub user_key: Vec<u8>,
    pub user_id: String,
    pub last_sync_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BwStatus {
    pub connected: bool,
    pub server: String,
    pub email: String,
    pub last_sync_at: i64,
    pub item_count: usize,
}

// ---------- 加密基元 ----------

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC 接受任意长度密钥");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// HKDF-Expand only（Bitwarden 的 stretchKey 就是这个）
fn hkdf_expand(prk: &[u8], info: &str, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut previous: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < len {
        let mut input = previous.clone();
        input.extend_from_slice(info.as_bytes());
        input.push(counter);
        previous = hmac_sha256(prk, &input);
        out.extend_from_slice(&previous);
        counter += 1;
    }
    out.truncate(len);
    out
}

fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plain: &[u8]) -> Vec<u8> {
    Aes256CbcEnc::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plain)
}

fn aes_cbc_decrypt(key: &[u8], iv: &[u8], cipher_text: &[u8]) -> Result<Vec<u8>, String> {
    Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(cipher_text)
        .map_err(|_| "AES_DECRYPT_FAILED".to_string())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// 加密为 Bitwarden 的 `2.<iv>|<ct>|<mac>` 格式
fn encrypt_to_bw(enc_key: &[u8], mac_key: &[u8], plain: &str) -> String {
    let iv = crypto::random_bytes(16);
    let ct = aes_cbc_encrypt(enc_key, &iv, plain.as_bytes());
    let mut mac_input = iv.clone();
    mac_input.extend_from_slice(&ct);
    let mac = hmac_sha256(mac_key, &mac_input);
    format!("2.{}|{}|{}", B64.encode(&iv), B64.encode(&ct), B64.encode(&mac))
}

/// 解密 Bitwarden 密文（兼容 `2.iv|ct|mac`，也兼容没有前缀的老格式）
fn decrypt_from_bw(enc_key: &[u8], mac_key: &[u8], value: &str) -> Result<String, String> {
    let text = value.trim();
    let body = text.strip_prefix("2.").unwrap_or(text);
    let parts: Vec<&str> = body.split('|').collect();
    if parts.len() != 3 {
        return Err("BAD_CIPHER_FORMAT".to_string());
    }
    let iv = B64.decode(parts[0]).map_err(|_| "BAD_IV".to_string())?;
    let ct = B64.decode(parts[1]).map_err(|_| "BAD_CT".to_string())?;
    let mac = B64.decode(parts[2]).map_err(|_| "BAD_MAC".to_string())?;
    let mut mac_input = iv.clone();
    mac_input.extend_from_slice(&ct);
    let expected = hmac_sha256(mac_key, &mac_input);
    if !constant_time_eq(&expected, &mac) {
        return Err("BW_MAC_MISMATCH".to_string());
    }
    let plain = aes_cbc_decrypt(enc_key, &iv, &ct)?;
    String::from_utf8(plain).map_err(|_| "INVALID_UTF8".to_string())
}

/// 从 JWT 中取 sub（当前用户 UUID）
pub fn jwt_subject(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return String::new();
    }
    let payload = parts[1].replace('-', "+").replace('_', "/");
    let padded = match payload.len() % 4 {
        2 => format!("{payload}=="),
        3 => format!("{payload}="),
        _ => payload,
    };
    let Ok(bytes) = B64.decode(padded) else { return String::new() };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else { return String::new() };
    value.get("sub").and_then(|v| v.as_str()).unwrap_or("").to_string()
}

// ---------- HTTP 层 ----------

fn normalize_server(server_url: &str) -> String {
    let trimmed = server_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return "https://vault.bitwarden.com".to_string();
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    }
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // 自建 Vaultwarden 常用自签名证书
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP_CLIENT_FAILED: {e}"))
}

async fn prelogin(base: &str, email: &str) -> Result<u32, String> {
    let url = format!("{base}/identity/accounts/prelogin");
    let response = client()?
        .post(&url)
        .json(&json!({ "email": email }))
        .send()
        .await
        .map_err(|e| format!("无法连接服务器：{e}"))?;
    if !response.status().is_success() {
        return Err(format!("预登录失败（HTTP {}）", response.status().as_u16()));
    }
    let body: Value = response.json().await.map_err(|e| format!("解析预登录响应失败：{e}"))?;
    let kdf = body.get("kdf").and_then(|v| v.as_u64()).unwrap_or(0);
    if kdf != 0 {
        return Err("该账号使用 Argon2 KDF，当前版本暂不支持，请在 Vaultwarden 网页端切换到 PBKDF2".to_string());
    }
    Ok(body.get("kdfIterations").and_then(|v| v.as_u64()).unwrap_or(600_000) as u32)
}

async fn request_token(base: &str, form: Vec<(&'static str, String)>) -> Result<Value, String> {
    let url = format!("{base}/identity/connect/token");
    let response = client()?
        .post(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("无法连接服务器：{e}"))?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(if status.as_u16() == 429 {
            "登录失败次数过多，服务器已临时限流，请稍后再试".to_string()
        } else {
            format!("登录失败（HTTP {}）：请确认账号填写的是注册邮箱，且主密码正确", status.as_u16())
        });
    }
    serde_json::from_str(&text).map_err(|e| format!("解析令牌失败：{e}"))
}

/// 登录：取 token、解出 userKey
pub async fn login(server_url: &str, email: &str, password: &str) -> Result<BwSession, String> {
    let base = normalize_server(server_url);
    let email = email.trim().to_string();
    if email.is_empty() || password.is_empty() {
        return Err("请填写邮箱与主密码".to_string());
    }

    let iterations = prelogin(&base, &email).await?;
    let master_key = crypto::pbkdf2_sha256(password.as_bytes(), email.to_lowercase().as_bytes(), iterations, 32);
    let master_hash = crypto::pbkdf2_sha256(&master_key, password.as_bytes(), 1, 32);

    let device_id = uuid::Uuid::new_v4().to_string();
    let form = vec![
        ("grant_type", "password".to_string()),
        ("username", email.clone()),
        ("password", B64.encode(&master_hash)),
        ("scope", "api offline_access".to_string()),
        ("client_id", "app".to_string()),
        ("deviceType", "7".to_string()),
        ("deviceIdentifier", device_id),
        ("deviceName", "mige-win".to_string()),
    ];
    let token: Value = request_token(&base, form).await?;

    let access_token = token.get("access_token").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let refresh_token = token.get("refresh_token").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if access_token.is_empty() {
        return Err("登录失败：未获取到访问令牌".to_string());
    }

    // 拉伸密钥（HKDF-Expand only）
    let stretch_enc = hkdf_expand(&master_key, "enc", 32);
    let stretch_mac = hkdf_expand(&master_key, "mac", 32);

    let user_key = if let Some(key_value) = token.get("Key").and_then(|v| v.as_str()) {
        let decrypted = decrypt_from_bw(&stretch_enc, &stretch_mac, key_value)
            .map_err(|_| "无法解密账号密钥：请确认主密码正确".to_string())?;
        // Vaultwarden 返回 64 字节原始 userKey；官方云端可能是 base64 文本
        if decrypted.len() == 64 {
            decrypted.as_bytes().to_vec()
        } else {
            B64.decode(decrypted.trim()).map_err(|_| "账号密钥格式不正确".to_string())?
        }
    } else {
        return Err("登录响应缺少账号密钥（Key）".to_string());
    };
    if user_key.len() != 64 {
        return Err(format!("账号密钥长度异常：{}", user_key.len()));
    }

    Ok(BwSession {
        server: base,
        email,
        user_id: jwt_subject(&access_token),
        access_token,
        refresh_token,
        kdf_iterations: iterations,
        user_key,
        last_sync_at: 0,
    })
}

/// 用 refresh_token 续期（返回新的 access/refresh token）
pub async fn refresh(session: &mut BwSession) -> Result<(), String> {
    if session.refresh_token.is_empty() {
        return Err("登录状态已过期，请重新登录".to_string());
    }
    let form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", session.refresh_token.clone()),
        ("client_id", "app".to_string()),
    ];
    let token = request_token(&session.server, form).await?;
    let access = token.get("access_token").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if access.is_empty() {
        return Err("登录状态已过期，请重新登录".to_string());
    }
    session.access_token = access;
    if let Some(refresh_token) = token.get("refresh_token").and_then(|v| v.as_str()) {
        session.refresh_token = refresh_token.to_string();
    }
    if session.user_id.is_empty() {
        session.user_id = jwt_subject(&session.access_token);
    }
    Ok(())
}

fn cipher_keys(session: &BwSession) -> (Vec<u8>, Vec<u8>) {
    (session.user_key[0..32].to_vec(), session.user_key[32..64].to_vec())
}

fn decrypt_field(session: &BwSession, value: Option<&Value>) -> String {
    let Some(Value::String(text)) = value else { return String::new() };
    if text.is_empty() {
        return String::new();
    }
    let (enc, mac) = cipher_keys(session);
    decrypt_from_bw(&enc, &mac, text).unwrap_or_default()
}

fn encrypt_field(session: &BwSession, value: &str) -> Option<String> {
    if value.trim().is_empty() {
        return None;
    }
    let (enc, mac) = cipher_keys(session);
    Some(encrypt_to_bw(&enc, &mac, value))
}

fn parse_totp(raw: &str) -> Option<TotpConfig> {
    if raw.is_empty() {
        return None;
    }
    if raw.starts_with("otpauth://") {
        return crate::totp::parse_otpauth(raw);
    }
    // 只有 Base32 密钥时按默认参数构造
    Some(TotpConfig { secret: raw.replace([' ', '-'], "").to_ascii_uppercase(), ..Default::default() })
}

/// 拉取并解密全库
pub async fn sync_vault(session: &mut BwSession) -> Result<Vec<VaultItem>, String> {
    let url = format!("{}/api/sync", session.server);
    let mut response = client()?
        .get(&url)
        .bearer_auth(&session.access_token)
        .send()
        .await
        .map_err(|e| format!("同步请求失败：{e}"))?;

    if response.status().as_u16() == 401 {
        refresh(session).await?;
        response = client()?
            .get(&url)
            .bearer_auth(&session.access_token)
            .send()
            .await
            .map_err(|e| format!("同步请求失败：{e}"))?;
    }
    if !response.status().is_success() {
        return Err(format!("同步失败（HTTP {}）", response.status().as_u16()));
    }

    let body: Value = response.json().await.map_err(|e| format!("解析同步数据失败：{e}"))?;
    let mut items = Vec::new();
    let Some(ciphers) = body.get("ciphers").and_then(|v| v.as_array()) else {
        return Ok(items);
    };

    for cipher in ciphers {
        let kind = cipher.get("type").and_then(|v| v.as_i64()).unwrap_or(1);
        if kind != 1 {
            continue;
        }
        let mut item = VaultItem {
            id: uuid::Uuid::new_v4().to_string().chars().take(8).collect(),
            created_at: crate::transfer::now_ms(),
            updated_at: crate::transfer::now_ms(),
            ..Default::default()
        };
        item.bw_id = cipher.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        item.name = decrypt_field(session, cipher.get("name"));
        item.notes = decrypt_field(session, cipher.get("notes"));
        item.favorite = cipher.get("favorite").and_then(|v| v.as_bool()).unwrap_or(false);
        if let Some(login) = cipher.get("login") {
            item.username = decrypt_field(session, login.get("username"));
            item.password = decrypt_field(session, login.get("password"));
            if let Some(uris) = login.get("uris").and_then(|v| v.as_array()) {
                if let Some(first) = uris.first() {
                    item.url = decrypt_field(session, first.get("uri"));
                }
            }
            let totp_raw = decrypt_field(session, login.get("totp"));
            item.totp = parse_totp(&totp_raw);
        }
        items.push(item);
    }

    session.last_sync_at = crate::transfer::now_ms();
    Ok(items)
}

/// 上传一条本地条目，返回服务端 id
pub async fn upload_item(session: &mut BwSession, item: &VaultItem) -> Result<String, String> {
    let login = json!({
        "username": encrypt_field(session, &item.username),
        "password": encrypt_field(session, &item.password),
        "totp": item.totp.as_ref().map(|cfg| encrypt_field(session, &crate::totp::build_otpauth(cfg))).flatten(),
        "uris": if item.url.trim().is_empty() {
            Vec::<Value>::new()
        } else {
            vec![json!({ "uri": encrypt_field(session, &item.url) })]
        }
    });
    let payload = json!({
        "type": 1,
        "name": encrypt_field(session, &item.name),
        "notes": encrypt_field(session, &item.notes),
        "favorite": item.favorite,
        "encryptedFor": session.user_id,
        "login": login
    });

    let url = format!("{}/api/ciphers", session.server);
    let mut response = client()?
        .post(&url)
        .bearer_auth(&session.access_token)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("上传请求失败：{e}"))?;

    if response.status().as_u16() == 401 {
        refresh(session).await?;
        response = client()?
            .post(&url)
            .bearer_auth(&session.access_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("上传请求失败：{e}"))?;
    }
    if !response.status().is_success() {
        return Err(format!("上传失败（HTTP {}）", response.status().as_u16()));
    }
    let body: Value = response.json().await.unwrap_or(Value::Null);
    Ok(body.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_expand_is_deterministic_and_distinct() {
        let prk = [7u8; 32];
        let enc = hkdf_expand(&prk, "enc", 32);
        let mac = hkdf_expand(&prk, "mac", 32);
        assert_eq!(enc, hkdf_expand(&prk, "enc", 32));
        assert_ne!(enc, mac);
        assert_eq!(enc.len(), 32);
    }

    #[test]
    fn bw_cipher_roundtrip_and_tamper() {
        let enc = [1u8; 32];
        let mac = [2u8; 32];
        let value = encrypt_to_bw(&enc, &mac, "我的密码 P@ss");
        assert!(value.starts_with("2."));
        assert_eq!(decrypt_from_bw(&enc, &mac, &value).unwrap(), "我的密码 P@ss");

        let mut broken = value.clone();
        broken.pop();
        broken.push('A');
        assert!(decrypt_from_bw(&enc, &mac, &broken).is_err());
        assert!(decrypt_from_bw(&enc, &[3u8; 32], &value).is_err());
    }

    #[test]
    fn jwt_subject_extracted() {
        let payload = B64.encode(br#"{"sub":"0f8c1a52-1111-4c2b-9f3d-123456789abc","exp":1999999999}"#);
        let token = format!("header.{payload}.sig");
        // 标准 base64 中的 +/ 在 JWT 里是 -_，这里内容不含，可直接验证
        assert_eq!(jwt_subject(&token), "0f8c1a52-1111-4c2b-9f3d-123456789abc");
        assert_eq!(jwt_subject("not-a-jwt"), "");
    }

    #[test]
    fn server_normalized() {
        assert_eq!(normalize_server(""), "https://vault.bitwarden.com");
        assert_eq!(normalize_server("vault.example.com/"), "https://vault.example.com");
        assert_eq!(normalize_server("http://192.168.1.2:8080/"), "http://192.168.1.2:8080");
    }
}
