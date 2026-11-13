//! Vaultwarden / Bitwarden 同步。
//!
//! 协议细节与鸿蒙版实现一致：
//! - 主密钥 = KDF(主密码, email 小写, 参数)：
//!   - PBKDF2-SHA256（`kdf=0`，默认 600000 次）
//!   - Argon2id（`kdf=1`，memory 单位 MiB、parallelism 条带数，Vaultwarden 新版默认）
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

/// 同步用的会话（内存态）
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

impl BwSession {
    /// 转成可持久化的配置（字段命名与鸿蒙版 BitwardenConfig 一致，便于两端互通）
    pub fn to_config(&self) -> BitwardenConfig {
        BitwardenConfig {
            server: self.server.clone(),
            email: self.email.clone(),
            kdf_iterations: self.kdf_iterations,
            enc_key: B64.encode(&self.user_key[..32.min(self.user_key.len())]),
            mac_key: B64.encode(&self.user_key[32.min(self.user_key.len())..]),
            user_key: B64.encode(&self.user_key),
            user_id: self.user_id.clone(),
            access_token: self.access_token.clone(),
            refresh_token: self.refresh_token.clone(),
            expires_at: 0,
            last_sync_at: self.last_sync_at,
            allow_insecure: false,
        }
    }

    /// 从持久化配置恢复会话；字段不全时返回 None（视为「未连接」）
    pub fn from_config(cfg: &BitwardenConfig) -> Option<BwSession> {
        if cfg.server.trim().is_empty() || cfg.user_key.trim().is_empty() {
            return None;
        }
        let user_key = B64.decode(cfg.user_key.trim()).ok()?;
        if user_key.len() != 64 {
            return None;
        }
        Some(BwSession {
            server: normalize_server(&cfg.server),
            email: cfg.email.clone(),
            access_token: cfg.access_token.clone(),
            refresh_token: cfg.refresh_token.clone(),
            kdf_iterations: cfg.kdf_iterations,
            user_key,
            user_id: cfg.user_id.clone(),
            last_sync_at: cfg.last_sync_at,
        })
    }
}

/// 随密码库一起加密落盘的 Vaultwarden 配置。
/// 字段与鸿蒙版保持一致（camelCase），账号 userKey 以 base64 保存，因此重启后无需重新登录。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BitwardenConfig {
    pub server: String,
    pub email: String,
    pub kdf_iterations: u32,
    /// base64(32B) enc 密钥
    pub enc_key: String,
    /// base64(32B) mac 密钥
    pub mac_key: String,
    /// base64(64B) userKey（enc ‖ mac）
    pub user_key: String,
    pub user_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
    pub last_sync_at: i64,
    pub allow_insecure: bool,
}

/// 服务器返回的 KDF 配置（prelogin 结果）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfConfig {
    /// 0 = PBKDF2-SHA256，1 = Argon2id
    pub kdf_type: u64,
    /// PBKDF2 迭代次数 / Argon2 时间成本（t）
    pub iterations: u32,
    /// 仅 Argon2：内存成本，单位 MiB
    pub memory_mib: u32,
    /// 仅 Argon2：并行度（条带数）
    pub parallelism: u32,
}

impl Default for KdfConfig {
    fn default() -> Self {
        // Bitwarden/Vaultwarden 的默认值
        KdfConfig { kdf_type: 0, iterations: 600_000, memory_mib: 64, parallelism: 4 }
    }
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

/// 解密 Bitwarden 密文为原始字节。
///
/// 前缀类型：`2.` = AesCbc256_HmacSha256_B64（MAC 用 macKey），
/// `0.` = AesCbc256_B64（MAC 用 encKey）；无前缀时按 2 处理。
/// 注意：账号 userKey 是 64 字节**二进制**，不能强制按 UTF-8 处理。
fn decrypt_from_bw_bytes(enc_key: &[u8], mac_key: &[u8], value: &str) -> Result<Vec<u8>, String> {
    let text = value.trim();
    let (enc_type, body) = match text.find('.') {
        Some(index) => (text[..index].parse::<u8>().unwrap_or(2), &text[index + 1..]),
        None => (2u8, text),
    };
    let parts: Vec<&str> = body.split('|').collect();
    if parts.len() < 3 {
        return Err("BAD_CIPHER_FORMAT".to_string());
    }
    let iv = B64.decode(parts[0]).map_err(|_| "BAD_IV".to_string())?;
    let ct = B64.decode(parts[1]).map_err(|_| "BAD_CT".to_string())?;
    let mac = B64.decode(parts[2]).map_err(|_| "BAD_MAC".to_string())?;
    let mac_key_used = if enc_type == 0 { enc_key } else { mac_key };
    let mut mac_input = iv.clone();
    mac_input.extend_from_slice(&ct);
    if !constant_time_eq(&hmac_sha256(mac_key_used, &mac_input), &mac) {
        return Err("BW_MAC_MISMATCH".to_string());
    }
    aes_cbc_decrypt(enc_key, &iv, &ct)
}

/// 解密 Bitwarden 密文为文本（条目字段用）
fn decrypt_from_bw(enc_key: &[u8], mac_key: &[u8], value: &str) -> Result<String, String> {
    let bytes = decrypt_from_bw_bytes(enc_key, mac_key, value)?;
    String::from_utf8(bytes).map_err(|_| "INVALID_UTF8".to_string())
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

async fn prelogin(base: &str, email: &str) -> Result<KdfConfig, String> {
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
    let kdf_type = body.get("kdf").and_then(|v| v.as_u64()).unwrap_or(0);
    let iterations = body
        .get("kdfIterations")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(KdfConfig::default().iterations);
    let memory_mib = body
        .get("kdfMemory")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .filter(|v| *v > 0)
        .unwrap_or(KdfConfig::default().memory_mib);
    let parallelism = body
        .get("kdfParallelism")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .filter(|v| *v > 0)
        .unwrap_or(KdfConfig::default().parallelism);
    Ok(KdfConfig { kdf_type, iterations, memory_mib, parallelism })
}

/// 由主密码派生 32 字节主密钥（Argon2id 的 salt 与 PBKDF2 一样是 email 小写）
fn derive_master_key(password: &str, email: &str, kdf: &KdfConfig) -> Result<Vec<u8>, String> {
    let salt = email.to_lowercase();
    match kdf.kdf_type {
        0 => Ok(crypto::pbkdf2_sha256(
            password.as_bytes(),
            salt.as_bytes(),
            kdf.iterations.max(1),
            32,
        )),
        1 => {
            // Bitwarden 的 memory 单位是 MiB，argon2 crate 要 KiB
            let memory_kib = kdf.memory_mib.saturating_mul(1024);
            let params = argon2::Params::new(
                memory_kib,
                kdf.iterations.max(1),
                kdf.parallelism.max(1),
                Some(32),
            )
            .map_err(|e| format!("Argon2 参数无效：{e}"))?;
            let hasher = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
            let mut out = vec![0u8; 32];
            hasher
                .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut out)
                .map_err(|e| {
                    if salt.len() < 8 {
                        "邮箱地址过短，无法用于 Argon2 密钥派生，请使用完整注册邮箱".to_string()
                    } else {
                        format!("Argon2 派生失败：{e}")
                    }
                })?;
            Ok(out)
        }
        other => Err(format!("服务器使用了不支持的 KDF 类型：{other}")),
    }
}

async fn request_token(base: &str, form: Vec<(&'static str, String)>) -> Result<Value, String> {
    let url = format!("{base}/identity/connect/token");
    let response = client()?
        .post(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("无法连接服务器：{e}"))?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        // 把服务器给的具体原因带出来（Bitwarden 协议返回 {"error":…,"error_description":…}）
        let detail = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| {
                let err = v.get("error").and_then(|x| x.as_str()).unwrap_or("");
                let desc = v.get("error_description").and_then(|x| x.as_str()).unwrap_or("");
                let joined = format!("{err} {desc}").trim().to_string();
                if joined.is_empty() {
                    None
                } else {
                    Some(joined)
                }
            })
            .unwrap_or_else(|| text.chars().take(160).collect::<String>().replace('\n', " "));
        return Err(if status.as_u16() == 429 {
            "登录失败次数过多，服务器已临时限流，请稍后再试".to_string()
        } else {
            format!("登录失败（HTTP {}）：{detail}", status.as_u16())
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

    let kdf = prelogin(&base, &email).await?;
    let master_key = derive_master_key(password, &email, &kdf)?;
    let master_hash = crypto::pbkdf2_sha256(&master_key, password.as_bytes(), 1, 32);

    let device_id = uuid::Uuid::new_v4().to_string();
    // client_id / deviceType 与鸿蒙版（已验证可与 Vaultwarden 通信）保持一致
    let form = vec![
        ("grant_type", "password".to_string()),
        ("username", email.to_lowercase()),
        ("password", B64.encode(&master_hash)),
        ("scope", "api offline_access".to_string()),
        ("client_id", "web".to_string()),
        ("deviceType", "10".to_string()),
        ("deviceIdentifier", device_id),
        ("deviceName", "Mige".to_string()),
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
        let decrypted = decrypt_from_bw_bytes(&stretch_enc, &stretch_mac, key_value)
            .map_err(|e| format!("无法解密账号密钥（{e}）：请确认主密码正确"))?;
        // Vaultwarden 返回 64 字节原始 userKey（二进制，非 UTF-8）；官方云端可能是 base64 文本
        if decrypted.len() == 64 {
            decrypted
        } else {
            let text = String::from_utf8(decrypted).map_err(|_| "账号密钥格式不正确".to_string())?;
            B64.decode(text.trim()).map_err(|_| "账号密钥格式不正确".to_string())?
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
        kdf_iterations: kdf.iterations,
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
        ("client_id", "web".to_string()),
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
/// 构造 cipher 请求体（新建与更新共用）
fn cipher_payload(session: &BwSession, item: &VaultItem) -> Value {
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
    json!({
        "type": 1,
        "name": encrypt_field(session, &item.name),
        "notes": encrypt_field(session, &item.notes),
        "favorite": item.favorite,
        "encryptedFor": session.user_id,
        "login": login
    })
}

/// 发送 create / update 请求（401 时自动续期重试一次）
async fn send_cipher(
    session: &mut BwSession,
    method: reqwest::Method,
    url: String,
    payload: &Value,
) -> Result<Value, String> {
    let mut response = client()?
        .request(method.clone(), &url)
        .bearer_auth(&session.access_token)
        .json(payload)
        .send()
        .await
        .map_err(|e| format!("上传请求失败：{e}"))?;

    if response.status().as_u16() == 401 {
        refresh(session).await?;
        response = client()?
            .request(method, &url)
            .bearer_auth(&session.access_token)
            .json(payload)
            .send()
            .await
            .map_err(|e| format!("上传请求失败：{e}"))?;
    }
    if !response.status().is_success() {
        return Err(format!("上传失败（HTTP {}）", response.status().as_u16()));
    }
    Ok(response.json().await.unwrap_or(Value::Null))
}

/// 新建条目，返回服务端 id
pub async fn upload_item(session: &mut BwSession, item: &VaultItem) -> Result<String, String> {
    let payload = cipher_payload(session, item);
    let url = format!("{}/api/ciphers", session.server);
    let body = send_cipher(session, reqwest::Method::POST, url, &payload).await?;
    Ok(body.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string())
}

/// 更新已关联条目（本地改了账号/密码/网址后用它同步到服务器）
pub async fn update_item(session: &mut BwSession, item: &VaultItem) -> Result<String, String> {
    if item.bw_id.trim().is_empty() {
        return Err("该条目尚未关联服务器记录".to_string());
    }
    let payload = cipher_payload(session, item);
    let url = format!("{}/api/ciphers/{}", session.server, item.bw_id);
    let body = send_cipher(session, reqwest::Method::PUT, url, &payload).await?;
    let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
    Ok(if id.is_empty() { item.bw_id.clone() } else { id.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_master_key_matches_bitwarden_params() {
        // 与 Bitwarden/Vaultwarden 一致的参数：memory 单位为 MiB → KiB 传入 argon2
        let kdf = KdfConfig { kdf_type: 1, iterations: 6, memory_mib: 32, parallelism: 4 };
        let key = derive_master_key("test-master-pw", "user@example.com", &kdf).unwrap();
        assert_eq!(key.len(), 32);
        // 确定性：同样输入必须得到同样密钥
        assert_eq!(key, derive_master_key("test-master-pw", "user@example.com", &kdf).unwrap());
        // 大小写不敏感（salt 用 email 小写）
        assert_eq!(key, derive_master_key("test-master-pw", "user@EXAMPLE.com", &kdf).unwrap());
        // 换密码必然不同
        assert_ne!(key, derive_master_key("test-master-pw2", "user@example.com", &kdf).unwrap());
    }

    #[test]
    fn pbkdf2_and_argon2_are_distinct() {
        let pbkdf2 = derive_master_key(
            "pw",
            "tester@example.com",
            &KdfConfig { kdf_type: 0, iterations: 1000, memory_mib: 64, parallelism: 4 },
        )
        .unwrap();
        let argon2id = derive_master_key(
            "pw",
            "tester@example.com",
            &KdfConfig { kdf_type: 1, iterations: 3, memory_mib: 16, parallelism: 2 },
        )
        .unwrap();
        assert_eq!(pbkdf2.len(), 32);
        assert_eq!(argon2id.len(), 32);
        assert_ne!(pbkdf2, argon2id);
        // 未知 KDF 类型必须报错，而不是静默降级
        assert!(derive_master_key("pw", "tester@example.com", &KdfConfig { kdf_type: 2, ..Default::default() }).is_err());
    }

    #[test]
    fn missing_kdf_fields_fall_back_to_defaults() {
        let d = KdfConfig::default();
        assert_eq!(d.kdf_type, 0);
        assert_eq!(d.iterations, 600_000);
        assert_eq!(d.memory_mib, 64);
        assert_eq!(d.parallelism, 4);
    }

    /// 真实服务器联调（默认跳过，凭据只走环境变量，不入库）：
    /// ```powershell
    /// $env:BW_SERVER='https://vault.example.com'; $env:BW_EMAIL='me@example.com'; $env:BW_PASSWORD='…'
    /// cargo test --lib bw_live_login -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn bw_live_login() {
        let (Ok(server), Ok(email), Ok(password)) = (
            std::env::var("BW_SERVER"),
            std::env::var("BW_EMAIL"),
            std::env::var("BW_PASSWORD"),
        ) else {
            println!("未设置 BW_SERVER / BW_EMAIL / BW_PASSWORD，跳过联调");
            return;
        };
        match tauri::async_runtime::block_on(login(&server, &email, &password)) {
            Ok(session) => println!(
                "登录成功：user_id={} kdf_iterations={} user_key_len={}",
                session.user_id,
                session.kdf_iterations,
                session.user_key.len()
            ),
            Err(err) => panic!("登录失败：{err}"),
        }
    }

    #[test]
    fn bw_config_serde_uses_camel_case() {
        // 落盘用的是 serde_json，字段名必须是 camelCase，否则重启后 from_config 读不到
        let config = BitwardenConfig {
            server: "https://vault.example.com".to_string(),
            kdf_iterations: 600_000,
            user_key: "abc".to_string(),
            ..Default::default()
        };
        let value = serde_json::to_value(&config).unwrap();
        assert!(value.get("kdfIterations").is_some(), "缺少 kdfIterations");
        assert!(value.get("encKey").is_some(), "缺少 encKey");
        assert!(value.get("userKey").is_some(), "缺少 userKey");
        assert!(value.get("lastSyncAt").is_some(), "缺少 lastSyncAt");
        let back: BitwardenConfig = serde_json::from_value(value).unwrap();
        assert_eq!(back.kdf_iterations, 600_000);
        assert_eq!(back.user_key, "abc");
    }

    #[test]
    fn bw_config_roundtrip() {
        let session = BwSession {
            server: "https://vault.example.com".to_string(),
            email: "user@example.com".to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            kdf_iterations: 600_000,
            user_key: vec![7u8; 64],
            user_id: "user-uuid".to_string(),
            last_sync_at: 1234,
        };
        let config = session.to_config();
        assert_eq!(config.enc_key, B64.encode(&[7u8; 32]));
        assert_eq!(config.mac_key, B64.encode(&[7u8; 32]));
        assert_eq!(config.user_key, B64.encode(&[7u8; 64]));

        // 重启后从落盘配置恢复，userKey 与账号信息必须完全一致
        let restored = BwSession::from_config(&config).expect("应能从配置恢复会话");
        assert_eq!(restored.server, "https://vault.example.com");
        assert_eq!(restored.email, "user@example.com");
        assert_eq!(restored.user_key, vec![7u8; 64]);
        assert_eq!(restored.user_id, "user-uuid");
        assert_eq!(restored.last_sync_at, 1234);

        // 配置不完整时视为「未连接」，不能恢复出半残会话
        let mut broken = config.clone();
        broken.user_key = String::new();
        assert!(BwSession::from_config(&broken).is_none());
        let mut short_key = config.clone();
        short_key.user_key = B64.encode(&[1u8; 16]);
        assert!(BwSession::from_config(&short_key).is_none());
    }

    #[test]
    fn cipher_payload_encrypts_fields_for_create_and_update() {
        let session = BwSession {
            server: "https://vault.example.com".to_string(),
            email: "user@example.com".to_string(),
            access_token: "access".to_string(),
            refresh_token: String::new(),
            kdf_iterations: 600_000,
            user_key: vec![3u8; 64],
            user_id: "user-uuid".to_string(),
            last_sync_at: 0,
        };
        let mut item = VaultItem::default();
        item.name = "示例站点".to_string();
        item.username = "alice".to_string();
        item.password = "P@ss".to_string();
        item.url = "https://example.com".to_string();

        // 新建与更新共用同一份载荷，字段必须齐全且都加密过
        let payload = cipher_payload(&session, &item);
        assert_eq!(payload["type"], 1);
        assert_eq!(payload["encryptedFor"], "user-uuid");
        assert!(payload["name"].as_str().unwrap_or("").starts_with("2."));
        assert!(payload["login"]["password"].as_str().unwrap_or("").starts_with("2."));
        let enc = &session.user_key[..32];
        let mac = &session.user_key[32..];
        let plain = decrypt_from_bw(enc, mac, payload["name"].as_str().unwrap()).unwrap();
        assert_eq!(plain, "示例站点");
        let password = decrypt_from_bw(enc, mac, payload["login"]["password"].as_str().unwrap()).unwrap();
        assert_eq!(password, "P@ss");
    }

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

    /// 真实服务器联调：登录 + 拉取（默认跳过，凭据只走环境变量）
    #[test]
    #[ignore]
    fn bw_live_sync() {
        let (Ok(server), Ok(email), Ok(password)) = (
            std::env::var("BW_SERVER"),
            std::env::var("BW_EMAIL"),
            std::env::var("BW_PASSWORD"),
        ) else {
            println!("未设置 BW_SERVER / BW_EMAIL / BW_PASSWORD，跳过联调");
            return;
        };
        let mut session =
            tauri::async_runtime::block_on(login(&server, &email, &password)).expect("登录失败");

        // 先看服务器原始数据，确认「0 条」是库真的空，还是解析过滤掉了
        let raw = tauri::async_runtime::block_on(async {
            let resp = client()
                .unwrap()
                .get(format!("{}/api/sync", session.server))
                .bearer_auth(&session.access_token)
                .send()
                .await
                .unwrap();
            resp.json::<Value>().await.unwrap()
        });
        let ciphers = raw.get("ciphers").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        println!("服务器 ciphers 原始数量 = {}", ciphers.len());
        for cipher in ciphers.iter().take(6) {
            println!(
                "  type={:?} 名称密文长度={:?} 已删除={:?}",
                cipher.get("type").and_then(|v| v.as_i64()),
                cipher.get("name").and_then(|v| v.as_str()).map(|s| s.len()),
                cipher.get("deletedDate").and_then(|v| v.as_str())
            );
        }
        println!("folders 数量 = {:?}", raw.get("folders").and_then(|v| v.as_array()).map(|a| a.len()));

        let items = tauri::async_runtime::block_on(sync_vault(&mut session)).expect("拉取失败");
        println!("解析出 {} 条条目", items.len());
    }

    /// 真实服务器联调：上传一条测试条目 → 拉回校验 → 删除（默认跳过）
    #[test]
    #[ignore]
    fn bw_live_roundtrip() {
        let (Ok(server), Ok(email), Ok(password)) = (
            std::env::var("BW_SERVER"),
            std::env::var("BW_EMAIL"),
            std::env::var("BW_PASSWORD"),
        ) else {
            println!("未设置 BW_SERVER / BW_EMAIL / BW_PASSWORD，跳过联调");
            return;
        };
        let mut session =
            tauri::async_runtime::block_on(login(&server, &email, &password)).expect("登录失败");

        let mut item = VaultItem::default();
        item.id = "live-test".to_string();
        item.name = "密阁同步测试（可删）".to_string();
        item.username = "mige-test-user".to_string();
        item.password = "P@ssw0rd-测试123".to_string();
        item.url = "https://example.com".to_string();
        item.notes = "由联调测试自动创建，测试结束会删除".to_string();

        let bw_id = tauri::async_runtime::block_on(upload_item(&mut session, &item)).expect("上传失败");
        println!("上传成功 bw_id={bw_id}");

        let pulled = tauri::async_runtime::block_on(sync_vault(&mut session)).expect("拉取失败");
        println!("拉回 {} 条", pulled.len());
        match pulled.iter().find(|x| x.bw_id == bw_id) {
            Some(x) => println!(
                "校验通过：名称={:?} 账号={:?} 密码匹配={} 网址={:?}",
                x.name,
                x.username,
                x.password == item.password,
                x.url
            ),
            None => println!("警告：上传后未在拉取结果中找到该条目"),
        }

        // 模拟「本地修改账密后再同步」：走 update 分支（PUT），不能被当成新条目
        let mut changed = item.clone();
        changed.bw_id = bw_id.clone();
        changed.username = "mige-test-user-updated".to_string();
        changed.password = "N3w-P@ss-改".to_string();
        let updated_id =
            tauri::async_runtime::block_on(update_item(&mut session, &changed)).expect("更新失败");
        println!("更新成功 id={updated_id}（应与 {bw_id} 相同）");

        let after_update = tauri::async_runtime::block_on(sync_vault(&mut session)).expect("拉取失败");
        println!("更新后服务器共 {} 条（应仍为 1 条，说明是更新而非新建）", after_update.len());
        match after_update.iter().find(|x| x.bw_id == bw_id) {
            Some(x) => println!(
                "更新校验：账号={:?} 新密码生效={} 旧密码残留={}",
                x.username,
                x.password == changed.password,
                x.password == item.password
            ),
            None => println!("警告：更新后找不到该条目"),
        }

        // 清理测试数据
        let status = tauri::async_runtime::block_on(async {
            client()
                .unwrap()
                .delete(format!("{}/api/ciphers/{bw_id}", session.server))
                .bearer_auth(&session.access_token)
                .send()
                .await
                .map(|r| r.status().as_u16())
                .unwrap_or(0)
        });
        println!("删除测试条目 HTTP={status}");
        let after = tauri::async_runtime::block_on(sync_vault(&mut session)).expect("拉取失败");
        println!("清理后剩余 {} 条", after.len());
    }
}
