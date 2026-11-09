//! 导入导出：格式与鸿蒙版 `service/TransferService.ets` 保持一致，
//! 因此两边的加密备份、JSON、CSV、otpauth 清单可以互相导入。

use serde_json::Value;

use crate::crypto::{self, VaultKey, PBKDF2_ITERATIONS};
use crate::types::{ImportOutcome, TotpConfig, VaultData, VaultItem};
use crate::totp;

pub const FORMAT_MIGE_ENCRYPTED: &str = "mige-encrypted";
pub const FORMAT_MIGE_JSON: &str = "mige-json";
pub const FORMAT_BITWARDEN_JSON: &str = "bitwarden-json";
pub const FORMAT_BITWARDEN_CSV: &str = "bitwarden-csv";
pub const FORMAT_OTPAUTH: &str = "otpauth";
pub const FORMAT_UNKNOWN: &str = "unknown";

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn new_item() -> VaultItem {
    VaultItem {
        id: uuid::Uuid::new_v4().to_string().chars().take(8).collect(),
        created_at: now_ms(),
        updated_at: now_ms(),
        ..Default::default()
    }
}

fn totp_uri(item: &VaultItem) -> String {
    match &item.totp {
        Some(cfg) if !cfg.secret.is_empty() => totp::build_otpauth(cfg),
        _ => String::new(),
    }
}

fn escape_csv(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// 按「引号外的换行」切分 CSV 记录（字段内换行不会被拆行）
fn split_csv_records(text: &str) -> Vec<String> {
    let mut records = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            '\r' if !in_quotes => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                records.push(std::mem::take(&mut current));
            }
            '\n' if !in_quotes => records.push(std::mem::take(&mut current)),
            other => current.push(other),
        }
    }
    if !current.is_empty() {
        records.push(current);
    }
    records
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    in_quotes = false;
                }
            }
            '"' => in_quotes = true,
            ',' if !in_quotes => fields.push(std::mem::take(&mut current)),
            other => current.push(other),
        }
    }
    fields.push(current);
    fields
}

/// 密阁明文 JSON
pub fn export_mige_json(data: &VaultData) -> String {
    let items: Vec<Value> = data
        .items
        .iter()
        .map(|item| {
            serde_json::json!({
                "name": item.name,
                "username": item.username,
                "password": item.password,
                "url": item.url,
                "appName": item.app_name,
                "notes": item.notes,
                "folder": item.folder,
                "favorite": item.favorite,
                "totp": totp_uri(item)
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "app": "mige",
        "version": 1,
        "items": items
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

/// Bitwarden / Vaultwarden 兼容 JSON
pub fn export_bitwarden_json(data: &VaultData) -> String {
    let items: Vec<Value> = data
        .items
        .iter()
        .map(|item| {
            let uris = if item.url.is_empty() {
                Vec::new()
            } else {
                vec![serde_json::json!({ "uri": item.url })]
            };
            let totp_value = if item.totp.is_some() { Value::String(totp_uri(item)) } else { Value::Null };
            serde_json::json!({
                "type": 1,
                "name": item.name,
                "notes": item.notes,
                "favorite": item.favorite,
                "login": {
                    "uris": uris,
                    "username": item.username,
                    "password": item.password,
                    "totp": totp_value
                }
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "encrypted": false,
        "folders": [],
        "items": items
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

/// Bitwarden 兼容 CSV
pub fn export_csv(data: &VaultData) -> String {
    let mut out = String::from(
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n",
    );
    for item in &data.items {
        let row = [
            escape_csv(&item.folder),
            if item.favorite { "1".to_string() } else { String::new() },
            "login".to_string(),
            escape_csv(&item.name),
            escape_csv(&item.notes),
            String::new(),
            String::new(),
            escape_csv(&item.url),
            escape_csv(&item.username),
            escape_csv(&item.password),
            escape_csv(&totp_uri(item)),
        ];
        out.push_str(&row.join(","));
        out.push('\n');
    }
    out
}

/// otpauth 链接清单
pub fn export_otpauth_list(data: &VaultData) -> String {
    let mut out = String::new();
    for item in &data.items {
        let uri = totp_uri(item);
        if !uri.is_empty() {
            out.push_str(&uri);
            out.push('\n');
        }
    }
    out
}

/// 加密备份（PBKDF2 派生 KEK + SM4-CBC + HMAC-SM3）
pub fn export_encrypted(data: &VaultData, password: &str) -> Result<String, String> {
    let salt = crypto::random_bytes(16);
    let kek_raw = crypto::pbkdf2_sha256(password.as_bytes(), &salt, PBKDF2_ITERATIONS, 32);
    let kek = VaultKey::from_slice(&kek_raw)?;
    let plain = serde_json::to_string(data).map_err(|e| e.to_string())?;
    let boxed = crypto::seal_text(&kek, &plain);

    Ok(serde_json::to_string_pretty(&serde_json::json!({
        "app": "mige",
        "version": 1,
        "kdf": "PBKDF2-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": crypto::b64_encode(&salt),
        "box": { "iv": boxed.iv, "ct": boxed.ct, "mac": boxed.mac }
    }))
    .map_err(|e| e.to_string())?)
}

/// 识别备份/导入文件的格式
pub fn detect_format(text: &str) -> &'static str {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return FORMAT_UNKNOWN;
    }
    if trimmed.starts_with("otpauth://") {
        return FORMAT_OTPAUTH;
    }
    if trimmed.starts_with('{') {
        if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
            if parsed.get("box").is_some() {
                return FORMAT_MIGE_ENCRYPTED;
            }
            if parsed.get("encrypted").is_some() {
                return FORMAT_BITWARDEN_JSON;
            }
            if parsed.get("app").is_some() {
                return FORMAT_MIGE_JSON;
            }
            if parsed.get("items").is_some() {
                return FORMAT_BITWARDEN_JSON;
            }
        }
        return FORMAT_UNKNOWN;
    }
    let first_line = trimmed.lines().next().unwrap_or("");
    if first_line.contains("login_password") || (first_line.contains("name") && first_line.contains(',')) {
        return FORMAT_BITWARDEN_CSV;
    }
    FORMAT_UNKNOWN
}

fn parse_mige_json(text: &str) -> Result<Vec<VaultItem>, String> {
    let parsed: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let mut items = Vec::new();
    let Some(list) = parsed.get("items").and_then(|v| v.as_array()) else {
        return Ok(items);
    };
    for raw in list {
        let mut item = new_item();
        item.name = raw.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        item.username = raw.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string();
        item.password = raw.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string();
        item.url = raw.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
        item.app_name = raw.get("appName").and_then(|v| v.as_str()).unwrap_or("").to_string();
        item.notes = raw.get("notes").and_then(|v| v.as_str()).unwrap_or("").to_string();
        item.folder = raw.get("folder").and_then(|v| v.as_str()).unwrap_or("").to_string();
        item.favorite = raw.get("favorite").and_then(|v| v.as_bool()).unwrap_or(false);
        if let Some(uri) = raw.get("totp").and_then(|v| v.as_str()) {
            if !uri.is_empty() {
                item.totp = totp::parse_otpauth(uri);
            }
        }
        items.push(item);
    }
    Ok(items)
}

fn parse_bitwarden_json(text: &str) -> Result<Vec<VaultItem>, String> {
    let parsed: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let mut items = Vec::new();
    let Some(list) = parsed.get("items").and_then(|v| v.as_array()) else {
        return Ok(items);
    };
    for raw in list {
        let kind = raw.get("type").map(|v| v.to_string()).unwrap_or_else(|| "1".to_string());
        if kind.trim_matches('"') != "1" {
            continue;
        }
        let mut item = new_item();
        item.name = raw.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        item.notes = raw.get("notes").and_then(|v| v.as_str()).unwrap_or("").to_string();
        item.favorite = raw.get("favorite").and_then(|v| v.as_bool()).unwrap_or(false);
        if let Some(login) = raw.get("login") {
            item.username = login.get("username").and_then(|v| v.as_str()).unwrap_or("").to_string();
            item.password = login.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if let Some(uris) = login.get("uris").and_then(|v| v.as_array()) {
                if let Some(first) = uris.first() {
                    item.url = first.get("uri").and_then(|v| v.as_str()).unwrap_or("").to_string();
                }
            }
            if let Some(uri) = login.get("totp").and_then(|v| v.as_str()) {
                if !uri.is_empty() {
                    item.totp = totp::parse_otpauth(uri);
                }
            }
        }
        items.push(item);
    }
    Ok(items)
}

fn parse_csv(text: &str) -> Vec<VaultItem> {
    let mut items = Vec::new();
    let records = split_csv_records(text);
    if records.len() < 2 {
        return items;
    }
    let header = parse_csv_line(&records[0]);
    let idx = |name: &str| header.iter().position(|h| h == name);
    let (i_folder, i_name, i_notes) = (idx("folder"), idx("name"), idx("notes"));
    let (i_uri, i_user, i_pass, i_totp) = (idx("login_uri"), idx("login_username"), idx("login_password"), idx("login_totp"));
    let (i_type, i_fav) = (idx("type"), idx("favorite"));

    for record in records.iter().skip(1) {
        if record.trim().is_empty() {
            continue;
        }
        let cells = parse_csv_line(record);
        let cell = |pos: Option<usize>| pos.and_then(|p| cells.get(p)).cloned().unwrap_or_default();
        if let Some(pos) = i_type {
            let kind = cells.get(pos).cloned().unwrap_or_default();
            if !kind.is_empty() && kind != "login" {
                continue;
            }
        }
        let mut item = new_item();
        item.folder = cell(i_folder);
        item.name = cell(i_name);
        item.notes = cell(i_notes);
        item.url = cell(i_uri);
        item.username = cell(i_user);
        item.password = cell(i_pass);
        item.favorite = matches!(cell(i_fav).to_lowercase().as_str(), "1" | "true");
        let totp_text = cell(i_totp);
        if !totp_text.is_empty() {
            item.totp = totp::parse_otpauth(&totp_text);
        }
        items.push(item);
    }
    items
}

fn parse_otpauth_text(text: &str) -> Vec<VaultItem> {
    let mut items = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("otpauth://") {
            continue;
        }
        let Some(cfg) = totp::parse_otpauth(trimmed) else { continue };
        let mut item = new_item();
        item.name = if !cfg.issuer.is_empty() {
            cfg.issuer.clone()
        } else if !cfg.account.is_empty() {
            cfg.account.clone()
        } else {
            "验证码".to_string()
        };
        item.username = cfg.account.clone();
        item.totp = Some(cfg);
        items.push(item);
    }
    items
}

/// 导入明文格式
pub fn import_plain(text: &str, format: &str) -> ImportOutcome {
    let parsed: Result<Vec<VaultItem>, String> = match format {
        FORMAT_MIGE_JSON => parse_mige_json(text),
        FORMAT_BITWARDEN_JSON => parse_bitwarden_json(text),
        FORMAT_BITWARDEN_CSV => Ok(parse_csv(text)),
        FORMAT_OTPAUTH => Ok(parse_otpauth_text(text)),
        _ => return ImportOutcome::failed(format, "无法识别的文件格式"),
    };
    match parsed {
        Ok(items) => ImportOutcome { items, format: format.to_string(), error: String::new() },
        Err(e) => ImportOutcome::failed(format, &format!("解析失败：{e}")),
    }
}

/// 解密并导入密阁加密备份
pub fn import_encrypted(text: &str, password: &str) -> ImportOutcome {
    let parsed: Result<VaultData, String> = (|| {
        let header: Value = serde_json::from_str(text).map_err(|_| "备份文件格式不正确".to_string())?;
        let boxed = header.get("box").ok_or_else(|| "备份文件格式不正确".to_string())?;
        let salt = header
            .get("salt")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "备份文件格式不正确".to_string())?;
        let iterations = header
            .get("iterations")
            .and_then(|v| v.as_u64())
            .unwrap_or(PBKDF2_ITERATIONS as u64) as u32;
        let salt_bytes = crypto::b64_decode(salt)?;
        let envelope = crate::types::SealedBox {
            iv: boxed.get("iv").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            ct: boxed.get("ct").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            mac: boxed.get("mac").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        };
        let kek_raw = crypto::pbkdf2_sha256(password.as_bytes(), &salt_bytes, iterations, 32);
        let kek = VaultKey::from_slice(&kek_raw)?;
        let plain = crypto::open_text(&kek, &envelope).map_err(|_| "密码错误".to_string())?;
        serde_json::from_str::<VaultData>(&plain).map_err(|_| "备份内容损坏".to_string())
    })();

    match parsed {
        Ok(data) => ImportOutcome { items: data.items, format: FORMAT_MIGE_ENCRYPTED.to_string(), error: String::new() },
        Err(_) => ImportOutcome::failed(FORMAT_MIGE_ENCRYPTED, "备份密码错误或文件已损坏"),
    }
}

/// 生成 totp（供测试与前端构造链接）
pub fn make_totp(secret: &str, issuer: &str, account: &str) -> TotpConfig {
    TotpConfig {
        secret: secret.to_string(),
        issuer: issuer.to_string(),
        account: account.to_string(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VaultData {
        let mut data = VaultData::default();
        let mut item = new_item();
        item.name = "淘宝, 购物".into();
        item.username = "tl@a.b".into();
        item.password = "aB3$kL9#\"x\"".into();
        item.url = "https://www.taobao.com".into();
        item.app_name = "淘宝".into();
        item.notes = "第一行\n第二行,\"带逗号\"".into();
        item.folder = "购物".into();
        item.favorite = true;
        item.totp = Some(make_totp("JBSWY3DPEHPK3PXP", "GitHub", "tl@a.b"));
        let mut plain = new_item();
        plain.name = "PlainItem".into();
        data.items.push(item);
        data.items.push(plain);
        data
    }

    #[test]
    fn mige_json_roundtrip() {
        let text = export_mige_json(&sample());
        assert_eq!(detect_format(&text), FORMAT_MIGE_JSON);
        let outcome = import_plain(&text, FORMAT_MIGE_JSON);
        assert!(outcome.error.is_empty());
        assert_eq!(outcome.items.len(), 2);
        assert_eq!(outcome.items[0].name, "淘宝, 购物");
        assert!(outcome.items[0].totp.is_some());
    }

    #[test]
    fn csv_keeps_multiline_fields() {
        let text = export_csv(&sample());
        assert_eq!(detect_format(&text), FORMAT_BITWARDEN_CSV);
        let outcome = import_plain(&text, FORMAT_BITWARDEN_CSV);
        assert_eq!(outcome.items.len(), 2);
        assert_eq!(outcome.items[0].notes, "第一行\n第二行,\"带逗号\"");
        assert!(outcome.items[0].favorite);
    }

    #[test]
    fn encrypted_backup_roundtrip() {
        let text = export_encrypted(&sample(), "Backup@123").unwrap();
        assert_eq!(detect_format(&text), FORMAT_MIGE_ENCRYPTED);
        assert!(!text.contains("aB3$kL9"));
        let ok = import_encrypted(&text, "Backup@123");
        assert!(ok.error.is_empty());
        assert_eq!(ok.items.len(), 2);
        let bad = import_encrypted(&text, "Wrong@123");
        assert!(bad.items.is_empty());
        assert!(!bad.error.is_empty());
    }

    #[test]
    fn otpauth_list_export_and_parse() {
        let text = export_otpauth_list(&sample());
        assert_eq!(detect_format(&text), FORMAT_OTPAUTH);
        let outcome = import_plain(&text, FORMAT_OTPAUTH);
        assert_eq!(outcome.items.len(), 1);
        assert!(outcome.items[0].totp.is_some());
    }

    #[test]
    fn malformed_json_is_safe() {
        let outcome = import_plain("{\"items\": \"not-an-array\"}", FORMAT_BITWARDEN_JSON);
        assert_eq!(outcome.items.len(), 0);
        assert_eq!(detect_format("hello"), FORMAT_UNKNOWN);
    }
}
