//! 数据模型：字段名与鸿蒙版 `common/Types.ets` 完全一致（camelCase），
//! 保证 vault.dat 与加密备份可以在两个平台之间互相读取。

use serde::{Deserialize, Serialize};

/// 加密信封：SM4-CBC 密文 + HMAC-SM3 校验值（base64）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SealedBox {
    pub iv: String,
    pub ct: String,
    pub mac: String,
}

/// TOTP（MFA）配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TotpConfig {
    pub secret: String,
    pub issuer: String,
    pub account: String,
    pub algorithm: String,
    pub digits: u32,
    pub period: u32,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            secret: String::new(),
            issuer: String::new(),
            account: String::new(),
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
        }
    }
}

/// 一条密码库记录
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VaultItem {
    pub id: String,
    pub name: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub app_name: String,
    pub notes: String,
    pub folder: String,
    pub favorite: bool,
    pub totp: Option<TotpConfig>,
    pub created_at: i64,
    pub updated_at: i64,
    pub bw_id: String,
}

impl Default for VaultItem {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            app_name: String::new(),
            notes: String::new(),
            folder: String::new(),
            favorite: false,
            totp: None,
            created_at: 0,
            updated_at: 0,
            bw_id: String::new(),
        }
    }
}

/// 库设置（Bitwarden 配置本轮不透传解析，原样保存以免丢字段）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VaultSettings {
    pub bitwarden: Option<serde_json::Value>,
    pub auto_lock_minutes: u32,
    pub quick_unlock: bool,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self { bitwarden: None, auto_lock_minutes: 5, quick_unlock: false }
    }
}

/// 加密库明文结构
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct VaultData {
    pub items: Vec<VaultItem>,
    pub settings: VaultSettings,
}

impl Default for VaultData {
    fn default() -> Self {
        Self { items: Vec::new(), settings: VaultSettings::default() }
    }
}

/// 密码生成规则（与鸿蒙版 PasswordRule 一致）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PasswordRule {
    pub length: usize,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordRule {
    fn default() -> Self {
        Self { length: 16, upper: true, lower: true, digits: true, symbols: true, exclude_ambiguous: false }
    }
}

/// 导入结果
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportOutcome {
    pub items: Vec<VaultItem>,
    pub format: String,
    pub error: String,
}

impl ImportOutcome {
    pub fn empty(format: &str) -> Self {
        Self { items: Vec::new(), format: format.to_string(), error: String::new() }
    }
    pub fn failed(format: &str, error: &str) -> Self {
        Self { items: Vec::new(), format: format.to_string(), error: error.to_string() }
    }
}
