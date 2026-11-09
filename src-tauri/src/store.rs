//! 本地存储：`meta.json`（盐、包裹后的主密钥、设置）与 `vault.dat`（加密库）。
//!
//! 文件格式与鸿蒙版一致：
//! - `vault.dat` = `{"v":1,"iv":"…","ct":"…","mac":"…"}`
//! - `meta.json` 保存 PBKDF2 参数与「用 KEK 包裹的主密钥」

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::crypto::{self, VaultKey, PBKDF2_ITERATIONS};
use crate::types::{SealedBox, VaultData};

pub const DEFAULT_AUTO_LOCK_MINUTES: u32 = 5;
pub const DEFAULT_LANG: &str = "zh";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Meta {
    pub initialized: bool,
    pub salt: String,
    pub iterations: u32,
    pub wrap_iv: String,
    pub wrap_ct: String,
    pub wrap_mac: String,
    pub auto_lock_minutes: u32,
    pub lang: String,
}

impl Default for Meta {
    fn default() -> Self {
        Self {
            initialized: false,
            salt: String::new(),
            iterations: PBKDF2_ITERATIONS,
            wrap_iv: String::new(),
            wrap_ct: String::new(),
            wrap_mac: String::new(),
            auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
            lang: DEFAULT_LANG.to_string(),
        }
    }
}

impl Meta {
    pub fn wrapped(&self) -> Option<SealedBox> {
        if self.wrap_iv.is_empty() || self.wrap_ct.is_empty() || self.wrap_mac.is_empty() {
            return None;
        }
        Some(SealedBox { iv: self.wrap_iv.clone(), ct: self.wrap_ct.clone(), mac: self.wrap_mac.clone() })
    }

    pub fn set_wrapped(&mut self, salt: &[u8], iterations: u32, boxed: &SealedBox) {
        self.salt = crypto::b64_encode(salt);
        self.iterations = iterations;
        self.wrap_iv = boxed.iv.clone();
        self.wrap_ct = boxed.ct.clone();
        self.wrap_mac = boxed.mac.clone();
    }
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        let _ = fs::create_dir_all(&dir);
        Self { dir }
    }

    pub fn dir(&self) -> &PathBuf {
        &self.dir
    }

    fn meta_path(&self) -> PathBuf {
        self.dir.join("meta.json")
    }

    fn vault_path(&self) -> PathBuf {
        self.dir.join("vault.dat")
    }

    pub fn load_meta(&self) -> Meta {
        fs::read_to_string(self.meta_path())
            .ok()
            .and_then(|text| serde_json::from_str::<Meta>(&text).ok())
            .unwrap_or_default()
    }

    pub fn save_meta(&self, meta: &Meta) -> Result<(), String> {
        let text = serde_json::to_string_pretty(meta).map_err(|e| e.to_string())?;
        fs::write(self.meta_path(), text).map_err(|e| format!("WRITE_META_FAILED: {e}"))
    }

    /// 读取并解密整个库；文件不存在时返回空库
    pub fn load_vault(&self, key: &VaultKey) -> Result<VaultData, String> {
        let path = self.vault_path();
        if !path.exists() {
            return Ok(VaultData::default());
        }
        let text = fs::read_to_string(&path).map_err(|e| format!("READ_VAULT_FAILED: {e}"))?;
        if text.trim().is_empty() {
            return Ok(VaultData::default());
        }
        let envelope: SealedBox =
            serde_json::from_str(&text).map_err(|e| format!("BAD_VAULT_ENVELOPE: {e}"))?;
        let plain = crypto::open_text(key, &envelope)?;
        serde_json::from_str(&plain).map_err(|e| format!("BAD_VAULT_JSON: {e}"))
    }

    /// 序列化 → 加密 → 写盘
    pub fn save_vault(&self, key: &VaultKey, data: &VaultData) -> Result<(), String> {
        let plain = serde_json::to_string(data).map_err(|e| e.to_string())?;
        let boxed = crypto::seal_text(key, &plain);
        let envelope = serde_json::json!({
            "v": 1,
            "iv": boxed.iv,
            "ct": boxed.ct,
            "mac": boxed.mac
        });
        fs::write(self.vault_path(), serde_json::to_string_pretty(&envelope).map_err(|e| e.to_string())?)
            .map_err(|e| format!("WRITE_VAULT_FAILED: {e}"))
    }

    pub fn vault_exists(&self) -> bool {
        self.vault_path().exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("mige-test-{}", uuid::Uuid::new_v4()));
        let store = Store::new(dir.clone());
        let key = VaultKey::random();
        let mut data = VaultData::default();
        let mut item = crate::types::VaultItem::default();
        item.id = "a1".into();
        item.name = "示例站点".into();
        item.password = "P@ssw0rd!".into();
        data.items.push(item);

        store.save_vault(&key, &data).unwrap();
        let loaded = store.load_vault(&key).unwrap();
        assert_eq!(loaded.items.len(), 1);
        assert_eq!(loaded.items[0].name, "示例站点");

        // 错误密钥必须失败
        assert!(store.load_vault(&VaultKey::random()).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
