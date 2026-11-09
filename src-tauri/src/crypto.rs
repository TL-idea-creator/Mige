//! 加密层：SM4-128-CBC + HMAC-SM3（encrypt-then-MAC）与 PBKDF2-SHA256 派生。
//!
//! 参数与鸿蒙版 `crypto/CryptoEngine.ets` 严格一致，因此两边产物可以互读：
//! - 主密钥 32 字节：前 16 字节 SM4 加密密钥，后 16 字节 HMAC-SM3 密钥；
//! - 信封 = `{ iv, ct, mac }`（均为 base64），MAC 覆盖 `iv || ct`；
//! - KEK = PBKDF2-SHA256(管理密码, 16 字节 salt, 120000 次, 32 字节)。

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use sm3::Sm3;
use sm4::Sm4;

use crate::types::SealedBox;

type Sm4CbcEnc = cbc::Encryptor<Sm4>;
type Sm4CbcDec = cbc::Decryptor<Sm4>;
type HmacSm3 = Hmac<Sm3>;

pub const MASTER_KEY_LEN: usize = 32;
pub const PBKDF2_ITERATIONS: u32 = 120_000;
pub const SM4_BLOCK: usize = 16;

/// 加密库主密钥（32 字节）
pub struct VaultKey(pub [u8; MASTER_KEY_LEN]);

impl VaultKey {
    pub fn from_slice(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != MASTER_KEY_LEN {
            return Err("INVALID_KEY_LEN".to_string());
        }
        let mut key = [0u8; MASTER_KEY_LEN];
        key.copy_from_slice(raw);
        Ok(Self(key))
    }

    pub fn random() -> Self {
        let mut key = [0u8; MASTER_KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key);
        Self(key)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn b64_decode(text: &str) -> Result<Vec<u8>, String> {
    B64.decode(text.trim()).map_err(|e| format!("BASE64_DECODE_FAILED: {e}"))
}

/// PBKDF2-HMAC-SHA256
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut out);
    out
}

/// HMAC-SM3
pub fn hmac_sm3(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <HmacSm3 as Mac>::new_from_slice(key).expect("HMAC 接受任意长度密钥");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// 定长比较，避免提前返回带来的时序差异
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

/// 用主密钥加密任意字节，返回信封
pub fn seal(key: &VaultKey, plain: &[u8]) -> SealedBox {
    let iv = random_bytes(SM4_BLOCK);
    let enc_key = &key.0[0..16];
    let mac_key = &key.0[16..32];
    let ct = Sm4CbcEnc::new(enc_key.into(), iv.as_slice().into())
        .encrypt_padded_vec_mut::<Pkcs7>(plain);

    let mut mac_input = iv.clone();
    mac_input.extend_from_slice(&ct);
    let mac = hmac_sm3(mac_key, &mac_input);

    SealedBox { iv: b64_encode(&iv), ct: b64_encode(&ct), mac: b64_encode(&mac) }
}

/// 校验 MAC 后解密（校验失败返回错误，调用方据此判定密码错误或文件损坏）
pub fn open(key: &VaultKey, envelope: &SealedBox) -> Result<Vec<u8>, String> {
    let iv = b64_decode(&envelope.iv)?;
    let ct = b64_decode(&envelope.ct)?;
    let mac = b64_decode(&envelope.mac)?;
    if iv.len() != SM4_BLOCK {
        return Err("INVALID_IV".to_string());
    }

    let mac_key = &key.0[16..32];
    let mut mac_input = iv.clone();
    mac_input.extend_from_slice(&ct);
    let expected = hmac_sm3(mac_key, &mac_input);
    if !constant_time_eq(&expected, &mac) {
        return Err("SM4_MAC_MISMATCH".to_string());
    }

    let enc_key = &key.0[0..16];
    Sm4CbcDec::new(enc_key.into(), iv.as_slice().into())
        .decrypt_padded_vec_mut::<Pkcs7>(&ct)
        .map_err(|_| "SM4_DECRYPT_FAILED".to_string())
}

pub fn seal_text(key: &VaultKey, plain: &str) -> SealedBox {
    seal(key, plain.as_bytes())
}

pub fn open_text(key: &VaultKey, envelope: &SealedBox) -> Result<String, String> {
    let bytes = open(key, envelope)?;
    String::from_utf8(bytes).map_err(|_| "INVALID_UTF8".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = VaultKey::random();
        let text = "密阁 SM4 往返测试 🔐";
        let boxed = seal_text(&key, text);
        assert_eq!(open_text(&key, &boxed).unwrap(), text);
    }

    #[test]
    fn tampered_mac_fails() {
        let key = VaultKey::random();
        let mut boxed = seal_text(&key, "secret");
        boxed.mac = b64_encode(&[0u8; 32]);
        assert!(open_text(&key, &boxed).is_err());
    }

    #[test]
    fn pbkdf2_is_deterministic() {
        let salt = b"0123456789abcdef";
        let a = pbkdf2_sha256(b"Master@123", salt, 1000, 32);
        let b = pbkdf2_sha256(b"Master@123", salt, 1000, 32);
        let c = pbkdf2_sha256(b"Master@124", salt, 1000, 32);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
