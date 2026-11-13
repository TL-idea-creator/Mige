//! 密阁 Windows 版（Tauri 2 后端）。
//!
//! 职责：持有主密钥与明文库数据的会话、加密落盘、密码生成、TOTP 计算、
//! 导入导出，以及与鸿蒙版完全一致的存储/备份格式。

mod bitwarden;
mod crypto;
mod password;
mod store;
mod totp;
mod transfer;
mod types;

use std::sync::Mutex;

use serde::Serialize;
use tauri::{Manager, State};

use crate::crypto::{VaultKey, PBKDF2_ITERATIONS};
use crate::store::{Store, DEFAULT_AUTO_LOCK_MINUTES, DEFAULT_LANG};
use crate::types::{ImportOutcome, PasswordRule, TotpConfig, VaultData, VaultItem};

/// 最小管理密码长度（与鸿蒙版一致）
const MIN_MASTER_LENGTH: usize = 8;

/// 会话：主密钥与明文库数据只在内存中，锁定即清空
struct Session {
    key: Option<VaultKey>,
    data: Option<VaultData>,
}

impl Session {
    fn locked() -> Self {
        Self { key: None, data: None }
    }
}

pub struct AppState {
    store: Store,
    session: Mutex<Session>,
    /// Vaultwarden 同步会话（仅内存，锁定时一并清空）
    bw: Mutex<Option<bitwarden::BwSession>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    initialized: bool,
    unlocked: bool,
    auto_lock_minutes: u32,
    lang: String,
    version: String,
    data_dir: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PasswordResult {
    password: String,
    strength: u32,
    candidates: usize,
}

fn validate_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_MASTER_LENGTH {
        return Err(format!("密码至少需要 {MIN_MASTER_LENGTH} 位"));
    }
    Ok(())
}

#[tauri::command]
fn app_info(state: State<AppState>) -> AppInfo {
    let meta = state.store.load_meta();
    let unlocked = state.session.lock().map(|s| s.key.is_some()).unwrap_or(false);
    AppInfo {
        initialized: meta.initialized && meta.wrapped().is_some(),
        unlocked,
        auto_lock_minutes: meta.auto_lock_minutes,
        lang: if meta.lang.is_empty() { DEFAULT_LANG.to_string() } else { meta.lang },
        version: env!("CARGO_PKG_VERSION").to_string(),
        data_dir: state.store.dir().to_string_lossy().to_string(),
    }
}

/// 首次创建密码库：随机主密钥用「管理密码派生的 KEK」包裹后保存
#[tauri::command]
fn setup_vault(state: State<AppState>, password: String) -> Result<VaultData, String> {
    validate_password(&password)?;

    let mut meta = state.store.load_meta();
    if meta.initialized {
        return Err("LIBRARY_ALREADY_EXISTS".to_string());
    }

    let salt = crypto::random_bytes(16);
    let kek_raw = crypto::pbkdf2_sha256(password.as_bytes(), &salt, PBKDF2_ITERATIONS, 32);
    let kek = VaultKey::from_slice(&kek_raw)?;
    let master = VaultKey::random();
    let wrapped = crypto::seal(&kek, master.as_slice());

    meta.set_wrapped(&salt, PBKDF2_ITERATIONS, &wrapped);
    meta.initialized = true;
    if meta.auto_lock_minutes == 0 {
        meta.auto_lock_minutes = DEFAULT_AUTO_LOCK_MINUTES;
    }
    state.store.save_meta(&meta)?;

    let data = VaultData::default();
    state.store.save_vault(&master, &data)?;

    let mut session = state.session.lock().map_err(|_| "STATE_LOCK_FAILED".to_string())?;
    *session = Session { key: Some(master), data: Some(data.clone()) };
    Ok(data)
}

/// 用管理密码解锁；密码是否正确由 HMAC-SM3 校验判定
#[tauri::command]
fn unlock(state: State<AppState>, password: String) -> Result<VaultData, String> {
    let meta = state.store.load_meta();
    let wrapped = meta.wrapped().ok_or_else(|| "NOT_INITIALIZED".to_string())?;
    let salt = crypto::b64_decode(&meta.salt)?;
    let iterations = if meta.iterations == 0 { PBKDF2_ITERATIONS } else { meta.iterations };
    let kek_raw = crypto::pbkdf2_sha256(password.as_bytes(), &salt, iterations, 32);
    let kek = VaultKey::from_slice(&kek_raw)?;
    let master_raw = crypto::open(&kek, &wrapped).map_err(|_| "BAD_PASSWORD".to_string())?;
    let master = VaultKey::from_slice(&master_raw)?;
    let data = state.store.load_vault(&master)?;

    let mut session = state.session.lock().map_err(|_| "STATE_LOCK_FAILED".to_string())?;
    *session = Session { key: Some(master), data: Some(data.clone()) };
    drop(session);

    // 解锁后恢复 Vaultwarden 会话（配置随密码库加密保存，重启后不必重新登录）
    let restored = data
        .settings
        .bitwarden
        .as_ref()
        .and_then(|v| serde_json::from_value::<bitwarden::BitwardenConfig>(v.clone()).ok())
        .and_then(|cfg| bitwarden::BwSession::from_config(&cfg));
    if let Ok(mut guard) = state.bw.lock() {
        *guard = restored;
    }
    Ok(data)
}

#[tauri::command]
fn lock(state: State<AppState>) -> Result<(), String> {
    let mut session = state.session.lock().map_err(|_| "STATE_LOCK_FAILED".to_string())?;
    *session = Session::locked();
    drop(session);
    // 锁定后一并丢弃同步会话（配置仍留在加密库里，下次解锁自动恢复）
    if let Ok(mut guard) = state.bw.lock() {
        *guard = None;
    }
    Ok(())
}

/// 前端修改条目后整体回传，这里加密落盘（未解锁时拒绝）
#[tauri::command]
fn save_vault(state: State<AppState>, data: VaultData) -> Result<(), String> {
    let mut session = state.session.lock().map_err(|_| "STATE_LOCK_FAILED".to_string())?;
    let key = session.key.as_ref().ok_or_else(|| "LOCKED".to_string())?;
    state.store.save_vault(key, &data)?;
    session.data = Some(data);
    Ok(())
}

/// 改管理密码：解出主密钥后用新密码重新包裹（库文件内容不变）
#[tauri::command]
fn change_password(
    state: State<AppState>,
    old_password: String,
    new_password: String,
) -> Result<(), String> {
    validate_password(&new_password)?;
    let mut meta = state.store.load_meta();
    let wrapped = meta.wrapped().ok_or_else(|| "NOT_INITIALIZED".to_string())?;
    let salt = crypto::b64_decode(&meta.salt)?;
    let iterations = if meta.iterations == 0 { PBKDF2_ITERATIONS } else { meta.iterations };

    let old_kek_raw = crypto::pbkdf2_sha256(old_password.as_bytes(), &salt, iterations, 32);
    let old_kek = VaultKey::from_slice(&old_kek_raw)?;
    let master_raw = crypto::open(&old_kek, &wrapped).map_err(|_| "BAD_PASSWORD".to_string())?;

    let new_salt = crypto::random_bytes(16);
    let new_kek_raw = crypto::pbkdf2_sha256(new_password.as_bytes(), &new_salt, PBKDF2_ITERATIONS, 32);
    let new_kek = VaultKey::from_slice(&new_kek_raw)?;
    let re_wrapped = crypto::seal(&new_kek, &master_raw);
    meta.set_wrapped(&new_salt, PBKDF2_ITERATIONS, &re_wrapped);
    state.store.save_meta(&meta)
}

#[tauri::command]
fn generate_password(rule: PasswordRule) -> PasswordResult {
    let pwd = password::generate(&rule);
    PasswordResult {
        strength: password::strength(&pwd),
        candidates: password::available_char_count(&rule),
        password: pwd,
    }
}

#[tauri::command]
fn totp_code(cfg: TotpConfig, at_ms: i64) -> String {
    totp::code_at(&cfg, at_ms)
}

#[tauri::command]
fn totp_parse(uri: String) -> Option<TotpConfig> {
    totp::parse_otpauth(&uri)
}

#[tauri::command]
fn totp_build(cfg: TotpConfig) -> String {
    totp::build_otpauth(&cfg)
}

#[tauri::command]
fn totp_meta(cfg: TotpConfig, at_ms: i64) -> (String, u32, String) {
    (totp::code_at(&cfg, at_ms), totp::remaining_of(&cfg, at_ms), totp::label_of(&cfg))
}

#[tauri::command]
fn export_plain(data: VaultData, format: String) -> Result<String, String> {
    match format.as_str() {
        transfer::FORMAT_MIGE_JSON => Ok(transfer::export_mige_json(&data)),
        transfer::FORMAT_BITWARDEN_JSON => Ok(transfer::export_bitwarden_json(&data)),
        transfer::FORMAT_BITWARDEN_CSV => Ok(transfer::export_csv(&data)),
        transfer::FORMAT_OTPAUTH => Ok(transfer::export_otpauth_list(&data)),
        other => Err(format!("UNSUPPORTED_FORMAT: {other}")),
    }
}

#[tauri::command]
fn import_plain(text: String, format: String) -> ImportOutcome {
    transfer::import_plain(&text, &format)
}

#[tauri::command]
fn detect_format(text: String) -> String {
    transfer::detect_format(&text).to_string()
}

#[tauri::command]
fn export_encrypted(data: VaultData, password: String) -> Result<String, String> {
    if password.chars().count() < MIN_MASTER_LENGTH {
        return Err(format!("备份密码至少 {MIN_MASTER_LENGTH} 位"));
    }
    transfer::export_encrypted(&data, &password)
}

#[tauri::command]
fn import_encrypted(text: String, password: String) -> ImportOutcome {
    transfer::import_encrypted(&text, &password)
}

#[tauri::command]
fn set_auto_lock(state: State<AppState>, minutes: u32) -> Result<(), String> {
    let mut meta = state.store.load_meta();
    meta.auto_lock_minutes = minutes;
    state.store.save_meta(&meta)
}

#[tauri::command]
fn set_lang(state: State<AppState>, lang: String) -> Result<(), String> {
    let mut meta = state.store.load_meta();
    meta.lang = if lang == "en" { "en".to_string() } else { "zh".to_string() };
    state.store.save_meta(&meta)
}

#[tauri::command]
fn write_text_file(path: String, content: String) -> Result<(), String> {
    std::fs::write(&path, content).map_err(|e| format!("WRITE_FAILED: {e}"))
}

#[tauri::command]
fn read_text_file(path: String) -> Result<String, String> {
    std::fs::read_to_string(&path).map_err(|e| format!("READ_FAILED: {e}"))
}

/// 用系统默认浏览器打开网址（Windows / macOS / Linux 分别调用对应命令）
#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    let target = if url.starts_with("http://") || url.starts_with("https://") {
        url
    } else {
        format!("https://{url}")
    };

    #[cfg(target_os = "windows")]
    let launch = std::process::Command::new("cmd")
        .args(["/C", "start", "", &target])
        .spawn();

    #[cfg(target_os = "macos")]
    let launch = std::process::Command::new("open").arg(&target).spawn();

    #[cfg(all(unix, not(target_os = "macos"), not(target_os = "android")))]
    let launch = std::process::Command::new("xdg-open").arg(&target).spawn();

    #[cfg(target_os = "android")]
    let launch: Result<std::process::Child, std::io::Error> =
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "Android 需用 Intent 打开链接"));

    launch.map(|_| ()).map_err(|e| format!("OPEN_URL_FAILED: {e}"))
}

// ---------- Vaultwarden / Bitwarden 同步 ----------

/// 把当前同步会话写进密码库配置并落盘（与鸿蒙版存放位置一致：settings.bitwarden）
fn persist_bw_session(state: &AppState, bw: &bitwarden::BwSession) -> Result<(), String> {
    let mut session = state.session.lock().map_err(|_| "STATE_LOCK_FAILED".to_string())?;
    let key = VaultKey(session.key.as_ref().ok_or_else(|| "LOCKED".to_string())?.0);
    let data = session.data.as_mut().ok_or_else(|| "LOCKED".to_string())?;
    data.settings.bitwarden = Some(
        serde_json::to_value(bw.to_config()).map_err(|e| format!("保存同步配置失败：{e}"))?,
    );
    state.store.save_vault(&key, data)
}

/// 清除密码库里的同步配置（断开连接时调用）
fn clear_bw_session(state: &AppState) -> Result<(), String> {
    let mut session = state.session.lock().map_err(|_| "STATE_LOCK_FAILED".to_string())?;
    let key = VaultKey(session.key.as_ref().ok_or_else(|| "LOCKED".to_string())?.0);
    let data = session.data.as_mut().ok_or_else(|| "LOCKED".to_string())?;
    if data.settings.bitwarden.is_none() {
        return Ok(());
    }
    data.settings.bitwarden = None;
    state.store.save_vault(&key, data)
}

fn bw_status_of(state: &AppState, session: &bitwarden::BwSession) -> bitwarden::BwStatus {
    let item_count = state
        .session
        .lock()
        .ok()
        .and_then(|guard| guard.data.as_ref().map(|d| d.items.len()))
        .unwrap_or(0);
    bitwarden::BwStatus {
        connected: true,
        server: session.server.clone(),
        email: session.email.clone(),
        last_sync_at: session.last_sync_at,
        item_count,
    }
}

#[tauri::command]
async fn bw_connect(
    state: State<'_, AppState>,
    server: String,
    email: String,
    password: String,
) -> Result<bitwarden::BwStatus, String> {
    let session = bitwarden::login(&server, &email, &password).await?;
    let status = bw_status_of(&state, &session);
    persist_bw_session(&state, &session)?;
    let mut guard = state.bw.lock().map_err(|_| "STATE_LOCK_FAILED".to_string())?;
    *guard = Some(session);
    Ok(status)
}

#[tauri::command]
fn bw_status(state: State<AppState>) -> Result<Option<bitwarden::BwStatus>, String> {
    let guard = state.bw.lock().map_err(|_| "STATE_LOCK_FAILED".to_string())?;
    Ok(guard.as_ref().map(|s| bw_status_of(&state, s)))
}

#[tauri::command]
async fn bw_pull(state: State<'_, AppState>) -> Result<Vec<VaultItem>, String> {
    let mut session = {
        let guard = state.bw.lock().map_err(|_| "STATE_LOCK_FAILED".to_string())?;
        guard.clone().ok_or_else(|| "尚未连接 Vaultwarden".to_string())?
    };
    let items = bitwarden::sync_vault(&mut session).await?;
    session.last_sync_at = crate::transfer::now_ms();
    persist_bw_session(&state, &session)?;
    {
        let mut guard = state.bw.lock().map_err(|_| "STATE_LOCK_FAILED".to_string())?;
        *guard = Some(session);
    }
    Ok(items)
}

/// 上传本地条目：未关联的新建、已关联的更新，返回带 bwId 的副本（前端据此写回）
#[tauri::command]
async fn bw_push(state: State<'_, AppState>, items: Vec<VaultItem>) -> Result<Vec<VaultItem>, String> {
    let mut session = {
        let guard = state.bw.lock().map_err(|_| "STATE_LOCK_FAILED".to_string())?;
        guard.clone().ok_or_else(|| "尚未连接 Vaultwarden".to_string())?
    };
    let mut updated = Vec::new();
    for item in &items {
        // 有 bw_id 的先尝试更新；服务器上没有这条（换了服务器 / 已被删除）则自动新建
        let id = bitwarden::push_item(&mut session, item).await?;
        let mut copy = item.clone();
        copy.bw_id = id;
        updated.push(copy);
    }
    session.last_sync_at = crate::transfer::now_ms();
    persist_bw_session(&state, &session)?;
    {
        let mut guard = state.bw.lock().map_err(|_| "STATE_LOCK_FAILED".to_string())?;
        *guard = Some(session);
    }
    Ok(updated)
}

#[tauri::command]
fn bw_disconnect(state: State<AppState>) -> Result<(), String> {
    let mut guard = state.bw.lock().map_err(|_| "STATE_LOCK_FAILED".to_string())?;
    *guard = None;
    drop(guard);
    clear_bw_session(&state)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."));
            app.manage(AppState {
                store: Store::new(dir),
                session: Mutex::new(Session::locked()),
                bw: Mutex::new(None),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            setup_vault,
            unlock,
            lock,
            save_vault,
            change_password,
            generate_password,
            totp_code,
            totp_parse,
            totp_build,
            totp_meta,
            export_plain,
            import_plain,
            detect_format,
            export_encrypted,
            import_encrypted,
            set_auto_lock,
            set_lang,
            write_text_file,
            read_text_file,
            open_url,
            bw_connect,
            bw_status,
            bw_pull,
            bw_push,
            bw_disconnect
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 配置随密码库加密落盘、重新加载后能完整恢复（回归「重启后 Vaultwarden 设置丢失」）
    #[test]
    fn vault_roundtrip_keeps_vaultwarden_config() {
        let dir = std::env::temp_dir().join(format!("mige-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::new(dir.clone());

        // 建库：随机主密钥用密码派生的 KEK 包裹
        let salt = crypto::random_bytes(16);
        let kek =
            VaultKey::from_slice(&crypto::pbkdf2_sha256(b"test-master-pw", &salt, 1000, 32)).unwrap();
        let master = VaultKey::random();
        let wrapped = crypto::seal(&kek, master.as_slice());
        let mut meta = store.load_meta();
        meta.set_wrapped(&salt, 1000, &wrapped);
        store.save_meta(&meta).unwrap();

        // 写入带 Vaultwarden 配置的库
        let bw_session = bitwarden::BwSession {
            server: "https://vault.example.com".to_string(),
            email: "user@example.com".to_string(),
            access_token: "access-abc".to_string(),
            refresh_token: "refresh-abc".to_string(),
            kdf_iterations: 600_000,
            user_key: vec![9u8; 64],
            user_id: "user-uuid".to_string(),
            last_sync_at: 4321,
        };
        let mut data = VaultData::default();
        data.settings.bitwarden = Some(serde_json::to_value(bw_session.to_config()).unwrap());
        store.save_vault(&master, &data).unwrap();

        // 模拟重启：用同一主密钥重新加载，配置应原样回来
        let loaded = store.load_vault(&master).unwrap();
        let restored = loaded
            .settings
            .bitwarden
            .clone()
            .and_then(|v| serde_json::from_value::<bitwarden::BitwardenConfig>(v).ok())
            .and_then(|cfg| bitwarden::BwSession::from_config(&cfg))
            .expect("重启后应能恢复同步配置");
        assert_eq!(restored.server, "https://vault.example.com");
        assert_eq!(restored.email, "user@example.com");
        assert_eq!(restored.user_key, vec![9u8; 64]);
        assert_eq!(restored.user_id, "user-uuid");
        assert_eq!(restored.last_sync_at, 4321);

        // 断开连接清空配置后，重新加载应为未连接
        let mut cleared = loaded.clone();
        cleared.settings.bitwarden = None;
        store.save_vault(&master, &cleared).unwrap();
        let reloaded = store.load_vault(&master).unwrap();
        assert!(reloaded.settings.bitwarden.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}