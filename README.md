# 密阁 · 多平台版（Tauri 2 + Vue 3）

与鸿蒙版**数据格式完全互通**的跨平台实现：同一套 SM4/HMAC-SM3 加密参数与文件布局，
鸿蒙版导出的 `.mige` 加密备份、JSON、CSV、otpauth 清单都能直接导入，反之亦然。

## 支持平台

| 平台 | 产物 | 本机（Windows）可直接构建 | CI 构建 |
| --- | --- | --- | --- |
| Windows x64 | `.exe`（NSIS 安装器）/ `.msi` | ✅ | ✅ `windows-latest` |
| Linux x64 | `.deb` / `.AppImage` / `.rpm` | ❌ 需 Linux 工具链与 WebKitGTK | ✅ `ubuntu-22.04` |
| macOS x64（Intel） | `.dmg` / `.app` | ❌ 需 macOS + Xcode | ✅ `macos-13` |
| macOS ARM64（Apple Silicon） | `.dmg` / `.app` | ❌ 同上 | ✅ `macos-latest` |
| Android | `.apk` | ❌ 需 Android SDK + NDK | ✅ `ubuntu-22.04` + setup-android |

> **为什么不能在一台 Windows 上打全部五个平台**：
> macOS 产物必须由 Xcode 工具链签名打包；Linux 依赖系统的 WebKitGTK/GTK 库；
> Android 需要 SDK、NDK 与四个 Rust 交叉编译目标。因此除 Windows 外的四个平台
> 统一交给 GitHub Actions 矩阵产出（见 `.github/workflows/build.yml`）。

## 一键出五平台产物（GitHub Actions）

```powershell
git tag v1.0.0
git push origin v1.0.0        # 触发 CI，五平台并行构建
```

也可以在 GitHub 仓库的 **Actions → build → Run workflow** 手动触发。
构建完成后在对应的 workflow run 页面下载 Artifacts：

```
mige-windows-x64    → mige_1.0.0_x64-setup.exe
mige-linux-x64      → mige_1.0.0_amd64.deb / .AppImage
mige-macos-x64      → mige_1.0.0_x64.dmg
mige-macos-arm64    → mige_1.0.0_aarch64.dmg
mige-android        → app-universal-release.apk
```

## 本机开发与构建

```powershell
npm install            # 首次或依赖变更
npm run tauri dev      # 开发模式（前端热更新，Rust 改动自动重编译）

npm run build          # 仅前端（vue-tsc 类型检查 + vite 打包）
cargo test --manifest-path src-tauri/Cargo.toml --lib   # 后端 25 项单测
npm run tauri build    # 本机打 Windows 安装包
```

**前置条件**：Node 18+、Rust（MSVC 工具链）、Visual Studio 2022（C++ 桌面开发）、WebView2 运行时（Win10/11 自带）。

### 已构建的 Windows 安装包

```powershell
npx tauri build --bundles nsis,msi      # 一次产出两种格式
```

| 文件 | 大小 | 说明 |
| --- | --- | --- |
| `密阁_1.0.1_x64-setup.exe` | 1.87 MB | NSIS 安装器，推荐；支持静默安装 `/S` |
| `密阁_1.0.1_x64_zh-CN.msi` | 2.54 MB | MSI，适合域环境／批量部署 |

- 产物目录：`src-tauri/target/release/bundle/{nsis,msi}/`，`installers/` 下为归档副本（不入库）
- 安装位置：`%LOCALAPPDATA%\密阁`（当前用户，无需管理员权限）
- 卸载：开始菜单「密阁」文件夹内，或 `%LOCALAPPDATA%\密阁\uninstall.exe`
- **未做代码签名**：首次运行 SmartScreen 会提示「Windows 已保护你的电脑」，点「更多信息 → 仍要运行」即可

## 技术栈

| 层 | 选型 | 说明 |
| --- | --- | --- |
| 壳 | Tauri 2 | Windows 用 WebView2、macOS 用 WKWebView、Linux 用 WebKitGTK、Android 用系统 WebView |
| 前端 | Vue 3 + Vite + TypeScript | 侧边导航 + 双栏布局，中英双语 |
| 后端 | Rust | 加密、存储、TOTP、导入导出、同步全部在 Rust 侧 |
| 密码学 | `sm4` / `sm3` / `hmac` / `pbkdf2` | SM4-128-CBC + HMAC-SM3 + PBKDF2-SHA256 |

## 与鸿蒙版的一致性

| 项目 | 参数（两边相同） |
| --- | --- |
| 主密钥 | 32 字节：前 16 字节 SM4 加密，后 16 字节 HMAC-SM3 |
| 库文件 | `vault.dat` = `{"v":1,"iv":…,"ct":…,"mac":…}` |
| 信封 | SM4-CBC-PKCS7 密文 + HMAC-SM3(iv ‖ ct)，均 base64 |
| KDF | PBKDF2-SHA256(管理密码, 16B salt, 120000 次, 32B) |
| 元数据 | `meta.json`：salt / iterations / 包裹后的主密钥 / 自动锁定 / 语言 |
| 加密备份 | `{app:"mige",version:1,kdf,salt,box:{iv,ct,mac}}` |
| TOTP | RFC 6238，SHA1/SHA256/SHA512，6/8 位，周期可配 |

## 数据目录（按平台）

| 平台 | 路径 |
| --- | --- |
| Windows | `%APPDATA%\org.liqihai.app.mige\` |
| macOS | `~/Library/Application Support/org.liqihai.app.mige/` |
| Linux | `~/.local/share/org.liqihai.app.mige/` |
| Android | 应用私有目录（不可由其它应用访问） |

> 标识符已统一为 `org.liqihai.app.mige`。若之前用过 `…mige.win` 的旧版，
> 旧数据仍在原目录，可先「导出加密备份」再在新版导入。

## 功能状态

| 功能 | 状态 |
| --- | --- |
| 创建密码库 / 解锁 / 立即锁定 | ✅ |
| 条目增删改查（名称/账号/密码/网址/APP/分组/备注/收藏） | ✅ |
| 密码生成器（长度 8–64、四类字符、排除易混淆、强度） | ✅ |
| MFA：动态码、倒计时、手填/链接解析 | ✅（桌面无摄像头，未做扫码） |
| 导入导出：加密备份 / 密阁 JSON / Vaultwarden JSON / CSV / otpauth | ✅ |
| 自动锁定（窗口失焦超过阈值即锁定） | ✅ |
| 界面语言切换（简体中文 / English，即时生效） | ✅ |
| Vaultwarden 在线同步（登录 / 拉取 / 上传 / token 续期） | ✅ 代码完成，待真实服务器联调 |
| 打开条目网址 | ✅ Windows / macOS / Linux |
| Android 打开网址 | ⏳ 需改用 Intent（当前提示复制链接） |

## 目录结构

```
tauri/
├── index.html / vite.config.ts / tsconfig.json / package.json
├── .github/workflows/build.yml      # 五平台 CI 矩阵
├── src/                             # Vue 前端
│   ├── main.ts  App.vue  api.ts  i18n.ts  styles.css
│   └── views/                       # 创建库 / 解锁 / 密码库 / 详情 / 编辑 / 生成器 / 验证器 / 设置
└── src-tauri/
    ├── Cargo.toml  tauri.conf.json  build.rs
    ├── capabilities/default.json
    ├── icons/                       # 含 ico / icns / png / android / ios
    └── src/
        ├── lib.rs                   # Tauri 命令与会话（主密钥只在内存）
        ├── bitwarden.rs             # Vaultwarden 同步
        ├── crypto.rs                # SM4 / HMAC-SM3 / PBKDF2
        ├── store.rs                 # meta.json / vault.dat
        ├── password.rs              # 密码生成
        ├── totp.rs                  # TOTP + otpauth
        ├── transfer.rs              # 导入导出（5 种格式）
        └── types.rs                 # 与鸿蒙版一致的数据模型
```

## 安全说明

- 主密钥与明文库只存在于进程内存，`lock` 命令立即清空；
- 落盘文件无明文，MAC 校验失败即拒绝解密（区分不了「密码错」与「文件被改」）；
- 除 Vaultwarden 同步外不联网，不上报任何数据；
- 管理密码忘记无法找回，请用「导出加密备份」保留副本。
