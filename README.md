# 密阁 · Windows 版（Tauri 2 + Vue 3）

与鸿蒙版**数据格式完全互通**的桌面实现：同一套 SM4/HMAC-SM3 加密参数与文件布局，
鸿蒙版导出的 `.mige` 加密备份、JSON、CSV、otpauth 清单都能直接导入，反之亦然。

## 技术栈

| 层 | 选型 | 说明 |
| --- | --- | --- |
| 壳 | Tauri 2 | 复用系统 WebView2，安装包体积小 |
| 前端 | Vue 3 + Vite + TypeScript | 复刻鸿蒙版信息架构（侧边导航 + 双栏） |
| 后端 | Rust | 加密、存储、TOTP、导入导出全部在 Rust 侧完成 |
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

> 因为密钥派生与信封格式一致，**同一份加密备份可以用同一管理密码在两个平台互相恢复**。

## 目录结构

```
win/
├── index.html / vite.config.ts / tsconfig.json / package.json
├── src/                      # Vue 前端
│   ├── main.ts  App.vue  api.ts  styles.css
│   └── views/                # 创建库 / 解锁 / 密码库 / 详情 / 编辑 / 生成器 / 验证器 / 设置
└── src-tauri/                # Rust 后端
    ├── Cargo.toml  tauri.conf.json  build.rs
    ├── capabilities/default.json
    └── src/
        ├── lib.rs            # Tauri 命令与会话（主密钥只在内存）
        ├── crypto.rs         # SM4/HMAC-SM3/PBKDF2
        ├── store.rs          # meta.json / vault.dat
        ├── password.rs       # 密码生成与强度
        ├── totp.rs           # TOTP + otpauth
        ├── transfer.rs       # 导入导出（5 种格式）
        └── types.rs          # 与鸿蒙版一致的数据模型
```

## 开发与构建

```powershell
cd win
npm install            # 首次
npm run tauri dev      # 开发（Vite + Tauri 热更新）

npm run build          # 仅构建前端（dist/）
cargo test --manifest-path src-tauri/Cargo.toml --lib   # 后端单元测试
npm run tauri build    # 生成 NSIS 安装包（src-tauri/target/release/bundle/nsis/）
```

要求：Rust（MSVC 工具链）、Visual Studio 2022（C++ 桌面开发）、WebView2 运行时（Win10/11 自带）、Node 18+。

## 功能状态

| 功能 | 状态 |
| --- | --- |
| 创建密码库 / 解锁 / 立即锁定 | ✅ |
| 条目增删改查（名称/账号/密码/网址/APP/分组/备注/收藏） | ✅ |
| 密码生成器（长度 8–64、四类字符、排除易混淆、强度） | ✅ |
| MFA：动态码、倒计时、手填/链接解析 | ✅（本机无摄像头，未做扫码） |
| 导入导出：加密备份 / 密阁 JSON / Vaultwarden JSON / CSV / otpauth | ✅ |
| 自动锁定（窗口失焦超过阈值即锁定） | ✅ |
| 修改管理密码、数据目录展示 | ✅ |
| Vaultwarden 在线同步（登录 / 拉取 / 上传 / token 续期） | ✅ 代码完成，加密基元有单测；**联调待你连上服务器验证** |
| 界面语言切换（简体中文 / English，即时生效） | ✅ 设置页「语言」行切换，偏好保存在 `meta.json` |

## 安全说明

- 主密钥与明文库只存在于进程内存，`lock` 命令立即清空；
- 落盘文件无明文，MAC 校验失败即拒绝解密（区分不了「密码错」与「文件被改」）；
- 不联网（除未来的同步功能），不上报任何数据；
- 管理密码忘记无法找回，请用「导出加密备份」保留副本。
