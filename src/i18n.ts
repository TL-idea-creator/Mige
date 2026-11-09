/**
 * 界面多语言：中文 / English。
 *
 * 采用「代码内文案表 + 响应式语言状态」，切换后由 Vue 直接重渲染，
 * 不需要重启应用（与鸿蒙版同一思路）。
 */
import { computed, ref } from 'vue';

export type Lang = 'zh' | 'en';

export interface Strings {
  // 通用
  appName: string;
  cancel: string;
  save: string;
  delete: string;
  copy: string;
  back: string;
  edit: string;
  language: string;
  langZh: string;
  langEn: string;
  languageHint: string;

  // 创建库
  setupSubtitle: string;
  masterLabel: string;
  masterPlaceholder: (min: number) => string;
  confirmMasterLabel: string;
  confirmMasterPlaceholder: string;
  createVault: string;
  creating: string;
  setupNote: string;
  errorMismatch: string;
  errorTooShort: (min: number) => string;

  // 解锁
  lockedTitle: string;
  unlockHint: string;
  unlockAction: string;
  unlocking: string;
  wrongPassword: string;
  unlockFailed: string;

  // 密码库列表
  vaultTitle: string;
  vaultNew: string;
  vaultSearch: string;
  vaultAll: string;
  vaultUncategorized: string;
  vaultNoUsername: string;
  vaultEmpty: string;
  vaultEmptyHint: string;
  vaultNoMatch: string;
  vaultNoMatchHint: string;
  badgeMfa: string;
  untitled: string;

  // 条目详情
  detailCopyCode: string;
  detailAccount: string;
  detailPassword: string;
  detailShow: string;
  detailHide: string;
  detailWebsite: string;
  detailOpen: string;
  detailApp: string;
  detailNotes: string;
  detailCreatedAt: (time: string) => string;
  detailDelete: string;
  detailOpenFailed: string;
  copiedCode: string;
  copiedAccount: string;
  copiedPassword: string;
  copiedUrl: string;
  copiedApp: string;
  saved: string;
  deleted: string;
  deleteConfirm: (name: string) => string;
  selectItemHint: string;

  // 条目编辑
  editorNew: string;
  editorEdit: string;
  editorNameLabel: string;
  editorNamePlaceholder: string;
  editorAccountLabel: string;
  editorAccountPlaceholder: string;
  editorShowGen: string;
  editorHideGen: string;
  editorPasswordPlaceholder: string;
  editorLength: string;
  editorRegenerate: (count: number) => string;
  editorUrlLabel: string;
  editorUrlPlaceholder: string;
  editorAppLabel: string;
  editorAppPlaceholder: string;
  editorFolderLabel: string;
  editorFolderPlaceholder: string;
  editorNotesLabel: string;
  editorNotesPlaceholder: string;
  editorFavorite: string;
  editorMfa: string;
  editorSecretLabel: string;
  editorParse: string;
  editorIssuerLabel: string;
  editorIssuerPlaceholder: string;
  editorAlgorithm: string;
  editorDigits: string;
  editorPeriod: string;
  editorErrNoName: string;
  editorErrBadLink: string;
  editorFilledFromLink: string;

  // 生成器
  genTitle: string;
  genNoneEnabled: string;
  genRegenerate: string;
  genLength: string;
  genRecent: string;
  genCandidates: (count: number) => string;
  genStrength: (label: string, length: number) => string;
  ruleUpper: string;
  ruleLower: string;
  ruleDigits: string;
  ruleSymbols: string;
  ruleExclude: string;

  // 验证器
  authTitle: string;
  authAdd: string;
  authEmpty: string;
  authEmptyHint: string;
  authNameLabel: string;
  authNamePlaceholder: string;
  authAccountLabel: string;
  authAccountPlaceholder: string;
  authFolderLabel: string;
  authFolderPlaceholder: string;
  authParseLink: string;
  authErrNoSecret: string;
  authErrBadSecret: string;
  authAdded: string;

  // 设置
  settingsTitle: string;
  autoLockLabel: string;
  autoLockOff: string;
  autoLockHint: (minutes: number) => string;
  autoLockAdjust: (minutes: number) => string;
  changeMasterLabel: string;
  changeMasterHint: string;
  collapse: string;
  pwdCurrent: string;
  pwdNew: string;
  pwdConfirm: string;
  btnConfirmChange: string;
  lockNowLabel: string;
  lockNowHint: string;
  lockNowAction: string;
  bwSection: string;
  bwConnected: string;
  bwServer: string;
  bwLastSync: string;
  bwPull: string;
  bwUpload: string;
  bwDisconnect: string;
  bwServerPlaceholder: string;
  bwEmail: string;
  bwPassword: string;
  bwConnectButton: string;
  bwConnecting: string;
  bwKdfHint: string;
  dataSection: string;
  exportLabel: string;
  backupPasswordPlaceholder: string;
  exportEncrypted: string;
  exportMigeJson: string;
  exportBwJson: string;
  exportCsv: string;
  exportOtpauth: string;
  importLabel: string;
  importPasswordPlaceholder: string;
  importButton: string;
  processing: string;
  aboutSection: string;
  aboutVersion: string;
  aboutDeveloper: string;
  aboutContact: string;
  aboutDataDir: string;
  aboutCrypto: (iterations: number) => string;

  // 状态提示
  stAutoLockOff: string;
  stAutoLockOn: (minutes: number) => string;
  stPwdTooShort: string;
  stPwdMismatch: string;
  stPwdUpdated: string;
  stOldPwdWrong: string;
  stBwNeedCreds: string;
  stBwConnecting: string;
  stBwConnected: (email: string) => string;
  stBwPulling: string;
  stBwPulled: (count: number) => string;
  stBwEmpty: string;
  stBwNothingToPush: string;
  stBwPushing: (count: number) => string;
  stBwPushed: (count: number) => string;
  stBwDisconnected: string;
  stBackupPwdShort: string;
  stExported: (path: string) => string;
  stExportCanceled: string;
  stExportFailed: (err: string) => string;
  stImportCanceled: string;
  stImportEmpty: string;
  stImported: (count: number) => string;
  stImportFailed: (err: string) => string;
  stVaultCreated: string;
  stInitFailed: (err: string) => string;
}

const ZH: Strings = {
  appName: '密阁',
  cancel: '取消',
  save: '保存',
  delete: '删除',
  copy: '复制',
  back: '返回',
  edit: '编辑',
  language: '语言',
  langZh: '简体中文',
  langEn: 'English',
  languageHint: '切换后界面立即生效',

  setupSubtitle: '创建你的管理密码',
  masterLabel: '管理密码',
  masterPlaceholder: (min) => `至少 ${min} 位`,
  confirmMasterLabel: '确认管理密码',
  confirmMasterPlaceholder: '再次输入',
  createVault: '创建密码库',
  creating: '正在创建…',
  setupNote: '管理密码只保存在本机，用于派生 SM4 加密密钥。忘记后无法找回，请务必备份。',
  errorMismatch: '两次输入的管理密码不一致',
  errorTooShort: (min) => `管理密码至少需要 ${min} 位`,

  lockedTitle: '密阁已锁定',
  unlockHint: '输入管理密码解锁',
  unlockAction: '解锁',
  unlocking: '解锁中…',
  wrongPassword: '管理密码不正确',
  unlockFailed: '解锁失败',

  vaultTitle: '密码库',
  vaultNew: '+ 新建',
  vaultSearch: '搜索名称、账号或网址',
  vaultAll: '全部',
  vaultUncategorized: '未分类',
  vaultNoUsername: '无账号信息',
  vaultEmpty: '还没有任何条目',
  vaultEmptyHint: '点击右上角「+ 新建」添加第一个账号密码',
  vaultNoMatch: '没有匹配的条目',
  vaultNoMatchHint: '换个关键词或分类试试',
  badgeMfa: 'MFA',
  untitled: '未命名条目',

  detailCopyCode: '复制验证码',
  detailAccount: '账号',
  detailPassword: '密码',
  detailShow: '显示',
  detailHide: '隐藏',
  detailWebsite: '网站',
  detailOpen: '打开',
  detailApp: '关联 APP',
  detailNotes: '备注',
  detailCreatedAt: (time) => `创建于 ${time}`,
  detailDelete: '删除此条目',
  detailOpenFailed: '打开失败，可复制网址手动访问',
  copiedCode: '验证码已复制',
  copiedAccount: '账号已复制',
  copiedPassword: '密码已复制',
  copiedUrl: '网址已复制',
  copiedApp: 'APP 名称已复制',
  saved: '已保存',
  deleted: '已删除',
  deleteConfirm: (name) => `确认删除「${name}」？该操作不可撤销。`,
  selectItemHint: '选择左侧条目查看详情',

  editorNew: '新建条目',
  editorEdit: '编辑条目',
  editorNameLabel: '名称 / 站点',
  editorNamePlaceholder: '例如 GitHub',
  editorAccountLabel: '账号 / 用户名',
  editorAccountPlaceholder: '例如 me@example.com',
  editorShowGen: '生成密码',
  editorHideGen: '收起生成器',
  editorPasswordPlaceholder: '手动输入或点击生成',
  editorLength: '长度',
  editorRegenerate: (count) => `重新生成（${count} 个候选字符）`,
  editorUrlLabel: '网站地址（可用浏览器快速打开）',
  editorUrlPlaceholder: '例如 https://github.com',
  editorAppLabel: '关联 APP 名称（仅记录）',
  editorAppPlaceholder: '例如 微信',
  editorFolderLabel: '分组',
  editorFolderPlaceholder: '例如 工作 / 个人',
  editorNotesLabel: '备注',
  editorNotesPlaceholder: '安全问题、恢复码等',
  editorFavorite: '收藏',
  editorMfa: '两步验证 (MFA)',
  editorSecretLabel: '密钥或 otpauth:// 链接',
  editorParse: '解析',
  editorIssuerLabel: '颁发方',
  editorIssuerPlaceholder: '例如 GitHub',
  editorAlgorithm: '算法',
  editorDigits: '位数',
  editorPeriod: '周期（秒）',
  editorErrNoName: '请至少填写名称或网站地址',
  editorErrBadLink: '无法识别该链接，请粘贴 otpauth:// 开头的完整 URI',
  editorFilledFromLink: '已从链接填充',

  genTitle: '密码生成器',
  genNoneEnabled: '请至少启用一种字符类型',
  genRegenerate: '重新生成',
  genLength: '密码长度',
  genRecent: '最近生成',
  genCandidates: (count) => `候选字符数：${count}`,
  genStrength: (label, length) => `${label} · ${length} 位`,
  ruleUpper: '大写字母 A-Z',
  ruleLower: '小写字母 a-z',
  ruleDigits: '数字 0-9',
  ruleSymbols: '特殊符号 !@#$…',
  ruleExclude: '排除易混淆字符 (I l 1 O 0 o)',

  authTitle: '验证器',
  authAdd: '+ 添加',
  authEmpty: '还没有添加两步验证',
  authEmptyHint: '点右上角「+ 添加」，填入 Base32 密钥或粘贴 otpauth 链接',
  authNameLabel: '名称（如 GitHub）',
  authNamePlaceholder: '可留空，默认用账号名',
  authAccountLabel: '账号（可选）',
  authAccountPlaceholder: '如 me@example.com',
  authFolderLabel: '分组（可选）',
  authFolderPlaceholder: '如 工作、个人，留空表示未分类',
  authParseLink: '解析链接',
  authErrNoSecret: '请填写密钥或粘贴 otpauth 链接',
  authErrBadSecret: '密钥格式不正确，Base32 只包含 A-Z 与 2-7',
  authAdded: '验证码已添加',

  settingsTitle: '设置',
  autoLockLabel: '自动锁定',
  autoLockOff: '已关闭',
  autoLockHint: (minutes) => `切到后台 ${minutes} 分钟后锁定`,
  autoLockAdjust: (minutes) => `调整（${minutes} 分钟）`,
  changeMasterLabel: '修改管理密码',
  changeMasterHint: '更换用于派生 SM4 密钥的管理密码',
  collapse: '收起',
  pwdCurrent: '当前管理密码',
  pwdNew: '新管理密码（至少 8 位）',
  pwdConfirm: '再次输入新管理密码',
  btnConfirmChange: '确认修改',
  lockNowLabel: '立即锁定',
  lockNowHint: '清空内存中的主密钥',
  lockNowAction: '锁定',
  bwSection: 'Vaultwarden 同步',
  bwConnected: '已连接',
  bwServer: '服务器',
  bwLastSync: '上次同步',
  bwPull: '拉取同步',
  bwUpload: '上传本地',
  bwDisconnect: '断开连接',
  bwServerPlaceholder: 'https://vault.example.com',
  bwEmail: '注册邮箱',
  bwPassword: '主密码（仅用于登录，不会保存）',
  bwConnectButton: '连接并同步',
  bwConnecting: '连接中…',
  bwKdfHint: '仅支持 PBKDF2 账号（Vaultwarden 默认）；Argon2 需先在网页端切换。自签名证书会自动跳过校验。',
  dataSection: '数据与备份',
  exportLabel: '导出（可选备份密码，加密备份需 ≥8 位）',
  backupPasswordPlaceholder: '备份密码（用于加密备份）',
  exportEncrypted: '导出加密备份',
  exportMigeJson: '密阁 JSON',
  exportBwJson: 'Vaultwarden JSON',
  exportCsv: 'CSV',
  exportOtpauth: 'otpauth 清单',
  importLabel: '导入（自动识别格式）',
  importPasswordPlaceholder: '若为加密备份，请输入备份密码',
  importButton: '选择文件并导入',
  processing: '处理中…',
  aboutSection: '关于',
  aboutVersion: '版本',
  aboutDeveloper: '开发者',
  aboutContact: '联系邮箱',
  aboutDataDir: '数据目录',
  aboutCrypto: (iterations) =>
    `加密算法 SM4-128-CBC + HMAC-SM3 · 密钥派生 PBKDF2-SHA256 (${iterations} 次) · 与鸿蒙版数据格式互通`,

  stAutoLockOff: '已关闭自动锁定',
  stAutoLockOn: (minutes) => `自动锁定：${minutes} 分钟`,
  stPwdTooShort: '新管理密码至少 8 位',
  stPwdMismatch: '两次输入的新管理密码不一致',
  stPwdUpdated: '管理密码已更新',
  stOldPwdWrong: '原管理密码不正确',
  stBwNeedCreds: '请填写 Vaultwarden 邮箱与主密码',
  stBwConnecting: '正在连接 Vaultwarden…',
  stBwConnected: (email) => `已连接 ${email}`,
  stBwPulling: '正在拉取云端条目…',
  stBwPulled: (count) => `已拉取 ${count} 条记录`,
  stBwEmpty: '云端没有可导入的登录条目',
  stBwNothingToPush: '没有需要上传的条目（都已关联）',
  stBwPushing: (count) => `正在上传 ${count} 条条目…`,
  stBwPushed: (count) => `已上传 ${count} 条记录`,
  stBwDisconnected: '已断开 Vaultwarden 连接',
  stBackupPwdShort: '备份密码至少 8 位',
  stExported: (path) => `已导出到 ${path}`,
  stExportCanceled: '导出已取消',
  stExportFailed: (err) => `导出失败：${err}`,
  stImportCanceled: '已取消导入',
  stImportEmpty: '文件中没有可导入的条目',
  stImported: (count) => `已导入 ${count} 条记录（重复条目自动跳过）`,
  stImportFailed: (err) => `导入失败：${err}`,
  stVaultCreated: '密码库已创建',
  stInitFailed: (err) => `初始化失败：${err}`
};

const EN: Strings = {
  appName: 'Mige',
  cancel: 'Cancel',
  save: 'Save',
  delete: 'Delete',
  copy: 'Copy',
  back: 'Back',
  edit: 'Edit',
  language: 'Language',
  langZh: '简体中文',
  langEn: 'English',
  languageHint: 'Applies immediately',

  setupSubtitle: 'Create your master password',
  masterLabel: 'Master password',
  masterPlaceholder: (min) => `At least ${min} characters`,
  confirmMasterLabel: 'Confirm master password',
  confirmMasterPlaceholder: 'Enter again',
  createVault: 'Create vault',
  creating: 'Creating…',
  setupNote:
    'The master password stays on this device and derives the SM4 encryption key. It cannot be recovered if forgotten — please keep a backup.',
  errorMismatch: 'The two passwords do not match',
  errorTooShort: (min) => `Master password must be at least ${min} characters`,

  lockedTitle: 'Mige is locked',
  unlockHint: 'Enter your master password',
  unlockAction: 'Unlock',
  unlocking: 'Unlocking…',
  wrongPassword: 'Incorrect master password',
  unlockFailed: 'Unlock failed',

  vaultTitle: 'Vault',
  vaultNew: '+ New',
  vaultSearch: 'Search name, account or URL',
  vaultAll: 'All',
  vaultUncategorized: 'Uncategorized',
  vaultNoUsername: 'No account',
  vaultEmpty: 'No items yet',
  vaultEmptyHint: 'Tap "+ New" to add your first account',
  vaultNoMatch: 'No matching items',
  vaultNoMatchHint: 'Try another keyword or group',
  badgeMfa: 'MFA',
  untitled: 'Untitled',

  detailCopyCode: 'Copy code',
  detailAccount: 'Account',
  detailPassword: 'Password',
  detailShow: 'Show',
  detailHide: 'Hide',
  detailWebsite: 'Website',
  detailOpen: 'Open',
  detailApp: 'App',
  detailNotes: 'Notes',
  detailCreatedAt: (time) => `Created ${time}`,
  detailDelete: 'Delete this item',
  detailOpenFailed: 'Could not open — copy the URL manually',
  copiedCode: 'Code copied',
  copiedAccount: 'Account copied',
  copiedPassword: 'Password copied',
  copiedUrl: 'URL copied',
  copiedApp: 'App name copied',
  saved: 'Saved',
  deleted: 'Deleted',
  deleteConfirm: (name) => `Delete "${name}"? This cannot be undone.`,
  selectItemHint: 'Select an item on the left',

  editorNew: 'New item',
  editorEdit: 'Edit item',
  editorNameLabel: 'Name / site',
  editorNamePlaceholder: 'e.g. GitHub',
  editorAccountLabel: 'Account / username',
  editorAccountPlaceholder: 'e.g. me@example.com',
  editorShowGen: 'Generate',
  editorHideGen: 'Hide generator',
  editorPasswordPlaceholder: 'Type or generate',
  editorLength: 'Length',
  editorRegenerate: (count) => `Regenerate (${count} chars available)`,
  editorUrlLabel: 'Website (open with browser)',
  editorUrlPlaceholder: 'e.g. https://github.com',
  editorAppLabel: 'Linked app name (record only)',
  editorAppPlaceholder: 'e.g. WeChat',
  editorFolderLabel: 'Group',
  editorFolderPlaceholder: 'e.g. Work / Personal',
  editorNotesLabel: 'Notes',
  editorNotesPlaceholder: 'Security questions, recovery codes…',
  editorFavorite: 'Favorite',
  editorMfa: 'Two-factor (MFA)',
  editorSecretLabel: 'Secret or otpauth:// link',
  editorParse: 'Parse',
  editorIssuerLabel: 'Issuer',
  editorIssuerPlaceholder: 'e.g. GitHub',
  editorAlgorithm: 'Algorithm',
  editorDigits: 'Digits',
  editorPeriod: 'Period (s)',
  editorErrNoName: 'Enter at least a name or a website',
  editorErrBadLink: 'Cannot parse — paste the full otpauth:// URI',
  editorFilledFromLink: 'Filled from link',

  genTitle: 'Password generator',
  genNoneEnabled: 'Enable at least one character type',
  genRegenerate: 'Regenerate',
  genLength: 'Length',
  genRecent: 'Recent',
  genCandidates: (count) => `Available characters: ${count}`,
  genStrength: (label, length) => `${label} · ${length} chars`,
  ruleUpper: 'Uppercase A-Z',
  ruleLower: 'Lowercase a-z',
  ruleDigits: 'Digits 0-9',
  ruleSymbols: 'Symbols !@#$…',
  ruleExclude: 'Exclude look-alikes (I l 1 O 0 o)',

  authTitle: 'Authenticator',
  authAdd: '+ Add',
  authEmpty: 'No two-factor codes yet',
  authEmptyHint: 'Tap "+ Add": enter a Base32 secret or paste an otpauth link',
  authNameLabel: 'Name (e.g. GitHub)',
  authNamePlaceholder: 'Optional — defaults to the account name',
  authAccountLabel: 'Account (optional)',
  authAccountPlaceholder: 'e.g. me@example.com',
  authFolderLabel: 'Group (optional)',
  authFolderPlaceholder: 'e.g. Work, Personal — leave empty for none',
  authParseLink: 'Parse',
  authErrNoSecret: 'Enter a secret or paste an otpauth link',
  authErrBadSecret: 'Invalid secret — Base32 only allows A-Z and 2-7',
  authAdded: 'Authenticator added',

  settingsTitle: 'Settings',
  autoLockLabel: 'Auto-lock',
  autoLockOff: 'Disabled',
  autoLockHint: (minutes) => `Lock after ${minutes} min in background`,
  autoLockAdjust: (minutes) => `Adjust (${minutes} min)`,
  changeMasterLabel: 'Change master password',
  changeMasterHint: 'Password used to derive the SM4 key',
  collapse: 'Collapse',
  pwdCurrent: 'Current master password',
  pwdNew: 'New master password (min 8 chars)',
  pwdConfirm: 'Enter the new password again',
  btnConfirmChange: 'Confirm',
  lockNowLabel: 'Lock now',
  lockNowHint: 'Clear the master key from memory',
  lockNowAction: 'Lock',
  bwSection: 'Vaultwarden sync',
  bwConnected: 'Connected',
  bwServer: 'Server',
  bwLastSync: 'Last sync',
  bwPull: 'Pull',
  bwUpload: 'Upload',
  bwDisconnect: 'Disconnect',
  bwServerPlaceholder: 'https://vault.example.com',
  bwEmail: 'Account email',
  bwPassword: 'Master password (login only, never stored)',
  bwConnectButton: 'Connect and sync',
  bwConnecting: 'Connecting…',
  bwKdfHint:
    'Only PBKDF2 accounts are supported (Vaultwarden default); switch Argon2 in the web vault first. Self-signed certificates are accepted.',
  dataSection: 'Data & backup',
  exportLabel: 'Export (backup password, min 8 chars for encrypted)',
  backupPasswordPlaceholder: 'Backup password (for encrypted backup)',
  exportEncrypted: 'Export encrypted backup',
  exportMigeJson: 'Mige JSON',
  exportBwJson: 'Vaultwarden JSON',
  exportCsv: 'CSV',
  exportOtpauth: 'otpauth list',
  importLabel: 'Import (format detected automatically)',
  importPasswordPlaceholder: 'Backup password (for encrypted backups)',
  importButton: 'Choose file and import',
  processing: 'Working…',
  aboutSection: 'About',
  aboutVersion: 'Version',
  aboutDeveloper: 'Developer',
  aboutContact: 'Email',
  aboutDataDir: 'Data directory',
  aboutCrypto: (iterations) =>
    `Cipher SM4-128-CBC + HMAC-SM3 · Key derivation PBKDF2-SHA256 (${iterations} rounds) · Compatible with the HarmonyOS version`,

  stAutoLockOff: 'Auto-lock disabled',
  stAutoLockOn: (minutes) => `Auto-lock: ${minutes} min`,
  stPwdTooShort: 'New master password must be at least 8 characters',
  stPwdMismatch: 'The two new passwords do not match',
  stPwdUpdated: 'Master password updated',
  stOldPwdWrong: 'Current master password is incorrect',
  stBwNeedCreds: 'Enter your Vaultwarden email and master password',
  stBwConnecting: 'Connecting to Vaultwarden…',
  stBwConnected: (email) => `Connected as ${email}`,
  stBwPulling: 'Pulling items from the server…',
  stBwPulled: (count) => `Pulled ${count} items`,
  stBwEmpty: 'No importable login items on the server',
  stBwNothingToPush: 'Nothing to upload (all items are already linked)',
  stBwPushing: (count) => `Uploading ${count} items…`,
  stBwPushed: (count) => `Uploaded ${count} items`,
  stBwDisconnected: 'Disconnected from Vaultwarden',
  stBackupPwdShort: 'Backup password must be at least 8 characters',
  stExported: (path) => `Exported to ${path}`,
  stExportCanceled: 'Export canceled',
  stExportFailed: (err) => `Export failed: ${err}`,
  stImportCanceled: 'Import canceled',
  stImportEmpty: 'No importable items in this file',
  stImported: (count) => `Imported ${count} items (duplicates skipped)`,
  stImportFailed: (err) => `Import failed: ${err}`,
  stVaultCreated: 'Vault created',
  stInitFailed: (err) => `Initialization failed: ${err}`
};

/** 当前语言（响应式） */
export const lang = ref<Lang>('zh');

/** 当前语言的文案表（模板里直接用 `s.vaultTitle` 这种写法） */
export const s = computed<Strings>(() => (lang.value === 'en' ? EN : ZH));

export function setLang(next: string | undefined): void {
  lang.value = next === 'en' ? 'en' : 'zh';
}

/** 强度标签（0 空 / 1 很弱 / 2 较弱 / 3 较强 / 4 很强） */
export function strengthText(level: number): string {
  const zh = ['空', '很弱', '较弱', '较强', '很强'];
  const en = ['Empty', 'Very weak', 'Weak', 'Good', 'Strong'];
  const index = Math.max(0, Math.min(4, level));
  return lang.value === 'en' ? en[index] : zh[index];
}
