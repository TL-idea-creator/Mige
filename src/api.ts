/**
 * Tauri 命令封装与数据类型（字段名与后端 / 鸿蒙版一致）。
 */
import { invoke } from '@tauri-apps/api/core';

export interface TotpConfig {
  secret: string;
  issuer: string;
  account: string;
  algorithm: string;
  digits: number;
  period: number;
}

export interface VaultItem {
  id: string;
  name: string;
  username: string;
  password: string;
  url: string;
  appName: string;
  notes: string;
  folder: string;
  favorite: boolean;
  totp: TotpConfig | null;
  createdAt: number;
  updatedAt: number;
  bwId: string;
}

export interface VaultSettings {
  bitwarden: unknown;
  autoLockMinutes: number;
  quickUnlock: boolean;
}

export interface VaultData {
  items: VaultItem[];
  settings: VaultSettings;
}

export interface AppInfo {
  initialized: boolean;
  unlocked: boolean;
  autoLockMinutes: number;
  lang: string;
  version: string;
  dataDir: string;
}

export interface PasswordRule {
  length: number;
  upper: boolean;
  lower: boolean;
  digits: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}

export interface PasswordResult {
  password: string;
  strength: number;
  candidates: number;
}

export interface ImportOutcome {
  items: VaultItem[];
  format: string;
  error: string;
}

export interface BwStatus {
  connected: boolean;
  server: string;
  email: string;
  lastSyncAt: number;
  itemCount: number;
}

export const FORMAT_MIGE_ENCRYPTED = 'mige-encrypted';
export const FORMAT_MIGE_JSON = 'mige-json';
export const FORMAT_BITWARDEN_JSON = 'bitwarden-json';
export const FORMAT_BITWARDEN_CSV = 'bitwarden-csv';
export const FORMAT_OTPAUTH = 'otpauth';

export const api = {
  info: () => invoke<AppInfo>('app_info'),
  setup: (password: string) => invoke<VaultData>('setup_vault', { password }),
  unlock: (password: string) => invoke<VaultData>('unlock', { password }),
  lock: () => invoke<void>('lock'),
  save: (data: VaultData) => invoke<void>('save_vault', { data }),
  changePassword: (oldPassword: string, newPassword: string) =>
    invoke<void>('change_password', { oldPassword, newPassword }),
  generatePassword: (rule: PasswordRule) => invoke<PasswordResult>('generate_password', { rule }),
  totpMeta: (cfg: TotpConfig, atMs: number) =>
    invoke<[string, number, string]>('totp_meta', { cfg, atMs }),
  totpParse: (uri: string) => invoke<TotpConfig | null>('totp_parse', { uri }),
  totpBuild: (cfg: TotpConfig) => invoke<string>('totp_build', { cfg }),
  exportPlain: (data: VaultData, format: string) => invoke<string>('export_plain', { data, format }),
  importPlain: (text: string, format: string) => invoke<ImportOutcome>('import_plain', { text, format }),
  detectFormat: (text: string) => invoke<string>('detect_format', { text }),
  exportEncrypted: (data: VaultData, password: string) =>
    invoke<string>('export_encrypted', { data, password }),
  importEncrypted: (text: string, password: string) =>
    invoke<ImportOutcome>('import_encrypted', { text, password }),
  setAutoLock: (minutes: number) => invoke<void>('set_auto_lock', { minutes }),
  setLang: (lang: string) => invoke<void>('set_lang', { lang }),
  writeFile: (path: string, content: string) => invoke<void>('write_text_file', { path, content }),
  readFile: (path: string) => invoke<string>('read_text_file', { path }),
  openUrl: (url: string) => invoke<void>('open_url', { url }),
  bwConnect: (server: string, email: string, password: string) =>
    invoke<BwStatus>('bw_connect', { server, email, password }),
  bwStatus: () => invoke<BwStatus | null>('bw_status'),
  bwPull: () => invoke<VaultItem[]>('bw_pull'),
  bwPush: (items: VaultItem[]) => invoke<VaultItem[]>('bw_push', { items }),
  bwDisconnect: () => invoke<void>('bw_disconnect')
};

/** 生成一个短 id（与鸿蒙版一致：8 位十六进制） */
export function newId(): string {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function createItem(): VaultItem {
  const now = Date.now();
  return {
    id: newId(),
    name: '',
    username: '',
    password: '',
    url: '',
    appName: '',
    notes: '',
    folder: '',
    favorite: false,
    totp: null,
    createdAt: now,
    updatedAt: now,
    bwId: ''
  };
}

export function createTotp(secret = '', issuer = '', account = ''): TotpConfig {
  return { secret, issuer, account, algorithm: 'SHA1', digits: 6, period: 30 };
}


export function formatTime(ms: number): string {
  if (!ms) return '—';
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
