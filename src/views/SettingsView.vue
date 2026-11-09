<script setup lang="ts">
import { computed, ref } from 'vue';
import { open, save } from '@tauri-apps/plugin-dialog';
import { api, copyText, formatTime, type AppInfo, type BwStatus, type VaultData, type VaultItem } from '../api';
import { lang, s, setLang } from '../i18n';

const props = defineProps<{ items: VaultItem[]; data: VaultData | null; info: AppInfo | null }>();
const emit = defineEmits<{
  lock: [];
  changed: [];
  toast: [text: string];
  merge: [items: VaultItem[]];
  pushed: [items: VaultItem[]];
}>();

const status = ref('');
const statusError = ref(false);
const busy = ref(false);

const autoLock = computed(() => props.info?.autoLockMinutes ?? 5);
const dataDir = computed(() => props.info?.dataDir ?? '');
const version = computed(() => props.info?.version ?? '');

function setStatus(text: string, isError: boolean) {
  status.value = text;
  statusError.value = isError;
}

/** 切换界面语言：立即生效并持久化到 meta.json */
async function switchLang() {
  const next: 'zh' | 'en' = lang.value === 'zh' ? 'en' : 'zh';
  setLang(next);
  await api.setLang(next);
  emit('changed');
}

async function cycleAutoLock() {
  const next = autoLock.value === 5 ? 15 : autoLock.value === 15 ? 30 : autoLock.value === 30 ? 0 : 5;
  await api.setAutoLock(next);
  emit('changed');
  setStatus(next === 0 ? s.value.stAutoLockOff : s.value.stAutoLockOn(next), false);
}

// ---------- 修改管理密码 ----------
const showChangePwd = ref(false);
const oldPwd = ref('');
const newPwd = ref('');
const confirmPwd = ref('');

async function changePassword() {
  if (newPwd.value.length < 8) {
    setStatus(s.value.stPwdTooShort, true);
    return;
  }
  if (newPwd.value !== confirmPwd.value) {
    setStatus(s.value.stPwdMismatch, true);
    return;
  }
  busy.value = true;
  try {
    await api.changePassword(oldPwd.value, newPwd.value);
    setStatus(s.value.stPwdUpdated, false);
    oldPwd.value = '';
    newPwd.value = '';
    confirmPwd.value = '';
    showChangePwd.value = false;
  } catch (err) {
    setStatus(String(err).includes('BAD_PASSWORD') ? s.value.stOldPwdWrong : String(err), true);
  } finally {
    busy.value = false;
  }
}

// ---------- Vaultwarden 同步 ----------
const bwServer = ref('');
const bwEmail = ref('');
const bwPassword = ref('');
const bwStatus = ref<BwStatus | null>(null);

async function refreshBwStatus() {
  try {
    bwStatus.value = await api.bwStatus();
  } catch {
    bwStatus.value = null;
  }
}

async function bwConnect() {
  if (!bwEmail.value.trim() || !bwPassword.value) {
    setStatus(s.value.stBwNeedCreds, true);
    return;
  }
  busy.value = true;
  setStatus(s.value.stBwConnecting, false);
  try {
    bwStatus.value = await api.bwConnect(bwServer.value, bwEmail.value, bwPassword.value);
    bwPassword.value = '';
    setStatus(s.value.stBwConnected(bwStatus.value.email), false);
  } catch (err) {
    setStatus(String(err), true);
  } finally {
    busy.value = false;
  }
}

async function bwPull() {
  busy.value = true;
  setStatus(s.value.stBwPulling, false);
  try {
    const items = await api.bwPull();
    if (items.length === 0) {
      setStatus(s.value.stBwEmpty, false);
      return;
    }
    emit('merge', items);
    setStatus(s.value.stBwPulled(items.length), false);
    await refreshBwStatus();
  } catch (err) {
    setStatus(String(err), true);
  } finally {
    busy.value = false;
  }
}

async function bwPush() {
  const pending = props.items.filter((it) => !it.bwId);
  if (pending.length === 0) {
    setStatus(s.value.stBwNothingToPush, false);
    return;
  }
  busy.value = true;
  setStatus(s.value.stBwPushing(pending.length), false);
  try {
    const updated = await api.bwPush(pending);
    emit('pushed', updated);
    setStatus(s.value.stBwPushed(updated.length), false);
  } catch (err) {
    setStatus(String(err), true);
  } finally {
    busy.value = false;
  }
}

async function bwDisconnect() {
  await api.bwDisconnect();
  bwStatus.value = null;
  setStatus(s.value.stBwDisconnected, false);
}

// ---------- 导出 / 导入 ----------
const backupPassword = ref('');
const importPassword = ref('');

async function exportFile(kind: 'encrypted' | 'mige-json' | 'bitwarden-json' | 'bitwarden-csv' | 'otpauth') {
  if (!props.data) return;
  if (kind === 'encrypted' && backupPassword.value.length < 8) {
    setStatus(s.value.stBackupPwdShort, true);
    return;
  }
  busy.value = true;
  try {
    let content: string;
    let name: string;
    if (kind === 'encrypted') {
      content = await api.exportEncrypted(props.data, backupPassword.value);
      name = `mige-backup-${Date.now()}.mige`;
    } else {
      content = await api.exportPlain(props.data, kind);
      const ext = kind === 'bitwarden-csv' ? 'csv' : kind === 'otpauth' ? 'txt' : 'json';
      name = `mige-${kind}-${Date.now()}.${ext}`;
    }
    const path = await save({ defaultPath: name });
    if (!path) {
      setStatus(s.value.stExportCanceled, false);
      return;
    }
    await api.writeFile(path, content);
    setStatus(s.value.stExported(path), false);
  } catch (err) {
    setStatus(s.value.stExportFailed(String(err)), true);
  } finally {
    busy.value = false;
  }
}

async function importFile() {
  busy.value = true;
  try {
    const path = await open({
      multiple: false,
      filters: [{ name: 'mige', extensions: ['json', 'csv', 'txt', 'mige'] }]
    });
    if (!path || Array.isArray(path)) {
      setStatus(s.value.stImportCanceled, false);
      return;
    }
    const text = await api.readFile(path);
    const format = await api.detectFormat(text);
    const outcome =
      format === 'mige-encrypted'
        ? await api.importEncrypted(text, importPassword.value)
        : await api.importPlain(text, format);
    if (outcome.error) {
      setStatus(outcome.error, true);
      return;
    }
    if (outcome.items.length === 0) {
      setStatus(s.value.stImportEmpty, true);
      return;
    }
    emit('merge', outcome.items);
    setStatus(s.value.stImported(outcome.items.length), false);
  } catch (err) {
    setStatus(s.value.stImportFailed(String(err)), true);
  } finally {
    busy.value = false;
  }
}

async function copyEmail() {
  if (await copyText('liqihai1987@foxmail.com')) emit('toast', 'liqihai1987@foxmail.com');
}

void refreshBwStatus();
</script>

<template>
  <div class="page">
    <div class="page-header">
      <div class="page-title">{{ s.settingsTitle }}</div>
    </div>

    <div v-if="status" class="banner" :class="statusError ? 'err' : 'ok'" @click="status = ''">
      {{ status }}
    </div>

    <div class="card">
      <div class="row" style="justify-content: space-between">
        <div>
          <div>{{ s.language }}</div>
          <div class="faint" style="margin-top: 3px">{{ s.languageHint }}</div>
        </div>
        <button class="btn btn-ghost btn-sm" @click="switchLang">
          {{ lang === 'zh' ? s.langZh : s.langEn }}
        </button>
      </div>
    </div>

    <div class="card">
      <div class="row" style="justify-content: space-between">
        <div>
          <div>{{ s.autoLockLabel }}</div>
          <div class="faint" style="margin-top: 3px">
            {{ autoLock === 0 ? s.autoLockOff : s.autoLockHint(autoLock) }}
          </div>
        </div>
        <button class="btn btn-ghost btn-sm" @click="cycleAutoLock">
          {{ s.autoLockAdjust(autoLock) }}
        </button>
      </div>
      <div class="divider" style="margin: 12px 0"></div>

      <div class="row" style="justify-content: space-between">
        <div>
          <div>{{ s.changeMasterLabel }}</div>
          <div class="faint" style="margin-top: 3px">{{ s.changeMasterHint }}</div>
        </div>
        <button class="btn btn-ghost btn-sm" @click="showChangePwd = !showChangePwd">
          {{ showChangePwd ? s.collapse : s.edit }}
        </button>
      </div>

      <div v-if="showChangePwd" style="margin-top: 10px">
        <input v-model="oldPwd" class="input" type="password" :placeholder="s.pwdCurrent" />
        <input v-model="newPwd" class="input" type="password" :placeholder="s.pwdNew" style="margin-top: 8px" />
        <input
          v-model="confirmPwd"
          class="input"
          type="password"
          :placeholder="s.pwdConfirm"
          style="margin-top: 8px"
        />
        <button class="btn btn-sm" style="margin-top: 10px" :disabled="busy" @click="changePassword">
          {{ s.btnConfirmChange }}
        </button>
      </div>

      <div class="divider" style="margin: 12px 0"></div>
      <div class="row" style="justify-content: space-between">
        <div>
          <div>{{ s.lockNowLabel }}</div>
          <div class="faint" style="margin-top: 3px">{{ s.lockNowHint }}</div>
        </div>
        <button class="btn btn-ghost btn-sm" @click="emit('lock')">{{ s.lockNowAction }}</button>
      </div>
    </div>

    <div class="card">
      <div style="font-weight: 600; margin-bottom: 10px">{{ s.bwSection }}</div>

      <template v-if="bwStatus">
        <div class="row" style="justify-content: space-between; padding: 6px 0">
          <span class="muted">{{ s.bwConnected }}</span>
          <span class="ok">{{ bwStatus.email }}</span>
        </div>
        <div class="row" style="justify-content: space-between; padding: 6px 0">
          <span class="muted">{{ s.bwServer }}</span>
          <span class="faint" style="max-width: 65%; overflow: hidden; text-overflow: ellipsis">
            {{ bwStatus.server }}
          </span>
        </div>
        <div class="row" style="justify-content: space-between; padding: 6px 0">
          <span class="muted">{{ s.bwLastSync }}</span>
          <span class="faint">{{ formatTime(bwStatus.lastSyncAt) }}</span>
        </div>
        <div class="row" style="gap: 8px; margin-top: 10px">
          <button class="btn btn-sm" :disabled="busy" @click="bwPull">{{ s.bwPull }}</button>
          <button class="btn btn-ghost btn-sm" :disabled="busy" @click="bwPush">{{ s.bwUpload }}</button>
          <button class="btn btn-danger btn-sm" :disabled="busy" @click="bwDisconnect">
            {{ s.bwDisconnect }}
          </button>
        </div>
      </template>

      <template v-else>
        <label class="label" style="margin-top: 0">{{ s.bwServer }}</label>
        <input v-model="bwServer" class="input" :placeholder="s.bwServerPlaceholder" />
        <label class="label">{{ s.bwEmail }}</label>
        <input v-model="bwEmail" class="input" placeholder="me@example.com" />
        <label class="label">{{ s.bwPassword }}</label>
        <input v-model="bwPassword" class="input" type="password" :placeholder="s.bwPassword" />
        <button class="btn btn-sm" style="margin-top: 10px" :disabled="busy" @click="bwConnect">
          {{ busy ? s.bwConnecting : s.bwConnectButton }}
        </button>
        <div class="faint" style="margin-top: 8px">{{ s.bwKdfHint }}</div>
      </template>
    </div>

    <div class="card">
      <div style="font-weight: 600; margin-bottom: 10px">{{ s.dataSection }}</div>

      <label class="label" style="margin-top: 0">{{ s.exportLabel }}</label>
      <input v-model="backupPassword" class="input" type="password" :placeholder="s.backupPasswordPlaceholder" />
      <div class="row" style="gap: 8px; margin-top: 8px; flex-wrap: wrap">
        <button class="btn btn-sm" :disabled="busy" @click="exportFile('encrypted')">
          {{ s.exportEncrypted }}
        </button>
        <button class="btn btn-ghost btn-sm" :disabled="busy" @click="exportFile('mige-json')">
          {{ s.exportMigeJson }}
        </button>
        <button class="btn btn-ghost btn-sm" :disabled="busy" @click="exportFile('bitwarden-json')">
          {{ s.exportBwJson }}
        </button>
        <button class="btn btn-ghost btn-sm" :disabled="busy" @click="exportFile('bitwarden-csv')">
          {{ s.exportCsv }}
        </button>
        <button class="btn btn-ghost btn-sm" :disabled="busy" @click="exportFile('otpauth')">
          {{ s.exportOtpauth }}
        </button>
      </div>

      <div class="divider" style="margin: 14px 0"></div>

      <label class="label" style="margin-top: 0">{{ s.importLabel }}</label>
      <input v-model="importPassword" class="input" type="password" :placeholder="s.importPasswordPlaceholder" />
      <button class="btn btn-sm" style="margin-top: 8px" :disabled="busy" @click="importFile">
        {{ busy ? s.processing : s.importButton }}
      </button>
    </div>

    <div class="card">
      <div style="font-weight: 600; margin-bottom: 10px">{{ s.aboutSection }}</div>
      <div class="row" style="justify-content: space-between; padding: 6px 0">
        <span class="muted">{{ s.aboutVersion }}</span>
        <span>{{ version || '—' }}</span>
      </div>
      <div class="row" style="justify-content: space-between; padding: 6px 0">
        <span class="muted">{{ s.aboutDeveloper }}</span>
        <span>李启海</span>
      </div>
      <div class="row" style="justify-content: space-between; padding: 6px 0">
        <span class="muted">{{ s.aboutContact }}</span>
        <span class="row" style="gap: 8px">
          <span style="color: #5b8cff">liqihai1987@foxmail.com</span>
          <button class="btn btn-ghost btn-sm" @click="copyEmail">{{ s.copy }}</button>
        </span>
      </div>
      <div class="row" style="justify-content: space-between; padding: 6px 0">
        <span class="muted">{{ s.aboutDataDir }}</span>
        <span class="faint" style="max-width: 60%; overflow: hidden; text-overflow: ellipsis">
          {{ dataDir || '—' }}
        </span>
      </div>
      <div class="faint" style="margin-top: 10px; line-height: 1.6">{{ s.aboutCrypto(120000) }}</div>
    </div>
  </div>
</template>
