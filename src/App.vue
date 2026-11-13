<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { api, createItem, type AppInfo, type VaultData, type VaultItem } from './api';
import { s, setLang } from './i18n';
import SetupView from './views/SetupView.vue';
import UnlockView from './views/UnlockView.vue';
import VaultListView from './views/VaultListView.vue';
import ItemDetailView from './views/ItemDetailView.vue';
import ItemEditorView from './views/ItemEditorView.vue';
import GeneratorView from './views/GeneratorView.vue';
import AuthenticatorView from './views/AuthenticatorView.vue';
import SettingsView from './views/SettingsView.vue';

type Phase = 'loading' | 'setup' | 'locked' | 'unlocked';
type Tab = 'vault' | 'auth' | 'generator' | 'settings';

const phase = ref<Phase>('loading');
const info = ref<AppInfo | null>(null);
const data = ref<VaultData | null>(null);
const busy = ref(false);
const message = ref('');
const tab = ref<Tab>('vault');
const selectedId = ref('');
const editorMode = ref<'' | 'new' | 'edit'>('');
const editorItem = ref<VaultItem>(createItem());
const toastText = ref('');
let toastTimer: number | undefined;

const tabs = computed<{ key: Tab; icon: string; label: string }[]>(() => [
  { key: 'vault', icon: '🔑', label: s.value.vaultTitle },
  { key: 'auth', icon: '🛡', label: s.value.authTitle },
  { key: 'generator', icon: '✦', label: s.value.genTitle },
  { key: 'settings', icon: '⚙', label: s.value.settingsTitle }
]);

const items = computed(() => data.value?.items ?? []);

const selectedItem = computed(() => items.value.find((it) => it.id === selectedId.value) ?? null);

/** 密码库分组筛选用的分类列表 */
const folders = computed(() => {
  const names = new Set<string>();
  for (const item of items.value) {
    const folder = item.folder.trim();
    if (folder) names.add(folder);
  }
  return Array.from(names).sort((a, b) => a.localeCompare(b));
});

function toast(text: string) {
  toastText.value = text;
  if (toastTimer) window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => (toastText.value = ''), 2000);
}

async function bootstrap() {
  phase.value = 'loading';
  try {
    info.value = await api.info();
    setLang(info.value.lang);
    phase.value = info.value.initialized ? 'locked' : 'setup';
  } catch (err) {
    message.value = s.value.stInitFailed(String(err));
    phase.value = 'setup';
  }
}

async function doSetup(password: string) {
  busy.value = true;
  message.value = '';
  try {
    data.value = await api.setup(password);
    phase.value = 'unlocked';
    info.value = await api.info();
    toast(s.value.stVaultCreated);
  } catch (err) {
    message.value = String(err);
  } finally {
    busy.value = false;
  }
}

async function doUnlock(password: string) {
  busy.value = true;
  message.value = '';
  try {
    data.value = await api.unlock(password);
    phase.value = 'unlocked';
    info.value = await api.info();
  } catch (err) {
    message.value = String(err).includes('BAD_PASSWORD') ? s.value.wrongPassword : s.value.unlockFailed;
  } finally {
    busy.value = false;
  }
}

async function lock() {
  await api.lock();
  data.value = null;
  selectedId.value = '';
  editorMode.value = '';
  phase.value = 'locked';
  message.value = '';
}

/** 修改后统一落盘（加密保存由后端完成） */
async function persist() {
  if (!data.value) return;
  await api.save(data.value);
}

function selectItem(id: string) {
  selectedId.value = id;
  editorMode.value = '';
}

function startCreate() {
  editorItem.value = createItem();
  editorMode.value = 'new';
}

function startEdit(item: VaultItem) {
  editorItem.value = JSON.parse(JSON.stringify(item)) as VaultItem;
  editorMode.value = 'edit';
}

async function saveItem(item: VaultItem) {
  if (!data.value) return;
  item.updatedAt = Date.now();
  const index = data.value.items.findIndex((it) => it.id === item.id);
  if (index >= 0) {
    data.value.items[index] = item;
  } else {
    data.value.items.push(item);
  }
  await persist();
  selectedId.value = item.id;
  editorMode.value = '';
  toast(s.value.saved);
}

async function deleteItem(item: VaultItem) {
  if (!data.value) return;
  const name = item.name.trim() || s.value.untitled;
  if (!window.confirm(s.value.deleteConfirm(name))) return;
  data.value.items = data.value.items.filter((it) => it.id !== item.id);
  await persist();
  selectedId.value = '';
  toast(s.value.deleted);
}

async function toggleFavorite(id: string) {
  if (!data.value) return;
  const item = data.value.items.find((it) => it.id === id);
  if (!item) return;
  item.favorite = !item.favorite;
  await persist();
}

/** 验证器新增条目：同时进入密码库 */
async function addAuthenticator(item: VaultItem) {
  if (!data.value) return;
  data.value.items.push(item);
  await persist();
  toast(s.value.authAdded);
}

/** 合并服务端条目：先按 bwId 就地更新已关联条目，再按「名称+账号+密码」去重，最后才新增 */
async function mergeItems(incoming: VaultItem[]) {
  if (!data.value) return;
  let added = 0;
  let updated = 0;
  let skipped = 0;
  for (const item of incoming) {
    // ① 已关联过这条服务端记录（bwId 相同）→ 就地更新，避免本地改动后拉取产生重复条目
    const linked = item.bwId ? data.value.items.find((it) => it.bwId === item.bwId) : undefined;
    if (linked) {
      linked.name = item.name;
      linked.username = item.username;
      linked.password = item.password;
      linked.url = item.url;
      linked.notes = item.notes;
      linked.favorite = item.favorite;
      if (item.totp) linked.totp = item.totp;
      linked.updatedAt = Date.now();
      updated++;
      continue;
    }
    // ② 内容完全一致视为重复（导入 CSV/JSON 场景）
    const exists = data.value.items.some(
      (it) => it.name === item.name && it.username === item.username && it.password === item.password
    );
    if (exists) {
      skipped++;
      continue;
    }
    data.value.items.push(item);
    added++;
  }
  await persist();
  if (updated > 0) {
    toast(s.value.stBwPulled(updated));
  } else if (added > 0) {
    toast(s.value.stImported(added));
  } else {
    toast(s.value.stBwEmpty + (skipped > 0 ? ` (${skipped})` : ''));
  }
}

/** 上传成功后把服务端 id 写回本地条目 */
async function applyPushed(updated: VaultItem[]) {
  if (!data.value) return;
  for (const item of updated) {
    const target = data.value.items.find((it) => it.id === item.id);
    if (target) {
      target.bwId = item.bwId;
    }
  }
  await persist();
  toast(s.value.stBwPushed(updated.length));
}

async function refreshInfo() {
  info.value = await api.info();
  setLang(info.value.lang);
}

// ---------- 自动锁定：窗口失焦超过阈值即锁定 ----------
let autoLockTimer: number | undefined;
let blurredAt = 0;

function onWindowBlur() {
  blurredAt = Date.now();
}

function onWindowFocus() {
  blurredAt = 0;
}

function checkAutoLock() {
  if (phase.value !== 'unlocked') return;
  const minutes = info.value?.autoLockMinutes ?? 5;
  if (minutes <= 0 || blurredAt === 0) return;
  if (Date.now() - blurredAt > minutes * 60 * 1000) {
    void lock();
  }
}

onMounted(() => {
  window.addEventListener('blur', onWindowBlur);
  window.addEventListener('focus', onWindowFocus);
  autoLockTimer = window.setInterval(checkAutoLock, 10_000);
  void bootstrap();
});

onBeforeUnmount(() => {
  window.removeEventListener('blur', onWindowBlur);
  window.removeEventListener('focus', onWindowFocus);
  if (autoLockTimer) window.clearInterval(autoLockTimer);
});
</script>

<template>
  <div v-if="phase === 'loading'" class="center-page muted">…</div>

  <SetupView v-else-if="phase === 'setup'" :busy="busy" :message="message" @submit="doSetup" />

  <UnlockView v-else-if="phase === 'locked'" :busy="busy" :message="message" @submit="doUnlock" />

  <div v-else class="shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-logo">密</div>
        <div class="brand-name">{{ s.appName }}</div>
      </div>
      <div
        v-for="item in tabs"
        :key="item.key"
        class="nav-item"
        :class="{ active: tab === item.key }"
        @click="tab = item.key"
      >
        <span class="nav-icon">{{ item.icon }}</span>
        <span>{{ item.label }}</span>
      </div>
      <div class="sidebar-footer">
        <button class="btn btn-ghost btn-sm" style="width: 100%" @click="lock">
          {{ s.lockNowLabel }}
        </button>
      </div>
    </aside>

    <main class="content">
      <div v-if="tab === 'vault'" class="shell" style="height: 100%">
        <div style="width: 340px; border-right: 1px solid #242b39; display: flex; flex-direction: column">
          <VaultListView
            :items="items"
            :folders="folders"
            :selected-id="selectedId"
            @select="selectItem"
            @new="startCreate"
            @favorite="toggleFavorite"
          />
        </div>
        <div class="content">
          <ItemEditorView
            v-if="editorMode"
            :initial="editorItem"
            @save="saveItem"
            @cancel="editorMode = ''"
          />
          <ItemDetailView
            v-else-if="selectedItem"
            :item="selectedItem"
            @edit="startEdit"
            @delete="deleteItem"
            @copied="toast"
          />
          <div v-else class="center-page muted" style="height: 100%">{{ s.selectItemHint }}</div>
        </div>
      </div>

      <AuthenticatorView v-else-if="tab === 'auth'" :items="items" @add="addAuthenticator" @copied="toast" />

      <GeneratorView v-else-if="tab === 'generator'" @copied="toast" />

      <SettingsView
        v-else
        :items="items"
        :data="data"
        :info="info"
        @lock="lock"
        @changed="refreshInfo"
        @toast="toast"
        @merge="mergeItems"
        @pushed="applyPushed"
      />
    </main>

    <div v-if="toastText" class="toast">{{ toastText }}</div>
  </div>
</template>
