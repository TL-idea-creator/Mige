<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue';
import { api, copyText, formatTime, type VaultItem } from '../api';
import { s } from '../i18n';

const props = defineProps<{ item: VaultItem }>();
const emit = defineEmits<{
  edit: [item: VaultItem];
  delete: [item: VaultItem];
  copied: [text: string];
}>();

const revealPassword = ref(false);
const code = ref('');
const remaining = ref(30);
const period = ref(30);
let timer: number | undefined;

const title = computed(
  () =>
    props.item.name.trim() ||
    props.item.appName.trim() ||
    props.item.username.trim() ||
    s.value.untitled
);

const totpLabel = computed(() => {
  const cfg = props.item.totp;
  if (!cfg) return '';
  if (cfg.issuer && cfg.account) return `${cfg.issuer} · ${cfg.account}`;
  return cfg.issuer || cfg.account;
});

async function refreshCode() {
  const cfg = props.item.totp;
  if (!cfg || !cfg.secret) {
    code.value = '';
    return;
  }
  try {
    const [value, left] = await api.totpMeta(cfg, Date.now());
    code.value = value;
    remaining.value = left;
    period.value = cfg.period > 0 ? cfg.period : 30;
  } catch {
    code.value = '';
  }
}

async function copy(text: string, label: string) {
  if (!text) return;
  if (await copyText(text)) emit('copied', label);
}

async function openSite() {
  if (!props.item.url) return;
  try {
    await api.openUrl(props.item.url);
  } catch {
    emit('copied', s.value.detailOpenFailed);
  }
}

function startTimer() {
  stopTimer();
  void refreshCode();
  timer = window.setInterval(refreshCode, 1000);
}

function stopTimer() {
  if (timer) {
    window.clearInterval(timer);
    timer = undefined;
  }
}

watch(
  () => props.item.id,
  () => {
    revealPassword.value = false;
    startTimer();
  },
  { immediate: true }
);

onBeforeUnmount(stopTimer);
</script>

<template>
  <div class="page">
    <div class="page-header">
      <div class="page-title">{{ title }}</div>
      <button class="btn btn-ghost btn-sm" @click="emit('edit', item)">{{ s.edit }}</button>
    </div>

    <div v-if="item.totp && item.totp.secret" class="card">
      <div class="faint">{{ totpLabel }}</div>
      <div class="row" style="margin-top: 6px">
        <span class="code" style="flex: 1">{{ code || '------' }}</span>
        <span class="muted" style="font-size: 13px">{{ remaining }}s</span>
      </div>
      <div class="progress" style="margin-top: 10px">
        <div :style="{ width: (remaining / period) * 100 + '%' }"></div>
      </div>
      <button class="btn btn-ghost btn-sm" style="margin-top: 10px" @click="copy(code, s.copiedCode)">
        {{ s.detailCopyCode }}
      </button>
    </div>

    <div class="card" style="margin-top: 12px">
      <div class="row" style="justify-content: space-between">
        <div>
          <div class="faint">{{ s.detailAccount }}</div>
          <div>{{ item.username || '—' }}</div>
        </div>
        <button
          v-if="item.username"
          class="btn btn-ghost btn-sm"
          @click="copy(item.username, s.copiedAccount)"
        >
          {{ s.copy }}
        </button>
      </div>
      <div class="divider" style="margin: 12px 0"></div>

      <div class="row" style="justify-content: space-between">
        <div style="flex: 1; min-width: 0">
          <div class="faint">{{ s.detailPassword }}</div>
          <div style="font-family: Consolas, monospace">
            {{ revealPassword ? item.password : '••••••••••' }}
          </div>
        </div>
        <div class="row" style="gap: 6px">
          <button class="btn btn-ghost btn-sm" @click="revealPassword = !revealPassword">
            {{ revealPassword ? s.detailHide : s.detailShow }}
          </button>
          <button class="btn btn-ghost btn-sm" @click="copy(item.password, s.copiedPassword)">
            {{ s.copy }}
          </button>
        </div>
      </div>

      <template v-if="item.url">
        <div class="divider" style="margin: 12px 0"></div>
        <div class="row" style="justify-content: space-between">
          <div style="flex: 1; min-width: 0">
            <div class="faint">{{ s.detailWebsite }}</div>
            <div style="color: #5b8cff; overflow: hidden; text-overflow: ellipsis">{{ item.url }}</div>
          </div>
          <div class="row" style="gap: 6px">
            <button class="btn btn-ghost btn-sm" @click="openSite">{{ s.detailOpen }}</button>
            <button class="btn btn-ghost btn-sm" @click="copy(item.url, s.copiedUrl)">
              {{ s.copy }}
            </button>
          </div>
        </div>
      </template>

      <template v-if="item.appName">
        <div class="divider" style="margin: 12px 0"></div>
        <div class="row" style="justify-content: space-between">
          <div>
            <div class="faint">{{ s.detailApp }}</div>
            <div>{{ item.appName }}</div>
          </div>
          <button class="btn btn-ghost btn-sm" @click="copy(item.appName, s.copiedApp)">
            {{ s.copy }}
          </button>
        </div>
      </template>

      <template v-if="item.notes">
        <div class="divider" style="margin: 12px 0"></div>
        <div class="faint">{{ s.detailNotes }}</div>
        <div style="white-space: pre-wrap; margin-top: 6px">{{ item.notes }}</div>
      </template>
    </div>

    <div class="row" style="margin-top: 12px; justify-content: space-between">
      <span class="faint">{{ s.detailCreatedAt(formatTime(item.createdAt)) }}</span>
      <button class="btn btn-danger btn-sm" @click="emit('delete', item)">{{ s.detailDelete }}</button>
    </div>
  </div>
</template>
