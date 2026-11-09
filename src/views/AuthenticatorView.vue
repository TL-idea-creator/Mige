<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue';
import { api, copyText, createItem, createTotp, type VaultItem } from '../api';
import { s } from '../i18n';

const props = defineProps<{ items: VaultItem[] }>();
const emit = defineEmits<{ add: [item: VaultItem]; copied: [text: string] }>();

interface Row {
  id: string;
  label: string;
  title: string;
  code: string;
  remaining: number;
  period: number;
}

const rows = ref<Row[]>([]);
const showAdd = ref(false);
const form = reactive({
  name: '',
  account: '',
  folder: '',
  secret: '',
  algorithm: 'SHA1',
  digits: 6,
  period: 30
});
const formError = ref('');
let timer: number | undefined;

const totpItems = computed(() => props.items.filter((it) => it.totp && it.totp.secret));

function titleOf(item: VaultItem): string {
  return item.name.trim() || item.appName.trim() || item.username.trim() || s.value.untitled;
}

async function tick() {
  const now = Date.now();
  const next: Row[] = [];
  for (const item of totpItems.value) {
    const cfg = item.totp;
    if (!cfg) continue;
    let code = '';
    let remaining = cfg.period > 0 ? cfg.period : 30;
    try {
      const [value, left] = await api.totpMeta(cfg, now);
      code = value;
      remaining = left;
    } catch {
      // 单条失败不影响其它条目
    }
    next.push({
      id: item.id,
      label: [cfg.issuer, cfg.account].filter(Boolean).join(' · '),
      title: titleOf(item),
      code,
      remaining,
      period: cfg.period > 0 ? cfg.period : 30
    });
  }
  rows.value = next;
}

async function copy(code: string) {
  if (code && (await copyText(code))) emit('copied', s.value.copiedCode);
}

async function parseLink() {
  if (!form.secret.trim()) {
    formError.value = s.value.authErrNoSecret;
    return;
  }
  const cfg = await api.totpParse(form.secret);
  if (!cfg) {
    formError.value = s.value.editorErrBadLink;
    return;
  }
  form.secret = cfg.secret;
  form.name = form.name || cfg.issuer || cfg.account;
  form.account = form.account || cfg.account;
  form.algorithm = cfg.algorithm;
  form.digits = cfg.digits;
  form.period = cfg.period;
  formError.value = s.value.editorFilledFromLink;
}

function save() {
  const secret = form.secret.replace(/[\s-]/g, '').toUpperCase();
  if (!secret) {
    formError.value = s.value.authErrNoSecret;
    return;
  }
  if (!/^[A-Z2-7]+$/.test(secret)) {
    formError.value = s.value.authErrBadSecret;
    return;
  }
  const item = createItem();
  item.name = form.name.trim() || form.account.trim() || s.value.untitled;
  item.username = form.account.trim();
  item.folder = form.folder.trim();
  item.totp = {
    ...createTotp(secret),
    issuer: form.name.trim(),
    account: form.account.trim(),
    algorithm: form.algorithm,
    digits: Number(form.digits),
    period: Number(form.period)
  };
  emit('add', item);
  showAdd.value = false;
  form.name = '';
  form.account = '';
  form.folder = '';
  form.secret = '';
  formError.value = '';
  setTimeout(tick, 50);
}

onMounted(() => {
  void tick();
  timer = window.setInterval(tick, 1000);
});

onBeforeUnmount(() => {
  if (timer) window.clearInterval(timer);
});
</script>

<template>
  <div class="page">
    <div class="page-header">
      <div class="page-title">{{ s.authTitle }}</div>
      <button v-if="!showAdd" class="btn btn-sm" @click="showAdd = true">{{ s.authAdd }}</button>
      <template v-else>
        <button class="btn btn-ghost btn-sm" @click="showAdd = false">{{ s.cancel }}</button>
        <button class="btn btn-sm" @click="save">{{ s.save }}</button>
      </template>
    </div>

    <div v-if="showAdd" class="card">
      <div class="row" style="gap: 12px">
        <div style="flex: 1">
          <label class="label">{{ s.authNameLabel }}</label>
          <input v-model="form.name" class="input" :placeholder="s.authNamePlaceholder" />
        </div>
        <div style="flex: 1">
          <label class="label">{{ s.authAccountLabel }}</label>
          <input v-model="form.account" class="input" :placeholder="s.authAccountPlaceholder" />
        </div>
      </div>

      <label class="label">{{ s.authFolderLabel }}</label>
      <input v-model="form.folder" class="input" :placeholder="s.authFolderPlaceholder" />

      <label class="label">{{ s.editorSecretLabel }}</label>
      <div class="row">
        <input v-model="form.secret" class="input" placeholder="JBSWY3DPEHPK3PXP" style="flex: 1" />
        <button class="btn btn-ghost btn-sm" @click="parseLink">{{ s.authParseLink }}</button>
      </div>

      <div class="row" style="gap: 12px">
        <div style="flex: 1">
          <label class="label">{{ s.editorAlgorithm }}</label>
          <select v-model="form.algorithm" class="input">
            <option value="SHA1">SHA1</option>
            <option value="SHA256">SHA256</option>
            <option value="SHA512">SHA512</option>
          </select>
        </div>
        <div style="width: 110px">
          <label class="label">{{ s.editorDigits }}</label>
          <select v-model.number="form.digits" class="input">
            <option :value="6">6</option>
            <option :value="8">8</option>
          </select>
        </div>
        <div style="width: 110px">
          <label class="label">{{ s.editorPeriod }}</label>
          <input v-model.number="form.period" class="input" type="number" />
        </div>
      </div>

      <div v-if="formError" class="error">{{ formError }}</div>
    </div>

    <div v-if="rows.length === 0 && !showAdd" class="card muted" style="text-align: center; padding: 36px">
      <div>{{ s.authEmpty }}</div>
      <div class="faint" style="margin-top: 6px">{{ s.authEmptyHint }}</div>
    </div>

    <div v-for="row in rows" :key="row.id" class="card" style="margin-top: 12px">
      <div class="row" style="justify-content: space-between">
        <span class="faint">{{ row.label || row.title }}</span>
        <span class="faint">{{ row.remaining }}s</span>
      </div>
      <div class="row" style="margin-top: 4px">
        <span class="code" style="flex: 1">{{ row.code || '------' }}</span>
        <span style="color: #5b8cff; font-size: 13px; cursor: pointer" @click="copy(row.code)">
          {{ s.copy }}
        </span>
      </div>
      <div class="progress" style="margin-top: 8px">
        <div :style="{ width: (row.remaining / row.period) * 100 + '%' }"></div>
      </div>
      <div class="faint" style="margin-top: 6px">{{ row.title }}</div>
    </div>
  </div>
</template>
