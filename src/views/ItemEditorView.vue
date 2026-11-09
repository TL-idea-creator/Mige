<script setup lang="ts">
import { computed, reactive, ref } from 'vue';
import { api, createTotp, type PasswordRule, type VaultItem } from '../api';
import { s, strengthText } from '../i18n';

const props = defineProps<{ initial: VaultItem }>();
const emit = defineEmits<{ save: [item: VaultItem]; cancel: [] }>();

const draft = reactive<VaultItem>(JSON.parse(JSON.stringify(props.initial)) as VaultItem);
const showGenerator = ref(false);
const error = ref('');
const parseHint = ref('');

const rule = reactive<PasswordRule>({
  length: 16,
  upper: true,
  lower: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: false
});

const strength = ref(0);
const candidates = ref(0);

const isNew = computed(() => !props.initial.name && !props.initial.username);

async function generate() {
  const result = await api.generatePassword(rule);
  draft.password = result.password;
  strength.value = result.strength;
  candidates.value = result.candidates;
}

function toggleMfa() {
  draft.totp = draft.totp ? null : createTotp();
}

async function parseLink(uri: string) {
  if (!uri.trim()) return;
  const cfg = await api.totpParse(uri);
  if (!cfg) {
    parseHint.value = s.value.editorErrBadLink;
    return;
  }
  draft.totp = cfg;
  parseHint.value = s.value.editorFilledFromLink;
}

function save() {
  const name = draft.name.trim();
  const url = draft.url.trim();
  if (!name && !url) {
    error.value = s.value.editorErrNoName;
    return;
  }
  if (draft.totp && !draft.totp.secret.trim()) {
    draft.totp = null;
  }
  error.value = '';
  emit('save', JSON.parse(JSON.stringify(draft)) as VaultItem);
}

const ruleRows = computed(() => [
  { key: 'upper', text: s.value.ruleUpper },
  { key: 'lower', text: s.value.ruleLower },
  { key: 'digits', text: s.value.ruleDigits },
  { key: 'symbols', text: s.value.ruleSymbols },
  { key: 'excludeAmbiguous', text: s.value.ruleExclude }
]);
</script>

<template>
  <div class="page">
    <div class="page-header">
      <div class="page-title">{{ isNew ? s.editorNew : s.editorEdit }}</div>
      <button class="btn btn-ghost btn-sm" @click="emit('cancel')">{{ s.cancel }}</button>
      <button class="btn btn-sm" @click="save">{{ s.save }}</button>
    </div>

    <div class="card">
      <label class="label">{{ s.editorNameLabel }}</label>
      <input v-model="draft.name" class="input" :placeholder="s.editorNamePlaceholder" />

      <label class="label">{{ s.editorAccountLabel }}</label>
      <input v-model="draft.username" class="input" :placeholder="s.editorAccountPlaceholder" />

      <div class="row" style="justify-content: space-between; margin: 14px 0 6px">
        <span class="label" style="margin: 0">{{ s.detailPassword }}</span>
        <span
          style="color: #5b8cff; font-size: 12px; cursor: pointer"
          @click="showGenerator = !showGenerator"
        >
          {{ showGenerator ? s.editorHideGen : s.editorShowGen }}
        </span>
      </div>
      <input
        v-model="draft.password"
        class="input"
        :placeholder="s.editorPasswordPlaceholder"
      />

      <div v-if="draft.password" class="faint" style="margin-top: 6px">
        {{ s.genStrength(strengthText(strength), draft.password.length) }}
      </div>

      <div v-if="showGenerator" style="margin-top: 10px">
        <div class="row">
          <span class="muted" style="width: 52px; font-size: 13px">{{ s.editorLength }}</span>
          <input
            v-model.number="rule.length"
            type="range"
            min="8"
            max="64"
            style="flex: 1"
            @change="generate"
          />
          <span style="width: 32px; text-align: right">{{ rule.length }}</span>
        </div>
        <label
          v-for="opt in ruleRows"
          :key="opt.key"
          class="row"
          style="padding: 6px 0; justify-content: space-between"
        >
          <span class="muted" style="font-size: 13px">{{ opt.text }}</span>
          <span
            class="switch"
            :class="{ on: (rule as any)[opt.key] }"
            @click="((rule as any)[opt.key] = !(rule as any)[opt.key]); generate()"
          ></span>
        </label>
        <button class="btn btn-ghost btn-sm" style="margin-top: 8px" @click="generate">
          {{ s.editorRegenerate(candidates) }}
        </button>
      </div>

      <label class="label">{{ s.editorUrlLabel }}</label>
      <input v-model="draft.url" class="input" :placeholder="s.editorUrlPlaceholder" />

      <label class="label">{{ s.editorAppLabel }}</label>
      <input v-model="draft.appName" class="input" :placeholder="s.editorAppPlaceholder" />

      <div class="row" style="gap: 12px">
        <div style="flex: 1">
          <label class="label">{{ s.editorFolderLabel }}</label>
          <input v-model="draft.folder" class="input" :placeholder="s.editorFolderPlaceholder" />
        </div>
        <div style="padding-top: 20px">
          <span
            class="row"
            style="gap: 6px; cursor: pointer"
            @click="draft.favorite = !draft.favorite"
          >
            <span :style="{ color: draft.favorite ? '#f2b255' : '#5c6577' }">★</span>
            <span class="muted" style="font-size: 13px">{{ s.editorFavorite }}</span>
          </span>
        </div>
      </div>

      <label class="label">{{ s.editorNotesLabel }}</label>
      <textarea v-model="draft.notes" class="textarea" :placeholder="s.editorNotesPlaceholder"></textarea>
    </div>

    <div class="card">
      <div class="row" style="justify-content: space-between">
        <span style="font-weight: 600">{{ s.editorMfa }}</span>
        <span class="switch" :class="{ on: !!draft.totp }" @click="toggleMfa"></span>
      </div>

      <template v-if="draft.totp">
        <label class="label">{{ s.editorSecretLabel }}</label>
        <div class="row">
          <input
            v-model="draft.totp.secret"
            class="input"
            placeholder="JBSWY3DPEHPK3PXP"
            style="flex: 1"
          />
          <button class="btn btn-ghost btn-sm" @click="parseLink(draft.totp!.secret)">
            {{ s.editorParse }}
          </button>
        </div>
        <div v-if="parseHint" class="faint" style="margin-top: 6px">{{ parseHint }}</div>

        <div class="row" style="gap: 12px">
          <div style="flex: 1">
            <label class="label">{{ s.editorIssuerLabel }}</label>
            <input v-model="draft.totp.issuer" class="input" :placeholder="s.editorIssuerPlaceholder" />
          </div>
          <div style="flex: 1">
            <label class="label">{{ s.detailAccount }}</label>
            <input v-model="draft.totp.account" class="input" :placeholder="s.editorAccountPlaceholder" />
          </div>
        </div>

        <div class="row" style="gap: 12px">
          <div style="flex: 1">
            <label class="label">{{ s.editorAlgorithm }}</label>
            <select v-model="draft.totp.algorithm" class="input">
              <option value="SHA1">SHA1</option>
              <option value="SHA256">SHA256</option>
              <option value="SHA512">SHA512</option>
            </select>
          </div>
          <div style="width: 110px">
            <label class="label">{{ s.editorDigits }}</label>
            <select v-model.number="draft.totp.digits" class="input">
              <option :value="6">6</option>
              <option :value="8">8</option>
            </select>
          </div>
          <div style="width: 110px">
            <label class="label">{{ s.editorPeriod }}</label>
            <input v-model.number="draft.totp.period" class="input" type="number" />
          </div>
        </div>
      </template>
    </div>

    <div v-if="error" class="error">{{ error }}</div>
  </div>
</template>
