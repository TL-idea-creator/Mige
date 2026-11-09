<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { api, copyText, type PasswordRule } from '../api';
import { s, strengthText } from '../i18n';

const emit = defineEmits<{ copied: [text: string] }>();

const rule = reactive<PasswordRule>({
  length: 16,
  upper: true,
  lower: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: false
});

const password = ref('');
const strength = ref(0);
const candidates = ref(0);
const history = ref<string[]>([]);

async function regenerate() {
  const result = await api.generatePassword(rule);
  password.value = result.password;
  strength.value = result.strength;
  candidates.value = result.candidates;
  if (result.password) {
    history.value = [result.password, ...history.value.filter((p) => p !== result.password)].slice(0, 6);
  }
}

async function change(patch: () => void) {
  patch();
  await regenerate();
}

async function copy(text: string) {
  if (text && (await copyText(text))) emit('copied', s.value.copiedPassword);
}

const ruleRows = computed(() => [
  { key: 'upper', text: s.value.ruleUpper },
  { key: 'lower', text: s.value.ruleLower },
  { key: 'digits', text: s.value.ruleDigits },
  { key: 'symbols', text: s.value.ruleSymbols },
  { key: 'excludeAmbiguous', text: s.value.ruleExclude }
]);

onMounted(regenerate);
</script>

<template>
  <div class="page">
    <div class="page-header">
      <div class="page-title">{{ s.genTitle }}</div>
    </div>

    <div class="card" style="text-align: center">
      <div
        style="
          font-family: Consolas, monospace;
          font-size: 22px;
          color: #5b8cff;
          word-break: break-all;
          line-height: 1.5;
        "
      >
        {{ password || s.genNoneEnabled }}
      </div>
      <div class="row" style="justify-content: center; gap: 14px; margin-top: 10px">
        <span class="faint">{{ s.genStrength(strengthText(strength), password.length) }}</span>
        <span class="faint">{{ s.genCandidates(candidates) }}</span>
        <button class="btn btn-ghost btn-sm" @click="copy(password)">{{ s.copy }}</button>
      </div>
      <button class="btn" style="width: 100%; margin-top: 14px" @click="regenerate">
        {{ s.genRegenerate }}
      </button>
    </div>

    <div class="card">
      <div class="row">
        <span class="muted" style="width: 90px">{{ s.genLength }}</span>
        <input
          v-model.number="rule.length"
          type="range"
          min="8"
          max="64"
          style="flex: 1"
          @change="change(() => {})"
        />
        <span style="width: 36px; text-align: right">{{ rule.length }}</span>
      </div>

      <div class="divider" style="margin: 10px 0"></div>

      <label
        v-for="opt in ruleRows"
        :key="opt.key"
        class="row"
        style="padding: 7px 0; justify-content: space-between"
      >
        <span>{{ opt.text }}</span>
        <span
          class="switch"
          :class="{ on: (rule as any)[opt.key] }"
          @click="change(() => { (rule as any)[opt.key] = !(rule as any)[opt.key]; })"
        ></span>
      </label>
    </div>

    <div v-if="history.length > 1" class="card">
      <div class="faint" style="margin-bottom: 6px">{{ s.genRecent }}</div>
      <div
        v-for="(value, index) in history"
        :key="value + index"
        class="row"
        style="justify-content: space-between; padding: 5px 0"
      >
        <span style="font-family: Consolas, monospace; font-size: 13px">{{ value }}</span>
        <span style="color: #5b8cff; font-size: 12px; cursor: pointer" @click="copy(value)">
          {{ s.copy }}
        </span>
      </div>
    </div>
  </div>
</template>
