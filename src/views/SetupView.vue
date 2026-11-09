<script setup lang="ts">
import { ref } from 'vue';
import { s } from '../i18n';

defineProps<{ busy: boolean; message: string }>();
const emit = defineEmits<{ submit: [password: string] }>();

const pwd1 = ref('');
const pwd2 = ref('');
const localError = ref('');

function submit() {
  if (pwd1.value.length < 8) {
    localError.value = s.value.errorTooShort(8);
    return;
  }
  if (pwd1.value !== pwd2.value) {
    localError.value = s.value.errorMismatch;
    return;
  }
  localError.value = '';
  emit('submit', pwd1.value);
}
</script>

<template>
  <div class="center-page">
    <div class="auth-card">
      <div class="auth-logo">密</div>
      <div class="auth-title">{{ s.appName }}</div>
      <div class="auth-sub">{{ s.setupSubtitle }}</div>

      <label class="label">{{ s.masterLabel }}</label>
      <input
        v-model="pwd1"
        class="input"
        type="password"
        :placeholder="s.masterPlaceholder(8)"
        @keyup.enter="submit"
      />

      <label class="label">{{ s.confirmMasterLabel }}</label>
      <input
        v-model="pwd2"
        class="input"
        type="password"
        :placeholder="s.confirmMasterPlaceholder"
        @keyup.enter="submit"
      />

      <button class="btn" style="width: 100%; margin-top: 16px" :disabled="busy" @click="submit">
        {{ busy ? s.creating : s.createVault }}
      </button>

      <div v-if="localError" class="error">{{ localError }}</div>
      <div v-if="message" class="error">{{ message }}</div>

      <div class="faint" style="margin-top: 14px; line-height: 1.6">{{ s.setupNote }}</div>
    </div>
  </div>
</template>
