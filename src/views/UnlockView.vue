<script setup lang="ts">
import { ref } from 'vue';
import { s } from '../i18n';

defineProps<{ busy: boolean; message: string }>();
const emit = defineEmits<{ submit: [password: string] }>();

const password = ref('');

function submit() {
  if (!password.value) return;
  emit('submit', password.value);
}
</script>

<template>
  <div class="center-page">
    <div class="auth-card">
      <div class="auth-logo">🔒</div>
      <div class="auth-title">{{ s.lockedTitle }}</div>
      <div class="auth-sub">{{ s.unlockHint }}</div>

      <input
        v-model="password"
        class="input"
        type="password"
        :placeholder="s.masterLabel"
        style="margin-top: 18px"
        @keyup.enter="submit"
      />

      <button
        class="btn"
        style="width: 100%; margin-top: 14px"
        :disabled="busy || !password"
        @click="submit"
      >
        {{ busy ? s.unlocking : s.unlockAction }}
      </button>

      <div v-if="message" class="error">{{ message }}</div>
    </div>
  </div>
</template>
