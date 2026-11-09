<script setup lang="ts">
import { computed, ref } from 'vue';
import type { VaultItem } from '../api';
import { s } from '../i18n';

const props = defineProps<{
  items: VaultItem[];
  folders: string[];
  selectedId: string;
}>();
const emit = defineEmits<{
  select: [id: string];
  new: [];
  favorite: [id: string];
}>();

const keyword = ref('');
const activeFolder = ref('');
const UNCATEGORIZED = '#none#';

const effectiveFolder = computed(() => {
  if (!activeFolder.value) return '';
  if (activeFolder.value === UNCATEGORIZED) return UNCATEGORIZED;
  return props.folders.includes(activeFolder.value) ? activeFolder.value : '';
});

const uncategorizedCount = computed(
  () => props.items.filter((it) => it.folder.trim().length === 0).length
);

const folderStats = computed(() =>
  props.folders.map((name) => ({
    name,
    count: props.items.filter((it) => it.folder.trim() === name).length
  }))
);

const filtered = computed(() => {
  const kw = keyword.value.trim().toLowerCase();
  const folder = effectiveFolder.value;
  return props.items.filter((item) => {
    const itemFolder = item.folder.trim();
    if (folder === UNCATEGORIZED) {
      if (itemFolder.length !== 0) return false;
    } else if (folder && itemFolder !== folder) {
      return false;
    }
    if (!kw) return true;
    return `${item.name} ${item.username} ${item.url} ${item.appName}`.toLowerCase().includes(kw);
  });
});

function titleOf(item: VaultItem): string {
  return item.name.trim() || item.appName.trim() || item.username.trim() || s.value.untitled;
}

const sorted = computed(() =>
  [...filtered.value].sort((a, b) => {
    if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
    return titleOf(a).localeCompare(titleOf(b));
  })
);
</script>

<template>
  <div style="display: flex; flex-direction: column; height: 100%">
    <div class="page-header" style="padding: 14px 16px 6px; margin: 0">
      <div class="page-title" style="font-size: 20px">{{ s.vaultTitle }}</div>
      <button class="btn btn-sm" @click="emit('new')">{{ s.vaultNew }}</button>
    </div>

    <div style="padding: 0 14px">
      <input v-model="keyword" class="input" :placeholder="s.vaultSearch" style="height: 36px" />
    </div>

    <div
      v-if="folders.length > 0"
      class="row"
      style="gap: 6px; padding: 10px 14px; flex-wrap: wrap"
    >
      <span class="chip" :class="{ active: effectiveFolder === '' }" @click="activeFolder = ''">
        {{ s.vaultAll }} {{ items.length }}
      </span>
      <span
        v-for="stat in folderStats"
        :key="stat.name"
        class="chip"
        :class="{ active: effectiveFolder === stat.name }"
        @click="activeFolder = stat.name"
      >
        {{ stat.name }} {{ stat.count }}
      </span>
      <span
        v-if="uncategorizedCount > 0"
        class="chip"
        :class="{ active: effectiveFolder === UNCATEGORIZED }"
        @click="activeFolder = UNCATEGORIZED"
      >
        {{ s.vaultUncategorized }} {{ uncategorizedCount }}
      </span>
    </div>

    <div style="flex: 1; overflow-y: auto; padding: 6px 8px 16px">
      <div v-if="sorted.length === 0" class="muted" style="text-align: center; padding: 40px 16px">
        <div>{{ items.length === 0 ? s.vaultEmpty : s.vaultNoMatch }}</div>
        <div class="faint" style="margin-top: 6px">
          {{ items.length === 0 ? s.vaultEmptyHint : s.vaultNoMatchHint }}
        </div>
      </div>

      <div
        v-for="item in sorted"
        :key="item.id"
        class="item-row"
        :class="{ active: item.id === selectedId }"
        @click="emit('select', item.id)"
      >
        <div class="avatar">{{ titleOf(item).charAt(0).toUpperCase() }}</div>
        <div style="flex: 1; min-width: 0">
          <div class="row" style="gap: 6px">
            <span
              style="
                font-weight: 500;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                flex: 1;
              "
              >{{ titleOf(item) }}</span
            >
            <span v-if="item.totp && item.totp.secret" class="badge">{{ s.badgeMfa }}</span>
          </div>
          <div class="row" style="gap: 6px; margin-top: 3px">
            <span
              class="faint"
              style="flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap"
              >{{ item.username || item.url || s.vaultNoUsername }}</span
            >
            <span v-if="item.folder.trim()" class="tag">{{ item.folder.trim() }}</span>
          </div>
        </div>
        <span
          style="font-size: 18px; padding: 4px"
          :style="{ color: item.favorite ? '#f2b255' : '#5c6577' }"
          @click.stop="emit('favorite', item.id)"
          >{{ item.favorite ? '★' : '☆' }}</span
        >
      </div>
    </div>
  </div>
</template>
