<script setup>
import AppIcon from './AppIcon.vue';
import { themeMode, setThemeMode } from '../lib/theme.js';

const options = [
  { value: 'light', label: '浅色', icon: 'sun' },
  { value: 'dark', label: '深色', icon: 'moon' },
  { value: 'system', label: '跟随系统', icon: 'monitor' },
];
</script>

<template>
  <div class="theme-switch" role="group" aria-label="界面主题">
    <button
      v-for="option in options"
      :key="option.value"
      class="theme-option"
      :class="{ active: themeMode === option.value }"
      type="button"
      :title="option.label"
      :aria-label="option.label"
      :aria-pressed="themeMode === option.value"
      @click="setThemeMode(option.value)"
    >
      <AppIcon :name="option.icon" :size="15" />
    </button>
  </div>
</template>

<style scoped>
.theme-switch {
  display: flex;
  gap: 2px;
  padding: 3px;
  border: 1px solid var(--border);
  border-radius: 9px;
  background: var(--inset-bg);
}
.theme-option {
  flex: 1;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  height: 26px;
  padding: 0;
  border: 0;
  border-radius: 7px;
  background: transparent;
  color: var(--muted);
  transition: background 0.15s ease, color 0.15s ease;
}
.theme-option:hover { color: var(--text); background: var(--hover-bg); }
.theme-option.active {
  background: var(--panel);
  color: var(--accent-text);
  box-shadow: 0 1px 3px var(--shadow-color);
}
.theme-option.active svg { color: var(--accent); }
</style>
