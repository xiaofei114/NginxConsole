<script setup>
import { toasts, dismissToast } from '../lib/toast.js';
import AppIcon from './AppIcon.vue';

const iconFor = (type) => ({
  success: 'check',
  error: 'alert',
  warn: 'alert',
  info: 'info',
}[type] || 'info');
</script>

<template>
  <div class="toast-host" aria-live="polite">
    <TransitionGroup name="toast">
      <div v-for="item in toasts" :key="item.id" class="toast" :class="`toast-${item.type}`">
        <span class="toast-icon"><AppIcon :name="iconFor(item.type)" :size="17" /></span>
        <span class="toast-message">{{ item.message }}</span>
        <button class="toast-close" type="button" aria-label="关闭提示" @click="dismissToast(item.id)">
          <AppIcon name="x" :size="14" />
        </button>
      </div>
    </TransitionGroup>
  </div>
</template>

<style scoped>
.toast-host {
  position: fixed;
  top: 18px;
  right: 18px;
  z-index: 200;
  display: flex;
  flex-direction: column;
  gap: 10px;
  width: min(380px, calc(100vw - 36px));
  pointer-events: none;
}
.toast {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 12px 14px;
  border-radius: 12px;
  background: var(--surface-raised);
  border: 1px solid var(--border-strong);
  box-shadow: 0 16px 40px var(--shadow-color);
  color: var(--text);
  font-size: 13.5px;
  line-height: 1.45;
  pointer-events: auto;
}
.toast-success { border-color: var(--accent-border); }
.toast-error { border-color: var(--danger-border); }
.toast-warn { border-color: var(--warn-border); }
.toast-icon { display: flex; margin-top: 1px; color: var(--text-dim); }
.toast-success .toast-icon { color: var(--accent-bright); }
.toast-error .toast-icon { color: var(--danger); }
.toast-warn .toast-icon { color: var(--warn); }
.toast-message { flex: 1; word-break: break-word; }
.toast-close {
  border: 0;
  background: transparent;
  color: var(--text-dim);
  cursor: pointer;
  padding: 2px;
  display: flex;
}
.toast-close:hover { color: var(--text); }
.toast-enter-active, .toast-leave-active { transition: all 0.22s ease; }
.toast-enter-from, .toast-leave-to { opacity: 0; transform: translateY(-8px); }
</style>
