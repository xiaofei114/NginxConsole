<script setup>
import ModalDialog from './ModalDialog.vue';
import AppIcon from './AppIcon.vue';

defineProps({
  open: { type: Boolean, default: false },
  title: { type: String, default: '确认操作' },
  message: { type: String, default: '' },
  confirmText: { type: String, default: '确认' },
  cancelText: { type: String, default: '取消' },
  danger: { type: Boolean, default: false },
  busy: { type: Boolean, default: false },
});
const emit = defineEmits(['confirm', 'close']);
</script>

<template>
  <ModalDialog :open="open" :title="title" width="440px" :busy="busy" @close="emit('close')">
    <div class="confirm-content" :class="{ danger }">
      <span class="confirm-icon"><AppIcon :name="danger ? 'alert' : 'info'" :size="20" /></span>
      <p>{{ message }}</p>
    </div>
    <template #footer>
      <button class="btn" type="button" :disabled="busy" @click="emit('close')">{{ cancelText }}</button>
      <button class="btn" :class="danger ? 'btn-danger' : 'btn-primary'" type="button" :disabled="busy" @click="emit('confirm')">
        {{ busy ? '执行中…' : confirmText }}
      </button>
    </template>
  </ModalDialog>
</template>

<style scoped>
.confirm-content {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  color: var(--text);
  font-size: 14px;
  line-height: 1.65;
}
.confirm-content p { margin: 0; white-space: pre-wrap; }
.confirm-icon {
  display: inline-flex;
  padding: 7px;
  border-radius: 10px;
  background: var(--info-soft);
  color: var(--blue);
}
.confirm-content.danger .confirm-icon {
  background: var(--danger-soft);
  color: var(--danger);
}
</style>
