<script setup>
import { nextTick, onBeforeUnmount, ref, watch } from 'vue';
import AppIcon from './AppIcon.vue';

const props = defineProps({
  open: { type: Boolean, default: false },
  title: { type: String, default: '' },
  subtitle: { type: String, default: '' },
  width: { type: String, default: '560px' },
  closeOnBackdrop: { type: Boolean, default: true },
  busy: { type: Boolean, default: false },
});

const emit = defineEmits(['close']);
const panel = ref(null);
let previousFocus = null;

function close() {
  if (props.busy) return;
  emit('close');
}

function onKeydown(event) {
  if (!props.open) return;
  if (event.key === 'Escape') {
    event.stopPropagation();
    close();
    return;
  }
  if (event.key !== 'Tab' || !panel.value) return;
  const focusable = [...panel.value.querySelectorAll(
    'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
  )].filter((element) => element.offsetParent !== null);
  if (focusable.length === 0) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

watch(() => props.open, async (open) => {
  if (open) {
    previousFocus = document.activeElement;
    document.body.classList.add('modal-open');
    document.addEventListener('keydown', onKeydown, true);
    await nextTick();
    const target = panel.value?.querySelector('[autofocus]')
      || panel.value?.querySelector('input, textarea, select, button');
    target?.focus();
  } else {
    document.body.classList.remove('modal-open');
    document.removeEventListener('keydown', onKeydown, true);
    if (previousFocus instanceof HTMLElement) previousFocus.focus();
    previousFocus = null;
  }
}, { immediate: true });

onBeforeUnmount(() => {
  document.body.classList.remove('modal-open');
  document.removeEventListener('keydown', onKeydown, true);
});
</script>

<template>
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="open" class="modal-backdrop" @click.self="closeOnBackdrop && close()">
        <div
          ref="panel"
          class="modal-panel"
          :style="{ width }"
          role="dialog"
          aria-modal="true"
          :aria-label="title"
        >
          <header class="modal-head">
            <div>
              <h2>{{ title }}</h2>
              <p v-if="subtitle" class="modal-subtitle">{{ subtitle }}</p>
            </div>
            <button class="icon-button" type="button" aria-label="关闭" :disabled="busy" @click="close">
              <AppIcon name="x" :size="18" />
            </button>
          </header>
          <div class="modal-body">
            <slot />
          </div>
          <footer v-if="$slots.footer" class="modal-footer">
            <slot name="footer" />
          </footer>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 120;
  background: var(--overlay);
  backdrop-filter: blur(6px);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
.modal-panel {
  max-width: 100%;
  max-height: min(88vh, 900px);
  display: flex;
  flex-direction: column;
  background: var(--surface-raised);
  border: 1px solid var(--border-strong);
  border-radius: 16px;
  box-shadow: 0 28px 70px var(--shadow-strong-color);
}
.modal-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 20px 22px 0;
}
.modal-head h2 {
  margin: 0;
  font-size: 17px;
  letter-spacing: 0.01em;
}
.modal-subtitle {
  margin: 6px 0 0;
  color: var(--muted);
  font-size: 13px;
  line-height: 1.5;
}
.modal-body {
  padding: 18px 22px;
  overflow: auto;
}
.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
  padding: 0 22px 20px;
}
.modal-enter-active, .modal-leave-active { transition: opacity 0.18s ease; }
.modal-enter-active .modal-panel, .modal-leave-active .modal-panel { transition: transform 0.18s ease, opacity 0.18s ease; }
.modal-enter-from, .modal-leave-to { opacity: 0; }
.modal-enter-from .modal-panel, .modal-leave-to .modal-panel { transform: translateY(10px) scale(0.98); opacity: 0; }
</style>
