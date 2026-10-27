<script setup>
import { computed, ref, watch } from 'vue';
import AppIcon from './AppIcon.vue';
import ModalDialog from './ModalDialog.vue';
import { api, ApiError } from '../lib/api.js';

const props = defineProps({
  open: { type: Boolean, default: false },
  serverId: { type: String, required: true },
});
const emit = defineEmits(['close', 'selected']);

const loading = ref(false);
const saving = ref(false);
const error = ref('');
const options = ref(null);
const manualPath = ref('');

const selected = computed(() => options.value?.current || '');

watch(() => props.open, (open) => {
  if (!open) return;
  error.value = '';
  manualPath.value = '';
  load();
});

async function load() {
  loading.value = true;
  try {
    options.value = await api.get(`/servers/${props.serverId}/workspace-options`);
  } catch (caught) {
    error.value = caught instanceof ApiError ? caught.message : '无法读取可选工作目录';
  } finally {
    loading.value = false;
  }
}

async function apply(path) {
  if (!path || saving.value) return;
  saving.value = true;
  error.value = '';
  try {
    const data = await api.put(`/servers/${props.serverId}/workspace`, { path });
    emit('selected', data);
    emit('close');
  } catch (caught) {
    error.value = caught instanceof ApiError ? caught.message : '切换工作目录失败';
  } finally {
    saving.value = false;
  }
}

function chooseManual() {
  const path = manualPath.value.trim();
  if (!path) {
    error.value = '请输入工作目录绝对路径';
    return;
  }
  apply(path);
}
</script>

<template>
  <ModalDialog
    :open="open"
    title="选择 Nginx 工作目录"
    subtitle="只能选择允许根目录下的路径。工作目录中应包含 nginx.conf（或其他主配置文件）。"
    width="660px"
    :busy="saving"
    @close="emit('close')"
  >
    <div v-if="error" class="alert alert-danger mb-16">
      <AppIcon name="alert" :size="15" />
      <div>{{ error }}</div>
    </div>

    <div v-if="loading" class="loading-row">
      <span class="spinner" />
      正在读取可选目录…
    </div>

    <template v-else-if="options">
      <div class="current-bar">
        <span class="small muted">当前工作目录</span>
        <span class="mono current-path">{{ selected || '尚未选择' }}</span>
      </div>

      <div v-for="root in options.roots" :key="root.path" class="root-block">
        <div class="root-head">
          <AppIcon name="folder" :size="15" />
          <span class="mono">{{ root.path }}</span>
        </div>
        <div class="workspace-list">
          <button
            v-for="item in root.workspaces"
            :key="item.path"
            class="workspace-row"
            :class="{ active: item.path === selected }"
            type="button"
            :disabled="saving"
            @click="apply(item.path)"
          >
            <span class="ws-icon"><AppIcon name="folder" :size="15" /></span>
            <span class="ws-main">
              <span class="ws-name">{{ item.name }}</span>
              <span class="ws-path mono">{{ item.path }}</span>
            </span>
            <span v-if="item.hasConfig" class="badge badge-ok">含 nginx.conf</span>
            <span v-else class="badge">无主配置</span>
            <AppIcon v-if="item.path === selected" name="check" :size="15" class="ws-check" />
          </button>
        </div>
      </div>

      <div class="divider" />
      <div class="field">
        <label for="manual-path">自定义路径（必须位于允许根目录内）</label>
        <div class="manual-row">
          <input
            id="manual-path"
            v-model="manualPath"
            type="text"
            class="mono"
            placeholder="/etc/nginx"
            spellcheck="false"
            @keydown.enter.prevent="chooseManual"
          />
          <button class="btn" type="button" :disabled="saving || !manualPath.trim()" @click="chooseManual">
            使用此目录
          </button>
        </div>
        <span class="hint">路径会在服务端经 realpath 校验，符号链接逃逸会被拒绝。</span>
      </div>
    </template>

    <template #footer>
      <button class="btn" type="button" :disabled="saving" @click="emit('close')">取消</button>
    </template>
  </ModalDialog>
</template>

<style scoped>
.current-bar {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 11px 13px;
  margin-bottom: 14px;
  border-radius: 9px;
  border: 1px solid var(--accent-border);
  background: var(--accent-soft);
}
.current-path { font-size: 12px; color: var(--ok-text); word-break: break-all; }
.root-block + .root-block { margin-top: 14px; }
.root-head {
  display: flex;
  align-items: center;
  gap: 7px;
  color: var(--muted);
  font-size: 11.5px;
  margin-bottom: 7px;
  min-width: 0;
}
.root-head span { overflow: hidden; text-overflow: ellipsis; }
.workspace-list {
  display: flex;
  flex-direction: column;
  gap: 3px;
  max-height: 210px;
  overflow: auto;
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 4px;
}
.workspace-row {
  display: flex;
  align-items: center;
  gap: 9px;
  width: 100%;
  padding: 8px 9px;
  border: 1px solid transparent;
  border-radius: 7px;
  background: transparent;
  color: var(--text);
  text-align: left;
}
.workspace-row:hover:not(:disabled) { background: var(--hover-bg); }
.workspace-row.active { background: var(--accent-soft); border-color: var(--accent-border); }
.workspace-row:disabled { opacity: 0.6; cursor: not-allowed; }
.ws-icon { color: var(--info-text); display: flex; flex: none; }
.ws-main { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 1px; }
.ws-name { font-size: 12px; font-weight: 600; }
.ws-path { font-size: 10px; color: var(--muted-2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ws-check { color: var(--accent-bright); flex: none; }
.manual-row { display: flex; gap: 8px; }
.manual-row input { flex: 1; }
</style>
