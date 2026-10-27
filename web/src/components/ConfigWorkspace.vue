<script setup>
import { computed, nextTick, onMounted, ref, watch } from 'vue';
import AppIcon from './AppIcon.vue';
import ConfirmDialog from './ConfirmDialog.vue';
import ModalDialog from './ModalDialog.vue';
import { api, ApiError } from '../lib/api.js';
import { formatBytes, formatTime } from '../lib/format.js';
import { toast } from '../lib/toast.js';

const props = defineProps({
  serverId: { type: String, required: true },
  info: { type: Object, default: null },
});
const emit = defineEmits(['pick-workspace']);

const dirPath = ref('');
const entries = ref([]);
const listLoading = ref(false);
const listError = ref('');
const truncated = ref(false);

const activeFile = ref(null);
const opening = ref(false);
const saving = ref(false);
const fileError = ref('');
const saveNotice = ref('');
const editorRef = ref(null);
const gutterRef = ref(null);

const busyOp = ref('');
const consoleOutput = ref('');
const consoleTone = ref('idle');

const discardOpen = ref(false);
const pendingAction = ref(null);

const newFileOpen = ref(false);
const newFilePath = ref('');
const newFileError = ref('');

const backupsOpen = ref(false);
const backups = ref([]);
const backupsLoading = ref(false);
const backupsError = ref('');
const restoreTarget = ref(null);
const restoreOpen = ref(false);
const restoring = ref(false);

const restartOpen = ref(false);

const workspace = computed(() => props.info?.workspace || '');
const dirty = computed(() => Boolean(activeFile.value) && activeFile.value.content !== activeFile.value.original);
const lineCount = computed(() => (activeFile.value ? activeFile.value.content.split('\n').length : 0));
const gutterText = computed(() => {
  const total = Math.min(lineCount.value, 20000);
  let text = '';
  for (let index = 1; index <= total; index += 1) text += `${index}\n`;
  return text;
});
const fileSize = computed(() => (activeFile.value ? new Blob([activeFile.value.content]).size : 0));
const parentPath = computed(() => {
  if (!dirPath.value) return null;
  const parts = dirPath.value.split('/').filter(Boolean);
  parts.pop();
  return parts.join('/');
});

onMounted(() => {
  if (workspace.value) loadEntries('');
});

watch(() => props.info?.workspace, (next, previous) => {
  if (next && next !== previous) {
    activeFile.value = null;
    dirPath.value = '';
    loadEntries('');
  }
});

async function loadEntries(path = dirPath.value) {
  if (!workspace.value) return;
  listLoading.value = true;
  listError.value = '';
  try {
    const data = await api.get(`/servers/${props.serverId}/files`, { path });
    entries.value = data.entries || [];
    dirPath.value = data.path || '';
    truncated.value = Boolean(data.truncated);
  } catch (caught) {
    listError.value = caught instanceof ApiError ? caught.message : '读取目录失败';
  } finally {
    listLoading.value = false;
  }
}

function guardDirty(action) {
  if (dirty.value) {
    pendingAction.value = action;
    discardOpen.value = true;
    return;
  }
  action();
}

function confirmDiscard() {
  discardOpen.value = false;
  const action = pendingAction.value;
  pendingAction.value = null;
  if (action) action();
}

function navigate(entry) {
  if (entry.type !== 'dir') return;
  guardDirty(() => loadEntries(entry.path));
}

function openEntry(entry) {
  if (entry.type === 'dir') {
    navigate(entry);
    return;
  }
  if (entry.type !== 'file' || !entry.editable) return;
  guardDirty(() => openFile(entry.path));
}

async function openFile(path) {
  opening.value = true;
  fileError.value = '';
  saveNotice.value = '';
  try {
    const data = await api.get(`/servers/${props.serverId}/file`, { path });
    activeFile.value = {
      path: data.path,
      content: data.content,
      original: data.content,
      hash: data.hash,
      mode: data.mode,
      mtime: data.mtime,
      size: data.size,
      isNew: false,
    };
    await nextTick();
    editorRef.value?.focus();
  } catch (caught) {
    fileError.value = caught instanceof ApiError ? caught.message : '打开文件失败';
    toast.error(fileError.value);
  } finally {
    opening.value = false;
  }
}

function closeFile() {
  guardDirty(() => {
    activeFile.value = null;
    fileError.value = '';
    saveNotice.value = '';
  });
}

function validateNewPath(path) {
  if (!path) return '请输入文件相对路径';
  if (path.length > 1024) return '路径过长';
  if (path.startsWith('/') || /^[A-Za-z]:/.test(path) || path.includes('\\')) return '仅允许工作目录内的相对路径';
  if (path.split('/').some((segment) => segment === '..')) return '路径不能包含 ..';
  if (!/\.(conf|inc|txt|pem|crt|cer|csr|dhparam|template)$/i.test(path) && path.split('/').pop() !== 'nginx.conf') {
    return '仅允许创建 .conf/.inc/.txt/.pem/.crt 等文本配置文件';
  }
  return '';
}

function startNewFile() {
  newFilePath.value = dirPath.value ? `${dirPath.value}/` : '';
  newFileError.value = '';
  newFileOpen.value = true;
}

function createNewFile() {
  const path = newFilePath.value.trim().replace(/^\.\//, '');
  const problem = validateNewPath(path);
  if (problem) {
    newFileError.value = problem;
    return;
  }
  newFileOpen.value = false;
  guardDirty(async () => {
    fileError.value = '';
    saveNotice.value = '新文件尚未保存';
    activeFile.value = {
      path,
      content: '',
      original: '',
      hash: null,
      mode: '0644',
      mtime: null,
      size: 0,
      isNew: true,
    };
    await nextTick();
    editorRef.value?.focus();
  });
}

async function saveFile() {
  if (!activeFile.value || saving.value) return;
  saving.value = true;
  fileError.value = '';
  saveNotice.value = '';
  consoleOutput.value = '';
  consoleTone.value = 'idle';
  try {
    const data = await api.put(`/servers/${props.serverId}/file`, {
      path: activeFile.value.path,
      content: activeFile.value.content,
      ...(activeFile.value.isNew ? {} : { baseHash: activeFile.value.hash }),
    });
    activeFile.value = {
      ...activeFile.value,
      hash: data.hash,
      original: activeFile.value.content,
      isNew: false,
      size: data.size,
      mtime: new Date().toISOString(),
    };
    saveNotice.value = data.tested
      ? '已保存，并通过 nginx -t 配置检测'
      : data.unchanged
        ? '内容没有变化'
        : '已保存（当前节点未执行配置检测）';
    toast.success(saveNotice.value);
    if (data.testOutput) {
      consoleOutput.value = data.testOutput;
      consoleTone.value = 'ok';
    }
    loadEntries(dirPath.value);
  } catch (caught) {
    if (caught instanceof ApiError) {
      fileError.value = caught.message;
      if (caught.details?.output) {
        consoleOutput.value = caught.details.output;
        consoleTone.value = 'error';
      }
      if (caught.code === 'FILE_CONFLICT') {
        saveNotice.value = '检测到并发修改，请关闭后重新打开文件。';
      }
    } else {
      fileError.value = '保存失败';
    }
    toast.error(fileError.value);
  } finally {
    saving.value = false;
  }
}

function syncScroll() {
  if (gutterRef.value && editorRef.value) {
    gutterRef.value.scrollTop = editorRef.value.scrollTop;
  }
}

function onEditorKeydown(event) {
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
    event.preventDefault();
    saveFile();
    return;
  }
  if (event.key === 'Tab') {
    event.preventDefault();
    const textarea = event.target;
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const value = activeFile.value.content;
    activeFile.value.content = `${value.slice(0, start)}    ${value.slice(end)}`;
    nextTick(() => {
      textarea.selectionStart = start + 4;
      textarea.selectionEnd = start + 4;
    });
  }
}

async function runOperation(operation) {
  if (busyOp.value) return;
  const endpoints = {
    test: { path: 'test', label: '配置检测' },
    reload: { path: 'reload', label: '平滑重载' },
    restart: { path: 'restart', label: '完全重启' },
  };
  const target = endpoints[operation];
  busyOp.value = operation;
  consoleOutput.value = `正在执行${target.label}…`;
  consoleTone.value = 'idle';
  try {
    const body = operation === 'restart' ? { confirm: true } : {};
    const data = await api.post(`/servers/${props.serverId}/${target.path}`, body);
    const parts = [];
    if (data.testOutput) parts.push(data.testOutput);
    if (data.output) parts.push(data.output);
    parts.push(`${target.label}成功${data.method ? `（${data.method}）` : ''}`);
    consoleOutput.value = parts.join('\n');
    consoleTone.value = 'ok';
    toast.success(`${target.label}成功`);
  } catch (caught) {
    if (caught instanceof ApiError) {
      const details = caught.details || {};
      consoleOutput.value = [caught.message, details.testOutput, details.output].filter(Boolean).join('\n\n');
    } else {
      consoleOutput.value = `${target.label}失败`;
    }
    consoleTone.value = 'error';
    toast.error(`${target.label}失败：${caught.message || ''}`);
  } finally {
    busyOp.value = '';
  }
}

function requestRestart() {
  restartOpen.value = true;
}

function confirmRestart() {
  restartOpen.value = false;
  runOperation('restart');
}

async function openBackups() {
  backupsOpen.value = true;
  backupsLoading.value = true;
  backupsError.value = '';
  try {
    const data = await api.get(`/servers/${props.serverId}/backups`);
    backups.value = data.backups || [];
  } catch (caught) {
    backupsError.value = caught instanceof ApiError ? caught.message : '读取备份失败';
  } finally {
    backupsLoading.value = false;
  }
}

function reasonLabel(reason) {
  return { write: '文件保存', certificate: '证书替换', restore: '备份恢复' }[reason] || reason;
}

function requestRestore(backup) {
  restoreTarget.value = backup;
  restoreOpen.value = true;
}

async function doRestore() {
  if (!restoreTarget.value || restoring.value) return;
  restoring.value = true;
  try {
    const data = await api.post(`/servers/${props.serverId}/backups/${restoreTarget.value.id}/restore`, { confirm: true });
    toast.success(`已恢复 ${data.path}`);
    if (data.testOutput) {
      consoleOutput.value = data.testOutput;
      consoleTone.value = 'ok';
    }
    restoreOpen.value = false;
    backupsOpen.value = false;
    const restored = restoreTarget.value;
    restoreTarget.value = null;
    await loadEntries(dirPath.value);
    if (activeFile.value && activeFile.value.path === restored.targetRel) {
      await openFile(restored.targetRel);
    }
  } catch (caught) {
    toast.error(caught.message || '恢复失败');
  } finally {
    restoring.value = false;
  }
}

function fileIcon(entry) {
  if (entry.type === 'dir') return 'folder';
  if (entry.privateKey) return 'key';
  if (entry.type === 'broken') return 'alert';
  return 'doc';
}

function entryTitle(entry) {
  if (entry.type === 'dir') return `进入目录 ${entry.name}`;
  if (entry.privateKey) return '私钥文件仅供证书功能使用，禁止在编辑器中读取';
  if (!entry.editable) return '此文件类型不允许在线编辑';
  return `打开 ${entry.name}`;
}
</script>

<template>
  <div class="config-panel">
    <div v-if="!workspace" class="card empty-state-card">
      <span class="empty-icon"><AppIcon name="folder" :size="30" /></span>
      <h3>尚未选择 Nginx 工作目录</h3>
      <p>请先选择包含 nginx.conf 的工作目录，才能浏览配置、检测和重载 Nginx。</p>
      <button class="btn btn-primary" type="button" @click="emit('pick-workspace')">
        <AppIcon name="folder" :size="14" />
        选择工作目录
      </button>
    </div>

    <template v-else>
      <div class="config-toolbar card">
        <div class="toolbar-path">
          <span class="small muted">工作目录</span>
          <span class="mono path-text" :title="workspace">{{ workspace }}</span>
        </div>
        <div class="toolbar-actions">
          <button class="btn btn-sm" type="button" :disabled="Boolean(busyOp)" @click="emit('pick-workspace')">
            <AppIcon name="folder" :size="13" />
            切换目录
          </button>
          <button class="btn btn-sm" type="button" :disabled="Boolean(busyOp)" @click="runOperation('test')">
            <span v-if="busyOp === 'test'" class="spinner" />
            <AppIcon v-else name="check" :size="13" />
            检测
          </button>
          <button class="btn btn-sm" type="button" :disabled="Boolean(busyOp)" @click="runOperation('reload')">
            <span v-if="busyOp === 'reload'" class="spinner" />
            <AppIcon v-else name="rotate" :size="13" />
            重载
          </button>
          <button class="btn btn-sm btn-danger" type="button" :disabled="Boolean(busyOp)" @click="requestRestart">
            <AppIcon name="power" :size="13" />
            重启
          </button>
          <button class="btn btn-sm btn-ghost" type="button" :disabled="Boolean(busyOp)" @click="openBackups">
            <AppIcon name="history" :size="13" />
            备份
          </button>
        </div>
      </div>

      <div class="editor-shell card">
        <aside class="file-pane">
          <div class="file-pane-head">
            <span class="pane-title"><AppIcon name="folder" :size="14" /> 文件</span>
            <div class="row">
              <button class="icon-button" type="button" title="刷新目录" @click="loadEntries(dirPath)">
                <AppIcon name="refresh" :size="14" />
              </button>
              <button class="icon-button" type="button" title="新建文件" @click="startNewFile">
                <AppIcon name="plus" :size="15" />
              </button>
            </div>
          </div>
          <div class="current-dir mono" :title="dirPath || workspace">
            <span class="dir-label">/{{ dirPath }}</span>
          </div>
          <div class="file-list">
            <button
              v-if="dirPath"
              class="file-row parent"
              type="button"
              @click="loadEntries(parentPath)"
            >
              <span class="file-icon"><AppIcon name="arrowLeft" :size="14" /></span>
              <span class="file-name">返回上级</span>
            </button>
            <div v-if="listLoading" class="loading-row">
              <span class="spinner" />
              读取中…
            </div>
            <div v-else-if="listError" class="file-error">
              {{ listError }}
              <button class="btn btn-sm mt-8" type="button" @click="loadEntries(dirPath)">重试</button>
            </div>
            <div v-else-if="entries.length === 0" class="empty small">目录为空</div>
            <template v-else>
              <button
                v-for="entry in entries"
                :key="entry.path"
                class="file-row"
                :class="{
                  active: activeFile && activeFile.path === entry.path,
                  disabled: entry.type !== 'dir' && (!entry.editable || entry.type !== 'file'),
                  dir: entry.type === 'dir',
                }"
                type="button"
                :title="entryTitle(entry)"
                @click="openEntry(entry)"
              >
                <span class="file-icon" :class="{ warn: entry.privateKey, danger: entry.type === 'broken' }">
                  <AppIcon :name="fileIcon(entry)" :size="14" />
                </span>
                <span class="file-name truncate">{{ entry.name }}</span>
                <span v-if="entry.symlink" class="file-tag" title="符号链接">链接</span>
                <span v-else-if="entry.type === 'file'" class="file-size">{{ formatBytes(entry.size) }}</span>
              </button>
            </template>
          </div>
          <div v-if="truncated" class="pane-foot">目录条目过多，仅展示前 500 项。</div>
        </aside>

        <section class="editor-pane">
          <div v-if="opening" class="loading-row editor-loading">
            <span class="spinner" />
            正在打开文件…
          </div>
          <div v-else-if="!activeFile" class="editor-empty">
            <span class="empty-icon"><AppIcon name="file" :size="30" /></span>
            <h3>选择左侧配置文件开始编辑</h3>
            <p>保存时会自动备份，写入后执行 nginx -t；检测失败将自动回滚。</p>
            <p class="small">推荐优先管理 sites-available / conf.d 下的站点配置。</p>
          </div>
          <template v-else>
            <div class="editor-head">
              <div class="editor-file">
                <AppIcon name="file" :size="14" />
                <span class="mono editor-path truncate">{{ activeFile.path }}</span>
                <span v-if="activeFile.isNew" class="badge badge-blue">新文件</span>
                <span v-if="dirty" class="badge badge-warn">未保存</span>
              </div>
              <div class="row">
                <button class="icon-button" type="button" title="关闭文件" aria-label="关闭文件" @click="closeFile">
                  <AppIcon name="x" :size="15" />
                </button>
              </div>
            </div>

            <div class="editor-area">
              <pre ref="gutterRef" class="gutter" aria-hidden="true">{{ gutterText }}</pre>
              <textarea
                ref="editorRef"
                v-model="activeFile.content"
                class="code-area"
                spellcheck="false"
                autocapitalize="off"
                autocomplete="off"
                wrap="off"
                aria-label="配置文件内容"
                @scroll="syncScroll"
                @keydown="onEditorKeydown"
              />
            </div>

            <div v-if="fileError" class="alert alert-danger editor-alert">
              <AppIcon name="alert" :size="15" />
              <div>{{ fileError }}</div>
            </div>
            <div v-if="saveNotice" class="alert alert-ok editor-alert">
              <AppIcon name="check" :size="15" />
              <div>{{ saveNotice }}</div>
            </div>

            <div class="editor-foot">
              <span class="small muted">
                {{ lineCount }} 行 · {{ formatBytes(fileSize) }} · {{ activeFile.mode }}
                <template v-if="activeFile.isNew"> · 尚未写入磁盘</template>
              </span>
              <div class="row">
                <span class="small muted shortcut">Ctrl / ⌘ + S 保存</span>
                <button class="btn btn-primary btn-sm" type="button" :disabled="saving || !dirty" @click="saveFile">
                  <span v-if="saving" class="spinner" />
                  <AppIcon v-else name="save" :size="13" />
                  {{ saving ? '保存中…' : '保存' }}
                </button>
              </div>
            </div>
          </template>
        </section>
      </div>

      <div v-if="consoleOutput" class="console-card card">
        <div class="console-head">
          <span class="card-title">
            <AppIcon name="terminal" :size="14" />
            执行结果
          </span>
          <button class="icon-button" type="button" aria-label="清除输出" @click="consoleOutput = ''">
            <AppIcon name="x" :size="14" />
          </button>
        </div>
        <pre class="console" :class="{ 'console-danger': consoleTone === 'error', 'console-ok': consoleTone === 'ok' }">{{ consoleOutput }}</pre>
      </div>
    </template>

    <ModalDialog :open="newFileOpen" title="新建文本文件" subtitle="文件将创建在当前目录，保存时才会写入磁盘。" width="480px" @close="newFileOpen = false">
      <div class="field">
        <label for="new-file-path">相对路径</label>
        <input
          id="new-file-path"
          v-model="newFilePath"
          type="text"
          class="mono"
          autofocus
          spellcheck="false"
          placeholder="conf.d/site.conf"
          @keydown.enter.prevent="createNewFile"
        />
        <span class="hint">仅允许 .conf/.inc/.txt 等文本类型；路径不能包含 ..，私钥请使用证书上传功能。</span>
      </div>
      <div v-if="newFileError" class="alert alert-danger mt-16">
        <AppIcon name="alert" :size="15" />
        <div>{{ newFileError }}</div>
      </div>
      <template #footer>
        <button class="btn" type="button" @click="newFileOpen = false">取消</button>
        <button class="btn btn-primary" type="button" @click="createNewFile">创建草稿</button>
      </template>
    </ModalDialog>

    <ModalDialog :open="backupsOpen" title="配置备份" subtitle="每次保存或证书替换前的自动备份，最多保留最近 100 份。" width="720px" @close="backupsOpen = false">
      <div v-if="backupsLoading" class="loading-row">
        <span class="spinner" />
        正在读取备份…
      </div>
      <div v-else-if="backupsError" class="alert alert-danger">
        <AppIcon name="alert" :size="15" />
        <div>{{ backupsError }}</div>
      </div>
      <div v-else-if="backups.length === 0" class="empty">
        <span class="empty-icon"><AppIcon name="history" :size="28" /></span>
        暂无备份
      </div>
      <div v-else class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>时间</th>
              <th>目标文件</th>
              <th>类型</th>
              <th>大小</th>
              <th />
            </tr>
          </thead>
          <tbody>
            <tr v-for="backup in backups" :key="backup.id">
              <td class="nowrap">{{ formatTime(backup.createdAt) }}</td>
              <td class="mono backup-target">{{ backup.targetRel }}</td>
              <td><span class="badge">{{ reasonLabel(backup.reason) }}</span></td>
              <td class="nowrap">{{ formatBytes(backup.size) }}</td>
              <td class="nowrap" style="text-align: right">
                <button class="btn btn-sm" type="button" @click="requestRestore(backup)">
                  <AppIcon name="rotate" :size="12" />
                  恢复
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </ModalDialog>

    <ConfirmDialog
      :open="discardOpen"
      title="放弃未保存的修改？"
      message="当前文件有尚未保存的修改，继续操作将丢失这些内容。"
      confirm-text="放弃修改"
      danger
      @close="discardOpen = false; pendingAction = null"
      @confirm="confirmDiscard"
    />

    <ConfirmDialog
      :open="restartOpen"
      title="重启 Nginx？"
      message="重启会短暂中断所有站点服务。系统会先执行 nginx -t，检测失败则拒绝重启。"
      confirm-text="确认重启"
      danger
      @close="restartOpen = false"
      @confirm="confirmRestart"
    />

    <ConfirmDialog
      :open="restoreOpen"
      :busy="restoring"
      title="恢复此备份？"
      :message="restoreTarget ? `将把 ${restoreTarget.targetRel} 恢复为 ${formatTime(restoreTarget.createdAt)} 的版本，当前内容会先自动备份，并执行 nginx -t 校验。` : ''"
      confirm-text="恢复并检测"
      danger
      @close="restoreOpen = false"
      @confirm="doRestore"
    />
  </div>
</template>

<style scoped>
.config-panel { display: flex; flex-direction: column; gap: 12px; }
.empty-state-card { padding: 46px 24px; display: flex; flex-direction: column; align-items: center; gap: 9px; text-align: center; }
.empty-state-card h3 { font-size: 15px; }
.empty-state-card p { color: var(--muted); font-size: 12.5px; max-width: 460px; line-height: 1.65; }
.empty-state-card .btn { margin-top: 8px; }
.config-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  padding: 11px 14px;
  flex-wrap: wrap;
}
.toolbar-path { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.path-text { font-size: 12px; color: var(--text-soft); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.toolbar-actions { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.editor-shell {
  display: grid;
  grid-template-columns: 248px minmax(0, 1fr);
  overflow: hidden;
  min-height: 520px;
}
.file-pane {
  display: flex;
  flex-direction: column;
  border-right: 1px solid var(--border);
  background: var(--inset-bg);
  min-height: 0;
}
.file-pane-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
}
.pane-title { display: inline-flex; align-items: center; gap: 6px; font-size: 11.5px; font-weight: 650; color: var(--text-soft); }
.current-dir {
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
  font-size: 10.5px;
  color: var(--info-text);
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
  direction: rtl;
  text-align: left;
}
.dir-label { direction: ltr; }
.file-list { flex: 1; overflow: auto; padding: 5px; min-height: 180px; max-height: 560px; }
.file-row {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 6px 8px;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--text-soft);
  text-align: left;
  font-size: 11.5px;
}
.file-row:hover:not(.disabled) { background: var(--hover-bg); }
.file-row.active { background: var(--accent-soft); color: var(--accent-text); }
.file-row.disabled { opacity: 0.5; cursor: not-allowed; }
.file-row.parent { color: var(--muted); }
.file-icon { display: flex; flex: none; color: var(--info-text); }
.file-icon.warn { color: var(--warn); }
.file-icon.danger { color: var(--danger); }
.file-name { flex: 1; min-width: 0; }
.file-size { color: var(--text-faint); font-size: 9.5px; flex: none; }
.file-tag {
  flex: none;
  font-size: 9px;
  color: var(--info-text);
  border: 1px solid var(--info-border);
  border-radius: 4px;
  padding: 1px 4px;
}
.file-error { color: var(--danger-text); font-size: 11.5px; padding: 12px; line-height: 1.5; }
.pane-foot { padding: 8px 12px; border-top: 1px solid var(--border); color: var(--text-faint); font-size: 10px; }
.editor-pane { display: flex; flex-direction: column; min-width: 0; min-height: 500px; }
.editor-loading { flex: 1; }
.editor-empty {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 30px;
  text-align: center;
}
.editor-empty h3 { font-size: 14px; margin-top: 3px; }
.editor-empty p { color: var(--muted); font-size: 12px; max-width: 430px; line-height: 1.65; }
.editor-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 9px 12px;
  border-bottom: 1px solid var(--border);
  background: var(--inset-bg);
}
.editor-file { display: flex; align-items: center; gap: 8px; min-width: 0; color: var(--info-text); }
.editor-path { font-size: 11.5px; color: var(--text-soft); }
.editor-area {
  display: flex;
  flex: 1;
  min-height: 0;
  height: clamp(360px, calc(100vh - 430px), 720px);
  background: var(--code-bg);
}
.gutter {
  margin: 0;
  padding: 12px 10px 12px 12px;
  font-family: var(--mono);
  font-size: 11.5px;
  line-height: 1.65;
  color: var(--text-faint);
  text-align: right;
  user-select: none;
  overflow: hidden;
  min-width: 48px;
  border-right: 1px solid var(--border);
}
.code-area {
  flex: 1;
  min-width: 0;
  height: 100%;
  padding: 12px 14px;
  border: 0;
  border-radius: 0;
  background: transparent;
  color: var(--text-soft);
  font-family: var(--mono);
  font-size: 11.5px;
  line-height: 1.65;
  resize: none;
  outline: none;
  white-space: pre;
  overflow: auto;
  tab-size: 4;
}
.code-area:focus { box-shadow: none; border: 0; }
.editor-alert { margin: 0 12px 8px; }
.editor-alert:first-of-type { margin-top: 8px; }
.editor-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 9px 12px;
  border-top: 1px solid var(--border);
  flex-wrap: wrap;
}
.shortcut { color: var(--text-faint); }
.console-card { overflow: hidden; }
.console-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
}
.console-card .console { border: 0; border-radius: 0; max-height: 320px; }
.backup-target { max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

@media (max-width: 900px) {
  .editor-shell { grid-template-columns: 1fr; }
  .file-pane { border-right: 0; border-bottom: 1px solid var(--border); }
  .file-list { max-height: 210px; }
  .editor-area { height: 60vh; min-height: 320px; }
}
</style>
