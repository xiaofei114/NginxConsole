<script setup>
import { computed, onMounted, ref } from 'vue';
import AppIcon from '../components/AppIcon.vue';
import { api } from '../lib/api.js';
import { actionLabel, copyText, formatTime } from '../lib/format.js';
import { toast } from '../lib/toast.js';

const entries = ref([]);
const servers = ref([]);
const loading = ref(false);
const error = ref('');
const serverId = ref('');
const actionPrefix = ref('');
const resultFilter = ref('');
const limit = ref(100);
const expanded = ref(null);

const actionGroups = [
  { value: 'auth.', label: '登录与账户安全' },
  { value: 'agent.', label: 'Agent 连接与注册' },
  { value: 'server.', label: '服务器、配置与证书' },
];

const filtersActive = computed(() => Boolean(serverId.value || actionPrefix.value || resultFilter.value));

async function loadServers() {
  try {
    const data = await api.get('/servers');
    servers.value = data.servers || [];
  } catch {
    servers.value = [];
  }
}

async function load() {
  loading.value = true;
  error.value = '';
  try {
    const data = await api.get('/audit', {
      limit: limit.value,
      serverId: serverId.value || undefined,
      action: actionPrefix.value || undefined,
      result: resultFilter.value || undefined,
    });
    entries.value = data.entries || [];
  } catch (caught) {
    error.value = caught.message || '读取审计日志失败';
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  loadServers();
  load();
});

function resetFilters() {
  serverId.value = '';
  actionPrefix.value = '';
  resultFilter.value = '';
  load();
}

function toggleExpand(entry) {
  expanded.value = expanded.value === entry.id ? null : entry.id;
}

async function copyEntry(entry) {
  if (await copyText(JSON.stringify(entry, null, 2))) toast.success('审计记录已复制');
  else toast.error('复制失败');
}

function metaSummary(meta) {
  if (!meta) return '';
  const parts = [];
  if (meta.reason) parts.push(`原因: ${meta.reason}`);
  if (meta.code) parts.push(`错误码: ${meta.code}`);
  if (meta.name) parts.push(`名称: ${meta.name}`);
  if (meta.fingerprint) parts.push(`指纹: ${meta.fingerprint}`);
  if (meta.retryAfter) parts.push(`重试: ${meta.retryAfter}s`);
  return parts.join(' · ');
}
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <span class="eyebrow"><AppIcon name="history" :size="12" /> AUDIT TRAIL</span>
        <h1 class="page-title">审计日志</h1>
        <p class="page-sub">记录登录、Agent 连接、配置写入、证书替换与 Nginx 进程操作。文件内容与私钥不会写入日志。</p>
      </div>
      <div class="head-actions">
        <button class="btn" type="button" :disabled="loading" @click="load">
          <span v-if="loading" class="spinner" />
          <AppIcon v-else name="refresh" :size="14" />
          刷新
        </button>
      </div>
    </div>

    <div class="filter-bar card">
      <div class="filter-field">
        <label for="filter-server">服务器</label>
        <select id="filter-server" v-model="serverId" @change="load">
          <option value="">全部节点</option>
          <option v-for="server in servers" :key="server.id" :value="server.id">{{ server.name }}</option>
        </select>
      </div>
      <div class="filter-field">
        <label for="filter-action">操作类型</label>
        <select id="filter-action" v-model="actionPrefix" @change="load">
          <option value="">全部操作</option>
          <option v-for="group in actionGroups" :key="group.value" :value="group.value">{{ group.label }}</option>
        </select>
      </div>
      <div class="filter-field">
        <label for="filter-result">结果</label>
        <select id="filter-result" v-model="resultFilter" @change="load">
          <option value="">全部</option>
          <option value="success">成功</option>
          <option value="failure">失败</option>
        </select>
      </div>
      <div class="filter-field">
        <label for="filter-limit">条数</label>
        <select id="filter-limit" v-model.number="limit" @change="load">
          <option :value="50">50</option>
          <option :value="100">100</option>
          <option :value="200">200</option>
        </select>
      </div>
      <button v-if="filtersActive" class="btn btn-ghost btn-sm filter-reset" type="button" @click="resetFilters">
        <AppIcon name="x" :size="13" />
        清除筛选
      </button>
    </div>

    <div v-if="error" class="alert alert-danger mb-16 mt-16">
      <AppIcon name="alert" :size="15" />
      <div>{{ error }}</div>
    </div>

    <div class="card audit-card">
      <div class="card-head">
        <span class="card-title"><AppIcon name="terminal" :size="14" /> 最近记录</span>
        <span class="small muted">{{ loading ? '读取中…' : `${entries.length} 条` }}</span>
      </div>

      <div v-if="loading && entries.length === 0" class="loading-row">
        <span class="spinner" />
        正在读取审计日志…
      </div>
      <div v-else-if="entries.length === 0" class="empty">
        <span class="empty-icon"><AppIcon name="history" :size="30" /></span>
        <span>没有符合条件的审计记录</span>
      </div>
      <div v-else class="audit-list">
        <article v-for="entry in entries" :key="entry.id" class="audit-row">
          <button class="audit-main" type="button" @click="toggleExpand(entry)">
            <span class="audit-time mono">{{ formatTime(entry.ts) }}</span>
            <span class="audit-action">
              <strong>{{ actionLabel(entry.action) }}</strong>
              <span class="audit-code mono">{{ entry.action }}</span>
            </span>
            <span class="audit-server truncate">
              {{ entry.serverName || '—' }}
              <span v-if="entry.target" class="audit-target mono" :title="entry.target">{{ entry.target }}</span>
            </span>
            <span class="audit-user">
              <span>{{ entry.username || '系统' }}</span>
              <span v-if="entry.ip" class="mono small">{{ entry.ip }}</span>
            </span>
            <span class="badge" :class="entry.result === 'failure' ? 'badge-danger' : 'badge-ok'">
              {{ entry.result === 'failure' ? '失败' : '成功' }}
            </span>
            <AppIcon :name="expanded === entry.id ? 'chevronDown' : 'chevronRight'" :size="14" class="audit-chevron" />
          </button>
          <div v-if="expanded === entry.id" class="audit-detail">
            <div class="detail-grid">
              <div><span>时间</span><strong>{{ formatTime(entry.ts) }}</strong></div>
              <div><span>操作者</span><strong>{{ entry.username || '系统' }}{{ entry.userId ? ` (${entry.userId.slice(0, 8)})` : '' }}</strong></div>
              <div><span>来源 IP</span><strong class="mono">{{ entry.ip || '—' }}</strong></div>
              <div><span>请求 ID</span><strong class="mono">{{ entry.requestId || '—' }}</strong></div>
              <div><span>服务器</span><strong>{{ entry.serverName || '—' }}</strong></div>
              <div><span>目标</span><strong class="mono break">{{ entry.target || '—' }}</strong></div>
            </div>
            <div v-if="metaSummary(entry.meta)" class="meta-line">{{ metaSummary(entry.meta) }}</div>
            <pre v-if="entry.meta" class="code-block audit-meta">{{ JSON.stringify(entry.meta, null, 2) }}</pre>
            <button class="btn btn-sm" type="button" @click="copyEntry(entry)">
              <AppIcon name="copy" :size="12" />
              复制记录
            </button>
          </div>
        </article>
      </div>
    </div>
  </div>
</template>

<style scoped>
.filter-bar {
  display: flex;
  align-items: flex-end;
  gap: 12px;
  padding: 13px 15px;
  flex-wrap: wrap;
}
.filter-field { display: flex; flex-direction: column; gap: 5px; min-width: 140px; }
.filter-field label { color: var(--muted); font-size: 10.5px; }
.filter-field select { height: 34px; font-size: 12px; }
.filter-reset { margin-left: auto; }
.audit-card { margin-top: 16px; overflow: hidden; }
.audit-list { display: flex; flex-direction: column; }
.audit-row { border-bottom: 1px solid var(--border); }
.audit-row:last-child { border-bottom: 0; }
.audit-main {
  display: grid;
  grid-template-columns: 138px minmax(150px, 1fr) minmax(140px, 1.1fr) minmax(110px, 0.8fr) 62px 22px;
  align-items: center;
  gap: 12px;
  width: 100%;
  padding: 11px 14px;
  border: 0;
  background: transparent;
  color: var(--text);
  text-align: left;
}
.audit-main:hover { background: var(--subtle-bg); }
.audit-time { font-size: 10.5px; color: var(--muted); white-space: nowrap; }
.audit-action { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.audit-action strong { font-size: 12px; font-weight: 600; }
.audit-code { font-size: 9.5px; color: var(--text-faint); }
.audit-server { display: flex; flex-direction: column; gap: 2px; font-size: 11.5px; color: var(--text-soft); min-width: 0; }
.audit-target { font-size: 9.5px; color: var(--text-faint); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.audit-user { display: flex; flex-direction: column; gap: 2px; font-size: 11.5px; color: var(--text-soft); }
.audit-user .small { color: var(--text-faint); font-size: 9.5px; }
.audit-chevron { color: var(--text-faint); }
.audit-detail {
  padding: 13px 16px 16px;
  background: var(--inset-bg);
  border-top: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  gap: 11px;
}
.detail-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px 16px; }
.detail-grid > div { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.detail-grid span { color: var(--text-faint); font-size: 9.5px; }
.detail-grid strong { font-size: 11.5px; font-weight: 500; color: var(--text-soft); }
.break { word-break: break-all; }
.meta-line { font-size: 11px; color: var(--text-dim); }
.audit-meta { max-height: 220px; font-size: 10.5px; }
.audit-detail .btn { align-self: flex-start; }

@media (max-width: 900px) {
  .audit-main { grid-template-columns: 1fr auto; gap: 6px; }
  .audit-time { grid-column: 1; }
  .audit-action { grid-column: 1; }
  .audit-server { grid-column: 1; }
  .audit-user { grid-column: 1; }
  .audit-main .badge { grid-column: 2; grid-row: 1; justify-self: end; }
  .audit-chevron { grid-column: 2; grid-row: 2 / span 2; justify-self: end; }
}
</style>
