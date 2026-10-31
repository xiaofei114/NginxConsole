<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { RouterLink, useRoute, useRouter } from 'vue-router';
import AppIcon from '../components/AppIcon.vue';
import ConfigWorkspace from '../components/ConfigWorkspace.vue';
import CertificatePanel from '../components/CertificatePanel.vue';
import ConfirmDialog from '../components/ConfirmDialog.vue';
import WorkspacePicker from '../components/WorkspacePicker.vue';
import { api, ApiError } from '../lib/api.js';
import { formatTime, shortFingerprint, timeAgo } from '../lib/format.js';
import { toast } from '../lib/toast.js';

const route = useRoute();
const router = useRouter();

const serverId = computed(() => String(route.params.serverId || 'local'));
const serverMeta = ref(null);
const info = ref(null);
const loading = ref(true);
const infoError = ref('');
const tab = ref(route.query.tab === 'certs' ? 'certs' : 'config');
const workspaceOpen = ref(false);
const refreshing = ref(false);

const revokeOpen = ref(false);
const deleteOpen = ref(false);
const dangerBusy = ref(false);

const isLocal = computed(() => serverId.value === 'local');
const name = computed(() => serverMeta.value?.name || (isLocal.value ? '主服务器（本地）' : `服务器 ${serverId.value.slice(0, 8)}`));
const online = computed(() => (isLocal.value ? true : Boolean(serverMeta.value?.online)));
const status = computed(() => {
  if (isLocal.value) return { label: '主服务器', tone: 'ok', dot: 'ok' };
  if (!serverMeta.value) return { label: '未知', tone: '', dot: '' };
  if (serverMeta.value.status === 'active' && serverMeta.value.online) return { label: '在线', tone: 'ok', dot: 'ok' };
  if (serverMeta.value.status === 'active') return { label: '离线', tone: 'danger', dot: 'danger' };
  if (serverMeta.value.status === 'pending') return { label: '等待注册', tone: 'warn', dot: 'warn' };
  return { label: '已撤销', tone: 'danger', dot: 'danger' };
});
const workspace = computed(() => info.value?.workspace || '');
const nginxLabel = computed(() => {
  if (!info.value) return '—';
  return info.value.nginxAvailable ? `nginx/${info.value.nginxVersion}` : '未检测到 nginx';
});
const showOffline = computed(() => !loading.value && !isLocal.value && !info.value);

let metaTimer = null;

onMounted(() => {
  loadAll();
  metaTimer = setInterval(refreshMeta, 30000);
  document.addEventListener('visibilitychange', onVisibility);
});

onBeforeUnmount(() => {
  clearInterval(metaTimer);
  document.removeEventListener('visibilitychange', onVisibility);
});

watch(serverId, () => {
  tab.value = 'config';
  loadAll();
});

function onVisibility() {
  if (document.visibilityState === 'visible') refreshMeta();
}

// Only refresh the server record (heartbeat / online state); the heavy info
// call stays on explicit refresh so polling does not hit the Agent every 30s.
async function refreshMeta() {
  if (document.visibilityState !== 'visible') return;
  try {
    const list = await api.get('/servers');
    const next = (list.servers || []).find((item) => item.id === serverId.value) || null;
    if (next) serverMeta.value = next;
  } catch {
    // Ignore transient polling errors.
  }
}

async function loadAll({ silent = false } = {}) {
  if (!silent) loading.value = true;
  else refreshing.value = true;
  infoError.value = '';
  try {
    const list = await api.get('/servers');
    serverMeta.value = (list.servers || []).find((item) => item.id === serverId.value) || null;
  } catch (caught) {
    if (!silent) infoError.value = caught.message;
  }
  try {
    info.value = await api.get(`/servers/${serverId.value}/info`, { force: '1' });
    infoError.value = '';
  } catch (caught) {
    if (caught instanceof ApiError && caught.code === 'AGENT_OFFLINE') {
      info.value = null;
      infoError.value = 'Agent 当前离线，无法读取服务器状态。';
    } else {
      info.value = null;
      infoError.value = caught.message || '读取服务器信息失败';
    }
  } finally {
    loading.value = false;
    refreshing.value = false;
  }
}

function onWorkspaceSelected(data) {
  info.value = { ...(info.value || {}), workspace: data.workspace, configFileExists: data.configFileExists };
  if (data.warning) toast.warn(data.warning);
  else toast.success('工作目录已切换');
  loadAll({ silent: true });
}

async function revokeAgent() {
  dangerBusy.value = true;
  try {
    await api.post(`/servers/${serverId.value}/revoke`, {});
    toast.success('Agent 已撤销，现有连接已断开');
    revokeOpen.value = false;
    await loadAll({ silent: true });
  } catch (caught) {
    toast.error(caught.message || '撤销失败');
  } finally {
    dangerBusy.value = false;
  }
}

async function deleteAgent() {
  dangerBusy.value = true;
  try {
    await api.delete(`/servers/${serverId.value}`);
    toast.success('服务器记录已删除');
    deleteOpen.value = false;
    router.push('/');
  } catch (caught) {
    toast.error(caught.message || '删除失败');
  } finally {
    dangerBusy.value = false;
  }
}
</script>

<template>
  <div>
    <RouterLink to="/" class="back-link">
      <AppIcon name="arrowLeft" :size="14" />
      返回服务器列表
    </RouterLink>

    <div class="page-head server-head">
      <div class="server-head-main">
        <div class="server-title-row">
          <span class="server-glyph" :class="{ local: isLocal }">
            <AppIcon :name="isLocal ? 'shield' : 'server'" :size="20" />
          </span>
          <h1 class="page-title truncate">{{ name }}</h1>
          <span class="badge" :class="`badge-${status.tone}`">
            <span class="status-dot" :class="status.dot" />
            {{ status.label }}
          </span>
        </div>
        <div class="server-facts">
          <span><AppIcon name="folder" :size="12" /> <span class="mono">{{ workspace || '未选择工作目录' }}</span></span>
          <span><AppIcon name="terminal" :size="12" /> {{ nginxLabel }}</span>
          <span v-if="info"><AppIcon name="lock" :size="12" /> {{ info.controlMode === 'systemd' ? `systemctl ${info.systemdUnit}` : 'nginx -s signal' }}</span>
          <span v-if="!isLocal && serverMeta"><AppIcon name="refresh" :size="12" /> {{ timeAgo(serverMeta.lastSeenAt) }}</span>
        </div>
      </div>
      <div class="head-actions">
        <button class="btn" type="button" :disabled="refreshing" @click="loadAll({ silent: true })">
          <span v-if="refreshing" class="spinner" />
          <AppIcon v-else name="refresh" :size="14" />
          刷新
        </button>
        <button class="btn" type="button" :disabled="!online" @click="workspaceOpen = true">
          <AppIcon name="folder" :size="14" />
          切换工作目录
        </button>
      </div>
    </div>

    <div v-if="loading" class="loading-row">
      <span class="spinner" />
      正在读取服务器状态…
    </div>

    <template v-else>
      <div v-if="showOffline" class="card offline-card">
        <span class="empty-icon"><AppIcon name="server" :size="32" /></span>
        <h3>Agent 当前离线</h3>
        <p>{{ infoError }}</p>
        <p class="small">Agent 会以指数退避自动重连；请检查子服务器进程、网络与主服务器地址。</p>
        <button class="btn" type="button" @click="loadAll()">
          <AppIcon name="refresh" :size="14" />
          重试
        </button>
      </div>

      <template v-else>
        <div v-if="info?.workspaceError" class="alert alert-warn mb-16">
          <AppIcon name="alert" :size="16" />
          <div>工作目录无效：{{ info.workspaceError }}。请重新选择工作目录后继续。</div>
        </div>
        <div v-if="info && !info.nginxAvailable" class="alert alert-warn mb-16">
          <AppIcon name="alert" :size="16" />
          <div>
            未检测到可执行的 Nginx（{{ info.nginxBin }}）。你仍可编辑与备份配置，但检测、重载、重启会失败。
          </div>
        </div>
        <div v-if="info && !info.enforceTest" class="alert alert-danger mb-16">
          <AppIcon name="alert" :size="16" />
          <div>当前节点已关闭 nginx -t 配置检测，写入后不会自动校验或回滚。请仅用于受控开发环境。</div>
        </div>

        <div class="tabs mb-16">
          <button class="tab" :class="{ active: tab === 'config' }" type="button" @click="tab = 'config'">
            <AppIcon name="file" :size="14" />
            配置文件
          </button>
          <button class="tab" :class="{ active: tab === 'certs' }" type="button" @click="tab = 'certs'">
            <AppIcon name="key" :size="14" />
            SSL 证书
          </button>
          <button class="tab" :class="{ active: tab === 'info' }" type="button" @click="tab = 'info'">
            <AppIcon name="settings" :size="14" />
            服务器信息
          </button>
        </div>

        <ConfigWorkspace
          v-show="tab === 'config'"
          :key="`config-${serverId}`"
          :server-id="serverId"
          :info="info"
          @pick-workspace="workspaceOpen = true"
          @refresh-info="loadAll({ silent: true })"
        />

        <CertificatePanel
          v-show="tab === 'certs'"
          :key="`certs-${serverId}`"
          :server-id="serverId"
          :info="info"
        />

        <div v-show="tab === 'info'" class="info-grid">
          <section class="card">
            <div class="card-head">
              <span class="card-title"><AppIcon name="server" :size="15" /> 运行环境</span>
              <span class="badge">{{ info?.platform || '—' }}</span>
            </div>
            <div class="card-body">
              <dl class="detail-list">
                <div><dt>主机名</dt><dd class="mono">{{ info?.hostname || '—' }}</dd></div>
                <div><dt>服务器时间</dt><dd>{{ formatTime(info?.serverTime) }}</dd></div>
                <div><dt>Nginx 版本</dt><dd>{{ nginxLabel }}</dd></div>
                <div><dt>Nginx 可执行文件</dt><dd class="mono break">{{ info?.nginxBin || '—' }}</dd></div>
                <div><dt>控制方式</dt><dd>{{ info?.controlMode === 'systemd' ? 'systemd' : '信号（nginx -s）' }}{{ info?.useSudo ? ' + sudo -n' : '' }}</dd></div>
                <div><dt>systemd 单元</dt><dd class="mono">{{ info?.systemdUnit || '—' }}</dd></div>
                <div><dt>证书目录</dt><dd class="mono">{{ info?.certDir || '—' }}</dd></div>
                <div><dt>配置检测</dt><dd>{{ info?.enforceTest ? '启用（nginx -t）' : '已关闭' }}</dd></div>
              </dl>
            </div>
          </section>

          <section class="card">
            <div class="card-head">
              <span class="card-title"><AppIcon name="folder" :size="15" /> 工作目录</span>
              <button class="btn btn-sm" type="button" @click="workspaceOpen = true">更改</button>
            </div>
            <div class="card-body">
              <dl class="detail-list">
                <div><dt>当前工作目录</dt><dd class="mono break">{{ info?.workspace || '未选择' }}</dd></div>
                <div><dt>主配置文件</dt><dd class="mono">{{ info?.configFile || 'nginx.conf' }}</dd></div>
                <div><dt>配置文件状态</dt><dd>{{ info?.configFileExists ? '已找到' : '未找到' }}</dd></div>
                <div><dt>允许根目录</dt><dd class="mono break allowed-roots">{{ (info?.allowedRoots || []).join('\n') || '—' }}</dd></div>
              </dl>
              <div class="alert alert-blue mt-16">
                <AppIcon name="info" :size="15" />
                <div>所有文件访问都限制在工作目录内，符号链接逃逸与私钥读取会被服务端拒绝。</div>
              </div>
            </div>
          </section>

          <section class="card">
            <div class="card-head">
              <span class="card-title"><AppIcon name="shield" :size="15" /> 身份与信任</span>
              <span class="badge" :class="isLocal ? 'badge-ok' : 'badge-blue'">{{ isLocal ? '本地节点' : 'Ed25519 Agent' }}</span>
            </div>
            <div class="card-body">
              <dl class="detail-list">
                <div><dt>节点类型</dt><dd>{{ isLocal ? '主服务器内置引擎' : '出站 Agent（无入站端口）' }}</dd></div>
                <div v-if="!isLocal"><dt>Agent ID</dt><dd class="mono break">{{ serverId }}</dd></div>
                <div v-if="!isLocal"><dt>公钥指纹</dt><dd class="mono break">{{ serverMeta?.keyFingerprint || '—' }}</dd></div>
                <div v-if="!isLocal"><dt>注册时间</dt><dd>{{ formatTime(serverMeta?.enrolledAt) }}</dd></div>
                <div v-if="!isLocal"><dt>最近心跳</dt><dd>{{ formatTime(serverMeta?.lastSeenAt) }}</dd></div>
                <div v-if="!isLocal"><dt>创建时间</dt><dd>{{ formatTime(serverMeta?.createdAt) }}</dd></div>
                <div v-if="!isLocal"><dt>主机信息</dt><dd>{{ serverMeta?.info?.hostname || info?.hostname || '—' }}</dd></div>
              </dl>
              <div v-if="!isLocal && serverMeta?.keyFingerprint" class="fingerprint-box">
                <span class="small muted">完整指纹</span>
                <span class="mono">{{ shortFingerprint(serverMeta.keyFingerprint) }}</span>
              </div>
            </div>
          </section>

          <section v-if="!isLocal" class="card danger-card">
            <div class="card-head">
              <span class="card-title"><AppIcon name="alert" :size="15" /> 危险操作</span>
            </div>
            <div class="card-body danger-body">
              <div class="danger-row">
                <div>
                  <strong>撤销 Agent 访问</strong>
                  <p>立即断开连接并吊销当前公钥。之后必须重新生成令牌并重新注册。</p>
                </div>
                <button class="btn btn-danger" type="button" @click="revokeOpen = true">
                  <AppIcon name="lock" :size="14" />
                  撤销
                </button>
              </div>
              <div class="danger-row">
                <div>
                  <strong>删除服务器记录</strong>
                  <p>删除后不可恢复，配置与证书不会被删除，但将无法通过本控制台管理该节点。</p>
                </div>
                <button class="btn btn-danger" type="button" @click="deleteOpen = true">
                  <AppIcon name="trash" :size="14" />
                  删除
                </button>
              </div>
            </div>
          </section>
        </div>
      </template>
    </template>

    <WorkspacePicker
      :open="workspaceOpen"
      :server-id="serverId"
      @close="workspaceOpen = false"
      @selected="onWorkspaceSelected"
    />

    <ConfirmDialog
      :open="revokeOpen"
      :busy="dangerBusy"
      title="撤销此 Agent？"
      message="撤销后 Agent 会立即断开，当前公钥失效。子服务器上的 Agent 将无法再连接，直到重新生成令牌并重新注册。"
      confirm-text="确认撤销"
      danger
      @close="revokeOpen = false"
      @confirm="revokeAgent"
    />

    <ConfirmDialog
      :open="deleteOpen"
      :busy="dangerBusy"
      title="删除服务器记录？"
      message="这会从控制台移除该服务器记录，操作不可恢复。Nginx 配置与证书文件不会被删除。"
      confirm-text="永久删除"
      danger
      @close="deleteOpen = false"
      @confirm="deleteAgent"
    />
  </div>
</template>

<style scoped>
.back-link {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: var(--muted);
  text-decoration: none;
  font-size: 11.5px;
  margin-bottom: 14px;
}
.back-link:hover { color: var(--text); }
.server-head { align-items: center; }
.server-head-main { min-width: 0; }
.server-title-row { display: flex; align-items: center; gap: 11px; flex-wrap: wrap; }
.server-glyph {
  width: 38px;
  height: 38px;
  flex: none;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 10px;
  background: var(--info-soft);
  color: var(--info-text);
  border: 1px solid var(--info-border);
}
.server-glyph.local { background: var(--accent-soft); color: var(--accent-bright); border-color: var(--accent-border); }
.server-facts {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
  margin-top: 10px;
  color: var(--muted);
  font-size: 11px;
}
.server-facts span { display: inline-flex; align-items: center; gap: 5px; max-width: 420px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.offline-card {
  padding: 52px 24px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 9px;
  text-align: center;
}
.offline-card h3 { font-size: 16px; }
.offline-card p { color: var(--muted); font-size: 12.5px; max-width: 480px; line-height: 1.7; }
.offline-card .btn { margin-top: 8px; }
.tab { display: inline-flex; align-items: center; gap: 6px; }
.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
  gap: 14px;
  align-items: start;
}
.detail-list { display: flex; flex-direction: column; gap: 0; margin: 0; }
.detail-list > div { display: flex; justify-content: space-between; gap: 18px; padding: 9px 0; border-bottom: 1px solid var(--border); }
.detail-list > div:last-child { border-bottom: 0; }
.detail-list dt { color: var(--muted); font-size: 11.5px; flex: none; }
.detail-list dd { margin: 0; font-size: 11.5px; color: var(--text-soft); text-align: right; min-width: 0; }
.break { word-break: break-all; }
.allowed-roots { white-space: pre-wrap; text-align: right; }
.fingerprint-box {
  margin-top: 12px;
  padding: 9px 11px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: var(--inset-bg);
  display: flex;
  flex-direction: column;
  gap: 2px;
  font-size: 10.5px;
  word-break: break-all;
}
.danger-card { border-color: var(--danger-soft); }
.danger-body { display: flex; flex-direction: column; gap: 16px; }
.danger-row { display: flex; align-items: flex-start; justify-content: space-between; gap: 14px; flex-wrap: wrap; }
.danger-row strong { font-size: 12.5px; }
.danger-row p { color: var(--muted); font-size: 11px; line-height: 1.6; margin-top: 4px; max-width: 380px; }
</style>
