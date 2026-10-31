<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';
import AppIcon from '../components/AppIcon.vue';
import ServerCard from '../components/ServerCard.vue';
import ModalDialog from '../components/ModalDialog.vue';
import { api, ApiError } from '../lib/api.js';
import { copyText, formatTime, shortFingerprint, timeAgo } from '../lib/format.js';
import { toast } from '../lib/toast.js';

const router = useRouter();
const servers = ref([]);
const meta = reactive({ mainKeyFingerprint: '', mainUrl: '', enrollmentTokenMinutes: 30 });
const loading = ref(true);
const refreshing = ref(false);
const error = ref('');
let refreshTimer = null;

const certOverview = ref(null);
const certLoading = ref(true);
const certError = ref('');

const alertTotal = computed(() => {
  if (!certOverview.value) return 0;
  return certOverview.value.expired.length + certOverview.value.expiresSoon.length;
});
const alertTone = computed(() => (certOverview.value?.expired.length ? 'badge-danger' : 'badge-warn'));

const createOpen = ref(false);
const createName = ref('');
const createError = ref('');
const creating = ref(false);

const tokenOpen = ref(false);
const tokenData = ref(null);
const tokenBusy = ref(false);

const stats = computed(() => {
  const agents = servers.value.filter((item) => item.kind === 'agent');
  return {
    total: servers.value.length,
    agents: agents.length,
    online: agents.filter((item) => item.status === 'active' && item.online).length,
    pending: agents.filter((item) => item.status === 'pending').length,
    offline: agents.filter((item) => item.status === 'active' && !item.online).length,
  };
});

const hasAgents = computed(() => servers.value.some((item) => item.kind === 'agent'));
const loopbackMainUrl = computed(() => Boolean(meta.mainUrl && /(localhost|127\.0\.0\.1|\[::1\])/.test(meta.mainUrl)));

const tokenCommand = computed(() => {
  if (!tokenData.value) return '';
  const { enrollmentToken, agent, mainUrl } = tokenData.value;
  return [
    'ncs-agent enroll \\',
    `  --main ${mainUrl || 'https://console.example.com'} \\`,
    `  --id ${agent.id} \\`,
    `  --token ${enrollmentToken} \\`,
    '  --allowed-root /etc/nginx \\',
    '  --workspace /etc/nginx',
  ].join('\n');
});

async function load({ silent = false } = {}) {
  if (!silent) loading.value = true;
  else refreshing.value = true;
  try {
    const data = await api.get('/servers');
    meta.mainKeyFingerprint = data.mainKeyFingerprint || '';
    meta.mainUrl = data.mainUrl || '';
    meta.enrollmentTokenMinutes = data.enrollmentTokenMinutes || 30;
    servers.value = await Promise.all((data.servers || []).map(async (server) => {
      if (server.id === 'local' || server.online) {
        try {
          const info = await api.get(`/servers/${server.id}/info`, { force: '1' });
          return { ...server, info, infoError: null };
        } catch (caught) {
          return { ...server, info: server.info || null, infoError: caught.message };
        }
      }
      return server;
    }));
    error.value = '';
  } catch (caught) {
    if (!silent) error.value = caught.message;
  } finally {
    loading.value = false;
    refreshing.value = false;
  }
}

async function loadCertificates({ force = false } = {}) {
  if (!certOverview.value) certLoading.value = true;
  try {
    const data = await api.get(`/certificates/overview${force ? '?force=1' : ''}`);
    certOverview.value = data;
    certError.value = '';
  } catch (caught) {
    certError.value = caught.message || '证书信息获取失败';
  } finally {
    certLoading.value = false;
  }
}

function refreshAll() {
  load({ silent: true });
  loadCertificates({ force: true });
}

function certFileName(cert) {
  const parts = String(cert.file || '').split('/');
  return parts[parts.length - 1] || cert.file;
}

function daysLabel(cert) {
  const days = Math.abs(Number(cert.daysRemaining) || 0);
  if (cert.expired) return days > 0 ? `已过期 ${days} 天` : '已过期';
  return days === 0 ? '今天到期' : `剩余 ${days} 天`;
}

function openServerCert(serverId) {
  router.push({ name: 'server', params: { serverId }, query: { tab: 'certs' } });
}

function scheduleRefresh() {
  clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    if (document.visibilityState === 'visible') {
      load({ silent: true });
      loadCertificates();
    }
  }, 20000);
}

function onVisibility() {
  if (document.visibilityState === 'visible') {
    load({ silent: true });
    loadCertificates();
  }
}

onMounted(() => {
  load();
  loadCertificates();
  scheduleRefresh();
  document.addEventListener('visibilitychange', onVisibility);
});

onBeforeUnmount(() => {
  clearInterval(refreshTimer);
  document.removeEventListener('visibilitychange', onVisibility);
});

function openServer(server) {
  router.push({ name: 'server', params: { serverId: server.id } });
}

function openCreate() {
  createName.value = '';
  createError.value = '';
  createOpen.value = true;
}

async function submitCreate() {
  const name = createName.value.trim();
  if (!name) {
    createError.value = '请输入服务器名称';
    return;
  }
  creating.value = true;
  createError.value = '';
  try {
    const data = await api.post('/servers', { name });
    createOpen.value = false;
    await load({ silent: true });
    tokenData.value = data;
    tokenOpen.value = true;
    toast.success('服务器已创建，请立即用注册令牌完成 Agent 注册');
  } catch (caught) {
    createError.value = caught instanceof ApiError ? caught.message : '创建失败';
  } finally {
    creating.value = false;
  }
}

async function requestToken(server) {
  if (tokenBusy.value) return;
  tokenBusy.value = true;
  try {
    const data = await api.post(`/servers/${server.id}/enrollment-token`, {});
    tokenData.value = data;
    tokenOpen.value = true;
    await load({ silent: true });
  } catch (caught) {
    toast.error(caught.message || '生成注册令牌失败');
  } finally {
    tokenBusy.value = false;
  }
}

function closeToken() {
  tokenOpen.value = false;
  tokenData.value = null;
}

async function copy(value, label = '内容') {
  const ok = await copyText(value);
  if (ok) toast.success(`${label}已复制`);
  else toast.error('复制失败，请手动选择文本');
}
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <span class="eyebrow"><AppIcon name="dashboard" :size="12" /> CONSOLE OVERVIEW</span>
        <h1 class="page-title">服务器</h1>
        <p class="page-sub">集中查看主服务器与子服务器状态，进入节点管理配置、证书与进程。</p>
      </div>
      <div class="head-actions">
        <button class="btn" type="button" :disabled="refreshing" @click="refreshAll">
          <span v-if="refreshing" class="spinner" />
          <AppIcon v-else name="refresh" :size="14" />
          {{ refreshing ? '刷新中…' : '刷新' }}
        </button>
        <button class="btn btn-primary" type="button" @click="openCreate">
          <AppIcon name="plus" :size="15" />
          新增子服务器
        </button>
      </div>
    </div>

    <Transition name="fade">
      <div v-if="error" class="alert alert-danger mb-16">
        <AppIcon name="alert" :size="16" />
        <div>{{ error }}</div>
      </div>
    </Transition>

    <section class="stat-grid">
      <div class="stat-card">
        <span class="stat-label">节点总数</span>
        <strong class="stat-value">{{ stats.total }}</strong>
        <span class="stat-note">含主服务器本地节点</span>
      </div>
      <div class="stat-card">
        <span class="stat-label">在线 Agent</span>
        <strong class="stat-value ok">{{ stats.online }}</strong>
        <span class="stat-note">共 {{ stats.agents }} 个子服务器</span>
      </div>
      <div class="stat-card">
        <span class="stat-label">等待注册</span>
        <strong class="stat-value warn">{{ stats.pending }}</strong>
        <span class="stat-note">需在有效期内完成注册</span>
      </div>
      <div class="stat-card">
        <span class="stat-label">离线 Agent</span>
        <strong class="stat-value danger">{{ stats.offline }}</strong>
        <span class="stat-note">Agent 会指数退避重连</span>
      </div>
    </section>

    <section class="security-strip">
      <div class="security-item">
        <span class="security-icon"><AppIcon name="key" :size="15" /></span>
        <div>
          <span class="security-label">主服务器签名指纹</span>
          <span class="security-value mono">{{ shortFingerprint(meta.mainKeyFingerprint) }}</span>
        </div>
        <button class="icon-button" type="button" aria-label="复制主服务器指纹" @click="copy(meta.mainKeyFingerprint, '指纹')">
          <AppIcon name="copy" :size="14" />
        </button>
      </div>
      <div class="security-item">
        <span class="security-icon"><AppIcon name="external" :size="15" /></span>
        <div>
          <span class="security-label">Agent 连接地址</span>
          <span class="security-value mono">{{ meta.mainUrl || '未配置 NCS_PUBLIC_ORIGIN' }}</span>
        </div>
        <button
          v-if="meta.mainUrl"
          class="icon-button"
          type="button"
          aria-label="复制连接地址"
          @click="copy(meta.mainUrl, '地址')"
        >
          <AppIcon name="copy" :size="14" />
        </button>
      </div>
      <div class="security-item">
        <span class="security-icon"><AppIcon name="lock" :size="15" /></span>
        <div>
          <span class="security-label">注册令牌有效期</span>
          <span class="security-value">{{ meta.enrollmentTokenMinutes }} 分钟 · 一次性</span>
        </div>
      </div>
    </section>

    <div v-if="loopbackMainUrl" class="alert alert-warn mt-16">
      <AppIcon name="alert" :size="16" />
      <div>
        当前 Agent 连接地址是回环地址，子服务器无法连接。请在主服务器配置
        <code class="mono">NCS_PUBLIC_ORIGIN=https://你的域名</code> 后重启主服务器。
      </div>
    </div>

    <section class="servers-section">
      <div class="section-head">
        <div class="section-title">
          <h2>全部节点</h2>
          <span class="badge">{{ servers.length }}</span>
        </div>
        <span class="small muted">每 20 秒自动刷新</span>
      </div>

      <div v-if="loading" class="loading-row">
        <span class="spinner" />
        正在加载节点信息…
      </div>
      <div v-else-if="servers.length === 0" class="empty card">
        <span class="empty-icon"><AppIcon name="server" :size="30" /></span>
        <span>还没有可管理的节点</span>
      </div>
      <div v-else class="server-grid">
        <ServerCard
          v-for="server in servers"
          :key="server.id"
          :server="server"
          @open="openServer"
          @enroll="requestToken"
        />
      </div>

      <div v-if="!loading && !hasAgents" class="onboard-card card">
        <div class="onboard-art"><AppIcon name="terminal" :size="22" /></div>
        <div class="onboard-text">
          <h3>还没有子服务器？</h3>
          <p>在目标服务器上安装 Agent 后，用一次性令牌注册，即可在此页面统一管理。</p>
        </div>
        <button class="btn" type="button" @click="openCreate">
          <AppIcon name="plus" :size="14" />
          创建注册令牌
        </button>
      </div>
    </section>

    <section class="cert-alerts">
      <div class="section-head">
        <div class="section-title">
          <h2>证书到期提醒</h2>
          <span v-if="certOverview" class="badge" :class="alertTotal ? alertTone : ''">{{ alertTotal }}</span>
        </div>
        <span v-if="certOverview" class="small muted">
          更新于 {{ timeAgo(certOverview.generatedAt) }}<template v-if="certOverview.cached"> · 缓存</template>
        </span>
        <span v-else-if="certLoading" class="small muted">正在汇总…</span>
      </div>

      <div v-if="certError" class="alert alert-danger">
        <AppIcon name="alert" :size="15" />
        <div>{{ certError }}</div>
      </div>

      <div v-if="certLoading && !certOverview" class="loading-row">
        <span class="spinner" />
        正在汇总各节点证书…
      </div>

      <template v-else-if="certOverview">
        <div v-if="!alertTotal" class="cert-ok card">
          <AppIcon name="check" :size="16" />
          <span>共 {{ certOverview.count }} 张证书，30 天内没有到期证书。</span>
        </div>
        <div v-else class="card cert-card">
          <div v-if="certOverview.expired.length" class="cert-group">
            <div class="cert-group-head danger">
              <span class="cert-dot" />
              已过期
              <em>{{ certOverview.expired.length }} 张</em>
            </div>
            <ul class="cert-rows">
              <li v-for="cert in certOverview.expired" :key="`${cert.serverId}:${cert.file}`">
                <button class="cert-file" type="button" :title="cert.file" @click="openServerCert(cert.serverId)">
                  {{ certFileName(cert) }}
                </button>
                <button class="cert-server" type="button" @click="openServerCert(cert.serverId)">
                  {{ cert.serverName }}
                </button>
                <span class="cert-date">{{ formatTime(cert.validTo) }}</span>
                <span class="badge badge-danger cert-days">{{ daysLabel(cert) }}</span>
              </li>
            </ul>
          </div>

          <div v-if="certOverview.expiresSoon.length" class="cert-group">
            <div class="cert-group-head warn">
              <span class="cert-dot" />
              即将到期
              <em>{{ certOverview.thresholdDays }} 天内 · {{ certOverview.expiresSoon.length }} 张</em>
            </div>
            <ul class="cert-rows">
              <li v-for="cert in certOverview.expiresSoon" :key="`${cert.serverId}:${cert.file}`">
                <button class="cert-file" type="button" :title="cert.file" @click="openServerCert(cert.serverId)">
                  {{ certFileName(cert) }}
                </button>
                <button class="cert-server" type="button" @click="openServerCert(cert.serverId)">
                  {{ cert.serverName }}
                </button>
                <span class="cert-date">{{ formatTime(cert.validTo) }}</span>
                <span class="badge badge-warn cert-days">{{ daysLabel(cert) }}</span>
              </li>
            </ul>
          </div>
        </div>

        <p v-if="certOverview.errors.length || certOverview.skipped.length" class="cert-note small muted">
          <template v-if="certOverview.errors.length">
            获取失败：{{ certOverview.errors.map((item) => `${item.serverName}（${item.error}）`).join('、') }}
          </template>
          <template v-if="certOverview.errors.length && certOverview.skipped.length">；</template>
          <template v-if="certOverview.skipped.length">
            未包含：{{ certOverview.skipped.map((item) => `${item.serverName}（${item.reason}）`).join('、') }}
          </template>
        </p>
      </template>
    </section>

    <ModalDialog :open="createOpen" title="新增子服务器" subtitle="创建后生成一次性注册令牌，令牌仅显示一次。" width="470px" :busy="creating" @close="createOpen = false">
      <form @submit.prevent="submitCreate">
        <div class="field">
          <label for="server-name">服务器名称</label>
          <input
            id="server-name"
            v-model="createName"
            type="text"
            maxlength="64"
            autofocus
            placeholder="例如 web-01 / 北京入口节点"
          />
          <span class="hint">仅用于展示，不会作为主机名或路径使用。</span>
        </div>
        <div v-if="createError" class="alert alert-danger mt-16">
          <AppIcon name="alert" :size="15" />
          <div>{{ createError }}</div>
        </div>
      </form>
      <template #footer>
        <button class="btn" type="button" :disabled="creating" @click="createOpen = false">取消</button>
        <button class="btn btn-primary" type="button" :disabled="creating" @click="submitCreate">
          <span v-if="creating" class="spinner" />
          {{ creating ? '创建中…' : '创建并生成令牌' }}
        </button>
      </template>
    </ModalDialog>

    <ModalDialog :open="tokenOpen" title="Agent 注册信息" subtitle="请在目标服务器上执行以下命令完成注册。" width="640px" @close="closeToken">
      <div v-if="tokenData" class="token-body">
        <div class="alert alert-warn">
          <AppIcon name="alert" :size="16" />
          <div>
            注册令牌只在此处显示一次，有效期至
            <strong>{{ formatTime(tokenData.enrollExpiresAt) }}</strong>。请勿通过聊天工具或工单传递。
          </div>
        </div>

        <div class="token-meta">
          <div><span>服务器</span><strong>{{ tokenData.agent.name }}</strong></div>
          <div>
            <span>Agent ID</span>
            <strong class="mono">{{ tokenData.agent.id }}</strong>
            <button class="icon-button" type="button" aria-label="复制 Agent ID" @click="copy(tokenData.agent.id, 'Agent ID')">
              <AppIcon name="copy" :size="13" />
            </button>
          </div>
          <div>
            <span>注册令牌</span>
            <strong class="mono token-text">{{ tokenData.enrollmentToken }}</strong>
            <button class="icon-button" type="button" aria-label="复制注册令牌" @click="copy(tokenData.enrollmentToken, '注册令牌')">
              <AppIcon name="copy" :size="13" />
            </button>
          </div>
        </div>

        <div class="command-head">
          <span>在子服务器执行（需先安装 Agent）</span>
          <button class="btn btn-sm" type="button" @click="copy(tokenCommand, '命令')">
            <AppIcon name="copy" :size="13" />
            复制命令
          </button>
        </div>
        <pre class="code-block">{{ tokenCommand }}</pre>

        <ul class="token-tips">
          <li><AppIcon name="check" :size="13" /> Agent 使用 Ed25519 密钥注册，主服务器只保存公钥。</li>
          <li><AppIcon name="check" :size="13" /> 注册完成后令牌立即失效，无法再次使用。</li>
          <li><AppIcon name="check" :size="13" /> 生产环境必须使用 HTTPS；Agent 只需主动出站。</li>
        </ul>
      </div>
      <template #footer>
        <button class="btn btn-primary" type="button" @click="closeToken">我已保存</button>
      </template>
    </ModalDialog>
  </div>
</template>

<style scoped>
.stat-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}
.stat-card {
  display: flex;
  flex-direction: column;
  gap: 5px;
  padding: 15px 16px;
  border: 1px solid var(--border);
  border-radius: 12px;
  background: linear-gradient(180deg, var(--surface-a), var(--surface-b));
}
.stat-label { color: var(--muted); font-size: 11px; }
.stat-value { font-size: 25px; line-height: 1.15; font-weight: 700; letter-spacing: -0.02em; }
.stat-value.ok { color: var(--ok-text); }
.stat-value.warn { color: var(--warn-text); }
.stat-value.danger { color: var(--danger-text); }
.stat-note { color: var(--text-faint); font-size: 10.5px; }
.cert-alerts { margin-top: 26px; }
.cert-card { padding: 0; overflow: hidden; }
.cert-group + .cert-group { border-top: 1px solid var(--border); }
.cert-group-head {
  display: flex;
  align-items: center;
  gap: 7px;
  padding: 8px 14px;
  background: var(--subtle-bg);
  border-bottom: 1px solid var(--border);
  font-size: 11px;
  font-weight: 600;
}
.cert-group-head.danger { color: var(--danger-text); }
.cert-group-head.warn { color: var(--warn-text); }
.cert-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; flex: none; }
.cert-group-head em { font-style: normal; font-weight: 400; color: var(--text-faint); }
.cert-rows { list-style: none; margin: 0; padding: 0; }
.cert-rows li {
  display: grid;
  grid-template-columns: minmax(0, 1.6fr) minmax(96px, 0.6fr) 140px 88px;
  align-items: center;
  gap: 12px;
  padding: 8px 14px;
}
.cert-rows li + li { border-top: 1px solid var(--border); }
.cert-rows li:hover { background: var(--hover-bg); }
.cert-file {
  background: none;
  border: 0;
  padding: 0;
  color: var(--text);
  font-size: 11.5px;
  font-weight: 600;
  text-align: left;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  cursor: pointer;
}
.cert-file:hover { color: var(--accent-bright); }
.cert-server {
  background: none;
  border: 0;
  padding: 0;
  color: var(--muted);
  font-size: 11px;
  text-align: left;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  cursor: pointer;
}
.cert-server:hover { color: var(--accent-bright); }
.cert-date { color: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums; white-space: nowrap; }
.cert-days { justify-self: end; }
.cert-ok {
  display: flex;
  align-items: center;
  gap: 9px;
  padding: 12px 14px;
  color: var(--ok-text);
  font-size: 12px;
}
.cert-note { margin-top: 8px; line-height: 1.6; }
.security-strip {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  margin-top: 14px;
  border: 1px solid var(--border);
  border-radius: 12px;
  background: var(--surface-b);
  overflow: hidden;
}
.security-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 15px;
  min-width: 0;
}
.security-item + .security-item { border-left: 1px solid var(--border); }
.security-icon {
  width: 28px;
  height: 28px;
  flex: none;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 8px;
  background: var(--hover-bg);
  color: var(--muted);
}
.security-item > div { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.security-label { color: var(--text-faint); font-size: 10px; }
.security-value { font-size: 11.5px; color: var(--text-soft); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.servers-section { margin-top: 28px; }
.section-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 13px; }
.section-title { display: flex; align-items: center; gap: 9px; }
.section-title h2 { font-size: 15px; }
.server-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(310px, 1fr));
  gap: 13px;
}
.empty { padding: 40px; display: flex; flex-direction: column; align-items: center; gap: 8px; }
.onboard-card {
  display: flex;
  align-items: center;
  gap: 15px;
  margin-top: 14px;
  padding: 16px 18px;
  flex-wrap: wrap;
}
.onboard-art {
  width: 42px;
  height: 42px;
  flex: none;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 11px;
  background: var(--accent-soft);
  color: var(--accent-bright);
  border: 1px solid var(--accent-border);
}
.onboard-text { flex: 1; min-width: 200px; }
.onboard-text h3 { font-size: 13px; margin-bottom: 4px; }
.onboard-text p { color: var(--muted); font-size: 11.5px; line-height: 1.6; }
.token-body { display: flex; flex-direction: column; gap: 14px; }
.token-meta {
  display: flex;
  flex-direction: column;
  gap: 1px;
  border: 1px solid var(--border);
  border-radius: 10px;
  overflow: hidden;
}
.token-meta > div {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 12px;
  background: var(--subtle-bg);
  min-width: 0;
}
.token-meta > div + div { border-top: 1px solid var(--border); }
.token-meta span { width: 92px; flex: none; color: var(--muted); font-size: 11px; }
.token-meta strong { font-size: 11.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.token-text { color: var(--warn); }
.command-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; font-size: 11.5px; color: var(--muted); }
.token-tips { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; }
.token-tips li { display: flex; gap: 7px; align-items: flex-start; color: var(--muted-2); font-size: 11px; line-height: 1.5; }
.token-tips svg { color: var(--accent-bright); margin-top: 1px; flex: none; }

@media (max-width: 1180px) {
  .stat-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .security-strip { grid-template-columns: 1fr; }
  .security-item + .security-item { border-left: 0; border-top: 1px solid var(--border); }
}
@media (max-width: 900px) {
  .cert-rows li {
    grid-template-columns: minmax(0, 1fr) auto;
    grid-template-areas: "file days" "server server";
    row-gap: 3px;
  }
  .cert-file { grid-area: file; }
  .cert-server { grid-area: server; }
  .cert-days { grid-area: days; }
  .cert-date { display: none; }
}
@media (max-width: 700px) {
  .server-grid { grid-template-columns: 1fr; }
}
</style>
