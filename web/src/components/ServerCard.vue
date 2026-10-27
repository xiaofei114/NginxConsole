<script setup>
import { computed } from 'vue';
import AppIcon from './AppIcon.vue';
import { timeAgo, shortFingerprint } from '../lib/format.js';

const props = defineProps({
  server: { type: Object, required: true },
});
const emit = defineEmits(['open', 'enroll']);

const status = computed(() => {
  if (props.server.kind === 'local') return { label: '主服务器', tone: 'ok', dot: 'ok' };
  if (props.server.status === 'active' && props.server.online) return { label: '在线', tone: 'ok', dot: 'ok' };
  if (props.server.status === 'active') return { label: '离线', tone: 'danger', dot: 'danger' };
  if (props.server.status === 'pending') return { label: '等待注册', tone: 'warn', dot: 'warn' };
  return { label: '已撤销', tone: 'danger', dot: 'danger' };
});

const info = computed(() => props.server.info || null);

const workspace = computed(() => info.value?.workspace || '尚未选择工作目录');
const hostname = computed(() => info.value?.hostname || (props.server.kind === 'local' ? '本机' : '—'));
const nginxVersion = computed(() => {
  if (!info.value) return '—';
  return info.value.nginxAvailable ? `nginx/${info.value.nginxVersion}` : '未检测到 nginx';
});
const canEnroll = computed(() => props.server.kind === 'agent' && props.server.status !== 'active');
const isOffline = computed(() => props.server.kind === 'agent' && props.server.status === 'active' && !props.server.online);
</script>

<template>
  <article
    class="server-card"
    :class="{ offline: isOffline, pending: canEnroll }"
    tabindex="0"
    role="button"
    :aria-label="`打开 ${server.name}`"
    @click="emit('open', server)"
    @keydown.enter.prevent="emit('open', server)"
    @keydown.space.prevent="emit('open', server)"
  >
    <div class="card-top">
      <div class="server-identity">
        <span class="server-glyph" :class="server.kind">
          <AppIcon :name="server.kind === 'local' ? 'shield' : 'server'" :size="18" />
        </span>
        <div class="server-name-wrap">
          <h3 class="server-name truncate" :title="server.name">{{ server.name }}</h3>
          <span class="mono server-id">{{ server.kind === 'local' ? 'LOCAL NODE' : server.id.slice(0, 8) }}</span>
        </div>
      </div>
      <span class="badge" :class="`badge-${status.tone}`">
        <span class="status-dot" :class="status.dot" />
        {{ status.label }}
      </span>
    </div>

    <dl class="server-meta">
      <div>
        <dt>主机名</dt>
        <dd class="truncate" :title="hostname">{{ hostname }}</dd>
      </div>
      <div>
        <dt>工作目录</dt>
        <dd class="mono truncate" :title="workspace">{{ workspace }}</dd>
      </div>
      <div>
        <dt>Nginx</dt>
        <dd class="truncate">{{ nginxVersion }}</dd>
      </div>
      <div>
        <dt>{{ server.kind === 'local' ? '访问方式' : '最近心跳' }}</dt>
        <dd>
          <span v-if="server.kind === 'local'">页面直连</span>
          <span v-else>{{ timeAgo(server.lastSeenAt) }}</span>
        </dd>
      </div>
    </dl>

    <div class="card-bottom">
      <span v-if="server.keyFingerprint" class="fingerprint" :title="server.keyFingerprint">
        <AppIcon name="key" :size="12" />
        {{ shortFingerprint(server.keyFingerprint) }}
      </span>
      <span v-else-if="server.kind === 'local'" class="fingerprint">
        <AppIcon name="lock" :size="12" />
        本地受控节点
      </span>
      <span v-else-if="server.status === 'pending'" class="fingerprint warn">
        <AppIcon name="alert" :size="12" />
        需生成注册令牌
      </span>
      <span v-else class="fingerprint">
        <AppIcon name="x" :size="12" />
        已撤销访问密钥
      </span>

      <button
        v-if="canEnroll"
        class="btn btn-sm enroll-btn"
        type="button"
        @click.stop="emit('enroll', server)"
      >
        <AppIcon name="key" :size="13" />
        注册
      </button>
      <span v-else class="open-hint">
        管理
        <AppIcon name="chevronRight" :size="13" />
      </span>
    </div>
  </article>
</template>

<style scoped>
.server-card {
  display: flex;
  flex-direction: column;
  gap: 15px;
  padding: 17px;
  border-radius: 14px;
  border: 1px solid var(--border);
  background: linear-gradient(180deg, var(--surface-a), var(--surface-b));
  transition: border-color 0.16s ease, transform 0.16s ease, box-shadow 0.16s ease;
  outline: none;
  cursor: pointer;
  min-width: 0;
}
.server-card:hover, .server-card:focus-visible {
  border-color: var(--border-strong);
  transform: translateY(-2px);
  box-shadow: 0 16px 36px var(--shadow-color);
}
.server-card.offline { border-style: dashed; }
.server-card.pending { background: linear-gradient(180deg, var(--surface-pending), var(--surface-b)); }
.card-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; }
.server-identity { display: flex; align-items: center; gap: 11px; min-width: 0; }
.server-glyph {
  width: 34px;
  height: 34px;
  flex: none;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 9px;
  background: var(--info-soft);
  color: var(--info-text);
  border: 1px solid var(--info-border);
}
.server-glyph.local {
  background: var(--accent-soft);
  color: var(--accent-bright);
  border-color: var(--accent-border);
}
.server-name-wrap { min-width: 0; }
.server-name { font-size: 14px; line-height: 1.3; }
.server-id { display: block; margin-top: 2px; font-size: 9.5px; color: var(--text-faint); letter-spacing: 0.06em; }
.server-meta {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px 12px;
  margin: 0;
  padding: 12px 0;
  border-top: 1px solid var(--border);
  border-bottom: 1px solid var(--border);
}
.server-meta dt { color: var(--text-faint); font-size: 10px; letter-spacing: 0.04em; margin-bottom: 3px; }
.server-meta dd { margin: 0; font-size: 11.5px; color: var(--text-soft); }
.card-bottom { display: flex; align-items: center; justify-content: space-between; gap: 10px; min-height: 26px; }
.fingerprint { display: inline-flex; align-items: center; gap: 5px; color: var(--text-faint); font-size: 10px; font-family: var(--mono); min-width: 0; }
.fingerprint.warn { color: var(--warn); font-family: var(--font); }
.open-hint { display: inline-flex; align-items: center; gap: 3px; color: var(--muted); font-size: 11px; }
.enroll-btn { flex: none; }
</style>
