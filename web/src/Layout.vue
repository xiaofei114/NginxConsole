<script setup>
import { computed, ref } from 'vue';
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router';
import AppIcon from './components/AppIcon.vue';
import ThemeSwitch from './components/ThemeSwitch.vue';
import { authState, logout } from './lib/auth.js';

const route = useRoute();
const router = useRouter();
const mobileOpen = ref(false);
const loggingOut = ref(false);

const nav = [
  { name: 'dashboard', label: '服务器', icon: 'dashboard', to: '/' },
  { name: 'audit', label: '审计日志', icon: 'history', to: '/audit' },
  { name: 'account', label: '账户与安全', icon: 'shield', to: '/account' },
];

const activeSection = computed(() => {
  if (route.name === 'server') return 'dashboard';
  return route.name;
});

const initial = computed(() => (authState.user?.username || '?').slice(0, 1).toUpperCase());

async function handleLogout() {
  if (loggingOut.value) return;
  loggingOut.value = true;
  await logout();
  loggingOut.value = false;
  router.push('/login');
}

function closeMobile() {
  mobileOpen.value = false;
}
</script>

<template>
  <div class="shell">
    <header class="mobile-bar">
      <button class="icon-button" type="button" aria-label="打开导航" @click="mobileOpen = true">
        <AppIcon name="menu" :size="20" />
      </button>
      <div class="brand brand-mobile">
        <span class="brand-mark">N</span>
        <span>Nginx Console</span>
      </div>
      <button class="icon-button" type="button" aria-label="退出登录" @click="handleLogout">
        <AppIcon name="logout" :size="18" />
      </button>
    </header>

    <aside class="sidebar" :class="{ open: mobileOpen }">
      <div class="brand">
        <span class="brand-mark">N</span>
        <div>
          <strong>Nginx Console</strong>
          <small>MULTI-SERVER CONTROL</small>
        </div>
        <button class="icon-button close-mobile" type="button" aria-label="关闭导航" @click="closeMobile">
          <AppIcon name="x" :size="18" />
        </button>
      </div>

      <nav class="nav">
        <RouterLink
          v-for="item in nav"
          :key="item.name"
          :to="item.to"
          class="nav-link"
          :class="{ active: activeSection === item.name }"
          @click="closeMobile"
        >
          <AppIcon :name="item.icon" :size="18" />
          <span>{{ item.label }}</span>
        </RouterLink>
      </nav>

      <div class="sidebar-note">
        <span class="note-dot" />
        <div>
          <strong>安全模式</strong>
          <span>命令白名单 · 双向签名</span>
        </div>
      </div>

      <div class="sidebar-footer">
        <div class="theme-row">
          <ThemeSwitch />
        </div>
        <div class="user-chip">
          <span class="avatar">{{ initial }}</span>
          <div class="user-text">
            <strong>{{ authState.user?.username || '—' }}</strong>
            <small>{{ authState.user?.totpEnabled ? '两步验证已启用' : '仅口令登录' }}</small>
          </div>
        </div>
        <button class="logout-button" type="button" :disabled="loggingOut" @click="handleLogout">
          <AppIcon name="logout" :size="16" />
          {{ loggingOut ? '退出中…' : '退出登录' }}
        </button>
      </div>
    </aside>

    <div v-if="mobileOpen" class="drawer-backdrop" @click="closeMobile" />

    <main class="app-main">
      <RouterView />
      <footer class="app-footer">
        <span>Nginx Console · 单管理员安全控制台</span>
        <span>所有敏感操作均记录审计日志</span>
      </footer>
    </main>
  </div>
</template>

<style scoped>
.shell { min-height: 100vh; }
.sidebar {
  position: fixed;
  inset: 0 auto 0 0;
  width: var(--sidebar-width);
  display: flex;
  flex-direction: column;
  padding: 22px 16px 18px;
  background: var(--sidebar-bg);
  border-right: 1px solid var(--border);
  z-index: 50;
}
.brand {
  display: flex;
  align-items: center;
  gap: 11px;
  padding: 4px 8px 24px;
}
.brand-mark {
  width: 34px;
  height: 34px;
  border-radius: 10px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-weight: 800;
  color: var(--primary-text);
  background: linear-gradient(140deg, var(--primary-from), var(--primary-to));
  box-shadow: 0 0 0 1px var(--accent-border), 0 8px 22px var(--accent-soft);
}
.brand strong { display: block; font-size: 14px; letter-spacing: 0.02em; }
.brand small {
  display: block;
  margin-top: 3px;
  color: var(--muted);
  font-size: 9px;
  letter-spacing: 0.16em;
}
.nav { display: flex; flex-direction: column; gap: 4px; }
.nav-link {
  display: flex;
  align-items: center;
  gap: 11px;
  padding: 10px 12px;
  border-radius: 10px;
  color: var(--muted);
  text-decoration: none;
  font-size: 13.5px;
  transition: background 0.15s ease, color 0.15s ease;
}
.nav-link:hover { color: var(--text); background: var(--hover-bg); }
.nav-link.active {
  color: var(--accent-text);
  background: linear-gradient(90deg, var(--accent-soft), var(--accent-soft));
  box-shadow: inset 2px 0 0 var(--accent);
}
.sidebar-note {
  display: flex;
  gap: 8px;
  margin: auto 6px 16px;
  padding: 12px;
  border-radius: 10px;
  background: var(--accent-soft);
  border: 1px solid var(--accent-soft);
  font-size: 11.5px;
  color: var(--muted);
}
.note-dot {
  width: 7px;
  height: 7px;
  margin-top: 4px;
  border-radius: 50%;
  background: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-soft);
  flex: none;
}
.sidebar-note strong { display: block; color: var(--ok-text); font-size: 11.5px; margin-bottom: 2px; }
.sidebar-footer { border-top: 1px solid var(--border); padding-top: 14px; }
.theme-row { padding: 0 2px 12px; }
.user-chip { display: flex; align-items: center; gap: 10px; padding: 0 4px 12px; }
.avatar {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: var(--avatar-bg);
  border: 1px solid var(--border-strong);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 13px;
  font-weight: 700;
  color: var(--ok-text);
}
.user-text strong { display: block; font-size: 12.5px; }
.user-text small { display: block; margin-top: 2px; color: var(--muted); font-size: 10.5px; }
.logout-button {
  width: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 9px;
  border-radius: 9px;
  border: 1px solid var(--border);
  background: transparent;
  color: var(--muted);
  font-size: 12px;
  cursor: pointer;
}
.logout-button:hover { color: var(--danger-text); border-color: var(--danger-border); }
.app-main {
  margin-left: var(--sidebar-width);
  padding: 34px 36px 20px;
  min-height: 100vh;
  max-width: 1500px;
}
.app-footer {
  display: flex;
  justify-content: space-between;
  gap: 20px;
  margin-top: 44px;
  padding: 18px 2px 10px;
  border-top: 1px solid var(--border);
  color: var(--text-faint);
  font-size: 11px;
}
.mobile-bar { display: none; }
.close-mobile { display: none; margin-left: auto; }
.drawer-backdrop { display: none; }

@media (max-width: 980px) {
  .mobile-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    position: sticky;
    top: 0;
    z-index: 40;
    padding: 10px 14px;
    background: var(--mobile-bar-bg);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--border);
  }
  .brand-mobile { padding: 0; gap: 8px; font-size: 12.5px; font-weight: 700; }
  .brand-mobile .brand-mark { width: 28px; height: 28px; border-radius: 8px; font-size: 12px; }
  .sidebar {
    transform: translateX(-100%);
    transition: transform 0.2s ease;
    width: 260px;
    z-index: 70;
  }
  .sidebar.open { transform: translateX(0); }
  .close-mobile { display: inline-flex; }
  .drawer-backdrop {
    display: block;
    position: fixed;
    inset: 0;
    z-index: 60;
    background: var(--overlay);
  }
  .app-main {
    margin-left: 0;
    padding: 22px 16px 16px;
  }
  .app-footer { flex-direction: column; gap: 4px; margin-top: 28px; }
}
</style>
