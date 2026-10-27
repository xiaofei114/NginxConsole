import { createRouter, createWebHistory } from 'vue-router';
import { ensureSession } from './lib/auth.js';
import Layout from './Layout.vue';
import LoginView from './views/LoginView.vue';
import DashboardView from './views/DashboardView.vue';
import ServerView from './views/ServerView.vue';
import AuditView from './views/AuditView.vue';
import AccountView from './views/AccountView.vue';

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: LoginView,
      meta: { public: true, title: '登录' },
    },
    {
      path: '/',
      component: Layout,
      children: [
        { path: '', name: 'dashboard', component: DashboardView, meta: { title: '服务器' } },
        { path: 'servers/:serverId', name: 'server', component: ServerView, meta: { title: '服务器详情' } },
        { path: 'audit', name: 'audit', component: AuditView, meta: { title: '审计日志' } },
        { path: 'account', name: 'account', component: AccountView, meta: { title: '账户与安全' } },
      ],
    },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
  scrollBehavior(to, from, saved) {
    if (saved) return saved;
    if (to.name !== from.name) return { top: 0 };
    return undefined;
  },
});

router.beforeEach(async (to) => {
  if (to.meta.public) return true;
  const user = await ensureSession();
  if (!user) {
    return { name: 'login', query: { redirect: to.fullPath } };
  }
  return true;
});

router.afterEach((to) => {
  const base = 'Nginx Console';
  document.title = to.meta.title ? `${to.meta.title} · ${base}` : base;
});

export default router;
