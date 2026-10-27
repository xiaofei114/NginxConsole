<script setup>
import { computed, onMounted, reactive, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import AppIcon from '../components/AppIcon.vue';
import ThemeSwitch from '../components/ThemeSwitch.vue';
import { ApiError } from '../lib/api.js';
import { authState, ensureSession, login } from '../lib/auth.js';

const router = useRouter();
const route = useRoute();
const form = reactive({ username: '', password: '', totp: '', recoveryCode: '' });
const useRecovery = ref(false);
const showPassword = ref(false);
const needTotp = ref(false);
const submitting = ref(false);
const error = reactive({ message: '', hint: '' });
const passwordInput = ref(null);

const secondFactorField = computed(() => (useRecovery.value ? 'recoveryCode' : 'totp'));

onMounted(async () => {
  const user = await ensureSession();
  if (user) {
    router.replace(typeof route.query.redirect === 'string' ? route.query.redirect : '/');
    return;
  }
  passwordInput.value?.focus();
});

function switchRecovery(value) {
  useRecovery.value = value;
  form.totp = '';
  form.recoveryCode = '';
}

async function submit() {
  if (submitting.value) return;
  error.message = '';
  error.hint = '';
  if (!form.username.trim() || !form.password) {
    error.message = '请输入用户名和口令';
    return;
  }
  submitting.value = true;
  try {
    const payload = { username: form.username.trim(), password: form.password };
    if (needTotp.value && form.totp) payload.totp = form.totp.trim();
    if (needTotp.value && form.recoveryCode) payload.recoveryCode = form.recoveryCode.trim();
    await login(payload);
    router.replace(typeof route.query.redirect === 'string' ? route.query.redirect : '/');
  } catch (caught) {
    if (caught instanceof ApiError) {
      if (caught.code === 'TOTP_REQUIRED') {
        needTotp.value = true;
        error.message = '请输入两步验证码';
      } else if (caught.code === 'INVALID_SECOND_FACTOR' || caught.code === 'INVALID_CREDENTIALS') {
        if (needTotp.value) error.message = caught.code === 'INVALID_SECOND_FACTOR' ? '两步验证码无效' : '用户名或口令错误';
        else error.message = caught.message;
      } else if (caught.code === 'ACCOUNT_LOCKED') {
        const retry = caught.details?.retryAfter;
        error.message = '账号已被临时锁定';
        error.hint = retry ? `请约 ${Math.ceil(retry / 60)} 分钟后重试。` : '请稍后重试。';
      } else if (caught.code === 'RATE_LIMITED') {
        error.message = '尝试次数过多';
        error.hint = caught.details?.retryAfter ? `请约 ${Math.ceil(caught.details.retryAfter / 60)} 分钟后重试。` : '请稍后再试。';
      } else {
        error.message = caught.message;
      }
    } else {
      error.message = '登录失败，请稍后重试';
    }
  } finally {
    submitting.value = false;
  }
}
</script>

<template>
  <div class="login-shell">
    <div class="login-theme">
      <ThemeSwitch />
    </div>
    <section class="login-brand">
      <div class="brand-line">
        <span class="brand-mark">N</span>
        <span class="brand-name">Nginx Console</span>
      </div>
      <h1>多服务器 Nginx<br />安全控制台</h1>
      <p class="brand-lead">
        一个公网页面，集中管理多台服务器的 Nginx 配置与 SSL 证书。
        子服务器只主动出站，不开放任何管理端口。
      </p>
      <ul class="brand-points">
        <li><AppIcon name="shield" :size="16" /> 固定命令白名单，无任意 Shell</li>
        <li><AppIcon name="key" :size="16" /> Agent 双向 Ed25519 签名与重放防护</li>
        <li><AppIcon name="file" :size="16" /> 写入前备份，检测失败自动回滚</li>
        <li><AppIcon name="history" :size="16" /> 全量审计，敏感内容不入日志</li>
      </ul>
      <p class="brand-foot">默认只监听 127.0.0.1 · 建议配合反向代理与 TLS</p>
    </section>

    <section class="login-panel">
      <form class="login-card" autocomplete="off" @submit.prevent="submit">
        <div class="login-head">
          <span class="eyebrow"><AppIcon name="lock" :size="12" /> ADMIN ACCESS</span>
          <h2>登录控制台</h2>
          <p>请使用管理员账号登录。所有操作都会写入审计日志。</p>
        </div>

        <div class="field">
          <label for="username">用户名</label>
          <input
            id="username"
            ref="passwordInput"
            v-model="form.username"
            type="text"
            autocomplete="username"
            autocapitalize="off"
            spellcheck="false"
            maxlength="64"
            placeholder="admin"
          />
        </div>

        <div class="field">
          <label for="password">口令</label>
          <div class="password-wrap">
            <input
              id="password"
              v-model="form.password"
              :type="showPassword ? 'text' : 'password'"
              autocomplete="current-password"
              maxlength="1024"
              placeholder="请输入管理员口令"
            />
            <button
              class="password-toggle"
              type="button"
              :aria-label="showPassword ? '隐藏口令' : '显示口令'"
              @click="showPassword = !showPassword"
            >
              <AppIcon :name="showPassword ? 'eyeOff' : 'eye'" :size="16" />
            </button>
          </div>
        </div>

        <Transition name="fade">
          <div v-if="needTotp" class="field totp-field">
            <label :for="secondFactorField">
              {{ useRecovery ? '恢复码' : '两步验证码' }}
            </label>
            <input
              v-if="!useRecovery"
              id="totp"
              v-model="form.totp"
              type="text"
              inputmode="numeric"
              maxlength="6"
              autocomplete="one-time-code"
              placeholder="6 位数字"
            />
            <input
              v-else
              id="recoveryCode"
              v-model="form.recoveryCode"
              type="text"
              maxlength="24"
              autocomplete="one-time-code"
              placeholder="XXXXX-XXXXX"
            />
            <button class="link-button" type="button" @click="switchRecovery(!useRecovery)">
              {{ useRecovery ? '使用验证器验证码' : '使用一次性恢复码' }}
            </button>
          </div>
        </Transition>

        <Transition name="fade">
          <div v-if="error.message" class="alert alert-danger" role="alert">
            <AppIcon name="alert" :size="16" />
            <div>
              <div>{{ error.message }}</div>
              <div v-if="error.hint" class="small" style="margin-top: 3px; opacity: 0.85">{{ error.hint }}</div>
            </div>
          </div>
        </Transition>

        <button class="btn btn-primary btn-lg btn-block login-submit" type="submit" :disabled="submitting">
          <span v-if="submitting" class="spinner" />
          {{ submitting ? '验证中…' : '登录' }}
        </button>

        <p class="login-note">
          <AppIcon name="info" :size="13" />
          首次启动的初始口令在服务端终端输出，登录后请立即修改并启用两步验证。
        </p>
      </form>
    </section>
  </div>
</template>

<style scoped>
.login-shell {
  position: relative;
  min-height: 100vh;
  display: grid;
  grid-template-columns: minmax(0, 1.05fr) minmax(0, 0.95fr);
}
.login-theme {
  position: absolute;
  top: 18px;
  right: 20px;
  width: 104px;
  z-index: 2;
}
.login-brand {
  display: flex;
  flex-direction: column;
  justify-content: center;
  padding: 64px clamp(28px, 6vw, 92px);
  border-right: 1px solid var(--border);
  background:
    radial-gradient(600px 300px at 20% 20%, var(--accent-soft), transparent 65%),
    linear-gradient(180deg, var(--bg-soft), var(--bg));
}
.brand-line { display: flex; align-items: center; gap: 10px; margin-bottom: 40px; }
.brand-mark {
  width: 36px;
  height: 36px;
  border-radius: 11px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-weight: 800;
  color: var(--primary-text);
  background: linear-gradient(140deg, var(--primary-from), var(--primary-to));
  box-shadow: 0 8px 24px var(--accent-soft);
}
.brand-name { font-size: 13px; font-weight: 650; letter-spacing: 0.04em; }
.login-brand h1 {
  font-size: clamp(30px, 3.2vw, 42px);
  line-height: 1.18;
  letter-spacing: -0.025em;
}
.brand-lead {
  margin-top: 18px;
  max-width: 460px;
  color: var(--muted);
  font-size: 13.5px;
  line-height: 1.75;
}
.brand-points {
  list-style: none;
  margin: 32px 0 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 13px;
  max-width: 460px;
}
.brand-points li {
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--text-soft);
  font-size: 12.5px;
}
.brand-points svg { color: var(--accent-bright); flex: none; }
.brand-foot {
  margin-top: 42px;
  color: var(--text-faint);
  font-size: 11px;
  letter-spacing: 0.02em;
}
.login-panel {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 44px 24px;
}
.login-card {
  width: min(400px, 100%);
  display: flex;
  flex-direction: column;
  gap: 15px;
  padding: 30px;
  border-radius: 18px;
  border: 1px solid var(--border);
  background: linear-gradient(180deg, var(--surface-a), var(--surface-b));
  box-shadow: 0 30px 70px var(--shadow-strong-color);
}
.login-head { margin-bottom: 4px; }
.login-head h2 { font-size: 22px; }
.login-head p { color: var(--muted); font-size: 12.5px; margin-top: 7px; line-height: 1.6; }
.password-wrap { position: relative; }
.password-wrap input { padding-right: 40px; }
.password-toggle {
  position: absolute;
  right: 6px;
  top: 50%;
  transform: translateY(-50%);
  width: 28px;
  height: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 0;
  background: transparent;
  color: var(--muted);
  border-radius: 6px;
}
.password-toggle:hover { color: var(--text); background: var(--hover-bg); }
.totp-field { padding: 12px; border-radius: 10px; background: var(--info-soft); border: 1px solid var(--info-border); }
.link-button {
  align-self: flex-start;
  margin-top: 2px;
  padding: 0;
  border: 0;
  background: transparent;
  color: var(--info-text);
  font-size: 11.5px;
}
.link-button:hover { text-decoration: underline; }
.login-submit { margin-top: 5px; }
.login-note {
  display: flex;
  gap: 7px;
  align-items: flex-start;
  color: var(--muted-2);
  font-size: 11px;
  line-height: 1.55;
  margin-top: 2px;
}
.login-note svg { margin-top: 1px; flex: none; }

@media (max-width: 900px) {
  .login-shell { grid-template-columns: 1fr; }
  .login-brand { display: none; }
  .login-panel { min-height: 100vh; }
}
</style>
