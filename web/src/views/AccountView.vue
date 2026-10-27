<script setup>
import { computed, onMounted, reactive, ref } from 'vue';
import AppIcon from '../components/AppIcon.vue';
import ModalDialog from '../components/ModalDialog.vue';
import QrCode from '../components/QrCode.vue';
import { api, ApiError } from '../lib/api.js';
import { authState, refreshSession } from '../lib/auth.js';
import { copyText, formatTime } from '../lib/format.js';
import { toast } from '../lib/toast.js';

const pwForm = reactive({
  currentPassword: '',
  newPassword: '',
  confirmPassword: '',
  totp: '',
  recoveryCode: '',
});
const pwBusy = ref(false);
const pwError = ref('');
const pwNotice = ref('');
const useRecoveryForPassword = ref(false);

const setupData = ref(null);
const setupBusy = ref(false);
const setupError = ref('');
const enableCode = ref('');
const enabling = ref(false);
const enableError = ref('');

const recoveryCodes = ref([]);
const recoveryOpen = ref(false);

const disableOpen = ref(false);
const disableForm = reactive({ password: '', totp: '', recoveryCode: '' });
const disabling = ref(false);
const disableError = ref('');
const useRecoveryForDisable = ref(false);

const totpEnabled = computed(() => Boolean(authState.user?.totpEnabled));
const secretDisplay = computed(() => {
  const secret = setupData.value?.secret || '';
  return secret.replace(/(.{4})/g, '$1 ').trim();
});

onMounted(async () => {
  try {
    await refreshSession();
  } catch {
    // The global handler will redirect on 401.
  }
});

async function submitPassword() {
  pwError.value = '';
  pwNotice.value = '';
  if (!pwForm.currentPassword || !pwForm.newPassword) {
    pwError.value = '请填写当前口令与新口令';
    return;
  }
  if (pwForm.newPassword.length < 12) {
    pwError.value = '新口令至少需要 12 个字符';
    return;
  }
  if (pwForm.newPassword !== pwForm.confirmPassword) {
    pwError.value = '两次输入的新口令不一致';
    return;
  }
  pwBusy.value = true;
  try {
    await api.post('/auth/password', {
      currentPassword: pwForm.currentPassword,
      newPassword: pwForm.newPassword,
      ...(useRecoveryForPassword.value ? { recoveryCode: pwForm.recoveryCode } : { totp: pwForm.totp }),
    });
    pwForm.currentPassword = '';
    pwForm.newPassword = '';
    pwForm.confirmPassword = '';
    pwForm.totp = '';
    pwForm.recoveryCode = '';
    pwNotice.value = '口令已更新，其他设备的会话已全部退出。';
    toast.success('口令已更新');
    await refreshSession();
  } catch (caught) {
    pwError.value = caught instanceof ApiError ? caught.message : '修改口令失败';
  } finally {
    pwBusy.value = false;
  }
}

async function beginTotp() {
  setupError.value = '';
  setupBusy.value = true;
  try {
    setupData.value = await api.post('/auth/totp/setup', {});
    enableCode.value = '';
  } catch (caught) {
    setupError.value = caught instanceof ApiError ? caught.message : '无法开始设置';
  } finally {
    setupBusy.value = false;
  }
}

function cancelSetup() {
  setupData.value = null;
  enableCode.value = '';
  enableError.value = '';
}

async function enableTotp() {
  enableError.value = '';
  if (!/^\d{6}$/.test(enableCode.value.trim())) {
    enableError.value = '请输入 6 位验证码';
    return;
  }
  enabling.value = true;
  try {
    const data = await api.post('/auth/totp/enable', { code: enableCode.value.trim() });
    recoveryCodes.value = data.recoveryCodes || [];
    setupData.value = null;
    enableCode.value = '';
    recoveryOpen.value = true;
    toast.success('两步验证已启用');
    await refreshSession();
  } catch (caught) {
    enableError.value = caught instanceof ApiError ? caught.message : '启用失败';
  } finally {
    enabling.value = false;
  }
}

async function copySecret() {
  if (await copyText(setupData.value?.secret || '')) toast.success('密钥已复制');
  else toast.error('复制失败');
}

async function copyUri() {
  if (await copyText(setupData.value?.uri || '')) toast.success('otpauth URI 已复制');
  else toast.error('复制失败');
}

async function copyRecoveryCodes() {
  if (await copyText(recoveryCodes.value.join('\n'))) toast.success('恢复码已复制');
  else toast.error('复制失败');
}

function downloadRecoveryCodes() {
  const blob = new Blob([
    'Nginx Console 两步验证恢复码\n',
    `账号: ${authState.user?.username || ''}\n`,
    `生成时间: ${new Date().toISOString()}\n\n`,
    `${recoveryCodes.value.join('\n')}\n\n`,
    '每个恢复码只能使用一次，请离线保存在安全位置。\n',
  ], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'nginx-console-recovery-codes.txt';
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function disableTotp() {
  disableError.value = '';
  if (!disableForm.password) {
    disableError.value = '请输入当前口令';
    return;
  }
  disabling.value = true;
  try {
    await api.post('/auth/totp/disable', {
      password: disableForm.password,
      ...(useRecoveryForDisable.value ? { recoveryCode: disableForm.recoveryCode } : { totp: disableForm.totp }),
    });
    disableOpen.value = false;
    disableForm.password = '';
    disableForm.totp = '';
    disableForm.recoveryCode = '';
    toast.success('两步验证已关闭');
    await refreshSession();
  } catch (caught) {
    disableError.value = caught instanceof ApiError ? caught.message : '关闭失败';
  } finally {
    disabling.value = false;
  }
}
</script>

<template>
  <div>
    <div class="page-head">
      <div>
        <span class="eyebrow"><AppIcon name="shield" :size="12" /> ACCOUNT SECURITY</span>
        <h1 class="page-title">账户与安全</h1>
        <p class="page-sub">管理管理员口令与两步验证。修改口令会使其他设备上的会话立即失效。</p>
      </div>
    </div>

    <div class="account-grid">
      <div class="column">
        <section class="card">
          <div class="card-head">
            <span class="card-title"><AppIcon name="shield" :size="15" /> 账户信息</span>
            <span class="badge" :class="totpEnabled ? 'badge-ok' : 'badge-warn'">
              {{ totpEnabled ? '两步验证已启用' : '未启用两步验证' }}
            </span>
          </div>
          <div class="card-body">
            <dl class="detail-list">
              <div><dt>用户名</dt><dd>{{ authState.user?.username || '—' }}</dd></div>
              <div><dt>账户 ID</dt><dd class="mono break">{{ authState.user?.id || '—' }}</dd></div>
              <div><dt>最近登录</dt><dd>{{ formatTime(authState.user?.lastLoginAt) }}</dd></div>
              <div><dt>创建时间</dt><dd>{{ formatTime(authState.user?.createdAt) }}</dd></div>
              <div><dt>当前会话到期</dt><dd>{{ formatTime(authState.session?.absoluteExpiresAt) }}</dd></div>
              <div v-if="totpEnabled"><dt>剩余恢复码</dt><dd>{{ authState.user?.recoveryCodesRemaining ?? 0 }} 个</dd></div>
            </dl>
            <div class="alert" :class="totpEnabled ? 'alert-ok' : 'alert-warn'" style="margin-top: 14px">
              <AppIcon :name="totpEnabled ? 'check' : 'alert'" :size="15" />
              <div v-if="totpEnabled">两步验证已启用。请确认恢复码已离线保存，且验证器时间同步正常。</div>
              <div v-else>强烈建议启用两步验证。仅口令登录一旦泄露，攻击者可完全控制所有 Agent。</div>
            </div>
          </div>
        </section>

        <section class="card">
          <div class="card-head">
            <span class="card-title"><AppIcon name="lock" :size="15" /> 修改口令</span>
          </div>
          <div class="card-body">
            <form @submit.prevent="submitPassword">
              <div class="field">
                <label for="current-password">当前口令</label>
                <input id="current-password" v-model="pwForm.currentPassword" type="password" autocomplete="current-password" maxlength="1024" />
              </div>
              <div class="field">
                <label for="new-password">新口令</label>
                <input id="new-password" v-model="pwForm.newPassword" type="password" autocomplete="new-password" maxlength="1024" />
                <span class="hint">至少 12 个字符，建议使用随机生成的 16 位以上口令。</span>
              </div>
              <div class="field">
                <label for="confirm-password">确认新口令</label>
                <input id="confirm-password" v-model="pwForm.confirmPassword" type="password" autocomplete="new-password" maxlength="1024" />
              </div>

              <template v-if="totpEnabled">
                <div class="divider" />
                <div class="field">
                  <label :for="useRecoveryForPassword ? 'pw-recovery' : 'pw-totp'">
                    {{ useRecoveryForPassword ? '恢复码' : '两步验证码' }}
                  </label>
                  <input
                    v-if="!useRecoveryForPassword"
                    id="pw-totp"
                    v-model="pwForm.totp"
                    type="text"
                    inputmode="numeric"
                    maxlength="6"
                    autocomplete="one-time-code"
                    placeholder="6 位数字"
                  />
                  <input
                    v-else
                    id="pw-recovery"
                    v-model="pwForm.recoveryCode"
                    type="text"
                    maxlength="24"
                    autocomplete="one-time-code"
                    placeholder="XXXXX-XXXXX"
                  />
                  <button class="link-button" type="button" @click="useRecoveryForPassword = !useRecoveryForPassword; pwForm.totp = ''; pwForm.recoveryCode = ''">
                    {{ useRecoveryForPassword ? '使用验证器验证码' : '使用一次性恢复码' }}
                  </button>
                </div>
              </template>

              <div v-if="pwError" class="alert alert-danger mt-16">
                <AppIcon name="alert" :size="15" />
                <div>{{ pwError }}</div>
              </div>
              <div v-if="pwNotice" class="alert alert-ok mt-16">
                <AppIcon name="check" :size="15" />
                <div>{{ pwNotice }}</div>
              </div>

              <button class="btn btn-primary mt-16" type="submit" :disabled="pwBusy">
                <span v-if="pwBusy" class="spinner" />
                <AppIcon v-else name="save" :size="14" />
                {{ pwBusy ? '更新中…' : '更新口令' }}
              </button>
            </form>
          </div>
        </section>
      </div>

      <div class="column">
        <section class="card">
          <div class="card-head">
            <span class="card-title"><AppIcon name="lock" :size="15" /> 两步验证（TOTP）</span>
            <span class="badge" :class="totpEnabled ? 'badge-ok' : ''">{{ totpEnabled ? '已启用' : '未启用' }}</span>
          </div>
          <div class="card-body">
            <template v-if="!totpEnabled">
              <p class="section-text">
                启用后登录需要使用验证器（Google Authenticator、1Password、Microsoft Authenticator 等）生成的 6 位验证码。
              </p>

              <div v-if="!setupData" class="totp-start">
                <button class="btn btn-primary" type="button" :disabled="setupBusy" @click="beginTotp">
                  <span v-if="setupBusy" class="spinner" />
                  <AppIcon v-else name="lock" :size="14" />
                  {{ setupBusy ? '生成中…' : '开始设置' }}
                </button>
                <p class="small muted">密钥只在设置期间显示，启用后仅保存加密副本。</p>
              </div>

              <div v-else class="totp-setup">
                <div class="alert alert-warn">
                  <AppIcon name="alert" :size="15" />
                  <div>请在 {{ Math.ceil((setupData.expiresInSeconds || 600) / 60) }} 分钟内完成验证，否则设置过期。</div>
                </div>

                <div class="qr-box">
                  <QrCode :value="setupData.uri" :size="168" />
                  <div class="qr-text">
                    <strong>用验证器扫描二维码</strong>
                    <p class="small muted">
                      Google Authenticator、1Password、Microsoft Authenticator 等扫码即可自动添加。
                      无法扫码时，可在下方手动输入密钥。
                    </p>
                  </div>
                </div>

                <div class="secret-box">
                  <span class="small muted">密钥（手动输入到验证器）</span>
                  <span class="secret mono">{{ secretDisplay }}</span>
                  <button class="btn btn-sm" type="button" @click="copySecret">
                    <AppIcon name="copy" :size="12" />
                    复制密钥
                  </button>
                </div>

                <div class="uri-box">
                  <span class="small muted">otpauth URI</span>
                  <span class="mono uri">{{ setupData.uri }}</span>
                  <button class="btn btn-sm" type="button" @click="copyUri">
                    <AppIcon name="copy" :size="12" />
                    复制 URI
                  </button>
                </div>

                <div class="field">
                  <label for="enable-code">验证器当前验证码</label>
                  <input
                    id="enable-code"
                    v-model="enableCode"
                    type="text"
                    inputmode="numeric"
                    maxlength="6"
                    autocomplete="one-time-code"
                    placeholder="6 位数字"
                    @keydown.enter.prevent="enableTotp"
                  />
                </div>
                <div v-if="enableError" class="alert alert-danger mt-16">
                  <AppIcon name="alert" :size="15" />
                  <div>{{ enableError }}</div>
                </div>
                <div class="row mt-16">
                  <button class="btn btn-primary" type="button" :disabled="enabling" @click="enableTotp">
                    <span v-if="enabling" class="spinner" />
                    {{ enabling ? '验证中…' : '验证并启用' }}
                  </button>
                  <button class="btn btn-ghost" type="button" :disabled="enabling" @click="cancelSetup">取消</button>
                </div>
              </div>

              <div v-if="setupError" class="alert alert-danger mt-16">
                <AppIcon name="alert" :size="15" />
                <div>{{ setupError }}</div>
              </div>
            </template>

            <template v-else>
              <p class="section-text">两步验证已启用。每个恢复码只能使用一次，使用后即失效。</p>
              <dl class="detail-list compact">
                <div><dt>剩余恢复码</dt><dd>{{ authState.user?.recoveryCodesRemaining ?? 0 }} / 10</dd></div>
                <div><dt>验证窗口</dt><dd>30 秒 · ±1 个周期</dd></div>
              </dl>
              <div class="alert alert-warn mt-16">
                <AppIcon name="alert" :size="15" />
                <div>如果验证器丢失，请使用恢复码登录后在下方关闭并重新设置。</div>
              </div>
              <button class="btn btn-danger mt-16" type="button" @click="disableOpen = true">
                <AppIcon name="x" :size="14" />
                关闭两步验证
              </button>
            </template>
          </div>
        </section>

        <section class="card">
          <div class="card-head">
            <span class="card-title"><AppIcon name="info" :size="15" /> 安全机制</span>
          </div>
          <div class="card-body">
            <ul class="security-list">
              <li><AppIcon name="check" :size="14" /> 口令使用 scrypt（N=32768）哈希，不存储明文。</li>
              <li><AppIcon name="check" :size="14" /> 会话令牌仅存 SHA-256，Cookie 为 HttpOnly + SameSite=Strict。</li>
              <li><AppIcon name="check" :size="14" /> 所有写请求需要 CSRF Token 与 Origin 校验。</li>
              <li><AppIcon name="check" :size="14" /> 连续失败会锁定账号，登录接口双层限速。</li>
              <li><AppIcon name="check" :size="14" /> Agent 消息使用 Ed25519 双向签名与重放防护。</li>
              <li><AppIcon name="check" :size="14" /> 审计日志脱敏，文件内容、口令、私钥不会记录。</li>
            </ul>
          </div>
        </section>
      </div>
    </div>

    <ModalDialog :open="recoveryOpen" title="请保存恢复码" subtitle="关闭后无法再次查看；每个恢复码只能使用一次。" width="560px" @close="recoveryOpen = false">
      <div class="alert alert-warn mb-16">
        <AppIcon name="alert" :size="16" />
        <div>请将恢复码离线保存（打印或密码管理器），不要截图发到聊天工具。</div>
      </div>
      <div class="recovery-grid">
        <span v-for="code in recoveryCodes" :key="code" class="recovery-code mono">{{ code }}</span>
      </div>
      <div class="row mt-16">
        <button class="btn" type="button" @click="copyRecoveryCodes">
          <AppIcon name="copy" :size="13" />
          复制全部
        </button>
        <button class="btn" type="button" @click="downloadRecoveryCodes">
          <AppIcon name="upload" :size="13" />
          下载文本
        </button>
      </div>
      <template #footer>
        <button class="btn btn-primary" type="button" @click="recoveryOpen = false">我已妥善保存</button>
      </template>
    </ModalDialog>

    <ModalDialog :open="disableOpen" title="关闭两步验证" subtitle="关闭后仅口令即可登录，请确认风险。" width="460px" :busy="disabling" @close="disableOpen = false">
      <div class="field">
        <label for="disable-password">当前口令</label>
        <input id="disable-password" v-model="disableForm.password" type="password" autocomplete="current-password" maxlength="1024" autofocus />
      </div>
      <div class="field">
        <label :for="useRecoveryForDisable ? 'disable-recovery' : 'disable-totp'">
          {{ useRecoveryForDisable ? '恢复码' : '两步验证码' }}
        </label>
        <input
          v-if="!useRecoveryForDisable"
          id="disable-totp"
          v-model="disableForm.totp"
          type="text"
          inputmode="numeric"
          maxlength="6"
          autocomplete="one-time-code"
          placeholder="6 位数字"
        />
        <input
          v-else
          id="disable-recovery"
          v-model="disableForm.recoveryCode"
          type="text"
          maxlength="24"
          autocomplete="one-time-code"
          placeholder="XXXXX-XXXXX"
        />
        <button class="link-button" type="button" @click="useRecoveryForDisable = !useRecoveryForDisable; disableForm.totp = ''; disableForm.recoveryCode = ''">
          {{ useRecoveryForDisable ? '使用验证器验证码' : '使用一次性恢复码' }}
        </button>
      </div>
      <div v-if="disableError" class="alert alert-danger mt-16">
        <AppIcon name="alert" :size="15" />
        <div>{{ disableError }}</div>
      </div>
      <template #footer>
        <button class="btn" type="button" :disabled="disabling" @click="disableOpen = false">取消</button>
        <button class="btn btn-danger" type="button" :disabled="disabling" @click="disableTotp">
          {{ disabling ? '关闭中…' : '确认关闭' }}
        </button>
      </template>
    </ModalDialog>
  </div>
</template>

<style scoped>
.account-grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 14px; align-items: start; }
.column { display: flex; flex-direction: column; gap: 14px; }
.detail-list { display: flex; flex-direction: column; margin: 0; }
.detail-list > div { display: flex; justify-content: space-between; gap: 16px; padding: 8px 0; border-bottom: 1px solid var(--border); }
.detail-list > div:last-child { border-bottom: 0; }
.detail-list dt { color: var(--muted); font-size: 11.5px; flex: none; }
.detail-list dd { margin: 0; font-size: 11.5px; color: var(--text-soft); text-align: right; word-break: break-all; }
.detail-list.compact > div { padding: 6px 0; }
.break { word-break: break-all; }
.link-button { align-self: flex-start; margin-top: 3px; padding: 0; border: 0; background: transparent; color: var(--info-text); font-size: 11.5px; }
.link-button:hover { text-decoration: underline; }
.section-text { color: var(--muted); font-size: 12px; line-height: 1.65; }
.totp-start { display: flex; flex-direction: column; gap: 9px; margin-top: 14px; }
.totp-setup { display: flex; flex-direction: column; gap: 12px; margin-top: 14px; }
.secret-box, .uri-box {
  display: flex;
  flex-direction: column;
  gap: 5px;
  padding: 11px 12px;
  border-radius: 9px;
  border: 1px solid var(--border);
  background: var(--inset-bg);
}
.qr-box {
  display: flex;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
  padding: 12px;
  border-radius: 10px;
  border: 1px solid var(--border);
  background: var(--inset-bg);
}
.qr-text { display: flex; flex-direction: column; gap: 5px; flex: 1; min-width: 150px; }
.qr-text strong { font-size: 12.5px; color: var(--text-soft); }
.qr-text p { line-height: 1.6; }
.secret { font-size: 15px; letter-spacing: 0.08em; color: var(--ok-text); word-break: break-all; }
.uri { font-size: 10px; color: var(--text-dim); word-break: break-all; }
.secret-box .btn, .uri-box .btn { align-self: flex-start; margin-top: 3px; }
.security-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 9px; }
.security-list li { display: flex; gap: 8px; align-items: flex-start; color: var(--muted); font-size: 11.5px; line-height: 1.55; }
.security-list svg { color: var(--accent-bright); flex: none; margin-top: 1px; }
.recovery-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 7px; }
.recovery-code {
  padding: 8px 10px;
  border-radius: 7px;
  border: 1px solid var(--border);
  background: var(--inset-bg);
  font-size: 12.5px;
  letter-spacing: 0.08em;
  color: var(--text-soft);
  text-align: center;
}
@media (max-width: 1000px) {
  .account-grid { grid-template-columns: 1fr; }
}
</style>
