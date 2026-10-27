<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue';
import AppIcon from './AppIcon.vue';
import { api, ApiError } from '../lib/api.js';
import { copyText, daysText, expiryTone, formatBytes, formatTime } from '../lib/format.js';
import { toast } from '../lib/toast.js';

const props = defineProps({
  serverId: { type: String, required: true },
  info: { type: Object, default: null },
});

const certDir = computed(() => props.info?.certDir || 'ssl');
const workspace = computed(() => props.info?.workspace || '');

const loading = ref(false);
const listError = ref('');
const certificates = ref([]);
const certErrors = ref([]);
const selected = ref(null);

const form = reactive({ name: '', certPem: '', chainPem: '', keyPem: '' });
const layout = ref('directory');
const uploading = ref(false);
const uploadError = ref('');
const uploadResult = ref(null);
const showPaste = ref(false);
const showKey = ref(false);
const certInput = ref(null);
const chainInput = ref(null);
const keyInput = ref(null);
const archiveInput = ref(null);
const archiveFile = ref(null);
const archiveUploading = ref(false);
const archiveError = ref('');

const ARCHIVE_LIMIT = 512 * 1024;
const CERT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

const snippet = computed(() => {
  const result = uploadResult.value;
  const name = result?.name || form.name || '<name>';
  const mode = result?.layout || layout.value;
  if (mode === 'directory') {
    return [
      `ssl_certificate     ${certDir.value}/${name}/fullchain.pem;`,
      `ssl_certificate_key ${certDir.value}/${name}/privkey.pem;`,
    ].join('\n');
  }
  return [
    `ssl_certificate     ${certDir.value}/${name}.crt;`,
    `ssl_certificate_key ${certDir.value}/${name}.key;`,
    `# 链证书（如服务器配置使用 fullchain，请合并或单独引用）`,
    `# ssl_certificate ${certDir.value}/${name}.chain.pem;`,
  ].join('\n');
});

const resultTone = computed(() => {
  if (!uploadResult.value) return 'muted';
  return expiryTone(uploadResult.value.certificate?.daysRemaining);
});

onMounted(load);

watch(() => props.serverId, () => {
  resetForm();
  load();
});

watch(() => props.info?.workspace, (next, previous) => {
  if (next && next !== previous) load();
});

async function load() {
  if (!workspace.value) {
    certificates.value = [];
    return;
  }
  loading.value = true;
  listError.value = '';
  try {
    const data = await api.get(`/servers/${props.serverId}/certs`);
    certificates.value = data.certificates || [];
    certErrors.value = data.errors || [];
  } catch (caught) {
    listError.value = caught instanceof ApiError ? caught.message : '读取证书失败';
  } finally {
    loading.value = false;
  }
}

function resetForm() {
  form.name = '';
  form.certPem = '';
  form.chainPem = '';
  form.keyPem = '';
  layout.value = 'directory';
  uploadError.value = '';
  uploadResult.value = null;
  showPaste.value = false;
  showKey.value = false;
  archiveFile.value = null;
  archiveUploading.value = false;
  archiveError.value = '';
  if (certInput.value) certInput.value.value = '';
  if (chainInput.value) chainInput.value.value = '';
  if (keyInput.value) keyInput.value.value = '';
  if (archiveInput.value) archiveInput.value.value = '';
}

async function readField(file, field, label) {
  if (!file) return;
  if (file.size > 256 * 1024) {
    uploadError.value = `${label}超过 256 KiB 限制`;
    toast.error(uploadError.value);
    return;
  }
  try {
    form[field] = await file.text();
    uploadError.value = '';
  } catch {
    uploadError.value = `无法读取${label}`;
  }
}

async function onCertFile(event) {
  await readField(event.target.files?.[0], 'certPem', '证书文件');
}

async function onChainFile(event) {
  await readField(event.target.files?.[0], 'chainPem', '证书链文件');
}

async function onKeyFile(event) {
  await readField(event.target.files?.[0], 'keyPem', '私钥文件');
}

function archiveBaseName(filename) {
  return String(filename || '').replace(/\.(tar\.gz|tgz|tar|zip)$/i, '');
}

function onArchiveFile(event) {
  const file = event.target.files?.[0] || null;
  archiveError.value = '';
  uploadResult.value = null;
  archiveFile.value = null;
  if (!file) return;
  if (file.size > ARCHIVE_LIMIT) {
    archiveError.value = '压缩包超过 512 KiB 限制';
    toast.error(archiveError.value);
    if (archiveInput.value) archiveInput.value.value = '';
    return;
  }
  archiveFile.value = file;
  const base = archiveBaseName(file.name);
  if (!form.name.trim() && CERT_NAME_RE.test(base)) form.name = base;
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

function validName(errorRef = uploadError) {
  const name = form.name.trim();
  if (!name) {
    errorRef.value = '请输入证书名称';
    return null;
  }
  if (!CERT_NAME_RE.test(name)) {
    errorRef.value = '证书名称仅允许字母、数字、点、下划线和短横线';
    return null;
  }
  return name;
}

async function submitArchive() {
  archiveError.value = '';
  uploadError.value = '';
  uploadResult.value = null;
  const name = validName(archiveError);
  if (!name) return;
  if (!archiveFile.value) {
    archiveError.value = '请选择要上传的压缩包';
    return;
  }
  archiveUploading.value = true;
  try {
    const archiveBase64 = arrayBufferToBase64(await archiveFile.value.arrayBuffer());
    const data = await api.post(`/servers/${props.serverId}/certs/archive`, {
      name,
      filename: archiveFile.value.name,
      archiveBase64,
      layout: layout.value,
    });
    uploadResult.value = data;
    toast.success('压缩包已解析，证书已通过校验并写入');
    archiveFile.value = null;
    if (archiveInput.value) archiveInput.value.value = '';
    await load();
  } catch (caught) {
    if (caught instanceof ApiError) {
      archiveError.value = caught.message;
      if (caught.details?.files?.length) {
        archiveError.value += `\n候选文件：${caught.details.files.join('、')}`;
      }
      if (caught.details?.output) archiveError.value += `\n${caught.details.output}`;
    } else {
      archiveError.value = '压缩包上传失败';
    }
    toast.error(caught.message || '压缩包上传失败');
  } finally {
    archiveUploading.value = false;
  }
}

function pickExisting(cert) {
  form.name = cert.directory ? cert.name : cert.name.replace(/\.(crt|cer|pem)$/i, '').replace(/\.chain$/i, '');
  layout.value = cert.directory ? 'directory' : 'flat';
  selected.value = cert.file;
  uploadError.value = '';
}

function subjectLabel(subject) {
  if (!subject) return '—';
  const lines = String(subject).split('\n');
  const cn = lines.find((line) => line.trim().startsWith('CN='));
  return cn ? cn.trim() : lines[0];
}

function sanPreview(san) {
  if (!Array.isArray(san) || san.length === 0) return [];
  return san.filter((item) => item.type === 'DNS').slice(0, 3).map((item) => item.value);
}

async function submitUpload() {
  uploadError.value = '';
  uploadResult.value = null;
  const name = validName();
  if (!name) return;
  if (!form.certPem.trim() || !form.keyPem.trim()) {
    uploadError.value = '证书与私钥都是必填项';
    return;
  }
  uploading.value = true;
  try {
    const data = await api.post(`/servers/${props.serverId}/certs`, {
      name,
      certPem: form.certPem,
      chainPem: form.chainPem,
      keyPem: form.keyPem,
      layout: layout.value,
    });
    uploadResult.value = data;
    form.keyPem = '';
    if (keyInput.value) keyInput.value.value = '';
    toast.success('证书已更新并通过校验');
    await load();
  } catch (caught) {
    if (caught instanceof ApiError) {
      uploadError.value = caught.message;
      if (caught.details?.output) uploadError.value += `\n${caught.details.output}`;
    } else {
      uploadError.value = '证书上传失败';
    }
    toast.error(caught.message || '证书上传失败');
  } finally {
    uploading.value = false;
  }
}

async function copy(value) {
  if (await copyText(value)) toast.success('已复制');
  else toast.error('复制失败');
}

function fileSize(text) {
  return formatBytes(new Blob([text || '']).size);
}
</script>

<template>
  <div class="cert-panel">
    <div v-if="!workspace" class="card empty-state-card">
      <span class="empty-icon"><AppIcon name="key" :size="30" /></span>
      <h3>尚未选择工作目录</h3>
      <p>证书会写入工作目录下的 <code class="mono">{{ certDir }}</code> 目录，请先在配置页选择工作目录。</p>
    </div>

    <template v-else>
      <div class="cert-grid">
        <section class="card upload-card">
          <div class="card-head">
            <span class="card-title"><AppIcon name="upload" :size="15" /> 上传 / 替换证书</span>
            <span class="badge">{{ certDir }}/</span>
          </div>
          <div class="card-body">
            <div class="security-note">
              <AppIcon name="shield" :size="15" />
              <span>私钥只写不读，文件权限 0600；写入前备份，nginx -t 失败自动回滚。</span>
            </div>

            <div class="field">
              <label>存放方式</label>
              <div class="layout-switch">
                <button
                  type="button"
                  :class="{ active: layout === 'directory' }"
                  @click="layout = 'directory'"
                >
                  目录（面板风格）
                </button>
                <button
                  type="button"
                  :class="{ active: layout === 'flat' }"
                  @click="layout = 'flat'"
                >
                  单文件
                </button>
              </div>
              <span class="hint">
                <template v-if="layout === 'directory'">
                  写入 {{ certDir }}/{{ form.name || 'example.com' }}/fullchain.pem 与 privkey.pem，可直接替换现有子目录证书
                </template>
                <template v-else>
                  写入 {{ certDir }}/{{ form.name || 'example.com' }}.crt / .chain.pem / .key
                </template>
              </span>
            </div>

            <div class="field">
              <label for="cert-name">证书名称</label>
              <input
                id="cert-name"
                v-model="form.name"
                type="text"
                maxlength="64"
                spellcheck="false"
                placeholder="example.com"
              />
              <span class="hint">
                <template v-if="layout === 'directory'">
                  填现有子目录名（如 nginx.xiaofei.icu_nginx），即可覆盖其中的 fullchain.pem 与 privkey.pem。
                </template>
                <template v-else>
                  例如 example.com，将生成 example.com.crt / .chain.pem / .key。
                </template>
              </span>
            </div>

            <div class="archive-box">
              <div class="file-field-head">
                <label>上传证书压缩包</label>
                <span class="small muted">ZIP / TAR / TAR.GZ / TGZ（TAR 需 USTAR）</span>
              </div>
              <input
                ref="archiveInput"
                type="file"
                accept=".zip,.tar,.tar.gz,.tgz,application/zip,application/x-tar,application/gzip"
                @change="onArchiveFile"
              />
              <span class="hint">
                自动提取叶证书、可选链证书与私钥；其他文件忽略。最大 512 KiB，不支持加密包、符号链接或带口令私钥。
              </span>
              <div v-if="archiveFile" class="archive-selected">
                <span class="mono truncate" :title="archiveFile.name">{{ archiveFile.name }}</span>
                <span class="small muted">{{ formatBytes(archiveFile.size) }}</span>
              </div>
              <p v-if="archiveError" class="inline-error">{{ archiveError }}</p>
              <button
                class="btn btn-primary btn-block"
                type="button"
                :disabled="archiveUploading || uploading || !archiveFile"
                @click="submitArchive"
              >
                <span v-if="archiveUploading" class="spinner" />
                <AppIcon v-else name="archive" :size="14" />
                {{ archiveUploading ? '解包、校验并写入…' : '解析压缩包并替换' }}
              </button>
            </div>

            <div class="section-divider"><span>或分别上传证书与私钥</span></div>

            <div class="file-field">
              <div class="file-field-head">
                <label>证书文件（叶证书）</label>
                <span class="small muted">{{ form.certPem ? fileSize(form.certPem) : 'PEM 格式' }}</span>
              </div>
              <input ref="certInput" type="file" accept=".crt,.cer,.pem" @change="onCertFile" />
            </div>

            <div class="file-field">
              <div class="file-field-head">
                <label>证书链（可选）</label>
                <span class="small muted">{{ form.chainPem ? fileSize(form.chainPem) : '中间证书，按顺序' }}</span>
              </div>
              <input ref="chainInput" type="file" accept=".crt,.cer,.pem" @change="onChainFile" />
            </div>

            <div class="file-field">
              <div class="file-field-head">
                <label>私钥文件</label>
                <span class="small muted">{{ form.keyPem ? fileSize(form.keyPem) : '不得带口令' }}</span>
              </div>
              <input ref="keyInput" type="file" accept=".key,.pem" @change="onKeyFile" />
            </div>

            <button class="link-button" type="button" @click="showPaste = !showPaste">
              {{ showPaste ? '收起手动粘贴' : '或手动粘贴 PEM 内容' }}
            </button>

            <div v-if="showPaste" class="paste-area">
              <div class="field">
                <label for="cert-pem">证书 PEM</label>
                <textarea id="cert-pem" v-model="form.certPem" class="mono" rows="5" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----" />
              </div>
              <div class="field">
                <label for="chain-pem">证书链 PEM（可选）</label>
                <textarea id="chain-pem" v-model="form.chainPem" class="mono" rows="4" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----" />
              </div>
              <div class="field">
                <label for="key-pem">私钥 PEM</label>
                <textarea id="key-pem" v-model="form.keyPem" class="mono" rows="5" spellcheck="false" placeholder="-----BEGIN PRIVATE KEY-----" />
              </div>
            </div>

            <div v-if="uploadError" class="alert alert-danger mt-16 upload-alert">
              <AppIcon name="alert" :size="15" />
              <div class="pre-line">{{ uploadError }}</div>
            </div>

            <button
              class="btn btn-primary btn-block mt-16"
              type="button"
              :disabled="uploading || archiveUploading"
              @click="submitUpload"
            >
              <span v-if="uploading" class="spinner" />
              <AppIcon v-else name="upload" :size="14" />
              {{ uploading ? '校验并写入…' : '上传并校验' }}
            </button>

            <div v-if="uploadResult" class="upload-result">
              <div class="result-head">
                <span class="card-title"><AppIcon name="check" :size="14" /> 已写入证书</span>
                <span class="badge" :class="`badge-${resultTone === 'danger' ? 'danger' : resultTone === 'warn' ? 'warn' : 'ok'}`">
                  {{ daysText(uploadResult.certificate?.daysRemaining) }}
                </span>
              </div>
              <dl class="result-meta">
                <div><dt>Subject</dt><dd>{{ subjectLabel(uploadResult.certificate?.subject) }}</dd></div>
                <div><dt>有效期至</dt><dd>{{ formatTime(uploadResult.certificate?.validTo) }}</dd></div>
                <div><dt>密钥</dt><dd>{{ uploadResult.certificate?.key?.type?.toUpperCase() }} {{ uploadResult.certificate?.key?.bits || uploadResult.certificate?.key?.curve }}</dd></div>
                <div><dt>链证书</dt><dd>{{ uploadResult.certificate?.chainCount || 0 }} 张</dd></div>
              </dl>
              <div v-if="uploadResult.archive" class="archive-result">
                <span class="file-chip">{{ uploadResult.archive.format.toUpperCase() }}</span>
                <span class="file-chip">证书 {{ uploadResult.archive.files.certificate }}</span>
                <span class="file-chip">私钥 {{ uploadResult.archive.files.privateKey }}</span>
                <span v-for="path in uploadResult.archive.files.chain" :key="`chain-${path}`" class="file-chip">
                  链 {{ path }}
                </span>
                <span v-if="uploadResult.archive.ignoredEntries?.length" class="small muted">
                  已忽略 {{ uploadResult.archive.ignoredEntries.length }} 个无关文件
                </span>
              </div>
              <div class="snippet-head">
                <span>在 Nginx 配置中引用</span>
                <button class="icon-button" type="button" aria-label="复制引用片段" @click="copy(snippet)">
                  <AppIcon name="copy" :size="13" />
                </button>
              </div>
              <pre class="code-block snippet">{{ snippet }}</pre>
              <div class="files-line">
                <span v-for="file in uploadResult.files" :key="file.path" class="file-chip mono">{{ file.path }}</span>
              </div>
            </div>
          </div>
        </section>

        <section class="card list-card">
          <div class="card-head">
            <span class="card-title"><AppIcon name="key" :size="15" /> 已管理证书</span>
            <button class="icon-button" type="button" aria-label="刷新证书" :disabled="loading" @click="load">
              <span v-if="loading" class="spinner" />
              <AppIcon v-else name="refresh" :size="14" />
            </button>
          </div>
          <div class="card-body cert-list-body">
            <div v-if="loading" class="loading-row">
              <span class="spinner" />
              正在扫描证书…
            </div>
            <div v-else-if="listError" class="alert alert-danger">
              <AppIcon name="alert" :size="15" />
              <div>{{ listError }}</div>
            </div>
            <div v-else-if="certificates.length === 0" class="empty">
              <span class="empty-icon"><AppIcon name="key" :size="28" /></span>
              工作目录 {{ certDir }}/ 中暂未发现证书（支持证书文件，以及域名子目录内的 fullchain.pem / cert.pem）
            </div>
            <div v-else class="cert-items">
              <article
                v-for="cert in certificates"
                :key="cert.file"
                class="cert-item"
                :class="{ selected: selected === cert.file }"
              >
                <div class="cert-item-head">
                  <span class="cert-name mono truncate" :title="cert.file">{{ cert.name }}</span>
                  <span class="badge" :class="`badge-${expiryTone(cert.daysRemaining) === 'danger' ? 'danger' : expiryTone(cert.daysRemaining) === 'warn' ? 'warn' : 'ok'}`">
                    {{ daysText(cert.daysRemaining) }}
                  </span>
                </div>
                <div class="cert-subject" :title="cert.subject">{{ subjectLabel(cert.subject) }}</div>
                <div class="san-row">
                  <span v-for="name in sanPreview(cert.san)" :key="name" class="san-chip mono">{{ name }}</span>
                  <span v-if="cert.chainCount > 0" class="san-chip chain">链 {{ cert.chainCount }}</span>
                  <span v-if="cert.directory" class="san-chip chain" title="证书位于子目录中">目录</span>
                  <span
                    class="san-chip"
                    :class="cert.keyPresent ? 'chain' : 'missing'"
                    :title="cert.keyPresent ? '同目录内存在私钥文件' : '未找到配套私钥文件'"
                  >
                    {{ cert.keyPresent ? '含私钥' : '缺私钥' }}
                  </span>
                </div>
                <div class="cert-foot">
                  <span class="small muted">至 {{ formatTime(cert.validTo) }}</span>
                  <div class="cert-actions">
                    <button class="icon-button" type="button" aria-label="复制证书路径" @click="copy(cert.file)">
                      <AppIcon name="copy" :size="13" />
                    </button>
                    <button class="btn btn-sm btn-ghost" type="button" @click="pickExisting(cert)">
                      替换
                      <AppIcon name="chevronRight" :size="12" />
                    </button>
                  </div>
                </div>
              </article>
            </div>

            <div v-if="certErrors.length" class="cert-errors">
              <span class="small muted">扫描告警</span>
              <div v-for="item in certErrors.slice(0, 6)" :key="item.file" class="cert-error-row">
                <span class="mono">{{ item.file }}</span>
                <span>{{ item.error }}</span>
              </div>
            </div>
          </div>
        </section>
      </div>
    </template>
  </div>
</template>

<style scoped>
.cert-panel { display: flex; flex-direction: column; gap: 12px; }
.empty-state-card { padding: 46px 24px; display: flex; flex-direction: column; align-items: center; gap: 9px; text-align: center; }
.empty-state-card h3 { font-size: 15px; }
.empty-state-card p { color: var(--muted); font-size: 12.5px; }
.cert-grid { display: grid; grid-template-columns: minmax(0, 1.05fr) minmax(0, 0.95fr); gap: 14px; align-items: start; }
.upload-card .card-body { display: flex; flex-direction: column; gap: 13px; }
.security-note {
  display: flex;
  gap: 8px;
  align-items: flex-start;
  padding: 10px 12px;
  border-radius: 9px;
  border: 1px solid var(--accent-border);
  background: var(--accent-soft);
  color: var(--ok-text);
  font-size: 11px;
  line-height: 1.55;
}
.security-note svg { color: var(--accent-bright); flex: none; margin-top: 1px; }
.file-field { display: flex; flex-direction: column; gap: 6px; }
.layout-switch { display: flex; gap: 6px; }
.layout-switch button {
  flex: 1;
  padding: 7px 10px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: var(--inset-bg);
  color: var(--text-dim);
  font-size: 11.5px;
}
.layout-switch button.active {
  border-color: var(--accent-border);
  background: var(--accent-soft);
  color: var(--accent-bright);
}
.file-field-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.file-field-head label { font-size: 12px; font-weight: 600; color: var(--text-soft); }
.link-button { align-self: flex-start; padding: 0; border: 0; background: transparent; color: var(--info-text); font-size: 11.5px; }
.link-button:hover { text-decoration: underline; }
.paste-area { display: flex; flex-direction: column; gap: 10px; padding: 12px; border-radius: 10px; border: 1px solid var(--border); background: var(--inset-bg); }
.paste-area textarea { font-size: 10.5px; }
.archive-box {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 12px;
  border-radius: 10px;
  border: 1px solid var(--info-border);
  background: var(--info-soft);
}
.archive-box label { font-size: 12px; font-weight: 600; color: var(--text-soft); }
.archive-selected { display: flex; align-items: center; justify-content: space-between; gap: 8px; font-size: 10.5px; color: var(--text-soft); }
.inline-error { margin: 0; color: var(--danger-text); font-size: 11px; line-height: 1.5; white-space: pre-line; }
.section-divider { display: flex; align-items: center; gap: 10px; color: var(--muted); font-size: 10px; }
.section-divider::before, .section-divider::after { content: ''; flex: 1; height: 1px; background: var(--border); }
.archive-result { display: flex; flex-wrap: wrap; align-items: center; gap: 5px; margin-bottom: 12px; padding: 8px; border-radius: 8px; border: 1px solid var(--info-border); background: var(--info-soft); }
.upload-alert .pre-line { white-space: pre-wrap; }
.upload-result { padding: 12px; border-radius: 10px; border: 1px solid var(--border); background: var(--inset-bg); }
.result-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 10px; }
.result-meta { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin: 0 0 12px; }
.result-meta dt { color: var(--text-faint); font-size: 9.5px; margin-bottom: 2px; }
.result-meta dd { margin: 0; font-size: 11px; color: var(--text-soft); word-break: break-all; }
.snippet-head { display: flex; align-items: center; justify-content: space-between; color: var(--muted); font-size: 10.5px; margin-bottom: 5px; }
.snippet { font-size: 10.5px; }
.files-line { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 9px; }
.file-chip { font-size: 9.5px; color: var(--info-text); border: 1px solid var(--info-border); border-radius: 5px; padding: 2px 5px; }
.list-card .card-body { padding: 10px; }
.cert-items { display: flex; flex-direction: column; gap: 7px; max-height: 660px; overflow: auto; }
.cert-item {
  padding: 11px 12px;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--inset-bg);
}
.cert-item.selected { border-color: var(--accent-border); background: var(--accent-soft); }
.cert-item-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.cert-name { font-size: 11.5px; color: var(--text-soft); }
.cert-subject { margin-top: 5px; color: var(--text-dim); font-size: 11.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.san-row { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 7px; }
.san-chip { font-size: 9.5px; color: var(--ok-text); background: var(--accent-soft); border: 1px solid var(--accent-border); border-radius: 4px; padding: 1px 5px; }
.san-chip.chain { color: var(--info-text); background: var(--info-soft); border-color: var(--info-border); }
.san-chip.missing { color: var(--warn-text); background: var(--warn-soft); border-color: var(--warn-border); }
.cert-foot { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-top: 8px; padding-top: 7px; border-top: 1px solid var(--border); }
.cert-actions { display: flex; align-items: center; gap: 4px; }
.cert-errors { margin-top: 10px; padding: 9px; border-radius: 8px; border: 1px solid var(--warn-border); background: var(--warn-soft); }
.cert-error-row { display: flex; flex-direction: column; gap: 1px; margin-top: 6px; font-size: 10px; color: var(--warn-text); word-break: break-all; }

@media (max-width: 1100px) {
  .cert-grid { grid-template-columns: 1fr; }
}
</style>
