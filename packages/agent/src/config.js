import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { NcsError, publicKeyFingerprint, validateEd25519PublicKey } from '@ncs/shared';
import { atomicWriteFile, ensurePrivateDirectory } from '@ncs/core';

const MAX_CONFIG_BYTES = 64 * 1024;
const AGENT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function defaultConfigPath() {
  if (process.env.NCS_AGENT_CONFIG) return path.resolve(process.env.NCS_AGENT_CONFIG);
  if (process.platform === 'win32') {
    const base = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
    return path.join(base, 'nginx-console', 'agent.json');
  }
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    return '/etc/nginx-console/agent.json';
  }
  const xdg = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config');
  return path.join(xdg, 'nginx-console', 'agent.json');
}

export function keyPathForConfig(configPath) {
  return path.join(path.dirname(path.resolve(configPath)), 'agent-key.pem');
}

export function normalizeMainUrl(input, { allowInsecure = false } = {}) {
  if (typeof input !== 'string' || input.length > 512) {
    throw new NcsError('INVALID_MAIN_URL', '主服务器地址无效', 400);
  }
  let url;
  try {
    url = new URL(input);
  } catch {
    throw new NcsError('INVALID_MAIN_URL', '主服务器地址无效', 400);
  }
  if (url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) {
    throw new NcsError('INVALID_MAIN_URL', '主服务器地址只能是纯源地址，不能包含路径、参数或凭据', 400);
  }
  const isHttps = url.protocol === 'https:';
  if (!isHttps && !(allowInsecure && url.protocol === 'http:')) {
    throw new NcsError('INSECURE_MAIN_URL', '必须使用 HTTPS 连接主服务器（本地开发可显式使用 --insecure-http）', 400);
  }
  return url.origin;
}

export function websocketUrl(mainUrl, { allowInsecure = false } = {}) {
  const normalized = normalizeMainUrl(mainUrl, { allowInsecure });
  const url = new URL(normalized);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.pathname = '/agent/ws';
  return url.toString();
}

async function assertPrivateFile(filePath, label) {
  if (process.platform === 'win32') return;
  let stat;
  try {
    stat = await fs.stat(filePath);
  } catch {
    throw new NcsError('CONFIG_NOT_FOUND', `${label}不存在：${filePath}`, 500);
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new NcsError('INSECURE_PERMISSIONS', `${label}权限过宽，必须为 0600：${filePath}`, 500);
  }
}

export async function loadIdentity(configPath, { create = false } = {}) {
  const keyPath = keyPathForConfig(configPath);
  let pem;
  try {
    await assertPrivateFile(keyPath, 'Agent 私钥');
    pem = await fs.readFile(keyPath, 'utf8');
  } catch (error) {
    if (!create) throw error;
    if (error?.code !== 'CONFIG_NOT_FOUND' && !(await fileMissing(keyPath))) throw error;
    await ensurePrivateDirectory(path.dirname(keyPath), 0o700);
    const pair = crypto.generateKeyPairSync('ed25519');
    pem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    await atomicWriteFile(keyPath, pem, { mode: 0o600 });
    pem = await fs.readFile(keyPath, 'utf8');
  }
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(pem);
  } catch {
    throw new NcsError('INVALID_AGENT_KEY', 'Agent 私钥无法解析', 500);
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw new NcsError('INVALID_AGENT_KEY', 'Agent 私钥必须是 Ed25519', 500);
  }
  const publicKeyPem = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString();
  return {
    privateKey,
    privateKeyPem: pem,
    publicKeyPem,
    fingerprint: publicKeyFingerprint(publicKeyPem),
    keyPath,
  };
}

async function fileMissing(filePath) {
  try {
    await fs.stat(filePath);
    return false;
  } catch (error) {
    return error?.code === 'ENOENT';
  }
}

function optionalString(value, name, maxLength = 512) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) {
    throw new NcsError('INVALID_AGENT_CONFIG', `Agent 配置字段 ${name} 无效`, 500);
  }
  return value;
}

export async function loadAgentConfig(configPath) {
  const resolvedPath = path.resolve(configPath);
  await assertPrivateFile(resolvedPath, 'Agent 配置文件');
  let raw;
  try {
    const stat = await fs.stat(resolvedPath);
    if (stat.size > MAX_CONFIG_BYTES) throw new Error('too large');
    raw = JSON.parse(await fs.readFile(resolvedPath, 'utf8'));
  } catch {
    throw new NcsError('INVALID_AGENT_CONFIG', 'Agent 配置文件无法读取或格式错误', 500);
  }
  if (!raw || typeof raw !== 'object' || raw.version !== 1) {
    throw new NcsError('INVALID_AGENT_CONFIG', 'Agent 配置文件版本无效', 500);
  }
  if (!AGENT_ID_RE.test(raw.agentId || '')) {
    throw new NcsError('INVALID_AGENT_CONFIG', 'agentId 无效', 500);
  }
  const allowInsecureHttp = Boolean(raw.allowInsecureHttp) && process.env.NODE_ENV !== 'production';
  const mainUrl = normalizeMainUrl(raw.mainUrl, { allowInsecure: allowInsecureHttp });
  validateEd25519PublicKey(raw.mainPublicKey);
  if (!Array.isArray(raw.allowedRoots) || raw.allowedRoots.length === 0 || raw.allowedRoots.length > 20) {
    throw new NcsError('INVALID_AGENT_CONFIG', 'allowedRoots 配置无效', 500);
  }
  for (const root of raw.allowedRoots) {
    if (typeof root !== 'string' || !path.isAbsolute(root)) {
      throw new NcsError('INVALID_AGENT_CONFIG', 'allowedRoots 必须都是绝对路径', 500);
    }
  }
  const workspace = optionalString(raw.workspace, 'workspace', 1024);
  if (workspace && !path.isAbsolute(workspace)) {
    throw new NcsError('INVALID_AGENT_CONFIG', 'workspace 必须是绝对路径', 500);
  }
  const nginxBin = path.isAbsolute(raw.nginxBin || '') ? raw.nginxBin : '/usr/sbin/nginx';
  const nginxPrefix = raw.nginxPrefix ? optionalString(raw.nginxPrefix, 'nginxPrefix', 1024) : null;
  if (nginxPrefix && !path.isAbsolute(nginxPrefix)) {
    throw new NcsError('INVALID_AGENT_CONFIG', 'nginxPrefix 必须是绝对路径', 500);
  }
  return {
    version: 1,
    agentId: raw.agentId,
    agentName: optionalString(raw.agentName, 'agentName', 128) || raw.agentId,
    mainUrl,
    mainPublicKey: raw.mainPublicKey,
    mainFingerprint: publicKeyFingerprint(raw.mainPublicKey),
    allowInsecureHttp,
    allowedRoots: [...new Set(raw.allowedRoots)],
    workspace,
    nginxBin,
    nginxPrefix,
    controlMode: raw.controlMode === 'systemd' ? 'systemd' : 'signal',
    systemdUnit: optionalString(raw.systemdUnit, 'systemdUnit', 128) || 'nginx',
    useSudo: Boolean(raw.useSudo),
    certDir: optionalString(raw.certDir, 'certDir', 256) || 'ssl',
    enforceTest: raw.enforceTest !== false,
    stateDir: path.dirname(resolvedPath),
    configPath: resolvedPath,
  };
}

export async function saveAgentConfig(configPath, config) {
  const resolvedPath = path.resolve(configPath);
  await ensurePrivateDirectory(path.dirname(resolvedPath), 0o700);
  const data = {
    version: 1,
    agentId: config.agentId,
    agentName: config.agentName,
    mainUrl: config.mainUrl,
    mainPublicKey: config.mainPublicKey,
    allowInsecureHttp: Boolean(config.allowInsecureHttp),
    allowedRoots: config.allowedRoots,
    workspace: config.workspace || null,
    nginxBin: config.nginxBin,
    nginxPrefix: config.nginxPrefix || null,
    controlMode: config.controlMode || 'signal',
    systemdUnit: config.systemdUnit || 'nginx',
    useSudo: Boolean(config.useSudo),
    certDir: config.certDir || 'ssl',
    enforceTest: config.enforceTest !== false,
  };
  JSON.parse(JSON.stringify(data)); // Ensure serializable.
  await atomicWriteFile(resolvedPath, JSON.stringify(data, null, 2), { mode: 0o600 });
  return { ...config, configPath: resolvedPath, stateDir: path.dirname(resolvedPath) };
}

export function assertAgentId(value) {
  if (!AGENT_ID_RE.test(value || '')) throw new NcsError('INVALID_AGENT_ID', 'Agent ID 无效', 400);
  return value;
}
