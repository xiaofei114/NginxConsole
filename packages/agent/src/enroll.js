import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  NcsError,
  isInside,
  publicKeyFingerprint,
  resolveWorkspace,
  validateEd25519PublicKey,
} from '@ncs/shared';
import {
  assertAgentId,
  detectConfigFile,
  loadIdentity,
  normalizeConfigFile,
  normalizeMainUrl,
  saveAgentConfig,
  keyPathForConfig,
} from './config.js';

const VERSION = '1.0.0';

async function resolveRoots(roots) {
  const resolved = [];
  for (const root of roots) {
    if (typeof root !== 'string' || !path.isAbsolute(root)) {
      throw new NcsError('INVALID_ALLOWED_ROOT', '允许的根目录必须是绝对路径', 400);
    }
    let real;
    try {
      real = await fs.realpath(root);
      const stat = await fs.stat(real);
      if (!stat.isDirectory()) throw new Error('not dir');
    } catch {
      throw new NcsError('INVALID_ALLOWED_ROOT', `允许的根目录不存在或不可访问：${root}`, 400);
    }
    if (!resolved.includes(real)) resolved.push(real);
  }
  return resolved;
}

/**
 * Enroll this agent with the main server. The enrollment token is single-use
 * and is never persisted.
 */
export async function enrollAgent(options) {
  const configPath = path.resolve(options.configPath);
  const agentId = assertAgentId(options.agentId);
  const allowInsecureHttp = Boolean(options.allowInsecureHttp) && process.env.NODE_ENV !== 'production';
  const mainUrl = normalizeMainUrl(options.mainUrl, { allowInsecure: allowInsecureHttp });
  if (typeof options.token !== 'string' || options.token.length < 16 || options.token.length > 256) {
    throw new NcsError('INVALID_ENROLL_TOKEN', '注册令牌无效', 400);
  }

  let existingConfig = null;
  try {
    existingConfig = JSON.parse(await fs.readFile(configPath, 'utf8'));
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      if (!options.force) {
        throw new NcsError('CONFIG_EXISTS', `Agent 配置文件已存在：${configPath}，如需重新注册请添加 --force`, 409);
      }
    }
  }
  if (existingConfig && !options.force) {
    throw new NcsError('CONFIG_EXISTS', `Agent 配置文件已存在：${configPath}，如需重新注册请添加 --force`, 409);
  }

  const requestedRoots = options.allowedRoots?.length ? options.allowedRoots : [];
  if (requestedRoots.length === 0 && options.workspace) requestedRoots.push(options.workspace);
  if (requestedRoots.length === 0) {
    if (process.platform === 'win32') {
      throw new NcsError(
        'MISSING_ALLOWED_ROOT',
        'Windows 上必须通过 --allowed-root 指定 Nginx 目录（例如 C:\\nginx），POSIX 默认路径 /etc/nginx 不适用',
        400,
      );
    }
    requestedRoots.push('/etc/nginx');
  }
  const allowedRoots = await resolveRoots(requestedRoots);
  const workspaceRequest = options.workspace || allowedRoots[0];
  const workspace = (await resolveWorkspace(allowedRoots, workspaceRequest)).path;
  const configFile = options.configFile
    ? normalizeConfigFile(options.configFile)
    : await detectConfigFile(workspace);

  const nginxBin = options.nginxBin
    || (process.platform === 'win32' ? '' : '/usr/sbin/nginx');
  if (!nginxBin) {
    throw new NcsError(
      'MISSING_NGINX_BIN',
      'Windows 上必须通过 --nginx-bin 指定 nginx.exe 的绝对路径（例如 C:\\nginx\\nginx.exe）',
      400,
    );
  }
  if (!path.isAbsolute(nginxBin)) {
    throw new NcsError('INVALID_NGINX_BIN', 'nginxBin 必须是绝对路径', 400);
  }
  if (options.nginxPrefix && !path.isAbsolute(options.nginxPrefix)) {
    throw new NcsError('INVALID_NGINX_PREFIX', 'nginxPrefix 必须是绝对路径', 400);
  }

  const identity = await loadIdentity(configPath, { create: true });
  const body = {
    agentId,
    token: options.token,
    publicKey: identity.publicKeyPem,
    meta: {
      hostname: os.hostname(),
      platform: process.platform,
      release: os.release(),
      agentVersion: VERSION,
    },
  };

  let response;
  try {
    response = await fetch(`${mainUrl}/api/agent/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': `ncs-agent/${VERSION}` },
      body: JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.timeout(20000),
    });
  } catch (error) {
    throw new NcsError(
      error?.name === 'TimeoutError' ? 'ENROLL_TIMEOUT' : 'ENROLL_NETWORK_ERROR',
      '无法连接主服务器完成注册，请检查地址、TLS 与网络',
      502,
    );
  }

  let parsed;
  try {
    parsed = await response.json();
  } catch {
    throw new NcsError('ENROLL_FAILED', `主服务器返回无效响应（HTTP ${response.status}）`, 502);
  }
  if (!response.ok || !parsed?.ok) {
    throw new NcsError(
      parsed?.error?.code || 'ENROLL_FAILED',
      parsed?.error?.message || `注册失败（HTTP ${response.status}）`,
      response.status === 200 ? 400 : response.status,
    );
  }

  const data = parsed.data || {};
  validateEd25519PublicKey(data.mainPublicKey);
  if (data.agent?.id && data.agent.id !== agentId) {
    throw new NcsError('ENROLL_FAILED', '主服务器返回的 Agent ID 不一致', 502);
  }
  if (existingConfig?.mainPublicKey && existingConfig.mainPublicKey !== data.mainPublicKey && !options.force) {
    throw new NcsError('MAIN_KEY_CHANGED', '主服务器公钥发生变化，拒绝在不确认的情况下继续', 409);
  }

  const saved = await saveAgentConfig(configPath, {
    version: 1,
    agentId,
    agentName: data.agent?.name || existingConfig?.agentName || agentId,
    mainUrl,
    mainPublicKey: data.mainPublicKey,
    allowInsecureHttp,
    allowedRoots,
    workspace,
    nginxBin: path.normalize(nginxBin),
    nginxPrefix: options.nginxPrefix || null,
    configFile,
    controlMode: options.controlMode === 'systemd' ? 'systemd' : 'signal',
    systemdUnit: options.systemdUnit || 'nginx',
    useSudo: Boolean(options.useSudo),
    certDir: options.certDir || 'ssl',
    enforceTest: options.enforceTest !== false,
  });

  return {
    config: saved,
    configPath,
    keyPath: keyPathForConfig(configPath),
    agentFingerprint: identity.fingerprint,
    mainFingerprint: publicKeyFingerprint(data.mainPublicKey),
    insecureHttp: allowInsecureHttp && mainUrl.startsWith('http://'),
  };
}
