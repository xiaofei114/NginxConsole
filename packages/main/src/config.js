import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import { NcsError } from '@ncs/shared';
import { ensurePrivateDirectory } from '@ncs/core';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

function envValue(env, name) {
  const value = env[name];
  return value === undefined || value === '' ? undefined : value;
}

function parseBoolean(value, defaultValue = false) {
  if (value === undefined) return defaultValue;
  if (['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase())) return true;
  if (['0', 'false', 'no', 'off'].includes(String(value).toLowerCase())) return false;
  throw new NcsError('INVALID_CONFIG', `布尔配置值无效：${value}`, 500);
}

function parseInteger(value, name, { min, max, defaultValue }) {
  if (value === undefined) return defaultValue;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new NcsError('INVALID_CONFIG', `配置 ${name} 必须是 ${min}-${max} 的整数`, 500);
  }
  return parsed;
}

function parseOrigin(value, isProduction) {
  if (!value) return null;
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new NcsError('INVALID_CONFIG', 'NCS_PUBLIC_ORIGIN 不是有效 URL', 500);
  }
  if (url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) {
    throw new NcsError('INVALID_CONFIG', 'NCS_PUBLIC_ORIGIN 只能是源地址', 500);
  }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new NcsError('INVALID_CONFIG', 'NCS_PUBLIC_ORIGIN 仅支持 http/https', 500);
  }
  if (isProduction && url.protocol !== 'https:') {
    throw new NcsError('INSECURE_CONFIG', '生产环境 NCS_PUBLIC_ORIGIN 必须使用 HTTPS', 500);
  }
  return url.origin;
}

function parseOriginList(value, name) {
  const origins = [];
  for (const item of String(value || '').split(',')) {
    const trimmed = item.trim();
    if (!trimmed) continue;
    let url;
    try {
      url = new URL(trimmed);
    } catch {
      throw new NcsError('INVALID_CONFIG', `${name} 包含无效 URL`, 500);
    }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password
      || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) {
      throw new NcsError('INVALID_CONFIG', `${name} 只能包含纯源地址`, 500);
    }
    origins.push(url.origin);
  }
  return origins;
}

function hostnameOfHost(host) {
  if (host.startsWith('[')) {
    const end = host.indexOf(']');
    return end > 0 ? host.slice(1, end).toLowerCase() : host.toLowerCase();
  }
  return host.split(':')[0].toLowerCase();
}

function validatePasswordStrength(password) {
  if (typeof password !== 'string' || password.length < 12 || Buffer.byteLength(password) > 1024) {
    throw new NcsError('WEAK_ADMIN_PASSWORD', '管理员口令至少 12 个字符且不超过 1024 字节', 500);
  }
}

function generateAdminPassword() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^&*+-_';
  const bytes = crypto.randomBytes(32);
  let output = '';
  for (const byte of bytes) output += alphabet[byte % alphabet.length];
  return output;
}

async function pathExists(target) {
  try {
    const stat = await fs.stat(target);
    return stat;
  } catch {
    return null;
  }
}

async function prepareDemoWorkspace(dataDir) {
  const workspace = path.join(dataDir, 'nginx-workspace');
  await ensurePrivateDirectory(workspace, 0o700);
  const configFile = path.join(workspace, 'nginx.conf');
  if (!(await pathExists(configFile))) {
    const sample = `# Nginx Console demo workspace (not a production configuration)\nworker_processes 1;\nevents { worker_connections 64; }\nhttp {\n    server {\n        listen 8080;\n        server_name localhost;\n        location / {\n            return 200 "nginx console demo\\n";\n        }\n    }\n}\n`;
    await fs.writeFile(configFile, sample, { mode: 0o600, flag: 'wx' }).catch(() => {});
  }
  return workspace;
}

/**
 * Load and normalize main server configuration from environment variables.
 * Fails closed on insecure combinations in production.
 */
export async function loadConfig(env = process.env, overrides = {}) {
  const isProduction = (env.NODE_ENV || 'development') === 'production';
  const warnings = [];
  const dataDir = path.resolve(overrides.dataDir || env.NCS_DATA_DIR || 'data');
  await ensurePrivateDirectory(dataDir, 0o700);
  const realDataDir = await fs.realpath(dataDir);

  const host = overrides.host || env.NCS_HOST || '127.0.0.1';
  if (host !== 'localhost' && net.isIP(host) === 0) {
    throw new NcsError('INVALID_CONFIG', 'NCS_HOST 必须是 IP 地址或 localhost', 500);
  }
  const port = parseInteger(env.NCS_PORT, 'NCS_PORT', { min: 1, max: 65535, defaultValue: 8787 });
  const publicOrigin = parseOrigin(env.NCS_PUBLIC_ORIGIN, isProduction);
  const trustProxy = parseBoolean(env.NCS_TRUST_PROXY, false);
  const allowInsecurePublic = parseBoolean(env.NCS_ALLOW_INSECURE_PUBLIC, false);
  const tlsCertPath = env.NCS_TLS_CERT ? path.resolve(env.NCS_TLS_CERT) : null;
  const tlsKeyPath = env.NCS_TLS_KEY ? path.resolve(env.NCS_TLS_KEY) : null;
  if (Boolean(tlsCertPath) !== Boolean(tlsKeyPath)) {
    throw new NcsError('INVALID_CONFIG', 'NCS_TLS_CERT 与 NCS_TLS_KEY 必须同时配置', 500);
  }
  const tls = Boolean(tlsCertPath);
  if (tls) {
    await fs.access(tlsCertPath).catch(() => {
      throw new NcsError('INVALID_CONFIG', 'TLS 证书文件不可读', 500);
    });
    await fs.access(tlsKeyPath).catch(() => {
      throw new NcsError('INVALID_CONFIG', 'TLS 私钥文件不可读', 500);
    });
  }

  const isLoopback = LOOPBACK_HOSTS.has(host);
  if (!isLoopback && !tls && !trustProxy && !allowInsecurePublic) {
    if (isProduction) {
      throw new NcsError('INSECURE_CONFIG', '不允许在公网接口上以明文方式运行；请使用反向代理/TLS，或显式设置 NCS_ALLOW_INSECURE_PUBLIC=1', 500);
    }
    warnings.push('主服务器监听非本机地址且未启用 TLS，仅适合本地开发。');
  }
  if (trustProxy) {
    warnings.push('已启用反向代理信任：必须确保代理覆盖 X-Forwarded-For 与 X-Forwarded-Proto，且只允许代理访问本端口。');
  }

  const cookieSecureDefault = Boolean(tls || publicOrigin?.startsWith('https://'));
  const cookieSecure = parseBoolean(env.NCS_COOKIE_SECURE, cookieSecureDefault);
  if (isProduction && !cookieSecure && !isLoopback && !allowInsecurePublic) {
    throw new NcsError('INSECURE_CONFIG', '生产环境必须启用 Secure Cookie（HTTPS）', 500);
  }

  const allowedHosts = new Set(
    (env.NCS_ALLOWED_HOSTS || '')
      .split(',')
      .map((item) => hostnameOfHost(item.trim().toLowerCase()))
      .filter(Boolean),
  );
  for (const fallback of ['localhost', '127.0.0.1', '::1']) allowedHosts.add(fallback);
  if (host !== '0.0.0.0' && host !== '::') allowedHosts.add(hostnameOfHost(host));
  if (publicOrigin) allowedHosts.add(new URL(publicOrigin).hostname.toLowerCase());

  const adminUsername = env.NCS_ADMIN_USER || 'admin';
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(adminUsername)) {
    throw new NcsError('INVALID_CONFIG', 'NCS_ADMIN_USER 仅允许字母、数字、点、下划线、短横线', 500);
  }
  let adminPassword = env.NCS_ADMIN_PASSWORD;
  let generatedAdminPassword = false;
  if (adminPassword) {
    validatePasswordStrength(adminPassword);
  } else {
    adminPassword = generateAdminPassword();
    generatedAdminPassword = true;
  }

  let allowedRoots = (env.NCS_ALLOWED_ROOTS || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => path.resolve(item));
  if (allowedRoots.length === 0 && overrides.allowedRoots?.length) {
    allowedRoots = overrides.allowedRoots.map((item) => path.resolve(item));
  }
  let demoWorkspace = false;
  if (allowedRoots.length === 0) {
    if (isProduction) {
      throw new NcsError('INVALID_CONFIG', '生产环境必须通过 NCS_ALLOWED_ROOTS 配置允许的 Nginx 根目录', 500);
    }
    allowedRoots = [await prepareDemoWorkspace(realDataDir)];
    demoWorkspace = true;
    warnings.push('未配置 NCS_ALLOWED_ROOTS，已创建仅用于演示的本地工作目录；生产环境请配置 /etc/nginx。');
  }
  for (const root of allowedRoots) {
    const stat = await pathExists(root);
    if (!stat?.isDirectory()) throw new NcsError('INVALID_CONFIG', `允许的根目录不存在：${root}`, 500);
  }

  const devSkipRequested = parseBoolean(env.NCS_DEV_UNSAFE_SKIP_NGINX_TEST, false);
  let enforceTest = true;
  if (devSkipRequested) {
    if (isProduction) warnings.push('生产环境已忽略 NCS_DEV_UNSAFE_SKIP_NGINX_TEST，配置检测保持开启。');
    else {
      enforceTest = false;
      warnings.push('危险：已跳过 nginx -t 配置检测（开发模式），禁止在生产使用。');
    }
  }
  if (demoWorkspace) {
    enforceTest = false;
    warnings.push('演示工作目录不会执行 nginx -t（本机可能未安装 Nginx），请勿用于生产。');
  }

  const localWorkspace = overrides.localWorkspace || env.NCS_LOCAL_WORKSPACE || allowedRoots[0];
  const localWorkspaceExplicit = Boolean(overrides.localWorkspace || env.NCS_LOCAL_WORKSPACE);

  const allowedOrigins = new Set();
  if (publicOrigin) allowedOrigins.add(publicOrigin);
  if (!isProduction) {
    for (const origin of parseOriginList(
      env.NCS_DEV_ORIGINS || 'http://localhost:5173,http://127.0.0.1:5173',
      'NCS_DEV_ORIGINS',
    )) {
      allowedOrigins.add(origin);
    }
  } else if (env.NCS_DEV_ORIGINS) {
    warnings.push('生产环境已忽略 NCS_DEV_ORIGINS。');
  }

  const config = {
    isProduction,
    dataDir: realDataDir,
    host,
    port,
    publicOrigin,
    publicUrl: publicOrigin || (tls ? `https://${host === '0.0.0.0' ? 'localhost' : host}:${port}` : null),
    trustProxy,
    cookieSecure,
    tls: tls
      ? {
          cert: await fs.readFile(tlsCertPath),
          key: await fs.readFile(tlsKeyPath),
          certPath: tlsCertPath,
          keyPath: tlsKeyPath,
        }
      : null,
    allowedHosts: [...allowedHosts],
    allowedOrigins: [...allowedOrigins],
    admin: {
      username: adminUsername,
      password: adminPassword,
      generated: generatedAdminPassword,
    },
    allowedRoots,
    localWorkspace,
    localWorkspaceExplicit,
    demoWorkspace,
    webDist: env.NCS_WEB_DIST ? path.resolve(env.NCS_WEB_DIST) : null,
    nginxBin: env.NCS_NGINX_BIN || '/usr/sbin/nginx',
    nginxPrefix: env.NCS_NGINX_PREFIX || null,
    controlMode: env.NCS_CONTROL_MODE === 'systemd' ? 'systemd' : 'signal',
    systemdUnit: env.NCS_SYSTEMD_UNIT || 'nginx',
    useSudo: parseBoolean(env.NCS_USE_SUDO, false),
    certDir: env.NCS_CERT_DIR || 'ssl',
    enforceTest,
    sessionIdleMinutes: parseInteger(env.NCS_SESSION_IDLE_MINUTES, 'NCS_SESSION_IDLE_MINUTES', { min: 5, max: 1440, defaultValue: 60 }),
    sessionAbsoluteMinutes: parseInteger(env.NCS_SESSION_ABSOLUTE_MINUTES, 'NCS_SESSION_ABSOLUTE_MINUTES', { min: 15, max: 1440, defaultValue: 720 }),
    enrollmentTokenMinutes: parseInteger(env.NCS_ENROLL_TOKEN_MINUTES, 'NCS_ENROLL_TOKEN_MINUTES', { min: 5, max: 1440, defaultValue: 30 }),
    warnings,
  };

  if (config.sessionIdleMinutes >= config.sessionAbsoluteMinutes) {
    throw new NcsError('INVALID_CONFIG', '空闲会话时长必须小于绝对会话时长', 500);
  }
  if (isProduction && !publicOrigin) {
    warnings.push('未配置 NCS_PUBLIC_ORIGIN，Origin/Host 校验将依赖请求头；强烈建议配置公网地址。');
  }
  return config;
}

export { hostnameOfHost, validatePasswordStrength };
