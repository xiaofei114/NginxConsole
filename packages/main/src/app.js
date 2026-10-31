import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import {
  LIMITS,
  NcsError,
  asLogger,
  asNcsError,
  publicError,
} from '@ncs/shared';
import { NginxEngine } from '@ncs/core';
import { Store } from './store.js';
import { AuditLog } from './audit.js';
import { SessionStore } from './sessions.js';
import { AuthService, createRequireAuth, createRequireCsrf } from './auth.js';
import { AgentHub } from './hub.js';
import { ServerManager } from './servers.js';
import { loadOrCreateMainKey, loadOrCreateMasterKey } from './keys.js';
import {
  RateLimiter,
  clearSessionCookie,
  getClientIp,
  getSessionToken,
  hostGuard,
  isLoopbackPeer,
  isSecureRequest,
  originGuard,
  securityHeaders,
  serializeSessionCookie,
} from './http-security.js';

const DEFAULT_WEB_DIST = fileURLToPath(new URL('../../../web/dist/', import.meta.url));
const AGENT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function route(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function sendOk(res, data, status = 200) {
  res.status(status).json({ ok: true, data });
}

function bodyOf(req) {
  return req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
}

function stringField(body, name, { required = true, max = 4096 } = {}) {
  const value = body[name];
  if (value === undefined || value === null) {
    if (required) throw new NcsError('INVALID_REQUEST', `缺少字段 ${name}`, 400);
    return null;
  }
  if (typeof value !== 'string' || value.length > max) {
    throw new NcsError('INVALID_REQUEST', `字段 ${name} 无效`, 400);
  }
  return value;
}

function optionalString(body, name, max = 4096) {
  return stringField(body, name, { required: false, max });
}

function requestIdMiddleware(req, res, next) {
  const incoming = req.headers['x-request-id'];
  const id = typeof incoming === 'string' && /^[A-Za-z0-9_-]{8,80}$/.test(incoming)
    ? incoming
    : crypto.randomUUID();
  req.requestId = id;
  res.setHeader('X-Request-Id', id);
  next();
}

function rateLimitMiddleware(limiter, { trustProxy }) {
  return (req, res, next) => {
    const result = limiter.hit(getClientIp(req, { trustProxy }));
    if (!result.allowed) {
      res.setHeader('Retry-After', String(result.retryAfter));
      next(new NcsError('RATE_LIMITED', '请求过于频繁，请稍后再试', 429, { retryAfter: result.retryAfter }));
      return;
    }
    next();
  };
}

function requestPathOf(req) {
  return String(req.originalUrl || '/').split('?')[0].slice(0, 512);
}

/**
 * 访问日志：只记录方法、路径、状态、耗时与来源 IP。
 * 不记录查询串与请求体，避免口令、令牌等敏感信息进入日志。
 */
function accessLogMiddleware(logger, { trustProxy }) {
  return (req, res, next) => {
    const startedAt = process.hrtime.bigint();
    // 必须在这里取路径：进入子路由后 req.url 会被改写为挂载点内的相对路径，
    // finish 回调里再读 req.path 会丢失 /api 前缀。
    const requestPath = requestPathOf(req);
    res.on('finish', () => {
      const status = res.statusCode;
      const isApi = requestPath === '/api' || requestPath.startsWith('/api/');
      const level = status >= 500 ? 'error' : status >= 400 ? 'warn' : isApi ? 'info' : 'debug';
      const write = logger[level] || logger.info;
      if (typeof write !== 'function') return;
      const durationMs = Math.round(Number(process.hrtime.bigint() - startedAt) / 1e5) / 10;
      write.call(logger, 'HTTP 请求', {
        requestId: req.requestId,
        method: req.method,
        path: requestPath,
        status,
        durationMs,
        ip: getClientIp(req, { trustProxy }),
      });
    });
    next();
  };
}

async function pathIsDirectory(target) {
  try {
    return (await fs.stat(target)).isDirectory();
  } catch {
    return false;
  }
}

export async function createApp(config, { logger } = {}) {
  const log = asLogger(logger, { app: 'main', component: 'app' });
  const masterKey = await loadOrCreateMasterKey(path.join(config.dataDir, 'master.key'));
  const mainKey = await loadOrCreateMainKey(path.join(config.dataDir, 'main-key.pem'));

  const store = await Store.open({
    file: path.join(config.dataDir, 'store.json'),
    adminUsername: config.admin.username,
    adminPassword: config.admin.password,
  });
  const audit = new AuditLog(path.join(config.dataDir, 'audit.jsonl'));
  await audit.init();

  const sessions = new SessionStore({
    idleTtlMs: config.sessionIdleMinutes * 60 * 1000,
    absoluteTtlMs: config.sessionAbsoluteMinutes * 60 * 1000,
  });
  sessions.startCleanup();

  const persistedWorkspace = store.snapshot().settings.localWorkspace;
  const initialWorkspace = config.localWorkspaceExplicit
    ? config.localWorkspace
    : persistedWorkspace || config.localWorkspace;

  const localEngine = await NginxEngine.create({
    stateDir: path.join(config.dataDir, 'engine'),
    allowedRoots: config.allowedRoots,
    workspace: initialWorkspace,
    nginxBin: config.nginxBin,
    nginxPrefix: config.nginxPrefix,
    configFile: config.configFile || 'nginx.conf',
    autoDetectConfigFile: config.autoDetectConfigFile,
    controlMode: config.controlMode,
    systemdUnit: config.systemdUnit,
    useSudo: config.useSudo,
    certDir: config.certDir,
    enforceTest: config.enforceTest,
    label: '主服务器本地 Nginx',
    onWorkspaceChange: async (workspace) => {
      await store.mutate((draft) => {
        draft.settings.localWorkspace = workspace;
      });
    },
  });

  const hub = new AgentHub({
    store,
    audit,
    privateKey: mainKey.privateKey,
    publicKey: mainKey.publicKeyObject,
    config,
    logger: log,
  });

  const manager = new ServerManager({
    store,
    hub,
    localEngine,
    mainPublicKey: mainKey.publicKeyPem,
    publicUrl: config.publicUrl,
    enrollmentTokenMinutes: config.enrollmentTokenMinutes,
    logger: log,
  });

  const auth = new AuthService({ store, sessions, audit, masterKey, config });
  const requireAuth = createRequireAuth({ sessions, store });
  const requireCsrf = createRequireCsrf({ sessions });

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustProxy ? 1 : false);
  app.use(requestIdMiddleware);
  app.use(accessLogMiddleware(log, { trustProxy: config.trustProxy }));
  app.use(securityHeaders(config));
  app.use(hostGuard(config));
  app.use(originGuard(config));
  app.use(express.json({
    limit: LIMITS.maxRequestBodyBytes,
    strict: true,
    type: ['application/json'],
  }));

  const loginIpLimiter = new RateLimiter({ windowMs: 10 * 60 * 1000, max: 30, blockMs: 10 * 60 * 1000 });
  const loginUserLimiter = new RateLimiter({ windowMs: 15 * 60 * 1000, max: 10, blockMs: 15 * 60 * 1000 });
  const enrollLimiter = new RateLimiter({ windowMs: 60 * 60 * 1000, max: 20, blockMs: 60 * 60 * 1000 });

  const getIp = (req) => getClientIp(req, { trustProxy: config.trustProxy });

  function serverName(serverId) {
    if (!serverId) return null;
    if (serverId === 'local') return '主服务器（本地）';
    try {
      return manager.getAgentRecord(serverId).name;
    } catch {
      return null;
    }
  }

  async function recordAudit(req, { action, serverId = null, target = null, result = 'success', meta = null }) {
    await audit.append({
      action,
      result,
      userId: req.user?.id || null,
      username: req.user?.username || null,
      ip: getIp(req),
      serverId,
      serverName: serverName(serverId),
      target,
      requestId: req.requestId,
      meta,
    });
  }

  async function withAudit(req, { action, serverId = null, target = null, meta = null }, work) {
    try {
      const data = await work();
      await recordAudit(req, { action, serverId, target, meta });
      return data;
    } catch (error) {
      const safe = asNcsError(error);
      await recordAudit(req, {
        action,
        serverId,
        target,
        result: 'failure',
        meta: { ...(meta || {}), code: safe.code },
      });
      throw error;
    }
  }

  const api = express.Router();
  api.use(rateLimitMiddleware(new RateLimiter({ windowMs: 60 * 1000, max: 600 }), { trustProxy: config.trustProxy }));

  api.get('/health', route(async (_req, res) => {
    sendOk(res, { status: 'ok', time: new Date().toISOString() });
  }));

  api.post('/auth/login', route(async (req, res) => {
    const ip = getIp(req);
    const body = bodyOf(req);
    const username = typeof body.username === 'string' ? body.username : '';
    const ipLimit = loginIpLimiter.hit(ip);
    if (!ipLimit.allowed) {
      res.setHeader('Retry-After', String(ipLimit.retryAfter));
      throw new NcsError('RATE_LIMITED', '登录尝试过于频繁，请稍后再试', 429, { retryAfter: ipLimit.retryAfter });
    }
    const userKey = `${ip}|${username.toLowerCase().slice(0, 64)}`;
    const userLimit = loginUserLimiter.hit(userKey);
    if (!userLimit.allowed) {
      res.setHeader('Retry-After', String(userLimit.retryAfter));
      throw new NcsError('RATE_LIMITED', '登录尝试过于频繁，请稍后再试', 429, { retryAfter: userLimit.retryAfter });
    }
    const result = await auth.login({
      username,
      password: typeof body.password === 'string' ? body.password : '',
      totp: optionalString(body, 'totp', 16),
      recoveryCode: optionalString(body, 'recoveryCode', 64),
      ip,
      userAgent: req.headers['user-agent'] || '',
    });
    res.setHeader(
      'Set-Cookie',
      serializeSessionCookie(result.token, config, config.sessionAbsoluteMinutes * 60),
    );
    sendOk(res, auth.me(result.user, result.session));
  }));

  api.post('/auth/logout', route(async (req, res) => {
    const token = getSessionToken(req);
    const session = token ? sessions.get(token) : null;
    const user = session ? store.findUserById(session.userId) : null;
    auth.logout(token, { userId: user?.id || null, username: user?.username || null, ip: getIp(req) });
    res.setHeader('Set-Cookie', clearSessionCookie(config));
    sendOk(res, { loggedOut: true });
  }));

  api.post('/agent/enroll', route(async (req, res) => {
    // The enrollment token is a bearer secret: never accept it over plaintext
    // from a remote peer in production, even if NCS_ALLOW_INSECURE_PUBLIC was
    // set for debugging. Loopback is allowed so a local TLS-terminating proxy
    // that forwards over HTTP keeps working.
    if (config.isProduction && !isSecureRequest(req, config) && !isLoopbackPeer(req)) {
      throw new NcsError('INSECURE_TRANSPORT', '生产环境要求通过 HTTPS 注册子服务器', 403);
    }
    const ip = getIp(req);
    const limit = enrollLimiter.hit(ip);
    if (!limit.allowed) {
      res.setHeader('Retry-After', String(limit.retryAfter));
      throw new NcsError('RATE_LIMITED', '注册请求过于频繁', 429, { retryAfter: limit.retryAfter });
    }
    const body = bodyOf(req);
    const agentId = typeof body.agentId === 'string' ? body.agentId : '';
    try {
      const data = await manager.enrollAgent({
        agentId,
        token: typeof body.token === 'string' ? body.token : '',
        publicKey: typeof body.publicKey === 'string' ? body.publicKey : '',
        meta: body.meta,
        ip,
      });
      await audit.append({
        action: 'agent.enroll',
        serverId: data.agent.id,
        serverName: data.agent.name,
        ip,
        requestId: req.requestId,
      });
      sendOk(res, data);
    } catch (error) {
      const safe = asNcsError(error);
      await audit.append({
        action: 'agent.enroll',
        result: 'failure',
        serverId: AGENT_ID_RE.test(agentId) ? agentId : null,
        serverName: serverName(agentId),
        ip,
        requestId: req.requestId,
        meta: { code: safe.code },
      });
      throw error;
    }
  }));

  api.use(requireAuth);
  api.use(requireCsrf);

  api.get('/auth/me', route(async (req, res) => {
    sendOk(res, auth.me(req.user, req.session));
  }));

  api.post('/auth/password', route(async (req, res) => {
    const body = bodyOf(req);
    const data = await auth.changePassword({
      userId: req.user.id,
      currentPassword: stringField(body, 'currentPassword', { max: 1024 }),
      newPassword: stringField(body, 'newPassword', { max: 1024 }),
      totp: optionalString(body, 'totp', 16),
      recoveryCode: optionalString(body, 'recoveryCode', 64),
      currentToken: req.sessionToken,
      ip: getIp(req),
    });
    sendOk(res, data);
  }));

  api.post('/auth/totp/setup', route(async (req, res) => {
    const data = await auth.setupTotp(req.user.id);
    await recordAudit(req, { action: 'auth.totp.setup' });
    sendOk(res, data);
  }));

  api.post('/auth/totp/enable', route(async (req, res) => {
    const body = bodyOf(req);
    const data = await auth.enableTotp(req.user.id, stringField(body, 'code', { max: 16 }), getIp(req));
    sendOk(res, data);
  }));

  api.post('/auth/totp/disable', route(async (req, res) => {
    const body = bodyOf(req);
    const data = await auth.disableTotp(req.user.id, {
      password: stringField(body, 'password', { max: 1024 }),
      totp: optionalString(body, 'totp', 16),
      recoveryCode: optionalString(body, 'recoveryCode', 64),
      ip: getIp(req),
    });
    sendOk(res, data);
  }));

  api.get('/servers', route(async (_req, res) => {
    sendOk(res, manager.list());
  }));

  api.post('/servers', route(async (req, res) => {
    const body = bodyOf(req);
    const name = stringField(body, 'name', { max: 128 });
    const data = await withAudit(req, { action: 'server.create', target: name, meta: { name } }, () => manager.createAgent(name));
    sendOk(res, data, 201);
  }));

  api.post('/servers/:serverId/enrollment-token', route(async (req, res) => {
    const { serverId } = req.params;
    const data = await withAudit(req, { action: 'server.enrollment_token', serverId }, () => manager.regenerateEnrollmentToken(serverId));
    sendOk(res, data);
  }));

  api.post('/servers/:serverId/revoke', route(async (req, res) => {
    const { serverId } = req.params;
    const data = await withAudit(req, { action: 'server.revoke', serverId }, () => manager.revokeAgent(serverId));
    sendOk(res, data);
  }));

  api.delete('/servers/:serverId', route(async (req, res) => {
    const { serverId } = req.params;
    const data = await withAudit(req, { action: 'server.delete', serverId }, () => manager.deleteAgent(serverId));
    sendOk(res, data);
  }));

  api.get('/servers/:serverId/info', route(async (req, res) => {
    const { serverId } = req.params;
    const force = req.query.force === '1';
    sendOk(res, await manager.info(serverId, { force }));
  }));

  api.get('/servers/:serverId/workspace-options', route(async (req, res) => {
    const { serverId } = req.params;
    sendOk(res, await manager.execute(serverId, 'workspace.options'));
  }));

  api.put('/servers/:serverId/workspace', route(async (req, res) => {
    const { serverId } = req.params;
    const body = bodyOf(req);
    const workspace = stringField(body, 'path', { max: 1024 });
    const data = await withAudit(req, { action: 'server.workspace.set', serverId, target: workspace }, () =>
      manager.execute(serverId, 'workspace.set', { path: workspace }));
    sendOk(res, data);
  }));

  api.get('/servers/:serverId/files', route(async (req, res) => {
    const { serverId } = req.params;
    const pathValue = typeof req.query.path === 'string' ? req.query.path : '';
    sendOk(res, await manager.execute(serverId, 'fs.list', { path: pathValue }));
  }));

  api.get('/servers/:serverId/file', route(async (req, res) => {
    const { serverId } = req.params;
    const pathValue = typeof req.query.path === 'string' ? req.query.path : '';
    sendOk(res, await manager.execute(serverId, 'fs.read', { path: pathValue }));
  }));

  api.put('/servers/:serverId/file', route(async (req, res) => {
    const { serverId } = req.params;
    const body = bodyOf(req);
    const filePath = stringField(body, 'path', { max: 1024 });
    const content = stringField(body, 'content', { max: LIMITS.maxFileBytes });
    const baseHash = optionalString(body, 'baseHash', 64);
    const data = await withAudit(req, { action: 'server.file.write', serverId, target: filePath }, () =>
      manager.execute(serverId, 'fs.write', { path: filePath, content, baseHash }));
    sendOk(res, data);
  }));

  api.get('/servers/:serverId/backups', route(async (req, res) => {
    const { serverId } = req.params;
    sendOk(res, await manager.execute(serverId, 'backup.list'));
  }));

  api.post('/servers/:serverId/backups/:backupId/restore', route(async (req, res) => {
    const { serverId, backupId } = req.params;
    const body = bodyOf(req);
    if (body.confirm !== true) throw new NcsError('CONFIRM_REQUIRED', '恢复备份需要显式确认', 400);
    const data = await withAudit(req, { action: 'server.backup.restore', serverId, target: backupId }, () =>
      manager.execute(serverId, 'backup.restore', { backupId }));
    sendOk(res, data);
  }));

  api.post('/servers/:serverId/test', route(async (req, res) => {
    const { serverId } = req.params;
    const data = await withAudit(req, { action: 'server.nginx.test', serverId }, () => manager.execute(serverId, 'nginx.test'));
    sendOk(res, data);
  }));

  api.post('/servers/:serverId/reload', route(async (req, res) => {
    const { serverId } = req.params;
    const data = await withAudit(req, { action: 'server.nginx.reload', serverId }, () => manager.execute(serverId, 'nginx.reload'));
    sendOk(res, data);
  }));

  api.post('/servers/:serverId/restart', route(async (req, res) => {
    const { serverId } = req.params;
    const body = bodyOf(req);
    if (body.confirm !== true) throw new NcsError('CONFIRM_REQUIRED', '重启 Nginx 需要显式确认', 400);
    const data = await withAudit(req, { action: 'server.nginx.restart', serverId }, () => manager.execute(serverId, 'nginx.restart'));
    sendOk(res, data);
  }));

  api.get('/certificates/overview', route(async (req, res) => {
    sendOk(res, await manager.certificateOverview({ force: req.query.force === '1' }));
  }));

  api.get('/servers/:serverId/certs', route(async (req, res) => {
    const { serverId } = req.params;
    sendOk(res, await manager.execute(serverId, 'cert.list'));
  }));

  api.post('/servers/:serverId/certs', route(async (req, res) => {
    const { serverId } = req.params;
    const body = bodyOf(req);
    const name = stringField(body, 'name', { max: 64 });
    const certPem = stringField(body, 'certPem', { max: LIMITS.maxCertificateBytes });
    const chainPem = optionalString(body, 'chainPem', LIMITS.maxCertificateBytes) || '';
    const keyPem = stringField(body, 'keyPem', { max: LIMITS.maxCertificateBytes });
    const layout = optionalString(body, 'layout', 16) || 'flat';
    const data = await withAudit(req, { action: 'server.cert.upload', serverId, target: name }, () =>
      manager.execute(serverId, 'cert.upload', { name, certPem, chainPem, keyPem, layout }));
    sendOk(res, data);
  }));

  api.post('/servers/:serverId/certs/archive', route(async (req, res) => {
    const { serverId } = req.params;
    const body = bodyOf(req);
    const name = stringField(body, 'name', { max: 64 });
    const filename = optionalString(body, 'filename', 255) || '';
    const archiveBase64 = stringField(body, 'archiveBase64', { max: LIMITS.maxArchiveBase64Chars });
    const layout = optionalString(body, 'layout', 16) || 'flat';
    const data = await withAudit(
      req,
      { action: 'server.cert.upload', serverId, target: name, meta: { source: 'archive', filename } },
      () => manager.execute(serverId, 'cert.uploadArchive', { name, archiveBase64, layout }),
    );
    sendOk(res, data);
  }));

  api.delete('/servers/:serverId/certs', route(async (req, res) => {
    const { serverId } = req.params;
    const body = bodyOf(req);
    const file = stringField(body, 'file', { max: 512 });
    if (body.confirm !== true) throw new NcsError('CONFIRM_REQUIRED', '删除证书需要显式确认', 400);
    const includeKey = body.includeKey !== false;
    const data = await withAudit(req, { action: 'server.cert.delete', serverId, target: file }, () =>
      manager.execute(serverId, 'cert.delete', { file, includeKey, confirm: true }));
    sendOk(res, data);
  }));

  api.get('/audit', route(async (req, res) => {
    const limit = Number(req.query.limit) || 100;
    const serverId = typeof req.query.serverId === 'string' ? req.query.serverId : null;
    const action = typeof req.query.action === 'string' ? req.query.action : null;
    const result = typeof req.query.result === 'string' ? req.query.result : null;
    sendOk(res, { entries: await audit.query({ limit, serverId, action, result }) });
  }));

  api.use((_req, res) => {
    res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: '接口不存在' } });
  });

  app.use('/api', api);

  const webRoot = config.webDist || DEFAULT_WEB_DIST;
  if (await pathIsDirectory(webRoot)) {
    app.use(express.static(webRoot, {
      index: false,
      etag: true,
      setHeaders: (res, filePath) => {
        if (filePath.includes(`${path.sep}assets${path.sep}`)) {
          res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        } else if (path.basename(filePath) === 'index.html') {
          res.setHeader('Cache-Control', 'no-store');
        } else {
          res.setHeader('Cache-Control', 'public, max-age=3600');
        }
      },
    }));
    app.get(/^\/(?!api\/|agent\/).*/, (req, res, next) => {
      res.sendFile(path.join(webRoot, 'index.html'), (error) => {
        if (error) next(error);
      });
    });
  } else {
    app.get('/', (_req, res) => {
      res.status(503).type('text/plain').send('前端尚未构建。请在 web 目录运行 npm run build，或使用 Vite 开发服务器。');
    });
  }

  app.use((_req, res) => {
    res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: '资源不存在' } });
  });

  // eslint-disable-next-line no-unused-vars
  app.use((error, req, res, _next) => {
    let resolved = error;
    if (error?.type === 'entity.too.large') {
      resolved = new NcsError('PAYLOAD_TOO_LARGE', '请求内容过大', 413);
    } else if (error?.type === 'entity.parse.failed' || (error instanceof SyntaxError && 'body' in error)) {
      resolved = new NcsError('INVALID_BODY', '请求 JSON 格式无效', 400);
    } else if (error?.type === 'encoding.unsupported') {
      resolved = new NcsError('UNSUPPORTED_ENCODING', '不支持的请求编码', 415);
    }
    const safe = asNcsError(resolved);
    if (safe.status >= 500) {
      log.error('请求处理失败', resolved, {
        fields: {
          requestId: req.requestId,
          method: req.method,
          path: requestPathOf(req),
          code: safe.code,
          status: safe.status,
        },
      });
    } else if (safe.status === 403 || safe.status === 429) {
      log.warn('请求被拒绝', {
        requestId: req.requestId,
        method: req.method,
        path: requestPathOf(req),
        code: safe.code,
        status: safe.status,
      });
    }
    if (res.headersSent) {
      res.destroy?.();
      return;
    }
    if (!res.getHeader('Cache-Control')) res.setHeader('Cache-Control', 'no-store');
    res.status(safe.status).json({
      ok: false,
      error: publicError(safe, { includeDetails: safe.status < 500 }),
      requestId: req.requestId,
    });
  });

  const server = http.createServer(config.tls ? { cert: config.tls.cert, key: config.tls.key } : {}, app);
  server.requestTimeout = 30000;
  server.headersTimeout = 20000;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 100;
  hub.attach(server, { allowedHosts: config.allowedHosts, trustProxy: config.trustProxy });

  let closing = false;
  async function close() {
    if (closing) return;
    closing = true;
    sessions.stop();
    await hub.close().catch(() => {});
    await new Promise((resolve) => {
      let settled = false;
      const done = () => {
        if (settled) return;
        settled = true;
        resolve();
      };
      server.close(done);
      server.closeIdleConnections?.();
      const timer = setTimeout(() => {
        server.closeAllConnections?.();
        done();
      }, 3000);
      timer.unref?.();
    });
    await audit.close();
  }

  return {
    app,
    server,
    config,
    store,
    audit,
    sessions,
    localEngine,
    hub,
    manager,
    auth,
    adminSeeded: store.adminSeeded,
    close,
  };
}
