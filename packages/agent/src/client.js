import crypto from 'node:crypto';
import {
  LIMITS,
  NcsError,
  ReplayGuard,
  asLogger,
  asNcsError,
  createSignedEnvelope,
  publicError,
  serializeAuthEnvelope,
  verifySignedEnvelope,
} from '@ncs/shared';
import { NginxEngine } from '@ncs/core';
import {
  loadAgentConfig,
  loadIdentity,
  saveAgentConfig,
  websocketUrl,
} from './config.js';
import WebSocket from 'ws';

const VERSION = '1.0.0';
const HELLO_TIMEOUT_MS = 10000;
const COMMAND_TIMEOUT_MS = 120000;
const MAX_INFLIGHT = LIMITS.maxConcurrentCommands;
const REQUEST_ID_RE = /^[A-Za-z0-9_-]{8,80}$/;

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class AgentClient {
  constructor({ config, identity, engine, logger, configPath }) {
    this.config = config;
    this.identity = identity;
    this.engine = engine;
    this.configPath = configPath;
    this.logger = asLogger(logger, { app: 'agent', component: 'client' });
    this.privateKey = identity.privateKey;
    this.mainPublicKey = crypto.createPublicKey(config.mainPublicKey);
    this.guard = new ReplayGuard({ ttlMs: 5 * 60 * 1000, maxEntries: 40000 });
    this.ws = null;
    this.stopped = true;
    this.ready = false;
    this.reconnectAttempt = 0;
    this.reconnectTimer = null;
    this.heartbeatTimer = null;
    this.helloTimer = null;
    this.pendingChallenge = null;
    this.lastPongAt = 0;
    this.inflight = 0;
    this.readyWaiters = [];
  }

  static async create({ configPath, logger } = {}) {
    if (!configPath) throw new NcsError('CONFIG_REQUIRED', '必须提供 Agent 配置文件路径', 400);
    const config = await loadAgentConfig(configPath);
    const identity = await loadIdentity(configPath);
    const persist = async (workspace) => {
      await saveAgentConfig(configPath, { ...config, workspace });
      config.workspace = workspace;
    };
    const engine = await NginxEngine.create({
      stateDir: config.stateDir,
      allowedRoots: config.allowedRoots,
      workspace: config.workspace,
      nginxBin: config.nginxBin,
      nginxPrefix: config.nginxPrefix,
      configFile: 'nginx.conf',
      controlMode: config.controlMode,
      systemdUnit: config.systemdUnit,
      useSudo: config.useSudo,
      certDir: config.certDir,
      enforceTest: config.enforceTest,
      label: config.agentName,
      onWorkspaceChange: persist,
    });
    return new AgentClient({ config, identity, engine, logger, configPath });
  }

  start() {
    if (!this.stopped) return this;
    this.stopped = false;
    this.reconnectAttempt = 0;
    this.connect();
    return this;
  }

  waitForReady(timeoutMs = 15000) {
    if (this.ready) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.readyWaiters = this.readyWaiters.filter((waiter) => waiter.resolve !== resolve);
        reject(new NcsError('AGENT_NOT_READY', '等待与主服务器建立连接超时', 503));
      }, timeoutMs);
      this.readyWaiters.push({
        resolve: () => {
          clearTimeout(timer);
          resolve();
        },
      });
    });
  }

  async stop() {
    this.stopped = true;
    this.ready = false;
    clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
    this.clearHeartbeat();
    this.readyWaiters.splice(0).forEach((waiter) => waiter.resolve?.());
    if (this.ws) {
      try {
        this.ws.close(1000, 'agent shutdown');
      } catch {
        this.ws.terminate?.();
      }
    }
    this.ws = null;
  }

  connect() {
    if (this.stopped) return;
    const url = websocketUrl(this.config.mainUrl, { allowInsecure: this.config.allowInsecureHttp });
    let auth;
    try {
      auth = createSignedEnvelope({
        kind: 'agent-auth',
        fields: { agentId: this.config.agentId, path: '/agent/ws', method: 'GET' },
        privateKey: this.privateKey,
      });
    } catch (error) {
      this.logger.error('无法生成连接认证签名', error?.message);
      this.scheduleReconnect();
      return;
    }

    this.logger.info(`正在连接主服务器 ${url}`);
    this.pendingChallenge = auth.nonce;
    let ws;
    try {
      ws = new WebSocket(url, {
        headers: {
          'X-NCS-Auth': serializeAuthEnvelope(auth),
          'User-Agent': `ncs-agent/${VERSION}`,
        },
        handshakeTimeout: 10000,
        maxPayload: LIMITS.maxWsMessageBytes,
        perMessageDeflate: false,
      });
    } catch (error) {
      this.logger.error('创建 WebSocket 连接失败', error?.message);
      this.scheduleReconnect();
      return;
    }
    this.ws = ws;
    this.ready = false;
    this.lastPongAt = Date.now();
    clearTimeout(this.helloTimer);
    this.helloTimer = null;

    ws.on('open', () => {
      this.logger.info('已建立 TCP/WebSocket 连接，等待主服务器认证...');
      clearTimeout(this.helloTimer);
      this.helloTimer = setTimeout(() => {
        this.logger.warn('等待主服务器握手超时');
        ws.terminate();
      }, HELLO_TIMEOUT_MS);
      this.startHeartbeat(ws);
    });

    ws.on('message', (data) => {
      this.handleMessage(ws, data).catch((error) => {
        this.logger.error('处理主服务器消息失败', error?.message);
        if (ws.readyState === WebSocket.OPEN) ws.close(1008, 'protocol error');
      });
    });

    ws.on('pong', () => {
      this.lastPongAt = Date.now();
    });

    ws.on('unexpected-response', (_request, response) => {
      const status = response?.statusCode;
      this.logger.warn(`主服务器拒绝连接（HTTP ${status}）`);
      response?.resume?.();
      setTimeout(() => ws.terminate(), 10);
    });

    ws.on('error', (error) => {
      this.logger.warn('连接错误', error?.message || String(error));
    });

    ws.on('close', (code, reasonBuffer) => {
      clearTimeout(this.helloTimer);
      this.helloTimer = null;
      this.clearHeartbeat();
      if (this.ws === ws) this.ws = null;
      const wasReady = this.ready;
      this.ready = false;
      const reason = reasonBuffer?.toString?.() || '';
      this.logger.warn(`连接已关闭 code=${code}${reason ? ` reason=${reason.slice(0, 200)}` : ''}`);
      if (!this.stopped) this.scheduleReconnect(wasReady);
    });
  }

  scheduleReconnect(wasReady = false) {
    if (this.stopped || this.reconnectTimer) return;
    if (wasReady) this.reconnectAttempt = 0;
    const base = Math.min(60000, 1000 * 2 ** Math.min(this.reconnectAttempt, 6));
    const jitter = Math.floor(Math.random() * 500);
    this.reconnectAttempt += 1;
    const wait = base + jitter;
    this.logger.info(`${Math.round(wait / 1000)} 秒后重连`);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, wait);
  }

  startHeartbeat(ws) {
    this.clearHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (ws.readyState !== WebSocket.OPEN) return;
      if (Date.now() - this.lastPongAt > 75000) {
        this.logger.warn('心跳超时，主动断开连接');
        ws.terminate();
        return;
      }
      try {
        ws.ping();
      } catch {
        ws.terminate();
      }
    }, 25000);
  }

  clearHeartbeat() {
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = null;
  }

  async handleMessage(ws, data) {
    const bytes = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
    if (bytes.length > LIMITS.maxWsMessageBytes) {
      throw new NcsError('MESSAGE_TOO_LARGE', '消息过大', 400);
    }
    let envelope;
    try {
      envelope = JSON.parse(bytes.toString('utf8'));
    } catch {
      throw new NcsError('INVALID_ENVELOPE', '无法解析消息', 400);
    }

    if (envelope?.kind === 'main-hello') {
      if (this.ready) throw new NcsError('INVALID_ENVELOPE', '重复握手', 400);
      verifySignedEnvelope(envelope, this.mainPublicKey, { allowedKinds: ['main-hello'] });
      this.guard.check(envelope.nonce);
      if (envelope.agentId !== this.config.agentId) {
        throw new NcsError('INVALID_ENVELOPE', '握手 Agent ID 不匹配', 400);
      }
      if (envelope.challenge !== this.pendingChallenge) {
        throw new NcsError('INVALID_ENVELOPE', '握手挑战值不匹配', 400);
      }
      this.pendingChallenge = null;
      clearTimeout(this.helloTimer);
      this.helloTimer = null;
      this.ready = true;
      this.reconnectAttempt = 0;
      this.logger.info('主服务器身份校验通过，Agent 已就绪');
      this.readyWaiters.splice(0).forEach((waiter) => waiter.resolve?.());
      return;
    }

    if (!this.ready) throw new NcsError('NOT_READY', '尚未完成握手', 400);

    if (envelope?.kind !== 'request') {
      throw new NcsError('INVALID_ENVELOPE', '不支持的消息类型', 400);
    }
    verifySignedEnvelope(envelope, this.mainPublicKey, { allowedKinds: ['request'] });
    this.guard.check(envelope.nonce);

    const { id, cmd, payload } = envelope;
    if (typeof id !== 'string' || !REQUEST_ID_RE.test(id)) {
      throw new NcsError('INVALID_ENVELOPE', '请求 ID 无效', 400);
    }
    if (typeof cmd !== 'string' || cmd.length === 0 || cmd.length > 64) {
      throw new NcsError('INVALID_ENVELOPE', '命令无效', 400);
    }
    if (payload !== undefined && (payload === null || typeof payload !== 'object' || Array.isArray(payload))) {
      throw new NcsError('INVALID_ENVELOPE', '命令参数无效', 400);
    }

    if (this.inflight >= MAX_INFLIGHT) {
      await this.sendResponse(ws, { id, ok: false, error: { code: 'AGENT_BUSY', message: 'Agent 繁忙，请稍后重试' } });
      return;
    }

    this.inflight += 1;
    let execution;
    try {
      execution = this.engine.execute(cmd, payload || {});
    } catch (error) {
      this.inflight -= 1;
      await this.sendResponse(ws, this.errorResponse(id, error));
      return;
    }
    execution.then(
      () => {
        this.inflight = Math.max(0, this.inflight - 1);
      },
      () => {
        this.inflight = Math.max(0, this.inflight - 1);
      },
    );
    let timer;
    const timeout = new Promise((resolve) => {
      timer = setTimeout(() => resolve(Symbol.for('ncs-timeout')), COMMAND_TIMEOUT_MS);
    });
    let outcome;
    try {
      outcome = await Promise.race([execution, timeout]);
    } catch (error) {
      clearTimeout(timer);
      await this.sendResponse(ws, this.errorResponse(id, error));
      return;
    }
    clearTimeout(timer);
    if (outcome === Symbol.for('ncs-timeout')) {
      this.logger.error(`命令执行超时：${cmd}`);
      await this.sendResponse(ws, {
        id,
        ok: false,
        error: { code: 'AGENT_COMMAND_TIMEOUT', message: '命令在本机执行超时' },
      });
      return;
    }
    let result;
    try {
      result = JSON.parse(JSON.stringify(outcome ?? null));
    } catch {
      await this.sendResponse(ws, {
        id,
        ok: false,
        error: { code: 'AGENT_SERIALIZATION_FAILED', message: '命令结果无法序列化' },
      });
      return;
    }
    await this.sendResponse(ws, { id, ok: true, result });
  }

  errorResponse(id, error) {
    const e = asNcsError(error);
    if (e.code === 'INTERNAL_ERROR') {
      this.logger.error('命令执行失败', error?.stack || e.message);
    }
    return {
      id,
      ok: false,
      error: { ...publicError(error), status: e.status },
    };
  }

  async sendResponse(ws, fields) {
    if (ws.readyState !== WebSocket.OPEN) return;
    if (!this.ready) return;
    let envelope;
    try {
      envelope = createSignedEnvelope({
        kind: 'response',
        fields,
        privateKey: this.privateKey,
      });
    } catch (error) {
      this.logger.error('响应签名失败', error?.message);
      return;
    }
    const text = JSON.stringify(envelope);
    if (Buffer.byteLength(text, 'utf8') > LIMITS.maxWsMessageBytes) {
      const fallback = createSignedEnvelope({
        kind: 'response',
        fields: { id: fields.id, ok: false, error: { code: 'RESPONSE_TOO_LARGE', message: '响应过大' } },
        privateKey: this.privateKey,
      });
      ws.send(JSON.stringify(fallback));
      return;
    }
    ws.send(text);
  }
}

export async function createAgentClient(options) {
  return AgentClient.create(options);
}

export { delay };
