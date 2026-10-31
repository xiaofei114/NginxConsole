import crypto from 'node:crypto';
import {
  LIMITS,
  NcsError,
  ReplayGuard,
  asLogger,
  createSignedEnvelope,
  parseAuthEnvelope,
  publicKeyFingerprint,
  validateEd25519PublicKey,
  verifySignedEnvelope,
} from '@ncs/shared';
import { WebSocketServer } from 'ws';
import { RateLimiter, getClientIp, normalizeHost } from './http-security.js';

const AGENT_PATH = '/agent/ws';
const AGENT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const REQUEST_ID_RE = /^[A-Za-z0-9_-]{8,80}$/;

function rejectUpgrade(socket, status, message) {
  if (!socket.writable) {
    socket.destroy();
    return;
  }
  const body = JSON.stringify({ ok: false, error: { code: 'UPGRADE_REJECTED', message } });
  socket.write(
    `HTTP/1.1 ${status} ${message}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
  );
  socket.destroy();
}

export class AgentHub {
  constructor({ store, audit, privateKey, publicKey, config, logger }) {
    this.store = store;
    this.audit = audit;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.config = config;
    this.logger = asLogger(logger, { app: 'main', component: 'hub' });
    this.connections = new Map();
    this.infoCache = new Map();
    this.replayGuards = new Map();
    this.upgradeLimiter = new RateLimiter({ windowMs: 10 * 60 * 1000, max: 120, blockMs: 10 * 60 * 1000 });
    this.heartbeatTimer = null;
    this.wss = new WebSocketServer({
      noServer: true,
      clientTracking: false,
      perMessageDeflate: false,
      maxPayload: LIMITS.maxWsMessageBytes,
    });
  }

  attach(httpServer, { allowedHosts, trustProxy }) {
    httpServer.on('upgrade', (req, socket, head) => {
      const host = normalizeHost(req.headers.host);
      if (!host || !allowedHosts.includes(host)) {
        rejectUpgrade(socket, 421, 'Misdirected Request');
        return;
      }
      let pathname;
      try {
        pathname = new URL(req.url, 'http://localhost').pathname;
      } catch {
        rejectUpgrade(socket, 400, 'Bad Request');
        return;
      }
      if (pathname !== AGENT_PATH) {
        rejectUpgrade(socket, 404, 'Not Found');
        return;
      }
      const ip = getClientIp(req, { trustProxy });
      const limit = this.upgradeLimiter.hit(ip);
      if (!limit.allowed) {
        rejectUpgrade(socket, 429, 'Too Many Requests');
        return;
      }
      this.authenticate(req)
        .then(({ agent, challenge }) => {
          if (socket.destroyed) return;
          this.wss.handleUpgrade(req, socket, head, (ws) => {
            this.acceptConnection(ws, agent, ip, challenge);
          });
        })
        .catch((error) => {
          const reason = error instanceof NcsError ? error.message : '认证失败';
          const agentId = this.extractAgentId(req);
          this.logger.warn('Agent 认证失败', { ip, reason, agentId });
          this.audit.append({
            action: 'agent.auth.failed',
            result: 'failure',
            ip,
            meta: { reason, agentId },
          });
          rejectUpgrade(socket, 401, 'Unauthorized');
        });
    });
    this.heartbeatTimer = setInterval(() => this.heartbeat(), 30000);
    this.heartbeatTimer.unref?.();
  }

  extractAgentId(req) {
    try {
      const envelope = parseAuthEnvelope(req.headers['x-ncs-auth']);
      return typeof envelope?.agentId === 'string' && AGENT_ID_RE.test(envelope.agentId) ? envelope.agentId : null;
    } catch {
      return null;
    }
  }

  async authenticate(req) {
    const header = req.headers['x-ncs-auth'];
    if (typeof header !== 'string') throw new NcsError('INVALID_ENVELOPE', '缺少认证头', 401);
    const envelope = parseAuthEnvelope(header);
    if (typeof envelope.agentId !== 'string' || !AGENT_ID_RE.test(envelope.agentId)) {
      throw new NcsError('INVALID_ENVELOPE', 'Agent ID 无效', 401);
    }
    const agent = this.store.findAgent(envelope.agentId);
    if (!agent || agent.status !== 'active' || !agent.publicKey) {
      throw new NcsError('AGENT_NOT_ACTIVE', 'Agent 未激活或已撤销', 401);
    }
    const { key } = validateEd25519PublicKey(agent.publicKey);
    verifySignedEnvelope(envelope, key, { allowedKinds: ['agent-auth'] });
    if (envelope.path !== AGENT_PATH || envelope.method !== 'GET') {
      throw new NcsError('INVALID_ENVELOPE', '认证消息与请求不匹配', 401);
    }
    let guard = this.replayGuards.get(agent.id);
    if (!guard) {
      guard = new ReplayGuard({ ttlMs: 5 * 60 * 1000, maxEntries: 20000 });
      this.replayGuards.set(agent.id, guard);
    }
    guard.check(envelope.nonce);
    return { agent, challenge: envelope.nonce };
  }

  acceptConnection(ws, agent, ip, challenge) {
    const previous = this.connections.get(agent.id);
    if (previous) this.drop(previous, 'replaced by new connection');
    let guard = this.replayGuards.get(agent.id);
    if (!guard) {
      guard = new ReplayGuard({ ttlMs: 5 * 60 * 1000, maxEntries: 20000 });
      this.replayGuards.set(agent.id, guard);
    }
    const conn = {
      ws,
      agentId: agent.id,
      publicKey: validateEd25519PublicKey(agent.publicKey).key,
      guard,
      pending: new Map(),
      alive: true,
      ip,
      connectedAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      persistedAt: Date.now(),
    };
    this.connections.set(agent.id, conn);
    this.infoCache.delete(agent.id);

    ws.on('pong', () => {
      this.markSeen(conn);
    });
    ws.on('message', (data) => {
      this.handleMessage(conn, data).catch((error) => {
        this.logger.warn('Agent 协议错误', { agentId: agent.id, reason: error?.message || String(error) });
        this.drop(conn, 'protocol error');
      });
    });
    ws.on('close', (code, reasonBuffer) => {
      const reason = reasonBuffer?.toString?.().slice(0, 200) || '';
      if (this.connections.get(agent.id) === conn) this.connections.delete(agent.id);
      this.rejectPending(conn, new NcsError('AGENT_OFFLINE', 'Agent 连接已断开', 503));
      this.logger.info('Agent 已断开', { agentId: agent.id, name: agent.name, code, reason });
      this.audit.append({
        action: 'agent.disconnect',
        serverId: agent.id,
        serverName: agent.name,
        ip,
        meta: { code, reason },
      });
      this.touchLastSeen(agent.id).catch(() => {});
    });
    ws.on('error', (error) => {
      this.logger.warn('Agent 连接错误', { agentId: agent.id, reason: error?.message || String(error) });
    });

    const hello = createSignedEnvelope({
      kind: 'main-hello',
      fields: { agentId: agent.id, challenge },
      privateKey: this.privateKey,
    });
    ws.send(JSON.stringify(hello));

    this.logger.info('Agent 已连接', { agentId: agent.id, name: agent.name, ip });
    this.audit.append({
      action: 'agent.connect',
      serverId: agent.id,
      serverName: agent.name,
      ip,
      meta: { fingerprint: agent.keyFingerprint || publicKeyFingerprint(agent.publicKey) },
    });
    this.touchLastSeen(agent.id).catch(() => {});
  }

  markSeen(conn) {
    conn.alive = true;
    conn.lastSeenAt = new Date().toISOString();
  }

  lastSeen(agentId) {
    const conn = this.connections.get(agentId);
    return conn ? conn.lastSeenAt : null;
  }

  async touchLastSeen(agentId) {
    const now = new Date().toISOString();
    await this.store
      .mutate((draft) => {
        const agent = draft.agents.find((item) => item.id === agentId);
        if (agent) agent.lastSeenAt = now;
      })
      .catch(() => {});
  }

  async handleMessage(conn, data) {
    const bytes = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
    if (bytes.length > LIMITS.maxWsMessageBytes) throw new NcsError('MESSAGE_TOO_LARGE', '消息过大', 400);
    let envelope;
    try {
      envelope = JSON.parse(bytes.toString('utf8'));
    } catch {
      throw new NcsError('INVALID_ENVELOPE', '无法解析 Agent 消息', 400);
    }
    if (envelope?.kind !== 'response') throw new NcsError('INVALID_ENVELOPE', '不支持的消息类型', 400);
    try {
      verifySignedEnvelope(envelope, conn.publicKey, { allowedKinds: ['response'] });
      conn.guard.check(envelope.nonce);
    } catch (error) {
      this.audit.append({
        action: 'agent.protocol.violation',
        serverId: conn.agentId,
        result: 'failure',
        ip: conn.ip,
        meta: { reason: error?.message || 'invalid signature' },
      });
      this.drop(conn, 'protocol violation');
      throw error;
    }
    // Any verified message proves the Agent is alive, not only the pong frame.
    this.markSeen(conn);
    if (typeof envelope.id !== 'string' || !REQUEST_ID_RE.test(envelope.id)) {
      this.drop(conn, 'invalid response id');
      throw new NcsError('INVALID_ENVELOPE', '响应 ID 无效', 400);
    }
    const pending = conn.pending.get(envelope.id);
    if (!pending) return;
    conn.pending.delete(envelope.id);
    clearTimeout(pending.timer);
    if (envelope.ok === true) {
      pending.resolve(envelope.result ?? null);
      return;
    }
    if (envelope.ok !== false) {
      pending.reject(new NcsError('INVALID_AGENT_RESPONSE', 'Agent 响应格式无效', 502));
      return;
    }
    const safe = envelope.error && typeof envelope.error === 'object' ? envelope.error : {};
    const status = Number.isSafeInteger(safe.status) && safe.status >= 400 && safe.status <= 599 ? safe.status : 502;
    pending.reject(
      new NcsError(
        typeof safe.code === 'string' ? safe.code : 'AGENT_ERROR',
        typeof safe.message === 'string' ? safe.message : 'Agent 执行失败',
        status,
        safe.details,
      ),
    );
  }

  rejectPending(conn, error) {
    for (const pending of conn.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    conn.pending.clear();
  }

  drop(conn, reason) {
    if (this.connections.get(conn.agentId) === conn) this.connections.delete(conn.agentId);
    this.rejectPending(conn, new NcsError('AGENT_OFFLINE', 'Agent 连接已断开', 503));
    try {
      conn.ws.close(4001, String(reason || 'disconnected').slice(0, 120));
    } catch {
      conn.ws.terminate?.();
    }
    const timer = setTimeout(() => conn.ws.terminate?.(), 2000);
    timer.unref?.();
  }

  heartbeat() {
    const now = Date.now();
    for (const conn of this.connections.values()) {
      if (!conn.alive) {
        conn.ws.terminate();
        continue;
      }
      conn.alive = false;
      try {
        conn.ws.ping();
      } catch {
        conn.ws.terminate();
        continue;
      }
      // Keep the stored timestamp reasonably fresh without rewriting the
      // store on every 30s ping; in-memory lastSeenAt covers the UI meanwhile.
      if (now - conn.persistedAt >= 5 * 60 * 1000) {
        conn.persistedAt = now;
        this.touchLastSeen(conn.agentId).catch(() => {});
      }
    }
  }

  isOnline(agentId) {
    const conn = this.connections.get(agentId);
    return Boolean(conn && conn.ws.readyState === 1);
  }

  connectionInfo(agentId) {
    const conn = this.connections.get(agentId);
    if (!conn) return null;
    return { connectedAt: conn.connectedAt, ip: conn.ip, online: conn.ws.readyState === 1 };
  }

  cachedInfo(agentId) {
    const cached = this.infoCache.get(agentId);
    return cached ? cached.data : null;
  }

  async request(agentId, cmd, payload = {}, { timeoutMs = 30000 } = {}) {
    const conn = this.connections.get(agentId);
    if (!conn || conn.ws.readyState !== 1) {
      throw new NcsError('AGENT_OFFLINE', 'Agent 离线', 503);
    }
    if (conn.pending.size >= LIMITS.maxConcurrentCommands) {
      throw new NcsError('AGENT_BUSY', 'Agent 正在处理过多命令，请稍后重试', 429);
    }
    if (typeof cmd !== 'string' || cmd.length === 0 || cmd.length > 64) {
      throw new NcsError('INVALID_COMMAND', '命令无效', 400);
    }
    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        conn.pending.delete(id);
        reject(new NcsError('AGENT_TIMEOUT', '等待 Agent 响应超时', 504));
      }, Math.max(5000, Math.min(timeoutMs, 120000)));
      timer.unref?.();
      conn.pending.set(id, { resolve, reject, timer, cmd });
      let envelope;
      try {
        envelope = createSignedEnvelope({
          kind: 'request',
          fields: { id, cmd, payload },
          privateKey: this.privateKey,
        });
        conn.ws.send(JSON.stringify(envelope), (error) => {
          if (!error) return;
          conn.pending.delete(id);
          clearTimeout(timer);
          reject(new NcsError('AGENT_SEND_FAILED', '向 Agent 发送命令失败', 503));
        });
      } catch (error) {
        conn.pending.delete(id);
        clearTimeout(timer);
        reject(error instanceof NcsError ? error : new NcsError('AGENT_SEND_FAILED', '发送命令失败', 503));
      }
    });
  }

  async getInfo(agentId, { force = false } = {}) {
    const cached = this.infoCache.get(agentId);
    if (!force && cached && Date.now() - cached.at < 15000) return cached.data;
    const data = await this.request(agentId, 'system.info', {}, { timeoutMs: 15000 });
    this.infoCache.set(agentId, { at: Date.now(), data });
    return data;
  }

  disconnect(agentId, reason = 'revoked') {
    const conn = this.connections.get(agentId);
    if (conn) this.drop(conn, reason);
    this.infoCache.delete(agentId);
  }

  async close() {
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    this.heartbeatTimer = null;
    for (const conn of this.connections.values()) {
      this.rejectPending(conn, new NcsError('SERVER_SHUTDOWN', '主服务器正在关闭', 503));
      try {
        conn.ws.terminate();
      } catch {
        // Ignore.
      }
    }
    this.connections.clear();
    await new Promise((resolve) => {
      let settled = false;
      const done = () => {
        if (settled) return;
        settled = true;
        resolve();
      };
      try {
        this.wss.close(done);
      } catch {
        done();
      }
      const timer = setTimeout(done, 500);
      timer.unref?.();
    });
  }
}
