import crypto from 'node:crypto';
import {
  NcsError,
  publicKeyFingerprint,
  validateEd25519PublicKey,
} from '@ncs/shared';
import { safeEqualString, sha256Hex } from './auth-utils.js';

const AGENT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_AGENTS = 200;
const MAX_AGENT_NAME = 64;

const REMOTE_TIMEOUTS = {
  'system.info': 20000,
  'workspace.options': 20000,
  'workspace.set': 30000,
  'fs.list': 20000,
  'fs.read': 20000,
  'fs.write': 60000,
  'backup.list': 20000,
  'backup.restore': 60000,
  'nginx.test': 30000,
  'nginx.reload': 45000,
  'nginx.restart': 120000,
  'cert.list': 30000,
  'cert.upload': 60000,
  'cert.uploadArchive': 60000,
};

function validateAgentName(name) {
  if (typeof name !== 'string') throw new NcsError('INVALID_NAME', '服务器名称无效', 400);
  const trimmed = name.trim();
  if (trimmed.length < 1 || trimmed.length > MAX_AGENT_NAME || /[\u0000-\u001f\u007f]/.test(trimmed)) {
    throw new NcsError('INVALID_NAME', `服务器名称必须为 1-${MAX_AGENT_NAME} 个字符且不含控制字符`, 400);
  }
  return trimmed;
}

function createEnrollmentToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function newTokenRecord(minutes) {
  const token = createEnrollmentToken();
  return {
    token,
    hash: sha256Hex(token),
    expiresAt: new Date(Date.now() + minutes * 60 * 1000).toISOString(),
  };
}

function sanitizeEnrollmentMeta(meta) {
  if (!meta || typeof meta !== 'object' || Array.isArray(meta)) return {};
  const output = {};
  for (const key of ['hostname', 'platform', 'release', 'agentVersion']) {
    const value = meta[key];
    if (typeof value === 'string' && value.length > 0) output[key] = value.slice(0, 128);
  }
  return output;
}

export class ServerManager {
  constructor({ store, hub, localEngine, mainPublicKey, publicUrl, enrollmentTokenMinutes, logger = console }) {
    this.store = store;
    this.hub = hub;
    this.localEngine = localEngine;
    this.mainPublicKey = mainPublicKey;
    this.mainKeyFingerprint = publicKeyFingerprint(mainPublicKey);
    this.publicUrl = publicUrl;
    this.enrollmentTokenMinutes = enrollmentTokenMinutes;
    this.logger = logger;
    this.localInfoCache = null;
  }

  list() {
    const data = this.store.snapshot();
    const servers = [
      {
        id: 'local',
        name: '主服务器（本地）',
        kind: 'local',
        status: 'online',
        online: true,
        keyFingerprint: null,
        createdAt: data.settings.createdAt || null,
        lastSeenAt: new Date().toISOString(),
        info: this.localInfoCache,
      },
    ];
    for (const agent of data.agents) {
      servers.push({
        id: agent.id,
        name: agent.name,
        kind: 'agent',
        status: agent.status,
        online: agent.status === 'active' && this.hub.isOnline(agent.id),
        keyFingerprint: agent.keyFingerprint || null,
        createdAt: agent.createdAt,
        lastSeenAt: agent.lastSeenAt || null,
        enrolledAt: agent.enrolledAt || null,
        info: this.hub.cachedInfo(agent.id),
      });
    }
    return {
      servers,
      mainKeyFingerprint: this.mainKeyFingerprint,
      mainUrl: this.publicUrl,
      enrollmentTokenMinutes: this.enrollmentTokenMinutes,
    };
  }

  getAgentRecord(agentId) {
    if (typeof agentId !== 'string' || !AGENT_ID_RE.test(agentId)) {
      throw new NcsError('INVALID_SERVER', '服务器标识无效', 400);
    }
    const data = this.store.snapshot();
    const agent = data.agents.find((item) => item.id === agentId);
    if (!agent) throw new NcsError('SERVER_NOT_FOUND', '服务器不存在', 404);
    return agent;
  }

  async info(serverId, { force = false } = {}) {
    if (serverId === 'local') {
      if (!force && this.localInfoCache && Date.now() - this.localInfoCache.at < 15000) {
        return this.localInfoCache.data;
      }
      const data = await this.localEngine.getInfo();
      this.localInfoCache = { at: Date.now(), data };
      return data;
    }
    const agent = this.getAgentRecord(serverId);
    if (agent.status !== 'active') throw new NcsError('AGENT_NOT_ACTIVE', 'Agent 尚未激活或已撤销', 409);
    if (!this.hub.isOnline(serverId)) {
      throw new NcsError('AGENT_OFFLINE', 'Agent 离线', 503);
    }
    return this.hub.getInfo(serverId, { force });
  }

  async execute(serverId, command, payload = {}, { timeoutMs } = {}) {
    if (typeof command !== 'string' || command.length === 0 || command.length > 64) {
      throw new NcsError('INVALID_COMMAND', '命令无效', 400);
    }
    if (serverId === 'local') {
      return this.localEngine.execute(command, payload);
    }
    const agent = this.getAgentRecord(serverId);
    if (agent.status !== 'active') throw new NcsError('AGENT_NOT_ACTIVE', 'Agent 尚未激活或已撤销', 409);
    return this.hub.request(serverId, command, payload, {
      timeoutMs: timeoutMs || REMOTE_TIMEOUTS[command] || 30000,
    });
  }

  async createAgent(name) {
    const validName = validateAgentName(name);
    const data = this.store.snapshot();
    if (data.agents.length >= MAX_AGENTS) throw new NcsError('AGENT_LIMIT', 'Agent 数量达到上限', 429);
    const id = crypto.randomUUID();
    const tokenRecord = newTokenRecord(this.enrollmentTokenMinutes);
    const now = new Date().toISOString();
    await this.store.mutate((draft) => {
      draft.agents.push({
        id,
        name: validName,
        status: 'pending',
        publicKey: null,
        keyFingerprint: null,
        enrollTokenHash: tokenRecord.hash,
        enrollExpiresAt: tokenRecord.expiresAt,
        createdAt: now,
        updatedAt: now,
        enrolledAt: null,
        enrolledIp: null,
        lastSeenAt: null,
        lastMeta: {},
      });
    });
    return {
      agent: { id, name: validName, status: 'pending' },
      enrollmentToken: tokenRecord.token,
      enrollExpiresAt: tokenRecord.expiresAt,
      mainUrl: this.publicUrl,
    };
  }

  async regenerateEnrollmentToken(agentId) {
    const agent = this.getAgentRecord(agentId);
    if (agent.status === 'active') {
      throw new NcsError('AGENT_ACTIVE', '请先撤销正在使用的 Agent，再重新生成注册令牌', 409);
    }
    const tokenRecord = newTokenRecord(this.enrollmentTokenMinutes);
    await this.store.mutate((draft) => {
      const target = draft.agents.find((item) => item.id === agentId);
      if (!target) throw new NcsError('SERVER_NOT_FOUND', '服务器不存在', 404);
      target.status = 'pending';
      target.publicKey = null;
      target.keyFingerprint = null;
      target.enrollTokenHash = tokenRecord.hash;
      target.enrollExpiresAt = tokenRecord.expiresAt;
      target.updatedAt = new Date().toISOString();
    });
    return {
      agent: { id: agentId, name: agent.name, status: 'pending' },
      enrollmentToken: tokenRecord.token,
      enrollExpiresAt: tokenRecord.expiresAt,
      mainUrl: this.publicUrl,
    };
  }

  async revokeAgent(agentId) {
    const agent = this.getAgentRecord(agentId);
    await this.store.mutate((draft) => {
      const target = draft.agents.find((item) => item.id === agentId);
      if (!target) throw new NcsError('SERVER_NOT_FOUND', '服务器不存在', 404);
      target.status = 'revoked';
      target.enrollTokenHash = null;
      target.enrollExpiresAt = null;
      target.updatedAt = new Date().toISOString();
    });
    this.hub.disconnect(agentId, 'revoked');
    return { agent: { id: agentId, name: agent.name, status: 'revoked' } };
  }

  async deleteAgent(agentId) {
    const agent = this.getAgentRecord(agentId);
    this.hub.disconnect(agentId, 'deleted');
    await this.store.mutate((draft) => {
      draft.agents = draft.agents.filter((item) => item.id !== agentId);
    });
    return { deleted: true, name: agent.name };
  }

  async enrollAgent({ agentId, token, publicKey, meta, ip = null }) {
    if (typeof agentId !== 'string' || !AGENT_ID_RE.test(agentId)) {
      throw new NcsError('INVALID_AGENT', 'Agent ID 无效', 401);
    }
    if (typeof token !== 'string' || token.length < 16 || token.length > 256) {
      throw new NcsError('INVALID_ENROLL_TOKEN', '注册令牌无效', 401);
    }
    if (typeof publicKey !== 'string' || publicKey.length > 4096) {
      throw new NcsError('INVALID_KEY', '公钥无效', 400);
    }
    const { fingerprint } = validateEd25519PublicKey(publicKey);
    const tokenHash = sha256Hex(token);

    return this.store.mutate((draft) => {
      const agent = draft.agents.find((item) => item.id === agentId);
      if (!agent) throw new NcsError('INVALID_ENROLL_TOKEN', '注册令牌无效', 401);
      if (agent.status !== 'pending') throw new NcsError('AGENT_NOT_PENDING', 'Agent 当前状态不允许注册', 409);
      if (!agent.enrollTokenHash || !safeEqualString(tokenHash, agent.enrollTokenHash)) {
        throw new NcsError('INVALID_ENROLL_TOKEN', '注册令牌无效', 401);
      }
      if (!agent.enrollExpiresAt || Date.now() > new Date(agent.enrollExpiresAt).getTime()) {
        agent.enrollTokenHash = null;
        agent.enrollExpiresAt = null;
        throw new NcsError('ENROLL_TOKEN_EXPIRED', '注册令牌已过期，请重新生成', 401);
      }
      const now = new Date().toISOString();
      agent.status = 'active';
      agent.publicKey = publicKey;
      agent.keyFingerprint = fingerprint;
      agent.enrollTokenHash = null;
      agent.enrollExpiresAt = null;
      agent.enrolledAt = now;
      agent.enrolledIp = ip;
      agent.updatedAt = now;
      agent.lastMeta = sanitizeEnrollmentMeta(meta);
      return { agent: { id: agent.id, name: agent.name }, mainPublicKey: this.mainPublicKey };
    });
  }
}
