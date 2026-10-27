import crypto from 'node:crypto';
import { NcsError } from '@ncs/shared';
import { randomToken, sha256Hex } from './auth-utils.js';

const SESSION_TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

export class SessionStore {
  constructor({ idleTtlMs, absoluteTtlMs }) {
    this.idleTtlMs = idleTtlMs;
    this.absoluteTtlMs = absoluteTtlMs;
    this.sessions = new Map();
    this.cleanupTimer = null;
    this.maxSessionsPerUser = 10;
  }

  create(userId, { ip = '', userAgent = '' } = {}) {
    this.prune();
    const token = randomToken(32);
    const tokenHash = sha256Hex(token);
    const now = Date.now();
    const existing = [...this.sessions.values()].filter((session) => session.userId === userId);
    if (existing.length >= this.maxSessionsPerUser) {
      existing.sort((a, b) => a.createdAt - b.createdAt);
      for (const stale of existing.slice(0, existing.length - this.maxSessionsPerUser + 1)) {
        this.sessions.delete(stale.tokenHash);
      }
    }
    const session = {
      tokenHash,
      csrfToken: randomToken(32),
      userId,
      ip,
      userAgent: String(userAgent || '').slice(0, 256),
      createdAt: now,
      lastSeenAt: now,
      absoluteExpiresAt: now + this.absoluteTtlMs,
    };
    this.sessions.set(tokenHash, session);
    return { token, session };
  }

  get(token) {
    if (typeof token !== 'string' || !SESSION_TOKEN_RE.test(token)) return null;
    const tokenHash = sha256Hex(token);
    const session = this.sessions.get(tokenHash);
    if (!session) return null;
    const now = Date.now();
    if (now >= session.absoluteExpiresAt || now - session.lastSeenAt > this.idleTtlMs) {
      this.sessions.delete(tokenHash);
      return null;
    }
    session.lastSeenAt = now;
    return session;
  }

  verifyCsrf(session, headerToken) {
    if (!session || typeof headerToken !== 'string' || headerToken.length === 0) return false;
    const left = Buffer.from(session.csrfToken, 'utf8');
    const right = Buffer.from(headerToken, 'utf8');
    if (left.length !== right.length) return false;
    return crypto.timingSafeEqual(left, right);
  }

  destroy(token) {
    if (typeof token !== 'string' || !SESSION_TOKEN_RE.test(token)) return;
    this.sessions.delete(sha256Hex(token));
  }

  destroyUserSessions(userId, { exceptToken = null } = {}) {
    const exceptHash = typeof exceptToken === 'string' && SESSION_TOKEN_RE.test(exceptToken) ? sha256Hex(exceptToken) : null;
    for (const [hash, session] of this.sessions) {
      if (session.userId === userId && hash !== exceptHash) this.sessions.delete(hash);
    }
  }

  destroyAll() {
    this.sessions.clear();
  }

  prune(now = Date.now()) {
    for (const [hash, session] of this.sessions) {
      if (now >= session.absoluteExpiresAt || now - session.lastSeenAt > this.idleTtlMs) {
        this.sessions.delete(hash);
      }
    }
  }

  startCleanup() {
    if (this.cleanupTimer) return;
    this.cleanupTimer = setInterval(() => this.prune(), 5 * 60 * 1000);
    this.cleanupTimer.unref?.();
  }

  stop() {
    if (this.cleanupTimer) clearInterval(this.cleanupTimer);
    this.cleanupTimer = null;
  }

  count() {
    return this.sessions.size;
  }
}

export function requireSession(store, token) {
  const session = store.get(token);
  if (!session) throw new NcsError('UNAUTHENTICATED', '登录状态已失效，请重新登录', 401);
  return session;
}
