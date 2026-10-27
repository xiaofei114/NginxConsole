import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { LIMITS, createLogger } from '@ncs/shared';
import { ensurePrivateDirectory } from '@ncs/core';

const MAX_AUDIT_BYTES = 10 * 1024 * 1024;
const ROTATIONS_KEPT = 10;
const SECRET_KEY_RE = /^(password|passwd|token|secret|privatekey|keypem|certpem|content|authorization|cookie|recoverycode)$/i;
const logger = createLogger({ app: 'main', component: 'audit' });

function sanitize(value, depth = 0) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value.length > 512 ? `${value.slice(0, 512)}…` : value;
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (depth > 3) return '[truncated]';
  if (Array.isArray(value)) return value.slice(0, 20).map((item) => sanitize(item, depth + 1));
  if (typeof value === 'object') {
    const output = {};
    for (const [key, item] of Object.entries(value).slice(0, 30)) {
      if (SECRET_KEY_RE.test(key) || /(?:privatekey|pem|password|token|secret)$/i.test(key)) continue;
      output[key] = sanitize(item, depth + 1);
    }
    return output;
  }
  return '[unsupported]';
}

export class AuditLog {
  constructor(file) {
    this.file = file;
    this.queue = Promise.resolve();
    this.lastRotateCheck = 0;
  }

  async init() {
    await ensurePrivateDirectory(path.dirname(this.file), 0o700);
    try {
      const stat = await fs.stat(this.file);
      if (process.platform !== 'win32') await fs.chmod(this.file, 0o600).catch(() => {});
      if (stat.size > MAX_AUDIT_BYTES) await this.rotate();
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      await fs.writeFile(this.file, '', { mode: 0o600, flag: 'a' });
    }
  }

  async rotate() {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const target = `${this.file}.${stamp}`;
    await fs.rename(this.file, target).catch(() => {});
    await fs.writeFile(this.file, '', { mode: 0o600, flag: 'a' });
    let names = [];
    try {
      names = await fs.readdir(path.dirname(this.file));
    } catch {
      return;
    }
    const rotations = names
      .filter((name) => name.startsWith(`${path.basename(this.file)}.`))
      .sort()
      .reverse();
    for (const stale of rotations.slice(ROTATIONS_KEPT)) {
      await fs.unlink(path.join(path.dirname(this.file), stale)).catch(() => {});
    }
  }

  append(entry) {
    const record = {
      id: crypto.randomUUID(),
      ts: new Date().toISOString(),
      action: typeof entry.action === 'string' ? entry.action.slice(0, 80) : 'unknown',
      result: entry.result === 'failure' ? 'failure' : 'success',
      userId: entry.userId || null,
      username: entry.username || null,
      ip: entry.ip || null,
      serverId: entry.serverId || null,
      serverName: entry.serverName || null,
      target: entry.target ? String(entry.target).slice(0, 512) : null,
      requestId: entry.requestId || null,
      meta: entry.meta ? sanitize(entry.meta) : null,
    };
    const line = `${JSON.stringify(record)}\n`;
    this.queue = this.queue
      .then(async () => {
        const now = Date.now();
        if (now - this.lastRotateCheck > 60 * 1000) {
          this.lastRotateCheck = now;
          try {
            const stat = await fs.stat(this.file);
            if (stat.size > MAX_AUDIT_BYTES) await this.rotate();
          } catch {
            // Ignore; append below will surface real errors.
          }
        }
        await fs.appendFile(this.file, line, { mode: 0o600 });
      })
      .catch((error) => {
        logger.error('写入审计日志失败', error);
      });
    return this.queue;
  }

  async query({ limit = 100, serverId = null, action = null, result = null } = {}) {
    const max = Math.max(1, Math.min(Number(limit) || 100, 200));
    let handle;
    let size;
    try {
      handle = await fs.open(this.file, 'r');
      size = (await handle.stat()).size;
    } catch {
      return [];
    }
    try {
      const start = Math.max(0, size - LIMITS.maxAuditReadBytes);
      const length = size - start;
      const buffer = Buffer.alloc(length);
      await handle.read(buffer, 0, length, start);
      const text = buffer.toString('utf8');
      const lines = text.split('\n');
      if (start > 0) lines.shift();
      const results = [];
      for (let index = lines.length - 1; index >= 0 && results.length < max; index -= 1) {
        const line = lines[index].trim();
        if (!line) continue;
        try {
          const record = JSON.parse(line);
          if (serverId && record.serverId !== serverId) continue;
          if (action && !String(record.action).startsWith(action)) continue;
          if (result && record.result !== result) continue;
          results.push(record);
        } catch {
          // Skip malformed lines.
        }
      }
      return results;
    } finally {
      await handle.close();
    }
  }

  async close() {
    await this.queue.catch(() => {});
  }
}
