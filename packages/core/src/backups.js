import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { LIMITS, NcsError, normalizeRelativePath } from '@ncs/shared';
import { atomicWriteFile, ensurePrivateDirectory, readFileLimited, sha256Hex } from './fs-utils.js';

const BACKUP_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export class BackupManager {
  constructor(stateDir) {
    this.directory = path.join(stateDir, 'backups');
  }

  async init() {
    await ensurePrivateDirectory(this.directory, 0o700);
  }

  async create({ workspace, relPath, absolutePath, reason = 'write', content = null, mode = null }) {
    const normalized = normalizeRelativePath(relPath, { allowEmpty: false });
    const id = crypto.randomUUID();
    let data = content;
    let stat = null;
    if (data === null) {
      stat = await fs.stat(absolutePath);
      data = await readFileLimited(absolutePath, LIMITS.maxFileBytes);
    }
    const effectiveMode = mode ?? (stat ? stat.mode & 0o777 : 0o600);
    const contentPath = path.join(this.directory, `${id}.bak`);
    const metaPath = path.join(this.directory, `${id}.json`);
    await atomicWriteFile(contentPath, data, { mode: 0o600 });
    const meta = {
      id,
      createdAt: new Date().toISOString(),
      reason,
      targetRel: normalized,
      workspace,
      size: data.length,
      mode: effectiveMode,
      sha256: sha256Hex(data),
    };
    await atomicWriteFile(metaPath, JSON.stringify(meta, null, 2), { mode: 0o600 });
    await this.prune();
    return meta;
  }

  async list(limit = 50) {
    let names;
    try {
      names = await fs.readdir(this.directory);
    } catch (error) {
      if (error?.code === 'ENOENT') return [];
      throw error;
    }
    const metas = [];
    for (const name of names) {
      if (!name.endsWith('.json')) continue;
      try {
        const raw = await readFileLimited(path.join(this.directory, name), 16 * 1024);
        const meta = JSON.parse(raw.toString('utf8'));
        if (!meta || !BACKUP_ID_RE.test(meta.id)) continue;
        metas.push(meta);
      } catch {
        // Ignore a corrupt backup metadata file; never let it break the console.
      }
    }
    metas.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
    return metas.slice(0, Math.max(1, Math.min(Number(limit) || 50, LIMITS.maxBackups)));
  }

  async get(id) {
    if (typeof id !== 'string' || !BACKUP_ID_RE.test(id)) {
      throw new NcsError('INVALID_BACKUP', '备份标识无效', 400);
    }
    let meta;
    try {
      const raw = await readFileLimited(path.join(this.directory, `${id}.json`), 16 * 1024);
      meta = JSON.parse(raw.toString('utf8'));
    } catch {
      throw new NcsError('BACKUP_NOT_FOUND', '备份不存在', 404);
    }
    if (!meta || meta.id !== id) throw new NcsError('BACKUP_NOT_FOUND', '备份不存在', 404);
    const targetRel = normalizeRelativePath(meta.targetRel, { allowEmpty: false });
    let content;
    try {
      content = await readFileLimited(path.join(this.directory, `${id}.bak`), LIMITS.maxFileBytes);
    } catch {
      throw new NcsError('BACKUP_NOT_FOUND', '备份内容不存在', 404);
    }
    if (sha256Hex(content) !== meta.sha256) {
      throw new NcsError('BACKUP_CORRUPT', '备份内容校验失败', 500);
    }
    return { meta: { ...meta, targetRel }, content };
  }

  async prune(maxEntries = LIMITS.maxBackups) {
    let names;
    try {
      names = await fs.readdir(this.directory);
    } catch {
      return;
    }
    const metas = [];
    for (const name of names) {
      if (!name.endsWith('.json')) continue;
      const id = name.slice(0, -5);
      if (!BACKUP_ID_RE.test(id)) continue;
      try {
        const stat = await fs.stat(path.join(this.directory, name));
        metas.push({ id, mtime: stat.mtimeMs });
      } catch {
        // Ignore.
      }
    }
    metas.sort((a, b) => b.mtime - a.mtime);
    for (const stale of metas.slice(maxEntries)) {
      await Promise.allSettled([
        fs.unlink(path.join(this.directory, `${stale.id}.json`)),
        fs.unlink(path.join(this.directory, `${stale.id}.bak`)),
      ]);
    }
  }
}
