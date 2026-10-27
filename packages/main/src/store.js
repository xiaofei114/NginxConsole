import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { NcsError } from '@ncs/shared';
import { atomicWriteFile, ensurePrivateDirectory } from '@ncs/core';
import { hashPassword } from './auth-utils.js';

const STORE_VERSION = 1;
const MAX_STORE_BYTES = 2 * 1024 * 1024;

function defaultData() {
  return {
    version: STORE_VERSION,
    users: [],
    agents: [],
    settings: {
      localWorkspace: null,
      createdAt: new Date().toISOString(),
    },
  };
}

function validateUser(user) {
  if (!user || typeof user !== 'object') return false;
  if (typeof user.id !== 'string' || typeof user.username !== 'string' || typeof user.passwordHash !== 'string') return false;
  if (!Number.isInteger(user.failedLogins) || user.failedLogins < 0) return false;
  if (!Array.isArray(user.recoveryCodeHashes)) return false;
  return true;
}

function validateAgent(agent) {
  if (!agent || typeof agent !== 'object') return false;
  if (typeof agent.id !== 'string' || typeof agent.name !== 'string') return false;
  if (!['pending', 'active', 'revoked'].includes(agent.status)) return false;
  return true;
}

export class Store {
  constructor(file, data, { adminSeeded = false } = {}) {
    this.file = file;
    this.data = data;
    this.adminSeeded = adminSeeded;
    this.queue = Promise.resolve();
  }

  static async open({ file, adminUsername, adminPassword }) {
    const resolved = path.resolve(file);
    await ensurePrivateDirectory(path.dirname(resolved), 0o700);
    let data;
    let adminSeeded = false;
    try {
      const stat = await fs.stat(resolved);
      if (stat.size > MAX_STORE_BYTES) throw new Error('store too large');
      const raw = await fs.readFile(resolved, 'utf8');
      data = JSON.parse(raw);
    } catch (error) {
      if (error?.code === 'ENOENT') {
        data = defaultData();
      } else {
        throw new NcsError('STORE_CORRUPT', '数据文件无法读取或已损坏，请从备份恢复', 500);
      }
    }
    if (!data || data.version !== STORE_VERSION || !Array.isArray(data.users) || !Array.isArray(data.agents)) {
      throw new NcsError('STORE_CORRUPT', '数据文件格式无效', 500);
    }
    data.settings = data.settings && typeof data.settings === 'object' ? data.settings : { localWorkspace: null };
    data.users = data.users.filter(validateUser);
    data.agents = data.agents.filter(validateAgent);

    if (data.users.length === 0) {
      const passwordHash = await hashPassword(adminPassword);
      const now = new Date().toISOString();
      data.users.push({
        id: crypto.randomUUID(),
        username: adminUsername,
        passwordHash,
        totpEnabled: false,
        totpSecretEnc: null,
        totpPendingEnc: null,
        totpPendingCreatedAt: null,
        totpLastCounter: 0,
        recoveryCodeHashes: [],
        failedLogins: 0,
        lockedUntil: 0,
        createdAt: now,
        updatedAt: now,
        lastLoginAt: null,
      });
      adminSeeded = true;
    }

    const store = new Store(resolved, data, { adminSeeded });
    await store.persist();
    if (process.platform !== 'win32') await fs.chmod(resolved, 0o600).catch(() => {});
    return store;
  }

  snapshot() {
    return structuredClone(this.data);
  }

  findUser(username) {
    return this.data.users.find((user) => user.username === username) || null;
  }

  findUserById(id) {
    return this.data.users.find((user) => user.id === id) || null;
  }

  findAgent(id) {
    return this.data.agents.find((agent) => agent.id === id) || null;
  }

  async persist() {
    const serialized = JSON.stringify(this.data, null, 2);
    await atomicWriteFile(this.file, serialized, { mode: 0o600 });
  }

  mutate(mutator) {
    const run = this.queue.then(async () => {
      const draft = structuredClone(this.data);
      const result = await mutator(draft);
      if (draft.version !== STORE_VERSION || !Array.isArray(draft.users) || !Array.isArray(draft.agents)) {
        throw new NcsError('STORE_INVALID', '数据修改导致格式无效', 500);
      }
      if (draft.users.some((user) => !validateUser(user)) || draft.agents.some((agent) => !validateAgent(agent))) {
        throw new NcsError('STORE_INVALID', '数据修改导致记录无效', 500);
      }
      await atomicWriteFile(this.file, JSON.stringify(draft, null, 2), { mode: 0o600 });
      this.data = draft;
      return result;
    });
    this.queue = run.catch(() => {});
    return run;
  }
}

export { STORE_VERSION };
