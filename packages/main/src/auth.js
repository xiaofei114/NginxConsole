import {
  NcsError,
} from '@ncs/shared';
import {
  decryptSecret,
  encryptSecret,
  generateRecoveryCodes,
  hashPassword,
  hashRecoveryCode,
  isRecoveryCodeFormat,
  normalizeRecoveryCode,
  safeEqualString,
  verifyDummyPassword,
  verifyPassword,
  validateNewPassword,
} from './auth-utils.js';
import { generateTotpSecret, isTotpCodeFormat, totpUri, verifyTotp } from './totp.js';
import { getSessionToken } from './http-security.js';
import { requireSession } from './sessions.js';

const MAX_LOCK_MS = 24 * 60 * 60 * 1000;
const BASE_LOCK_MS = 15 * 60 * 1000;
const TOTP_PENDING_MS = 10 * 60 * 1000;
const TOTP_ENABLED_MAX_FAILURES = 5;

function lockDurationForFailures(failures) {
  if (failures < TOTP_ENABLED_MAX_FAILURES) return 0;
  const exponent = Math.min(failures - TOTP_ENABLED_MAX_FAILURES, 10);
  return Math.min(MAX_LOCK_MS, BASE_LOCK_MS * 2 ** exponent);
}

export class AuthService {
  constructor({ store, sessions, audit, masterKey, config }) {
    this.store = store;
    this.sessions = sessions;
    this.audit = audit;
    this.masterKey = masterKey;
    this.config = config;
    this.cookieMaxAgeSeconds = config.sessionAbsoluteMinutes * 60;
  }

  userView(user) {
    return {
      id: user.id,
      username: user.username,
      totpEnabled: Boolean(user.totpEnabled),
      recoveryCodesRemaining: Array.isArray(user.recoveryCodeHashes) ? user.recoveryCodeHashes.length : 0,
      lastLoginAt: user.lastLoginAt || null,
      createdAt: user.createdAt || null,
    };
  }

  async login({ username, password, totp, recoveryCode, ip, userAgent }) {
    if (typeof username !== 'string' || typeof password !== 'string'
      || username.length < 1 || username.length > 64
      || password.length < 1 || Buffer.byteLength(password, 'utf8') > 1024) {
      throw new NcsError('INVALID_CREDENTIALS', '用户名或口令错误', 401);
    }
    if (totp !== undefined && totp !== null && typeof totp !== 'string') {
      throw new NcsError('INVALID_CREDENTIALS', '用户名或口令错误', 401);
    }
    if (recoveryCode !== undefined && recoveryCode !== null && typeof recoveryCode !== 'string') {
      throw new NcsError('INVALID_CREDENTIALS', '用户名或口令错误', 401);
    }
    if (totp && recoveryCode) {
      throw new NcsError('INVALID_SECOND_FACTOR', '请只提供一种两步验证方式', 400);
    }
    if (totp && !isTotpCodeFormat(totp)) {
      throw new NcsError('INVALID_SECOND_FACTOR', '两步验证码格式无效', 400);
    }

    const user = this.store.findUser(username);
    if (!user) {
      await verifyDummyPassword(password);
      await this.audit.append({
        action: 'auth.login.failed',
        result: 'failure',
        username: username.slice(0, 64),
        ip,
        meta: { reason: 'unknown_user' },
      });
      throw new NcsError('INVALID_CREDENTIALS', '用户名或口令错误', 401);
    }

    const lockedUntil = Number(user.lockedUntil) || 0;
    if (lockedUntil > Date.now()) {
      await this.audit.append({
        action: 'auth.login.locked',
        result: 'failure',
        userId: user.id,
        username: user.username,
        ip,
      });
      throw new NcsError('ACCOUNT_LOCKED', '登录失败次数过多，账号已被临时锁定', 423, {
        retryAfter: Math.ceil((lockedUntil - Date.now()) / 1000),
      });
    }

    const passwordCheck = await verifyPassword(password, user.passwordHash);
    if (!passwordCheck.ok) {
      await this.registerFailure(user.id);
      await this.audit.append({
        action: 'auth.login.failed',
        result: 'failure',
        userId: user.id,
        username: user.username,
        ip,
        meta: { reason: 'bad_password' },
      });
      throw new NcsError('INVALID_CREDENTIALS', '用户名或口令错误', 401);
    }

    if (user.totpEnabled) {
      if (!totp && !recoveryCode) {
        throw new NcsError('TOTP_REQUIRED', '请输入两步验证码', 401, { totpRequired: true });
      }
      let factor;
      try {
        factor = await this.verifySecondFactor(user.id, { totp, recoveryCode });
      } catch (error) {
        await this.registerFailure(user.id);
        await this.audit.append({
          action: 'auth.login.failed',
          result: 'failure',
          userId: user.id,
          username: user.username,
          ip,
          meta: { reason: 'totp_unavailable' },
        });
        throw error;
      }
      if (!factor.ok) {
        await this.registerFailure(user.id);
        await this.audit.append({
          action: 'auth.login.failed',
          result: 'failure',
          userId: user.id,
          username: user.username,
          ip,
          meta: { reason: recoveryCode ? 'bad_recovery_code' : 'bad_totp' },
        });
        throw new NcsError('INVALID_SECOND_FACTOR', '两步验证码无效', 401);
      }
    }

    const updated = await this.store.mutate(async (draft) => {
      const target = draft.users.find((item) => item.id === user.id);
      if (!target) throw new NcsError('INVALID_CREDENTIALS', '用户名或口令错误', 401);
      target.failedLogins = 0;
      target.lockedUntil = 0;
      target.lastLoginAt = new Date().toISOString();
      target.updatedAt = new Date().toISOString();
      if (passwordCheck.needsRehash) {
        target.passwordHash = await hashPassword(password);
      }
      return this.userView(target);
    });

    this.sessions.destroyUserSessions(updated.id);
    const { token, session } = this.sessions.create(updated.id, { ip, userAgent });
    await this.audit.append({
      action: 'auth.login',
      userId: updated.id,
      username: updated.username,
      ip,
    });
    return { user: updated, token, session };
  }

  async registerFailure(userId) {
    const outcome = await this.store.mutate((draft) => {
      const target = draft.users.find((item) => item.id === userId);
      if (!target) return { lockedUntil: 0, failedLogins: 0 };
      target.failedLogins = Math.min((Number(target.failedLogins) || 0) + 1, 100);
      const lockMs = lockDurationForFailures(target.failedLogins);
      if (lockMs > 0) target.lockedUntil = Date.now() + lockMs;
      target.updatedAt = new Date().toISOString();
      return { failedLogins: target.failedLogins, lockedUntil: target.lockedUntil || 0 };
    });
    return outcome;
  }

  async verifySecondFactor(userId, { totp = null, recoveryCode = null }) {
    if (recoveryCode) {
      if (!isRecoveryCodeFormat(recoveryCode)) return { ok: false, recoveryUsed: false };
      const hash = hashRecoveryCode(this.masterKey, normalizeRecoveryCode(recoveryCode));
      if (!hash) return { ok: false, recoveryUsed: false };
      return this.store.mutate((draft) => {
        const target = draft.users.find((item) => item.id === userId);
        if (!target || !target.totpEnabled) return { ok: false, recoveryUsed: false };
        const index = target.recoveryCodeHashes.findIndex((item) => safeEqualString(item, hash));
        if (index < 0) return { ok: false, recoveryUsed: false };
        target.recoveryCodeHashes.splice(index, 1);
        target.updatedAt = new Date().toISOString();
        return { ok: true, recoveryUsed: true };
      });
    }
    if (!totp || !isTotpCodeFormat(totp)) return { ok: false, recoveryUsed: false };
    const pending = this.store.snapshot().users.find((item) => item.id === userId);
    if (!pending?.totpEnabled || !pending.totpSecretEnc) return { ok: false, recoveryUsed: false };
    let secret;
    try {
      secret = decryptSecret(this.masterKey, pending.totpSecretEnc, `user:${userId}:totp`);
    } catch {
      throw new NcsError('AUTH_CONFIGURATION_ERROR', '两步验证配置无法解密，请联系管理员恢复数据', 500);
    }
    return this.store.mutate((draft) => {
      const target = draft.users.find((item) => item.id === userId);
      if (!target || !target.totpEnabled) return { ok: false, recoveryUsed: false };
      const result = verifyTotp(secret, totp, { lastCounter: Number(target.totpLastCounter) || 0 });
      if (!result.ok) return { ok: false, recoveryUsed: false };
      target.totpLastCounter = result.counter;
      target.updatedAt = new Date().toISOString();
      return { ok: true, recoveryUsed: false };
    });
  }

  async requireSecondFactor(userId, { totp, recoveryCode }) {
    const user = this.store.findUserById(userId);
    if (!user) throw new NcsError('UNAUTHENTICATED', '登录状态失效', 401);
    if (!user.totpEnabled) return { recoveryUsed: false };
    if (!totp && !recoveryCode) {
      throw new NcsError('TOTP_REQUIRED', '该操作需要两步验证码', 401, { totpRequired: true });
    }
    const factor = await this.verifySecondFactor(userId, { totp, recoveryCode });
    if (!factor.ok) {
      await this.registerFailure(userId);
      throw new NcsError('INVALID_SECOND_FACTOR', '两步验证码无效', 401);
    }
    return factor;
  }

  async verifyCurrentPassword(user, password) {
    if (typeof password !== 'string' || password.length === 0 || Buffer.byteLength(password, 'utf8') > 1024) {
      throw new NcsError('INVALID_CREDENTIALS', '当前口令错误', 401);
    }
    const check = await verifyPassword(password, user.passwordHash);
    if (!check.ok) {
      await this.registerFailure(user.id);
      throw new NcsError('INVALID_CREDENTIALS', '当前口令错误', 401);
    }
  }

  logout(token, { userId = null, username = null, ip = null } = {}) {
    this.sessions.destroy(token);
    this.audit.append({ action: 'auth.logout', userId, username, ip });
  }

  async changePassword({ userId, currentPassword, newPassword, totp, recoveryCode, currentToken, ip }) {
    const user = this.store.findUserById(userId);
    if (!user) throw new NcsError('UNAUTHENTICATED', '登录状态失效', 401);
    await this.verifyCurrentPassword(user, currentPassword);
    if (user.totpEnabled) {
      await this.requireSecondFactor(userId, { totp, recoveryCode });
    }
    validateNewPassword(newPassword, user.username);
    const sameAsOld = await verifyPassword(newPassword, user.passwordHash);
    if (sameAsOld.ok) throw new NcsError('PASSWORD_UNCHANGED', '新口令不能与当前口令相同', 400);
    const hash = await hashPassword(newPassword);
    await this.store.mutate((draft) => {
      const target = draft.users.find((item) => item.id === userId);
      if (!target) throw new NcsError('UNAUTHENTICATED', '登录状态失效', 401);
      target.passwordHash = hash;
      target.failedLogins = 0;
      target.lockedUntil = 0;
      target.updatedAt = new Date().toISOString();
    });
    this.sessions.destroyUserSessions(userId, { exceptToken: currentToken });
    await this.audit.append({
      action: 'auth.password.change',
      userId,
      username: user.username,
      ip,
    });
    return { changed: true };
  }

  async setupTotp(userId) {
    const user = this.store.findUserById(userId);
    if (!user) throw new NcsError('UNAUTHENTICATED', '登录状态失效', 401);
    if (user.totpEnabled) throw new NcsError('TOTP_ALREADY_ENABLED', '两步验证已启用', 409);
    const secret = generateTotpSecret();
    const encrypted = encryptSecret(this.masterKey, secret, `user:${userId}:totp-pending`);
    await this.store.mutate((draft) => {
      const target = draft.users.find((item) => item.id === userId);
      if (!target) throw new NcsError('UNAUTHENTICATED', '登录状态失效', 401);
      target.totpPendingEnc = encrypted;
      target.totpPendingCreatedAt = new Date().toISOString();
      target.updatedAt = new Date().toISOString();
    });
    return {
      secret,
      uri: totpUri({ secret, username: user.username }),
      expiresInSeconds: Math.floor(TOTP_PENDING_MS / 1000),
    };
  }

  async enableTotp(userId, code, ip) {
    if (!isTotpCodeFormat(code)) throw new NcsError('INVALID_SECOND_FACTOR', '两步验证码格式无效', 400);
    const user = this.store.findUserById(userId);
    if (!user) throw new NcsError('UNAUTHENTICATED', '登录状态失效', 401);
    if (user.totpEnabled) throw new NcsError('TOTP_ALREADY_ENABLED', '两步验证已启用', 409);
    if (!user.totpPendingEnc || !user.totpPendingCreatedAt) {
      throw new NcsError('TOTP_SETUP_REQUIRED', '请先开始设置两步验证', 400);
    }
    if (Date.now() - new Date(user.totpPendingCreatedAt).getTime() > TOTP_PENDING_MS) {
      await this.store.mutate((draft) => {
        const target = draft.users.find((item) => item.id === userId);
        if (target) {
          target.totpPendingEnc = null;
          target.totpPendingCreatedAt = null;
        }
      });
      throw new NcsError('TOTP_SETUP_EXPIRED', '设置已过期，请重新开始', 400);
    }
    let secret;
    try {
      secret = decryptSecret(this.masterKey, user.totpPendingEnc, `user:${userId}:totp-pending`);
    } catch {
      throw new NcsError('AUTH_CONFIGURATION_ERROR', '两步验证配置无法解密', 500);
    }
    const verification = verifyTotp(secret, code, { lastCounter: 0 });
    if (!verification.ok) throw new NcsError('INVALID_SECOND_FACTOR', '两步验证码无效', 400);

    const encrypted = encryptSecret(this.masterKey, secret, `user:${userId}:totp`);
    const recoveryCodes = generateRecoveryCodes(10);
    const hashes = recoveryCodes
      .map((item) => hashRecoveryCode(this.masterKey, item))
      .filter(Boolean);
    await this.store.mutate((draft) => {
      const target = draft.users.find((item) => item.id === userId);
      if (!target) throw new NcsError('UNAUTHENTICATED', '登录状态失效', 401);
      target.totpEnabled = true;
      target.totpSecretEnc = encrypted;
      target.totpPendingEnc = null;
      target.totpPendingCreatedAt = null;
      target.totpLastCounter = verification.counter;
      target.recoveryCodeHashes = hashes;
      target.updatedAt = new Date().toISOString();
    });
    await this.audit.append({ action: 'auth.totp.enable', userId, username: user.username, ip });
    return { recoveryCodes };
  }

  async disableTotp(userId, { password, totp, recoveryCode, ip }) {
    const user = this.store.findUserById(userId);
    if (!user) throw new NcsError('UNAUTHENTICATED', '登录状态失效', 401);
    if (!user.totpEnabled) throw new NcsError('TOTP_NOT_ENABLED', '两步验证未启用', 409);
    await this.verifyCurrentPassword(user, password);
    await this.requireSecondFactor(userId, { totp, recoveryCode });
    await this.store.mutate((draft) => {
      const target = draft.users.find((item) => item.id === userId);
      if (!target) throw new NcsError('UNAUTHENTICATED', '登录状态失效', 401);
      target.totpEnabled = false;
      target.totpSecretEnc = null;
      target.totpPendingEnc = null;
      target.totpPendingCreatedAt = null;
      target.totpLastCounter = 0;
      target.recoveryCodeHashes = [];
      target.updatedAt = new Date().toISOString();
    });
    await this.audit.append({ action: 'auth.totp.disable', userId, username: user.username, ip });
    return { disabled: true };
  }

  me(user, session) {
    return {
      user: this.userView(user),
      csrfToken: session.csrfToken,
      session: {
        createdAt: new Date(session.createdAt).toISOString(),
        absoluteExpiresAt: new Date(session.absoluteExpiresAt).toISOString(),
        idleTtlSeconds: this.config.sessionIdleMinutes * 60,
      },
    };
  }
}

export function createRequireAuth({ sessions, store }) {
  return (req, _res, next) => {
    try {
      const token = getSessionToken(req);
      const session = requireSession(sessions, token);
      const user = store.findUserById(session.userId);
      if (!user) throw new NcsError('UNAUTHENTICATED', '登录状态已失效，请重新登录', 401);
      req.sessionToken = token;
      req.session = session;
      req.user = user;
      next();
    } catch (error) {
      next(error);
    }
  };
}

export function createRequireCsrf({ sessions }) {
  return (req, _res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    const header = req.headers['x-csrf-token'];
    if (typeof header !== 'string' || !sessions.verifyCsrf(req.session, header)) {
      next(new NcsError('INVALID_CSRF', '请求校验失败，请刷新页面后重试', 403));
      return;
    }
    next();
  };
}
