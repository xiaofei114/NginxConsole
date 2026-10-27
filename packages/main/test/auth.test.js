import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  decryptSecret,
  encryptSecret,
  hashPassword,
  parsePasswordHash,
  validateNewPassword,
  verifyPassword,
} from '../src/auth-utils.js';
import {
  currentTotpCounter,
  decodeBase32,
  encodeBase32,
  generateTotp,
  generateTotpSecret,
  isTotpCodeFormat,
  verifyTotp,
} from '../src/totp.js';
import { Store } from '../src/store.js';
import { AuditLog } from '../src/audit.js';
import { SessionStore } from '../src/sessions.js';
import { AuthService } from '../src/auth.js';

function hasCode(code) {
  return (error) => {
    assert.equal(error?.code, code, `expected ${code}, got ${error?.code}: ${error?.message}`);
    return true;
  };
}

test('password hashing is memory-hard and verifiable', async () => {
  const hash = await hashPassword('CorrectHorseBatteryStaple!');
  assert.match(hash, /^scrypt\$32768\$8\$1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
  const parsed = parsePasswordHash(hash);
  assert.equal(parsed.N, 32768);
  assert.equal(parsed.r, 8);
  assert.equal(parsed.p, 1);
  assert.equal((await verifyPassword('CorrectHorseBatteryStaple!', hash)).ok, true);
  assert.equal((await verifyPassword('wrong password', hash)).ok, false);

  assert.equal(parsePasswordHash('not-a-hash'), null);
  assert.equal(parsePasswordHash('scrypt$1$1$1$a$b'), null);
  assert.equal(parsePasswordHash(null), null);

  assert.throws(() => validateNewPassword('short'), hasCode('WEAK_PASSWORD'));
  assert.throws(() => validateNewPassword('adminpassword123', 'admin'), hasCode('WEAK_PASSWORD'));
  assert.throws(() => validateNewPassword('a'.repeat(2000)), hasCode('WEAK_PASSWORD'));
  assert.equal(validateNewPassword('a-very-long-password'), 'a-very-long-password');
});

test('secrets use AES-256-GCM with authenticated additional data', () => {
  const masterKey = crypto.randomBytes(32);
  const packed = encryptSecret(masterKey, 'JBSWY3DPEHPK3PXP', 'user:1:totp');
  assert.match(packed, /^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  assert.equal(decryptSecret(masterKey, packed, 'user:1:totp'), 'JBSWY3DPEHPK3PXP');
  assert.throws(() => decryptSecret(masterKey, packed, 'user:2:totp'));
  assert.throws(() => decryptSecret(crypto.randomBytes(32), packed, 'user:1:totp'));
  assert.throws(() => decryptSecret(masterKey, 'v1.bad', 'user:1:totp'));
  assert.throws(() => encryptSecret(Buffer.alloc(16), 'secret'));
});

test('TOTP codes follow RFC 6238 semantics and cannot be replayed', () => {
  const secret = generateTotpSecret();
  assert.match(secret, /^[A-Z2-7]+$/);
  assert.equal(encodeBase32(decodeBase32(secret)), secret);
  assert.throws(() => decodeBase32('not base32!'));

  const counter = 5_000;
  const now = counter * 30 * 1000;
  const code = generateTotp(secret, counter);
  assert.match(code, /^\d{6}$/);
  assert.equal(isTotpCodeFormat(code), true);
  assert.equal(isTotpCodeFormat('12345'), false);

  const first = verifyTotp(secret, code, { lastCounter: counter - 1, now });
  assert.deepEqual(first, { ok: true, counter });
  assert.deepEqual(verifyTotp(secret, code, { lastCounter: counter, now }), { ok: false, counter: null });
  assert.deepEqual(verifyTotp(secret, '000000', { lastCounter: 0, now }), { ok: false, counter: null });
  assert.deepEqual(verifyTotp(secret, 'abcdef', { lastCounter: 0, now }), { ok: false, counter: null });

  // A code from two steps ago is outside the +/-1 window.
  const stale = generateTotp(secret, counter - 3);
  assert.equal(verifyTotp(secret, stale, { lastCounter: 0, now }).ok, false);
});

test('session store enforces CSRF binding and expiry', async () => {
  const sessions = new SessionStore({ idleTtlMs: 1_000, absoluteTtlMs: 10_000 });
  const { token, session } = sessions.create('user-1', { ip: '127.0.0.1', userAgent: 'test' });
  assert.match(token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(sessions.get(token).userId, 'user-1');
  assert.equal(sessions.verifyCsrf(session, session.csrfToken), true);
  assert.equal(sessions.verifyCsrf(session, `${session.csrfToken}x`), false);
  assert.equal(sessions.verifyCsrf(null, session.csrfToken), false);

  session.lastSeenAt = Date.now() - 2_000;
  assert.equal(sessions.get(token), null);

  const second = sessions.create('user-1');
  sessions.destroy(second.token);
  assert.equal(sessions.get(second.token), null);
  assert.equal(sessions.get('invalid token'), null);
});

test('AuthService login, TOTP, recovery codes and password rotation', async (t) => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'ncs-auth-'));
  const store = await Store.open({
    file: path.join(base, 'store.json'),
    adminUsername: 'admin',
    adminPassword: 'AdminPassword123!',
  });
  const audit = new AuditLog(path.join(base, 'audit.jsonl'));
  await audit.init();
  const sessions = new SessionStore({ idleTtlMs: 60 * 60 * 1000, absoluteTtlMs: 12 * 60 * 60 * 1000 });
  const masterKey = crypto.randomBytes(32);
  const auth = new AuthService({
    store,
    sessions,
    audit,
    masterKey,
    config: { sessionIdleMinutes: 60, sessionAbsoluteMinutes: 720 },
  });
  t.after(async () => {
    sessions.stop();
    await audit.close();
    await fs.rm(base, { recursive: true, force: true });
  });

  const admin = store.findUser('admin');
  assert.equal(store.adminSeeded, true);

  await t.test('rejects bad credentials and accepts the seeded password', async () => {
    await assert.rejects(
      auth.login({ username: 'admin', password: 'wrong password', ip: '127.0.0.1' }),
      hasCode('INVALID_CREDENTIALS'),
    );
    await assert.rejects(
      auth.login({ username: 'nobody', password: 'whatever', ip: '127.0.0.1' }),
      hasCode('INVALID_CREDENTIALS'),
    );
    const result = await auth.login({
      username: 'admin',
      password: 'AdminPassword123!',
      ip: '127.0.0.1',
      userAgent: 'test-agent',
    });
    assert.equal(result.user.username, 'admin');
    assert.equal(result.token.length, 43);
    assert.equal(result.session.userId, result.user.id);
    assert.equal(store.findUser('admin').failedLogins, 0);
  });

  let totpSecret = null;
  let recoveryCodes = null;

  await t.test('enables TOTP and requires a second factor', async () => {
    const setup = await auth.setupTotp(admin.id);
    assert.match(setup.secret, /^[A-Z2-7]+$/);
    assert.match(setup.uri, /^otpauth:\/\/totp\//);
    totpSecret = setup.secret;

    const code = generateTotp(totpSecret, currentTotpCounter());
    const enabled = await auth.enableTotp(admin.id, code, '127.0.0.1');
    assert.equal(enabled.recoveryCodes.length, 10);
    recoveryCodes = enabled.recoveryCodes;
    assert.equal(store.findUserById(admin.id).totpEnabled, true);

    await assert.rejects(
      auth.login({ username: 'admin', password: 'AdminPassword123!', ip: '127.0.0.1' }),
      hasCode('TOTP_REQUIRED'),
    );

    const futureCode = generateTotp(totpSecret, currentTotpCounter() + 5);
    await assert.rejects(
      auth.login({ username: 'admin', password: 'AdminPassword123!', totp: futureCode, ip: '127.0.0.1' }),
      hasCode('INVALID_SECOND_FACTOR'),
    );

    const loginCode = generateTotp(totpSecret, currentTotpCounter() + 1);
    const login = await auth.login({
      username: 'admin',
      password: 'AdminPassword123!',
      totp: loginCode,
      ip: '127.0.0.1',
    });
    assert.equal(login.user.totpEnabled, true);
  });

  await t.test('accepts a recovery code exactly once', async () => {
    const before = store.findUserById(admin.id).recoveryCodeHashes.length;
    const login = await auth.login({
      username: 'admin',
      password: 'AdminPassword123!',
      recoveryCode: recoveryCodes[0],
      ip: '127.0.0.1',
    });
    assert.equal(login.user.recoveryCodesRemaining, before - 1);
    await assert.rejects(
      auth.login({
        username: 'admin',
        password: 'AdminPassword123!',
        recoveryCode: recoveryCodes[0],
        ip: '127.0.0.1',
      }),
      hasCode('INVALID_SECOND_FACTOR'),
    );
  });

  await t.test('disables TOTP with password and recovery code', async () => {
    await assert.rejects(
      auth.disableTotp(admin.id, { password: 'wrong password', recoveryCode: recoveryCodes[1] }),
      hasCode('INVALID_CREDENTIALS'),
    );
    const result = await auth.disableTotp(admin.id, {
      password: 'AdminPassword123!',
      recoveryCode: recoveryCodes[1],
      ip: '127.0.0.1',
    });
    assert.deepEqual(result, { disabled: true });
    assert.equal(store.findUserById(admin.id).totpEnabled, false);
  });

  await t.test('rotates the password and invalidates other sessions', async () => {
    const current = store.findUser('admin');
    const { token: keepToken } = sessions.create(current.id);
    const { token: otherToken } = sessions.create(current.id);

    await assert.rejects(
      auth.changePassword({
        userId: current.id,
        currentPassword: 'AdminPassword123!',
        newPassword: 'short',
        currentToken: keepToken,
      }),
      hasCode('WEAK_PASSWORD'),
    );

    const changed = await auth.changePassword({
      userId: current.id,
      currentPassword: 'AdminPassword123!',
      newPassword: 'N3wSecurePassphrase!42',
      currentToken: keepToken,
      ip: '127.0.0.1',
    });
    assert.deepEqual(changed, { changed: true });
    assert.ok(sessions.get(keepToken));
    assert.equal(sessions.get(otherToken), null);

    await assert.rejects(
      auth.login({ username: 'admin', password: 'AdminPassword123!', ip: '127.0.0.1' }),
      hasCode('INVALID_CREDENTIALS'),
    );
    const login = await auth.login({ username: 'admin', password: 'N3wSecurePassphrase!42', ip: '127.0.0.1' });
    assert.equal(login.user.username, 'admin');
  });
});
