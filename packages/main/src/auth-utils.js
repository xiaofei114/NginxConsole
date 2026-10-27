import crypto from 'node:crypto';
import { NcsError } from '@ncs/shared';

const SCRYPT_N = 32768;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 32;
const MAX_PASSWORD_BYTES = 1024;
const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const RECOVERY_HASH_DOMAIN = 'ncs-recovery-v1:';

function scrypt(password, salt, { N, r, p, keylen, maxmem }) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, { N, r, p, maxmem }, (error, key) => {
      if (error) reject(error);
      else resolve(key);
    });
  });
}

export function validateNewPassword(password, username = '') {
  if (typeof password !== 'string') throw new NcsError('WEAK_PASSWORD', '口令格式无效', 400);
  const characters = Array.from(password);
  if (characters.length < 12) throw new NcsError('WEAK_PASSWORD', '口令至少需要 12 个字符', 400);
  if (Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES) {
    throw new NcsError('WEAK_PASSWORD', '口令过长', 400);
  }
  if (password.includes('\u0000')) throw new NcsError('WEAK_PASSWORD', '口令包含非法字符', 400);
  if (username && password.toLowerCase().includes(String(username).toLowerCase())) {
    throw new NcsError('WEAK_PASSWORD', '口令不能包含用户名', 400);
  }
  return password;
}

export async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    keylen: SCRYPT_KEYLEN,
    maxmem: 64 * 1024 * 1024,
  });
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('base64')}$${key.toString('base64')}`;
}

export function parsePasswordHash(stored) {
  if (typeof stored !== 'string' || stored.length > 512) return null;
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return null;
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (![N, r, p].every(Number.isSafeInteger)) return null;
  if (N < 16384 || N > 262144 || (N & (N - 1)) !== 0 || r < 1 || r > 16 || p < 1 || p > 4) return null;
  let salt;
  let hash;
  try {
    salt = Buffer.from(parts[4], 'base64');
    hash = Buffer.from(parts[5], 'base64');
  } catch {
    return null;
  }
  if (salt.length < 8 || salt.length > 64 || hash.length < 16 || hash.length > 128) return null;
  return { N, r, p, salt, hash };
}

export async function verifyPassword(password, stored) {
  const parsed = parsePasswordHash(stored);
  if (!parsed) return { ok: false, needsRehash: false };
  try {
    const key = await scrypt(password, parsed.salt, {
      N: parsed.N,
      r: parsed.r,
      p: parsed.p,
      keylen: parsed.hash.length,
      maxmem: 256 * 1024 * 1024,
    });
    return {
      ok: key.length === parsed.hash.length && crypto.timingSafeEqual(key, parsed.hash),
      needsRehash: parsed.N !== SCRYPT_N || parsed.r !== SCRYPT_R || parsed.p !== SCRYPT_P || parsed.hash.length !== SCRYPT_KEYLEN,
    };
  } catch {
    return { ok: false, needsRehash: false };
  }
}

let dummyHashPromise = null;
export function getDummyPasswordHash() {
  if (!dummyHashPromise) {
    dummyHashPromise = hashPassword(crypto.randomBytes(24).toString('base64url')).catch(() => null);
  }
  return dummyHashPromise;
}

export async function verifyDummyPassword(password) {
  const hash = await getDummyPasswordHash();
  if (!hash) return;
  await verifyPassword(password, hash).catch(() => {});
}

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function sha256(value) {
  return crypto.createHash('sha256').update(value).digest();
}

export function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function safeEqualString(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

export function encryptSecret(masterKey, plaintext, aad = '') {
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) throw new Error('Invalid master key');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1.${iv.toString('base64url')}.${tag.toString('base64url')}.${ciphertext.toString('base64url')}`;
}

export function decryptSecret(masterKey, packed, aad = '') {
  if (typeof packed !== 'string' || packed.length > 4096) throw new Error('Invalid encrypted secret');
  const parts = packed.split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') throw new Error('Invalid encrypted secret');
  try {
    const iv = Buffer.from(parts[1], 'base64url');
    const tag = Buffer.from(parts[2], 'base64url');
    const ciphertext = Buffer.from(parts[3], 'base64url');
    if (iv.length !== 12 || tag.length !== 16) throw new Error('Invalid encrypted secret');
    const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, iv);
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    throw new Error('Unable to decrypt secret');
  }
}

export function generateRecoveryCodes(count = 10) {
  const codes = [];
  for (let index = 0; index < count; index += 1) {
    const bytes = crypto.randomBytes(10);
    let raw = '';
    for (const byte of bytes) {
      raw += RECOVERY_ALPHABET[byte % RECOVERY_ALPHABET.length];
      if (raw.length === 5) raw += '-';
    }
    codes.push(raw.slice(0, 11));
  }
  return codes;
}

export function normalizeRecoveryCode(code) {
  return String(code || '')
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '');
}

export function hashRecoveryCode(masterKey, code) {
  const normalized = normalizeRecoveryCode(code);
  if (normalized.length !== 10) return null;
  return crypto
    .createHmac('sha256', masterKey)
    .update(RECOVERY_HASH_DOMAIN + normalized)
    .digest('hex');
}

export function isRecoveryCodeFormat(code) {
  const normalized = normalizeRecoveryCode(code);
  return normalized.length === 10 && [...normalized].every((char) => RECOVERY_ALPHABET.includes(char));
}
