import crypto from 'node:crypto';
import { safeEqualString } from './auth-utils.js';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const PERIOD_SECONDS = 30;
const DIGITS = 6;

export function encodeBase32(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

export function decodeBase32(input) {
  const normalized = String(input || '').toUpperCase().replace(/=+$/g, '');
  if (!/^[A-Z2-7]+$/.test(normalized)) throw new Error('Invalid base32');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const char of normalized) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index < 0) throw new Error('Invalid base32');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

export function generateTotpSecret() {
  return encodeBase32(crypto.randomBytes(20));
}

function counterBuffer(counter) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  return buffer;
}

export function generateTotp(secret, counter) {
  const key = decodeBase32(secret);
  const digest = crypto.createHmac('sha1', key).update(counterBuffer(counter)).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0');
}

export function currentTotpCounter(now = Date.now()) {
  return Math.floor(now / 1000 / PERIOD_SECONDS);
}

/**
 * Verify a 6 digit TOTP code with a +/-1 step window. Rejects any counter that
 * has already been consumed to prevent replay of the same code.
 */
export function verifyTotp(secret, code, { lastCounter = 0, now = Date.now(), window = 1 } = {}) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return { ok: false, counter: null };
  const current = currentTotpCounter(now);
  for (let offset = window; offset >= -window; offset -= 1) {
    const counter = current + offset;
    if (counter <= lastCounter) continue;
    const expected = generateTotp(secret, counter);
    if (safeEqualString(code, expected)) return { ok: true, counter };
  }
  return { ok: false, counter: null };
}

export function totpUri({ secret, username, issuer = 'Nginx Console' }) {
  const label = `${issuer}:${username}`;
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(PERIOD_SECONDS),
  });
  return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
}

export function isTotpCodeFormat(code) {
  return typeof code === 'string' && /^\d{6}$/.test(code);
}
