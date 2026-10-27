import crypto from 'node:crypto';
import { canonicalize } from './canonical.js';
import { NcsError } from './errors.js';

export const PROTOCOL_VERSION = 1;
export const ENVELOPE_DOMAIN = 'nginx-console-envelope-v1\n';
export const MAX_CLOCK_SKEW_MS = 60 * 1000;
export const NONCE_RE = /^[A-Za-z0-9_-]{16,64}$/;

const RESERVED_KEYS = new Set(['v', 'kind', 'ts', 'nonce', 'sig']);

export function generateNonce() {
  return crypto.randomBytes(18).toString('base64url');
}

export function generateEd25519KeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

export function publicKeyFingerprint(publicKeyPem) {
  const key = crypto.createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new NcsError('INVALID_KEY', '仅支持 Ed25519 公钥', 400);
  }
  const der = key.export({ type: 'spki', format: 'der' });
  const digest = crypto.createHash('sha256').update(der).digest('base64url');
  return `SHA256:${digest}`;
}

export function validateEd25519PublicKey(publicKeyPem) {
  if (typeof publicKeyPem !== 'string' || publicKeyPem.length > 4096) {
    throw new NcsError('INVALID_KEY', '公钥格式无效', 400);
  }
  let key;
  try {
    key = crypto.createPublicKey(publicKeyPem);
  } catch {
    throw new NcsError('INVALID_KEY', '公钥格式无效', 400);
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new NcsError('INVALID_KEY', '仅支持 Ed25519 公钥', 400);
  }
  return { key, fingerprint: publicKeyFingerprint(publicKeyPem) };
}

function envelopeSigningBytes(envelope) {
  const { sig: _sig, ...unsigned } = envelope;
  return Buffer.from(ENVELOPE_DOMAIN + canonicalize(unsigned), 'utf8');
}

/**
 * Build and sign an envelope.
 * @param {{kind:string, fields?:Record<string,unknown>, privateKey: crypto.KeyObject|string, ts?:number, nonce?:string}} options
 */
export function createSignedEnvelope({ kind, fields = {}, privateKey, ts = Date.now(), nonce = generateNonce() }) {
  if (typeof kind !== 'string' || kind.length > 64) throw new NcsError('INVALID_ENVELOPE', '消息类型无效', 400);
  if (!fields || typeof fields !== 'object' || Array.isArray(fields)) throw new NcsError('INVALID_ENVELOPE', '消息字段无效', 400);
  for (const key of Object.keys(fields)) {
    if (RESERVED_KEYS.has(key)) throw new NcsError('INVALID_ENVELOPE', '消息字段包含保留键', 400);
  }
  if (!Number.isSafeInteger(ts) || ts <= 0) throw new NcsError('INVALID_ENVELOPE', '消息时间戳无效', 400);
  if (!NONCE_RE.test(nonce)) throw new NcsError('INVALID_ENVELOPE', '消息随机数无效', 400);

  const envelope = { v: PROTOCOL_VERSION, kind, ts, nonce, ...fields };
  const signature = crypto.sign(null, envelopeSigningBytes(envelope), privateKey);
  envelope.sig = signature.toString('base64url');
  return envelope;
}

/**
 * Verify signature, protocol version, timestamp and nonce format.
 * Replay protection is intentionally separate (see ReplayGuard) so that an
 * unauthenticated packet cannot poison the replay cache.
 */
export function verifySignedEnvelope(
  envelope,
  publicKey,
  { allowedKinds = null, maxSkewMs = MAX_CLOCK_SKEW_MS, now = Date.now() } = {},
) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    throw new NcsError('INVALID_ENVELOPE', '消息格式无效', 401);
  }
  if (envelope.v !== PROTOCOL_VERSION) {
    throw new NcsError('INVALID_ENVELOPE', '协议版本不兼容', 401);
  }
  if (typeof envelope.kind !== 'string' || envelope.kind.length > 64) {
    throw new NcsError('INVALID_ENVELOPE', '消息类型无效', 401);
  }
  if (allowedKinds && !allowedKinds.includes(envelope.kind)) {
    throw new NcsError('INVALID_ENVELOPE', '不允许的消息类型', 401);
  }
  if (!Number.isSafeInteger(envelope.ts) || Math.abs(now - envelope.ts) > maxSkewMs) {
    throw new NcsError('STALE_MESSAGE', '消息时间戳超出允许范围，请检查服务器时间同步', 401);
  }
  if (typeof envelope.nonce !== 'string' || !NONCE_RE.test(envelope.nonce)) {
    throw new NcsError('INVALID_ENVELOPE', '消息随机数无效', 401);
  }
  if (typeof envelope.sig !== 'string' || envelope.sig.length > 128) {
    throw new NcsError('INVALID_SIGNATURE', '消息签名无效', 401);
  }
  let signature;
  try {
    signature = Buffer.from(envelope.sig, 'base64url');
  } catch {
    throw new NcsError('INVALID_SIGNATURE', '消息签名无效', 401);
  }
  let ok = false;
  try {
    ok = crypto.verify(null, envelopeSigningBytes(envelope), publicKey, signature);
  } catch {
    ok = false;
  }
  if (!ok) throw new NcsError('INVALID_SIGNATURE', '消息签名校验失败', 401);
  return envelope;
}

export function serializeAuthEnvelope(envelope) {
  const json = JSON.stringify(envelope);
  if (Buffer.byteLength(json) > 4096) throw new NcsError('INVALID_ENVELOPE', '认证消息过大', 400);
  return Buffer.from(json, 'utf8').toString('base64url');
}

export function parseAuthEnvelope(headerValue) {
  if (typeof headerValue !== 'string' || headerValue.length < 16 || headerValue.length > 6000) {
    throw new NcsError('INVALID_ENVELOPE', '认证头无效', 401);
  }
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(headerValue, 'base64url').toString('utf8'));
  } catch {
    throw new NcsError('INVALID_ENVELOPE', '认证头无效', 401);
  }
  return parsed;
}

export class ReplayGuard {
  constructor({ ttlMs = 2 * 60 * 1000, maxEntries = 20000 } = {}) {
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    /** @type {Map<string, number>} */
    this.seen = new Map();
  }

  check(nonce, now = Date.now()) {
    this.prune(now);
    const expiresAt = this.seen.get(nonce);
    if (expiresAt && expiresAt > now) {
      throw new NcsError('REPLAY_DETECTED', '检测到重放消息', 401);
    }
    if (this.seen.size >= this.maxEntries) {
      // Fail closed: refusing new messages is safer than forgetting old nonces.
      throw new NcsError('MESSAGE_RATE_LIMITED', '消息过于频繁', 429);
    }
    this.seen.set(nonce, now + this.ttlMs);
  }

  prune(now = Date.now()) {
    if (this.seen.size === 0) return;
    for (const [nonce, expiresAt] of this.seen) {
      if (expiresAt <= now) this.seen.delete(nonce);
    }
  }

  clear() {
    this.seen.clear();
  }
}
