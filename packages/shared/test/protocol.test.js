import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  ReplayGuard,
  createSignedEnvelope,
  generateEd25519KeyPair,
  publicKeyFingerprint,
  parseAuthEnvelope,
  serializeAuthEnvelope,
  validateEd25519PublicKey,
  verifySignedEnvelope,
} from '@ncs/shared';

function hasCode(code) {
  return (error) => {
    assert.equal(error?.code, code, `expected ${code}, got ${error?.code}: ${error?.message}`);
    return true;
  };
}

test('signed envelopes verify, reject tampering and enforce clock skew', () => {
  const { privateKeyPem, publicKeyPem } = generateEd25519KeyPair();
  const envelope = createSignedEnvelope({
    kind: 'agent-request',
    fields: { requestId: 'req-12345678', command: 'fs.list' },
    privateKey: privateKeyPem,
    ts: Date.now(),
  });

  assert.equal(envelope.v, 1);
  assert.equal(envelope.kind, 'agent-request');
  assert.equal(typeof envelope.sig, 'string');
  assert.deepEqual(
    verifySignedEnvelope(structuredClone(envelope), publicKeyPem, { allowedKinds: ['agent-request'] }),
    envelope,
  );

  assert.throws(
    () => verifySignedEnvelope({ ...envelope, command: 'fs.write' }, publicKeyPem),
    hasCode('INVALID_SIGNATURE'),
  );
  assert.throws(
    () => verifySignedEnvelope(envelope, publicKeyPem, { allowedKinds: ['agent-auth'] }),
    hasCode('INVALID_ENVELOPE'),
  );
  assert.throws(
    () => verifySignedEnvelope(envelope, publicKeyPem, { now: envelope.ts + 61_000 }),
    hasCode('STALE_MESSAGE'),
  );
  assert.throws(
    () => verifySignedEnvelope(envelope, publicKeyPem, { now: envelope.ts - 61_000 }),
    hasCode('STALE_MESSAGE'),
  );

  const { publicKeyPem: otherKey } = generateEd25519KeyPair();
  assert.throws(() => verifySignedEnvelope(envelope, otherKey), hasCode('INVALID_SIGNATURE'));
});

test('envelope construction rejects reserved keys and invalid inputs', () => {
  const { privateKeyPem } = generateEd25519KeyPair();
  assert.throws(
    () => createSignedEnvelope({ kind: 'x', fields: { ts: 1 }, privateKey: privateKeyPem }),
    hasCode('INVALID_ENVELOPE'),
  );
  assert.throws(
    () => createSignedEnvelope({ kind: 'x', fields: { sig: 'a' }, privateKey: privateKeyPem }),
    hasCode('INVALID_ENVELOPE'),
  );
  assert.throws(
    () => createSignedEnvelope({ kind: 'x', privateKey: privateKeyPem, nonce: 'short' }),
    hasCode('INVALID_ENVELOPE'),
  );
  assert.throws(
    () => createSignedEnvelope({ kind: 'x', privateKey: privateKeyPem, ts: -1 }),
    hasCode('INVALID_ENVELOPE'),
  );
});

test('replay guard detects nonce reuse until the TTL expires', () => {
  const guard = new ReplayGuard({ ttlMs: 1_000 });
  const now = Date.now();
  guard.check('nonce-abcdefghijklmnop', now);
  assert.throws(() => guard.check('nonce-abcdefghijklmnop', now + 10), hasCode('REPLAY_DETECTED'));
  assert.doesNotThrow(() => guard.check('nonce-abcdefghijklmnop', now + 1_001));

  const full = new ReplayGuard({ maxEntries: 2 });
  full.check('nonce-aaaaaaaaaaaaaaaa', now);
  full.check('nonce-bbbbbbbbbbbbbbbb', now);
  assert.throws(() => full.check('nonce-cccccccccccccccc', now), hasCode('MESSAGE_RATE_LIMITED'));
});

test('auth envelopes serialize round-trip and reject malformed headers', () => {
  const { privateKeyPem } = generateEd25519KeyPair();
  const envelope = createSignedEnvelope({
    kind: 'agent-auth',
    fields: { agentId: '00000000-0000-4000-8000-000000000000' },
    privateKey: privateKeyPem,
  });
  const serialized = serializeAuthEnvelope(envelope);
  assert.match(serialized, /^[A-Za-z0-9_-]+$/);
  assert.deepEqual(parseAuthEnvelope(serialized), envelope);

  assert.throws(() => parseAuthEnvelope('not-base64!'), hasCode('INVALID_ENVELOPE'));
  assert.throws(() => parseAuthEnvelope('short'), hasCode('INVALID_ENVELOPE'));
  assert.throws(
    () => parseAuthEnvelope(Buffer.from('{"a":1}').toString('base64url')),
    hasCode('INVALID_ENVELOPE'),
  );
});

test('Ed25519 fingerprints are stable and non-Ed25519 keys are rejected', () => {
  const { publicKeyPem } = generateEd25519KeyPair();
  const fingerprint = publicKeyFingerprint(publicKeyPem);
  assert.match(fingerprint, /^SHA256:[A-Za-z0-9_-]{43}$/);
  assert.equal(validateEd25519PublicKey(publicKeyPem).fingerprint, fingerprint);

  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const rsaPublicPem = rsa.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  assert.throws(() => validateEd25519PublicKey(rsaPublicPem), hasCode('INVALID_KEY'));
  assert.throws(() => validateEd25519PublicKey('garbage'), hasCode('INVALID_KEY'));
});
