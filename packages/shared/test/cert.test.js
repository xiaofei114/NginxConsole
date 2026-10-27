import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {
  inspectCertificatePem,
  validateCertificateBundle,
  validateChain,
} from '@ncs/shared';

async function fixture(relativePath) {
  return fs.readFile(new URL(`./fixtures/${relativePath}`, import.meta.url), 'utf8');
}

function hasCode(code) {
  return (error) => {
    assert.equal(error?.code, code, `expected ${code}, got ${error?.code}: ${error?.message}`);
    return true;
  };
}

test('inspectCertificatePem parses metadata and enforces single leaf certificate', async () => {
  const certPem = await fixture('valid/cert.pem');
  const inspected = inspectCertificatePem(certPem);
  assert.match(inspected.subject, /CN=localhost/);
  assert.equal(inspected.certificateCount, 1);
  assert.ok(inspected.san.some((entry) => entry.type === 'DNS' && entry.value === 'localhost'));
  assert.equal(inspected.key.type, 'rsa');
  assert.ok(inspected.key.bits >= 2048);
  assert.match(inspected.normalizedPem, /^-----BEGIN CERTIFICATE-----/);

  assert.throws(() => inspectCertificatePem(`${certPem}${certPem}`), hasCode('CERT_INVALID'));
  assert.throws(() => inspectCertificatePem(`${certPem}trailing`), hasCode('CERT_INVALID'));
  assert.throws(() => inspectCertificatePem(''), hasCode('CERT_INVALID'));
  assert.throws(() => inspectCertificatePem('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'), hasCode('CERT_INVALID'));
});

test('validateCertificateBundle accepts a matching certificate and key', async () => {
  const certPem = await fixture('valid/cert.pem');
  const keyPem = await fixture('valid/key.pem');
  const bundle = validateCertificateBundle({ certPem, keyPem });
  assert.equal(bundle.certificate.chainCount, 0);
  assert.equal(bundle.certificate.subject, inspectCertificatePem(certPem).subject);
  assert.equal(bundle.certificate.key.type, 'rsa');
  assert.match(bundle.certPem, /-----BEGIN CERTIFICATE-----/);
  assert.match(bundle.keyPem, /-----BEGIN PRIVATE KEY-----|-----BEGIN RSA PRIVATE KEY-----/);
});

test('validateCertificateBundle rejects mismatched, weak, encrypted and expired material', async () => {
  const certPem = await fixture('valid/cert.pem');
  const otherKeyPem = await fixture('valid/other-key.pem');
  assert.throws(
    () => validateCertificateBundle({ certPem, keyPem: otherKeyPem }),
    hasCode('CERT_KEY_MISMATCH'),
  );

  const weakCert = await fixture('weak/cert.pem');
  const weakKey = await fixture('weak/key.pem');
  assert.throws(
    () => validateCertificateBundle({ certPem: weakCert, keyPem: weakKey }),
    hasCode('CERT_WEAK_KEY'),
  );

  const encryptedKey = '-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n';
  const keyPem = await fixture('valid/key.pem');
  assert.throws(
    () => validateCertificateBundle({ certPem, keyPem: encryptedKey }),
    hasCode('KEY_ENCRYPTED'),
  );
  assert.throws(
    () => validateCertificateBundle({ certPem, keyPem: 'not a pem key' }),
    hasCode('KEY_INVALID'),
  );

  const inFifteenYears = Date.now() + 15 * 365 * 24 * 60 * 60 * 1000;
  assert.throws(
    () => validateCertificateBundle({ certPem, keyPem, now: inFifteenYears }),
    hasCode('CERT_EXPIRED'),
  );
  const fiveYearsAgo = Date.now() - 5 * 365 * 24 * 60 * 60 * 1000;
  assert.throws(
    () => validateCertificateBundle({ certPem, keyPem, now: fiveYearsAgo }),
    hasCode('CERT_NOT_YET_VALID'),
  );

  assert.throws(
    () => validateCertificateBundle({ certPem: '', keyPem }),
    hasCode('CERT_INVALID'),
  );
});

test('certificate chain validation enforces ordering and signature', async () => {
  const leafPem = await fixture('chain/leaf.crt');
  const intermediatePem = await fixture('chain/intermediate.crt');
  const leafKey = await fixture('chain/leaf.key.pem');
  const validCert = await fixture('valid/cert.pem');

  const chain = validateChain(leafPem, intermediatePem);
  assert.equal(chain.chainCertificates.length, 1);

  const bundle = validateCertificateBundle({
    certPem: leafPem,
    chainPem: intermediatePem,
    keyPem: leafKey,
  });
  assert.equal(bundle.certificate.chainCount, 1);
  assert.match(bundle.certificate.subject, /CN=chain\.example\.com/);

  assert.throws(() => validateChain(leafPem, validCert), hasCode('CHAIN_INVALID'));
  assert.throws(
    () => validateChain(leafPem, `${intermediatePem}${validCert}`),
    hasCode('CHAIN_INVALID'),
  );
  assert.throws(
    () => validateChain(leafPem, 'not a certificate'),
    hasCode('CHAIN_INVALID'),
  );
  assert.throws(
    () => validateChain(`${leafPem}${intermediatePem}`, ''),
    hasCode('CERT_INVALID'),
  );

  // Reversed order is rejected because the leaf cannot sign the intermediate.
  assert.throws(() => validateChain(intermediatePem, leafPem), hasCode('CHAIN_INVALID'));
});
