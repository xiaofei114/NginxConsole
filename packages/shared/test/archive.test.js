import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import {
  decodeArchiveBase64,
  extractArchiveEntries,
  inspectCertificatePem,
  parseCertificateArchive,
} from '@ncs/shared';
import { buildTar, buildTarGz, buildZip } from './helpers/archives.js';

const fixtures = fileURLToPath(new URL('./fixtures/', import.meta.url));

async function fixture(relativePath) {
  return fs.readFile(path.join(fixtures, relativePath), 'utf8');
}

function hasCode(code) {
  return (error) => {
    assert.equal(error?.code, code, `expected ${code}, got ${error?.code}: ${error?.message}`);
    return true;
  };
}

test('ZIP archives are parsed with bounds checks and CRC verification', async () => {
  const certPem = await fixture('valid/cert.pem');
  const keyPem = await fixture('valid/key.pem');
  const archive = buildZip([
    { name: 'bundle/', data: '', externalAttributes: 0o040755 << 16 },
    { name: 'bundle/server.crt', data: certPem },
    { name: 'bundle/server.key', data: keyPem },
    { name: 'bundle/README.txt', data: 'not certificate material\n', method: 0 },
  ]);
  const extracted = extractArchiveEntries(archive);
  assert.equal(extracted.format, 'zip');
  assert.deepEqual(extracted.entries.map((entry) => entry.path), [
    'bundle/server.crt',
    'bundle/server.key',
    'bundle/README.txt',
  ]);

  const parsed = parseCertificateArchive(archive);
  assert.equal(parsed.format, 'zip');
  assert.equal(parsed.entriesScanned, 3);
  assert.equal(parsed.files.certificate, 'bundle/server.crt');
  assert.equal(parsed.files.privateKey, 'bundle/server.key');
  assert.deepEqual(parsed.files.chain, []);
  assert.deepEqual(parsed.ignoredEntries, ['bundle/README.txt']);
  assert.equal(parsed.chainPem, '');
  assert.match(parsed.certPem, /^-----BEGIN CERTIFICATE-----/);
  assert.match(parsed.keyPem, /^-----BEGIN PRIVATE KEY-----/);
});

test('ZIP archives reject traversal, duplicates, links, encryption and bombs', async () => {
  const certPem = await fixture('valid/cert.pem');
  const keyPem = await fixture('valid/key.pem');

  assert.throws(
    () => extractArchiveEntries(buildZip([{ name: '../evil.pem', data: keyPem }])),
    hasCode('ARCHIVE_UNSAFE_PATH'),
  );
  assert.throws(
    () => extractArchiveEntries(buildZip([{ name: '/etc/passwd', data: keyPem }])),
    hasCode('ARCHIVE_UNSAFE_PATH'),
  );
  assert.throws(
    () => extractArchiveEntries(buildZip([{ name: 'config\\server.key', data: keyPem }])),
    hasCode('ARCHIVE_UNSAFE_PATH'),
  );
  assert.throws(
    () => extractArchiveEntries(buildZip([
      { name: 'server.crt', data: certPem },
      { name: 'server.crt', data: certPem },
    ])),
    hasCode('ARCHIVE_UNSAFE_PATH'),
  );
  assert.throws(
    () => extractArchiveEntries(buildZip([
      { name: 'link.pem', data: '/etc/passwd', externalAttributes: 0o120777 << 16 },
    ])),
    hasCode('ARCHIVE_UNSUPPORTED'),
  );
  assert.throws(
    () => extractArchiveEntries(buildZip([{ name: 'server.key', data: keyPem, flags: 0x0001 }])),
    hasCode('ARCHIVE_UNSUPPORTED'),
  );
  assert.throws(
    () => extractArchiveEntries(buildZip([{ name: 'server.key', data: keyPem, method: 99 }])),
    hasCode('ARCHIVE_UNSUPPORTED'),
  );
  assert.throws(
    () => extractArchiveEntries(buildZip([
      { name: 'bomb.pem', data: 'AAAA', uncompressedSize: 300 * 1024 },
    ])),
    hasCode('ARCHIVE_ENTRY_TOO_LARGE'),
  );
  assert.throws(
    () => extractArchiveEntries(buildZip([{ name: 'bad.pem', data: keyPem, method: 0, crc: 0 }])),
    hasCode('ARCHIVE_INVALID'),
  );
  assert.throws(
    () => extractArchiveEntries(buildZip([{ name: 'empty.pem', data: keyPem, method: 0, uncompressedSize: 1 }])),
    hasCode('ARCHIVE_INVALID'),
  );
  assert.throws(() => extractArchiveEntries(Buffer.alloc(0)), hasCode('ARCHIVE_EMPTY'));
  assert.throws(() => extractArchiveEntries(Buffer.from('not an archive')), hasCode('ARCHIVE_UNSUPPORTED'));
  assert.throws(
    () => extractArchiveEntries(Buffer.alloc(512 * 1024 + 1)),
    hasCode('ARCHIVE_TOO_LARGE'),
  );
});

test('TAR and TAR.GZ archives are parsed and unsafe entries rejected', async () => {
  const certPem = await fixture('valid/cert.pem');
  const keyPem = await fixture('valid/key.pem');
  const entries = [
    { name: 'certs/', type: '5' },
    { name: 'certs/fullchain.pem', data: certPem },
    { name: 'certs/privkey.pem', data: keyPem },
  ];

  const tar = buildTar(entries);
  const tarParsed = parseCertificateArchive(tar);
  assert.equal(tarParsed.format, 'tar');
  assert.equal(tarParsed.files.certificate, 'certs/fullchain.pem');
  assert.equal(tarParsed.files.privateKey, 'certs/privkey.pem');

  const gz = buildTarGz(entries);
  const gzParsed = parseCertificateArchive(gz);
  assert.equal(gzParsed.format, 'tar.gz');
  assert.equal(gzParsed.entriesScanned, 2);

  assert.throws(
    () => extractArchiveEntries(buildTar([{ name: '..', type: '5' }])),
    hasCode('ARCHIVE_UNSAFE_PATH'),
  );
  assert.throws(
    () => extractArchiveEntries(buildTar([{ name: '../server.key', data: keyPem }])),
    hasCode('ARCHIVE_UNSAFE_PATH'),
  );
  assert.throws(
    () => extractArchiveEntries(buildTar([{ name: 'server.key', data: keyPem, type: '2' }])),
    hasCode('ARCHIVE_UNSUPPORTED'),
  );
  assert.throws(
    () => extractArchiveEntries(buildTar([{ name: 'server.key', data: keyPem, type: '1' }])),
    hasCode('ARCHIVE_UNSUPPORTED'),
  );
  assert.throws(
    () => extractArchiveEntries(buildTar([{ name: 'bomb.pem', data: 'A', size: 300 * 1024 }])),
    hasCode('ARCHIVE_ENTRY_TOO_LARGE'),
  );
  assert.throws(
    () => extractArchiveEntries(buildTar([{ name: 'truncated.pem', data: keyPem, size: 999_999 }])),
    hasCode('ARCHIVE_ENTRY_TOO_LARGE'),
  );

  const badChecksum = Buffer.from(tar);
  badChecksum.write('0000000\0', 148, 8, 'latin1');
  assert.throws(() => extractArchiveEntries(badChecksum), hasCode('ARCHIVE_INVALID'));

  assert.throws(
    () => extractArchiveEntries(buildTar([{ name: 'plain.txt', data: 'hello' }]).subarray(0, 512)),
    hasCode('ARCHIVE_INVALID'),
  );
  assert.throws(() => extractArchiveEntries(gzipSync(Buffer.from('not tar'))), hasCode('ARCHIVE_UNSUPPORTED'));
  assert.throws(
    () => extractArchiveEntries(gzipSync(Buffer.alloc(9 * 1024 * 1024))),
    hasCode('ARCHIVE_TOO_LARGE'),
  );
});

test('certificate selection finds a valid chain and rejects ambiguity', async () => {
  const leaf = await fixture('chain/leaf.crt');
  const intermediate = await fixture('chain/intermediate.crt');
  const leafKey = await fixture('chain/leaf.key.pem');
  const validCert = await fixture('valid/cert.pem');
  const validKey = await fixture('valid/key.pem');
  const otherKey = await fixture('valid/other-key.pem');

  const chained = buildTarGz([
    { name: 'fullchain.pem', data: `${leaf}\n${intermediate}\n` },
    { name: 'privkey.pem', data: leafKey },
  ]);
  const chainedResult = parseCertificateArchive(chained);
  assert.match(inspectCertificatePem(chainedResult.certPem).subject, /CN=chain\.example\.com/);
  assert.match(chainedResult.chainPem, /BEGIN CERTIFICATE/);
  assert.match(inspectCertificatePem(chainedResult.chainPem).subject, /CN=NCS Test Intermediate CA/);
  assert.equal(chainedResult.files.certificate, 'fullchain.pem');
  assert.deepEqual(chainedResult.files.chain, ['fullchain.pem']);

  const oneBundledFile = buildZip([{ name: 'all.pem', data: `${leaf}${intermediate}${leafKey}` }]);
  const bundledResult = parseCertificateArchive(oneBundledFile);
  assert.equal(bundledResult.files.certificate, 'all.pem');
  assert.equal(bundledResult.files.privateKey, 'all.pem');
  assert.equal(bundledResult.files.chain[0], 'all.pem');

  assert.throws(
    () => parseCertificateArchive(buildZip([
      { name: 'a.key', data: validKey },
      { name: 'b.key', data: otherKey },
      { name: 'a.crt', data: validCert },
    ])),
    hasCode('ARCHIVE_AMBIGUOUS'),
  );
  assert.throws(
    () => parseCertificateArchive(buildZip([
      { name: 'server.key', data: validKey },
      { name: 'server.crt', data: leaf },
    ])),
    hasCode('CERT_KEY_MISMATCH'),
  );

  const duplicateKey = parseCertificateArchive(buildZip([
    { name: 'privkey.pem', data: validKey },
    { name: 'backup/privkey-copy.pem', data: validKey.replace(/\n/g, '\r\n') },
    { name: 'fullchain.pem', data: validCert },
  ]));
  assert.equal(duplicateKey.files.privateKey, 'privkey.pem');
  assert.ok(duplicateKey.ignoredEntries.includes('backup/privkey-copy.pem'));
  assert.throws(
    () => parseCertificateArchive(buildZip([
      { name: 'server.key', data: '-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n' },
      { name: 'server.crt', data: validCert },
    ])),
    hasCode('KEY_ENCRYPTED'),
  );
  assert.throws(
    () => parseCertificateArchive(buildZip([{ name: 'server.crt', data: validCert }])),
    hasCode('ARCHIVE_KEY_MISSING'),
  );
  assert.throws(
    () => parseCertificateArchive(buildZip([{ name: 'server.key', data: validKey }])),
    hasCode('ARCHIVE_CERT_MISSING'),
  );
  assert.throws(
    () => parseCertificateArchive(buildZip([{ name: 'notes.txt', data: 'nothing here' }])),
    hasCode('ARCHIVE_EMPTY'),
  );
  assert.throws(
    () => parseCertificateArchive(buildZip([
      { name: 'server.key', data: validKey },
      { name: 'broken.crt', data: '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n' },
    ])),
    hasCode('CERT_INVALID'),
  );

  const withNoise = parseCertificateArchive(buildZip([
    { name: 'server.key', data: validKey },
    { name: 'server.crt', data: 'not a certificate' },
    { name: 'valid.crt', data: validCert },
    { name: 'duplicate.crt', data: validCert },
  ]));
  assert.equal(withNoise.files.certificate, 'valid.crt');
  assert.ok(withNoise.ignoredEntries.includes('server.crt'));
  assert.ok(withNoise.ignoredEntries.includes('duplicate.crt'));
});

test('base64 decoding requires canonical bounded input', () => {
  const zip = buildZip([{ name: 'a.pem', data: 'x' }]);
  const encoded = zip.toString('base64');
  assert.deepEqual(decodeArchiveBase64(encoded), zip);
  assert.throws(() => decodeArchiveBase64(''), hasCode('ARCHIVE_INVALID'));
  assert.throws(() => decodeArchiveBase64('not*b64'), hasCode('ARCHIVE_INVALID'));
  assert.throws(() => decodeArchiveBase64('eA'), hasCode('ARCHIVE_INVALID'));
  assert.throws(() => decodeArchiveBase64('eA='), hasCode('ARCHIVE_INVALID'));
  assert.throws(
    () => decodeArchiveBase64(Buffer.alloc(512 * 1024 + 1).toString('base64')),
    hasCode('ARCHIVE_TOO_LARGE'),
  );
});
