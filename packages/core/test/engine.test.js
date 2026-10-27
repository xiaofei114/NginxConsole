import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { NginxEngine } from '@ncs/core';
import { buildZip } from '../../shared/test/helpers/archives.js';

const fixtures = fileURLToPath(new URL('../../shared/test/fixtures/', import.meta.url));

async function fixture(relativePath) {
  return fs.readFile(path.join(fixtures, relativePath), 'utf8');
}

function hasCode(code) {
  return (error) => {
    assert.equal(error?.code, code, `expected ${code}, got ${error?.code}: ${error?.message}`);
    return true;
  };
}

const ORIGINAL_CONF = 'worker_processes 1;\nevents { worker_connections 64; }\n';

test('NginxEngine enforces workspace sandbox, optimistic locking and backups', async (t) => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'ncs-engine-'));
  const root = path.join(base, 'nginx');
  const outside = path.join(base, 'outside');
  await fs.mkdir(path.join(root, 'conf.d'), { recursive: true });
  await fs.mkdir(outside, { recursive: true });
  await fs.writeFile(path.join(root, 'nginx.conf'), ORIGINAL_CONF);
  await fs.writeFile(path.join(root, 'conf.d', 'site.conf'), 'server { listen 8080; }\n');
  await fs.writeFile(path.join(outside, 'secret.conf'), 'secret\n');

  const missingBinary = path.resolve(base, 'no-such-nginx-binary');
  const engine = await NginxEngine.create({
    stateDir: path.join(base, 'state'),
    allowedRoots: [root],
    workspace: root,
    nginxBin: missingBinary,
    systemctlBin: path.resolve(base, 'no-such-systemctl'),
    sudoBin: path.resolve(base, 'no-such-sudo'),
    controlMode: 'signal',
    configFile: 'nginx.conf',
    certDir: 'ssl',
    enforceTest: false,
    label: 'test-node',
  });
  t.after(() => fs.rm(base, { recursive: true, force: true }));

  await t.test('reports info and file tree inside the workspace', async () => {
    const info = await engine.getInfo();
    assert.equal(info.label, 'test-node');
    assert.equal(path.resolve(info.workspace), path.resolve(await fs.realpath(root)));
    assert.equal(info.configFileExists, true);
    assert.equal(info.configFile, 'nginx.conf');
    assert.equal(info.nginxAvailable, false);
    assert.equal(info.enforceTest, false);
    assert.deepEqual(info.allowedRoots, [await fs.realpath(root)]);

    const listing = await engine.listFiles('');
    const names = listing.entries.map((entry) => entry.name);
    assert.ok(names.includes('nginx.conf'));
    assert.ok(names.includes('conf.d'));
    const config = listing.entries.find((entry) => entry.name === 'nginx.conf');
    assert.equal(config.type, 'file');
    assert.equal(config.editable, true);
    assert.equal(config.privateKey, false);
    const directory = listing.entries.find((entry) => entry.name === 'conf.d');
    assert.equal(directory.type, 'dir');

    const child = await engine.listFiles('conf.d');
    assert.equal(child.path, 'conf.d');
    assert.deepEqual(child.entries.map((entry) => entry.name), ['site.conf']);
  });

  await t.test('reads and writes files with hashes and rollback backups', async () => {
    const original = await engine.readFile('nginx.conf');
    assert.equal(original.content, ORIGINAL_CONF);
    assert.match(original.hash, /^[a-f0-9]{64}$/);

    const updated = await engine.writeFile({
      path: 'nginx.conf',
      content: `${ORIGINAL_CONF}# updated\n`,
      baseHash: original.hash,
    });
    assert.equal(updated.unchanged, false);
    assert.match(updated.backupId, /^[0-9a-f-]{36}$/);
    assert.notEqual(updated.hash, original.hash);

    const afterUpdate = await engine.readFile('nginx.conf');
    assert.equal(afterUpdate.content, `${ORIGINAL_CONF}# updated\n`);

    const backups = await engine.backups.list(10);
    assert.equal(backups[0].targetRel, 'nginx.conf');
    assert.equal(backups[0].reason, 'write');

    const restored = await engine.restoreBackup(updated.backupId);
    assert.equal(restored.restored, updated.backupId);
    assert.match(restored.preRestoreBackupId, /^[0-9a-f-]{36}$/);
    assert.equal((await engine.readFile('nginx.conf')).content, ORIGINAL_CONF);

    const unchanged = await engine.writeFile({
      path: 'nginx.conf',
      content: ORIGINAL_CONF,
      baseHash: (await engine.readFile('nginx.conf')).hash,
    });
    assert.equal(unchanged.unchanged, true);
    assert.equal(unchanged.backupId, null);

    await assert.rejects(
      engine.writeFile({ path: 'nginx.conf', content: 'changed\n', baseHash: '0'.repeat(64) }),
      hasCode('FILE_CONFLICT'),
    );

    const created = await engine.writeFile({ path: 'conf.d/new.conf', content: 'server { listen 8081; }\n' });
    assert.equal(created.unchanged, false);
    assert.equal(created.backupId, null);
    assert.equal((await engine.readFile('conf.d/new.conf')).content, 'server { listen 8081; }\n');
  });

  await t.test('rejects traversal, private keys and disallowed file types', async () => {
    await assert.rejects(engine.readFile('../outside/secret.conf'), hasCode('INVALID_PATH'));
    await assert.rejects(engine.readFile('/etc/passwd'), hasCode('INVALID_PATH'));
    await assert.rejects(
      engine.writeFile({ path: '../outside/secret.conf', content: 'changed\n' }),
      hasCode('INVALID_PATH'),
    );
    await assert.rejects(engine.readFile('ssl/server.key'), hasCode('FILE_TYPE_NOT_ALLOWED'));
    await assert.rejects(engine.readFile('run.sh'), hasCode('FILE_TYPE_NOT_ALLOWED'));
    await assert.rejects(
      engine.writeFile({
        path: 'secret.pem',
        content: '-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n',
      }),
      hasCode('PRIVATE_KEY_WRITE_DENIED'),
    );
    await assert.rejects(
      engine.writeFile({
        path: 'nginx.conf',
        content: `${ORIGINAL_CONF}\u0000`,
      }),
      hasCode('INVALID_CONTENT'),
    );
    await assert.rejects(
      engine.writeFile({ path: 'nginx.conf', content: 'x'.repeat(600 * 1024) }),
      hasCode('FILE_TOO_LARGE'),
    );
  });

  await t.test('only allows selecting a workspace inside the allowlist', async () => {
    await assert.rejects(engine.setWorkspace(outside), hasCode('WORKSPACE_NOT_ALLOWED'));
    await assert.rejects(engine.setWorkspace('relative/path'), hasCode('INVALID_WORKSPACE'));
    const options = await engine.getWorkspaceOptions();
    assert.equal(options.current, path.resolve(await fs.realpath(root)));
    assert.equal(options.roots.length, 1);
    assert.ok(options.roots[0].workspaces.some((workspace) => workspace.hasConfig));
  });

  await t.test('uploads validated certificate bundles and never exposes keys', async () => {
    const certPem = await fixture('valid/cert.pem');
    const keyPem = await fixture('valid/key.pem');

    await assert.rejects(
      engine.uploadCertificate({ name: '../evil', certPem, keyPem }),
      hasCode('INVALID_CERT_NAME'),
    );
    await assert.rejects(
      engine.uploadCertificate({ name: 'example.com', certPem, keyPem: await fixture('valid/other-key.pem') }),
      hasCode('CERT_KEY_MISMATCH'),
    );

    const result = await engine.uploadCertificate({ name: 'example.com', certPem, keyPem });
    assert.equal(result.files.length, 3);
    const keyFile = result.files.find((file) => file.kind === 'privateKey');
    assert.equal(keyFile.path, 'ssl/example.com.key');
    assert.equal(keyFile.mode, '0600');
    assert.ok(!JSON.stringify(result.certificate).includes('PRIVATE KEY'));

    assert.equal(await fs.readFile(path.join(root, 'ssl', 'example.com.key'), 'utf8'), (await fixture('valid/key.pem')).replace(/\s+$/, '\n'));
    const keyStat = await fs.stat(path.join(root, 'ssl', 'example.com.key'));
    if (process.platform !== 'win32') assert.equal(keyStat.mode & 0o777, 0o600);

    const listing = await engine.listCertificates();
    assert.ok(listing.certificates.some((item) => item.name === 'example.com.crt'));
    await assert.rejects(engine.readFile('ssl/example.com.key'), hasCode('FILE_TYPE_NOT_ALLOWED'));

    // Invalid material is rejected before anything is written.
    await assert.rejects(
      engine.uploadCertificate({ name: 'example.com', certPem, keyPem: await fixture('valid/other-key.pem') }),
      hasCode('CERT_KEY_MISMATCH'),
    );
    assert.equal(await fs.readFile(path.join(root, 'ssl', 'example.com.key'), 'utf8'), (await fixture('valid/key.pem')).replace(/\s+$/, '\n'));

    // A successful overwrite creates backups for every replaced file.
    const overwritten = await engine.uploadCertificate({ name: 'example.com', certPem, keyPem });
    assert.ok(overwritten.files.every((file) => /^[0-9a-f-]{36}$/.test(file.backupId)));
  });

  await t.test('imports certificate material from a ZIP archive', async () => {
    const certPem = await fixture('valid/cert.pem');
    const keyPem = await fixture('valid/key.pem');
    const archive = buildZip([
      { name: 'release/fullchain.pem', data: certPem },
      { name: 'release/privkey.pem', data: keyPem },
      { name: 'release/README.txt', data: 'ignore me\n' },
    ]);
    const result = await engine.execute('cert.uploadArchive', {
      name: 'archive.example.com',
      archiveBase64: archive.toString('base64'),
    });
    assert.equal(result.archive.format, 'zip');
    assert.equal(result.archive.files.certificate, 'release/fullchain.pem');
    assert.equal(result.archive.files.privateKey, 'release/privkey.pem');
    assert.deepEqual(result.archive.ignoredEntries, ['release/README.txt']);
    assert.equal(result.files.length, 3);
    assert.ok(!JSON.stringify(result).includes('PRIVATE KEY'));
    assert.equal((await fs.stat(path.join(root, 'ssl', 'archive.example.com.key'))).isFile(), true);

    const unsafe = buildZip([
      { name: '../escape/fullchain.pem', data: certPem },
      { name: '../escape/privkey.pem', data: keyPem },
    ]);
    await assert.rejects(
      engine.uploadCertificateArchive({ name: 'escape.example.com', archiveBase64: unsafe.toString('base64') }),
      hasCode('ARCHIVE_UNSAFE_PATH'),
    );
    await assert.rejects(
      engine.uploadCertificateArchive({ name: 'archive.example.com', archiveBase64: 'not base64!' }),
      hasCode('ARCHIVE_INVALID'),
    );
  });

  await t.test('lists certificates kept in panel-style subdirectories', async () => {
    const certPem = await fixture('valid/cert.pem');
    const keyPem = await fixture('valid/key.pem');
    const panelDir = path.join(root, 'ssl', 'panel.example_nginx');
    await fs.mkdir(panelDir, { recursive: true });
    await fs.writeFile(path.join(panelDir, 'fullchain.pem'), certPem);
    await fs.writeFile(path.join(panelDir, 'privkey.pem'), keyPem);
    await fs.mkdir(path.join(root, 'ssl', 'empty.example'), { recursive: true });

    const listing = await engine.listCertificates();
    const entry = listing.certificates.find((item) => item.name === 'panel.example_nginx');
    assert.ok(entry, 'subdirectory certificate should be listed');
    assert.equal(entry.directory, true);
    assert.equal(entry.keyPresent, true);
    assert.equal(entry.file, 'ssl/panel.example_nginx/fullchain.pem');
    assert.ok(!JSON.stringify(entry).includes('PRIVATE KEY'));

    const flat = listing.certificates.find((item) => item.name === 'example.com.crt');
    assert.equal(flat.directory, false);
    assert.equal(flat.keyPresent, true);
    assert.ok(!listing.errors.some((item) => item.file.includes('empty.example')));
  });

  await t.test('uploads certificates into panel-style directories', async () => {
    const certPem = await fixture('valid/cert.pem');
    const keyPem = await fixture('valid/key.pem');
    const payload = { name: 'panel2.example_nginx', certPem, keyPem, layout: 'directory' };

    await assert.rejects(
      engine.uploadCertificate({ ...payload, layout: 'weird' }),
      hasCode('INVALID_CERT_LAYOUT'),
    );

    const result = await engine.uploadCertificate(payload);
    assert.equal(result.layout, 'directory');
    assert.equal(result.directory, 'panel2.example_nginx');
    assert.deepEqual(result.files.map((file) => file.path), [
      'ssl/panel2.example_nginx/panel2.example_bundle.crt',
      'ssl/panel2.example_nginx/panel2.example.key',
    ]);
    const fullchain = await fs.readFile(path.join(root, 'ssl', 'panel2.example_nginx', 'panel2.example_bundle.crt'), 'utf8');
    assert.match(fullchain, /BEGIN CERTIFICATE/);
    assert.ok(!fullchain.includes('PRIVATE KEY'));
    const keyFile = result.files.find((file) => file.kind === 'privateKey');
    assert.equal(keyFile.mode, '0600');

    const added = await engine.uploadCertificate({ ...payload, name: 'panel3.example' });
    assert.equal(added.directory, 'panel3.example_nginx');
    assert.equal(added.files[0].path, 'ssl/panel3.example_nginx/panel3.example_bundle.crt');

    const overwritten = await engine.uploadCertificate(payload);
    assert.ok(overwritten.files.every((file) => /^[0-9a-f-]{36}$/.test(file.backupId)));

    const listing = await engine.listCertificates();
    const entry = listing.certificates.find((item) => item.name === 'panel2.example_nginx');
    assert.equal(entry.directory, true);
    assert.equal(entry.keyPresent, true);
    assert.equal(entry.file, 'ssl/panel2.example_nginx/panel2.example_bundle.crt');
  });
});
