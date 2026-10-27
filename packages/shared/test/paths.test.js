import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  assertAllowedTextFile,
  assertSafeCertificateName,
  isInside,
  isPrivateKeyContent,
  normalizeRelativePath,
  resolveSafeDirectory,
  resolveSafeFile,
  resolveWorkspace,
} from '@ncs/shared';

function hasCode(code) {
  return (error) => {
    assert.equal(error?.code, code, `expected ${code}, got ${error?.code}: ${error?.message}`);
    return true;
  };
}

test('normalizeRelativePath rejects traversal and platform ambiguity', () => {
  assert.equal(normalizeRelativePath('conf.d/site.conf'), 'conf.d/site.conf');
  assert.equal(normalizeRelativePath('./conf.d//site.conf'), 'conf.d/site.conf');
  assert.equal(normalizeRelativePath(''), '');
  // '..' is always rejected, even when it would normalize back inside.
  assert.throws(() => normalizeRelativePath('a/../b'), hasCode('INVALID_PATH'));
  assert.throws(() => normalizeRelativePath('a/./b/../c'), hasCode('INVALID_PATH'));

  for (const bad of ['../etc/passwd', '/etc/passwd', 'C:/Windows/system.ini', 'conf\\site.conf', 'a\u0000b']) {
    assert.throws(() => normalizeRelativePath(bad), hasCode('INVALID_PATH'), bad);
  }
  assert.throws(() => normalizeRelativePath('', { allowEmpty: false }), hasCode('INVALID_PATH'));
  assert.throws(() => normalizeRelativePath('a'.repeat(300)), hasCode('INVALID_PATH'));
});

test('text file and certificate name allowlists are enforced', () => {
  for (const name of ['nginx.conf', 'conf.d/site.conf', 'ssl/server.pem', 'notes.txt', 'chain.crt']) {
    assert.doesNotThrow(() => assertAllowedTextFile(name), name);
  }
  for (const name of ['ssl/server.key', 'run.sh', 'payload.bin', 'no-extension']) {
    assert.throws(() => assertAllowedTextFile(name), hasCode('FILE_TYPE_NOT_ALLOWED'), name);
  }

  assert.equal(assertSafeCertificateName('example.com'), 'example.com');
  assert.equal(assertSafeCertificateName('a_b-c.d'), 'a_b-c.d');
  for (const name of ['../evil', '.hidden', '', 'a/b', 'a'.repeat(65), 'name with space']) {
    assert.throws(() => assertSafeCertificateName(name), hasCode('INVALID_CERT_NAME'), name);
  }
});

test('private key detection covers PEM variants', () => {
  assert.equal(isPrivateKeyContent('-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----'), true);
  assert.equal(isPrivateKeyContent('-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----'), true);
  assert.equal(isPrivateKeyContent('-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----'), true);
  assert.equal(isPrivateKeyContent('server { listen 80; }'), false);
  assert.equal(isPrivateKeyContent(null), false);
});

test('resolveSafeFile and resolveWorkspace stay inside the configured root', async (t) => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'ncs-paths-'));
  const root = path.join(base, 'root');
  const outside = path.join(base, 'outside');
  await fs.mkdir(path.join(root, 'conf.d'), { recursive: true });
  await fs.mkdir(outside, { recursive: true });
  await fs.writeFile(path.join(root, 'nginx.conf'), 'worker_processes 1;\n');
  await fs.writeFile(path.join(root, 'conf.d', 'site.conf'), 'server { listen 80; }\n');
  await fs.writeFile(path.join(outside, 'secret.conf'), 'secret\n');
  t.after(() => fs.rm(base, { recursive: true, force: true }));

  const realRoot = await fs.realpath(root);
  const directory = await resolveSafeDirectory(realRoot, 'conf.d');
  assert.equal(directory.relativePath, 'conf.d');
  assert.ok(directory.realPath.endsWith('conf.d'));

  const file = await resolveSafeFile(realRoot, 'conf.d/site.conf', { mustExist: true });
  assert.equal(file.existed, true);
  assert.equal(await fs.readFile(file.absolutePath, 'utf8'), 'server { listen 80; }\n');

  const created = await resolveSafeFile(realRoot, 'conf.d/new.conf', { forWrite: true });
  assert.equal(created.existed, false);

  assert.equal(isInside(realRoot, outside), false);
  assert.equal(isInside(realRoot, path.join(realRoot, 'a', 'b')), true);
  await assert.rejects(
    resolveSafeFile(realRoot, '../outside/secret.conf', { mustExist: true }),
    hasCode('INVALID_PATH'),
  );
  await assert.rejects(
    resolveSafeFile(realRoot, 'conf.d/missing.conf', { mustExist: true }),
    hasCode('NOT_FOUND'),
  );

  const workspace = await resolveWorkspace([realRoot], path.join(realRoot, 'conf.d'));
  assert.equal(workspace.root, realRoot);
  assert.equal((await resolveWorkspace([realRoot], realRoot)).path, realRoot);
  await assert.rejects(resolveWorkspace([realRoot], outside), hasCode('WORKSPACE_NOT_ALLOWED'));
  await assert.rejects(resolveWorkspace([realRoot], 'relative/path'), hasCode('INVALID_WORKSPACE'));
});

test('symlinks that escape the root are rejected when supported', async (t) => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'ncs-link-'));
  const root = path.join(base, 'root');
  const outside = path.join(base, 'outside');
  await fs.mkdir(root, { recursive: true });
  await fs.mkdir(outside, { recursive: true });
  await fs.writeFile(path.join(outside, 'secret.conf'), 'secret\n');
  t.after(() => fs.rm(base, { recursive: true, force: true }));

  const realRoot = await fs.realpath(root);
  let created = false;
  try {
    await fs.symlink(outside, path.join(root, 'escape'), 'dir');
    created = true;
  } catch {
    // Windows may require elevated privileges; skip instead of failing the suite.
  }
  if (!created) {
    t.skip('symlink creation not permitted on this platform');
    return;
  }
  const realOutside = await fs.realpath(outside);
  await assert.rejects(
    resolveSafeFile(realRoot, 'escape/secret.conf', { mustExist: true }),
    (error) => ['PATH_ESCAPE', 'PATH_ERROR'].includes(error?.code),
  );
  assert.ok(!isInside(realRoot, realOutside));
});
