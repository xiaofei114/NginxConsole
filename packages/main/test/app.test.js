import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateEd25519KeyPair } from '@ncs/shared';
import { buildTarGz, buildZip } from '../../shared/test/helpers/archives.js';
import { loadConfig } from '../src/config.js';
import { createApp } from '../src/app.js';

const ORIGINAL_CONF = 'worker_processes 1;\nevents { worker_connections 64; }\n';
const UPDATED_CONF = 'worker_processes 2;\nevents { worker_connections 256; }\n';
const fixtures = fileURLToPath(new URL('../../shared/test/fixtures/', import.meta.url));

async function fixture(relativePath) {
  return fs.readFile(path.join(fixtures, relativePath), 'utf8');
}

function request(port, {
  method = 'GET',
  requestPath = '/',
  headers = {},
  body = null,
} = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === null ? null : Buffer.from(JSON.stringify(body), 'utf8');
    const allHeaders = { ...headers };
    if (payload) {
      allHeaders['content-type'] = 'application/json';
      allHeaders['content-length'] = String(payload.length);
    }
    const req = http.request(
      { host: '127.0.0.1', port, method, path: requestPath, headers: allHeaders, agent: false },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try {
            json = JSON.parse(text);
          } catch {
            json = null;
          }
          resolve({ status: res.statusCode, headers: res.headers, text, json });
        });
      },
    );
    req.setTimeout(15_000, () => req.destroy(new Error('request timeout')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function hasError(response, code, status) {
  assert.equal(response.status, status, `unexpected status ${response.status}: ${response.text}`);
  assert.equal(response.json?.ok, false);
  assert.equal(response.json?.error?.code, code, `unexpected error ${JSON.stringify(response.json)}`);
}

test('main server API enforces auth, CSRF, origin and host, and manages local Nginx', async (t) => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'ncs-app-'));
  const root = path.join(base, 'nginx');
  await fs.mkdir(root, { recursive: true });
  await fs.writeFile(path.join(root, 'nginx.conf'), ORIGINAL_CONF);

  const config = await loadConfig({
    NODE_ENV: 'development',
    NCS_DATA_DIR: path.join(base, 'data'),
    NCS_ALLOWED_ROOTS: root,
    NCS_LOCAL_WORKSPACE: root,
    NCS_ADMIN_USER: 'admin',
    NCS_ADMIN_PASSWORD: 'AdminPassword123!',
    NCS_DEV_UNSAFE_SKIP_NGINX_TEST: '1',
    NCS_COOKIE_SECURE: '0',
  });
  assert.equal(config.demoWorkspace, false);
  assert.equal(config.enforceTest, false);

  const runtime = await createApp(config, { logger: { error() {} } });
  await new Promise((resolve, reject) => {
    runtime.server.once('error', reject);
    runtime.server.listen(0, '127.0.0.1', resolve);
  });
  const port = runtime.server.address().port;
  const origin = `http://127.0.0.1:${port}`;

  t.after(async () => {
    await runtime.close();
    await fs.rm(base, { recursive: true, force: true });
  });

  let cookie = null;
  let csrfToken = null;
  let agentId = null;

  await t.test('serves health and hides server identity headers', async () => {
    const response = await request(port, { requestPath: '/api/health' });
    assert.equal(response.status, 200);
    assert.equal(response.json.ok, true);
    assert.equal(response.json.data.status, 'ok');
    assert.equal(response.headers['x-powered-by'], undefined);
    assert.match(response.headers['content-security-policy'], /default-src 'self'/);
    assert.equal(response.headers['cache-control'], 'no-store, max-age=0');
  });

  await t.test('rejects disallowed Host and Origin values', async () => {
    hasError(await request(port, { requestPath: '/api/health', headers: { host: 'evil.example' } }), 'INVALID_HOST', 421);
    hasError(
      await request(port, { method: 'POST', requestPath: '/api/auth/login', body: { username: 'admin', password: 'x' } }),
      'INVALID_ORIGIN',
      403,
    );
    hasError(
      await request(port, {
        method: 'POST',
        requestPath: '/api/auth/login',
        headers: { origin: 'https://evil.example' },
        body: { username: 'admin', password: 'x' },
      }),
      'INVALID_ORIGIN',
      403,
    );
    hasError(
      await request(port, {
        method: 'POST',
        requestPath: '/api/auth/login',
        headers: { origin: 'null' },
        body: { username: 'admin', password: 'x' },
      }),
      'INVALID_ORIGIN',
      403,
    );
  });

  await t.test('logs in with a hardened session cookie', async () => {
    const bad = await request(port, {
      method: 'POST',
      requestPath: '/api/auth/login',
      headers: { origin },
      body: { username: 'admin', password: 'WrongPassword123!' },
    });
    hasError(bad, 'INVALID_CREDENTIALS', 401);

    const response = await request(port, {
      method: 'POST',
      requestPath: '/api/auth/login',
      headers: { origin },
      body: { username: 'admin', password: 'AdminPassword123!' },
    });
    assert.equal(response.status, 200);
    assert.equal(response.json.data.user.username, 'admin');
    assert.match(response.json.data.csrfToken, /^[A-Za-z0-9_-]{43}$/);
    const setCookie = response.headers['set-cookie'];
    const rawCookie = Array.isArray(setCookie) ? setCookie[0] : setCookie;
    assert.ok(rawCookie, 'expected Set-Cookie');
    assert.match(rawCookie, /HttpOnly/);
    assert.match(rawCookie, /SameSite=Strict/);
    assert.doesNotMatch(rawCookie, /Secure/);
    cookie = rawCookie.split(';')[0];
    csrfToken = response.json.data.csrfToken;

    const me = await request(port, { requestPath: '/api/auth/me', headers: { cookie } });
    assert.equal(me.status, 200);
    assert.equal(me.json.data.user.username, 'admin');
    assert.equal(me.json.data.csrfToken, csrfToken);

    hasError(await request(port, { requestPath: '/api/auth/me' }), 'UNAUTHENTICATED', 401);
  });

  await t.test('requires CSRF for state-changing requests', async () => {
    const response = await request(port, {
      method: 'POST',
      requestPath: '/api/servers',
      headers: { cookie, origin },
      body: { name: 'edge-1' },
    });
    hasError(response, 'INVALID_CSRF', 403);
  });

  await t.test('creates an agent and completes one-time enrollment', async () => {
    const created = await request(port, {
      method: 'POST',
      requestPath: '/api/servers',
      headers: { cookie, origin, 'x-csrf-token': csrfToken },
      body: { name: 'edge-1' },
    });
    assert.equal(created.status, 201);
    assert.equal(created.json.data.agent.name, 'edge-1');
    assert.equal(created.json.data.agent.status, 'pending');
    assert.match(created.json.data.enrollmentToken, /^[A-Za-z0-9_-]{43}$/);
    agentId = created.json.data.agent.id;
    const enrollmentToken = created.json.data.enrollmentToken;

    const before = await request(port, { requestPath: '/api/servers', headers: { cookie } });
    assert.equal(before.status, 200);
    const pending = before.json.data.servers.find((server) => server.id === agentId);
    assert.equal(pending.status, 'pending');
    assert.equal(pending.online, false);

    const { publicKeyPem } = generateEd25519KeyPair();
    const enrolled = await request(port, {
      method: 'POST',
      requestPath: '/api/agent/enroll',
      body: {
        agentId,
        token: enrollmentToken,
        publicKey: publicKeyPem,
        meta: { hostname: 'edge-1', platform: 'linux' },
      },
    });
    assert.equal(enrolled.status, 200);
    assert.equal(enrolled.json.data.agent.id, agentId);
    assert.match(enrolled.json.data.mainPublicKey, /-----BEGIN PUBLIC KEY-----/);

    const replay = await request(port, {
      method: 'POST',
      requestPath: '/api/agent/enroll',
      body: { agentId, token: enrollmentToken, publicKey: publicKeyPem },
    });
    hasError(replay, 'AGENT_NOT_PENDING', 409);

    const after = await request(port, { requestPath: '/api/servers', headers: { cookie } });
    const active = after.json.data.servers.find((server) => server.id === agentId);
    assert.equal(active.status, 'active');
    assert.equal(active.online, false);
    assert.match(active.keyFingerprint, /^SHA256:/);
    assert.ok(!after.text.includes('publicKey'), 'agent public keys must not be listed');
  });

  await t.test('reads and writes local nginx.conf with backup rollback', async () => {
    const info = await request(port, { requestPath: '/api/servers/local/info', headers: { cookie } });
    assert.equal(info.status, 200);
    assert.equal(info.json.data.label, '主服务器本地 Nginx');
    assert.equal(info.json.data.configFileExists, true);
    assert.equal(info.json.data.enforceTest, false);
    assert.equal(path.resolve(info.json.data.workspace), path.resolve(await fs.realpath(root)));

    const read = await request(port, {
      requestPath: '/api/servers/local/file?path=nginx.conf',
      headers: { cookie },
    });
    assert.equal(read.status, 200);
    assert.equal(read.json.data.content, ORIGINAL_CONF);
    assert.match(read.json.data.hash, /^[a-f0-9]{64}$/);

    const write = await request(port, {
      method: 'PUT',
      requestPath: '/api/servers/local/file',
      headers: { cookie, origin, 'x-csrf-token': csrfToken },
      body: { path: 'nginx.conf', content: UPDATED_CONF, baseHash: read.json.data.hash },
    });
    assert.equal(write.status, 200);
    assert.match(write.json.data.backupId, /^[0-9a-f-]{36}$/);

    const changed = await request(port, {
      requestPath: '/api/servers/local/file?path=nginx.conf',
      headers: { cookie },
    });
    assert.equal(changed.json.data.content, UPDATED_CONF);

    const stale = await request(port, {
      method: 'PUT',
      requestPath: '/api/servers/local/file',
      headers: { cookie, origin, 'x-csrf-token': csrfToken },
      body: { path: 'nginx.conf', content: 'worker_processes 3;\n', baseHash: read.json.data.hash },
    });
    hasError(stale, 'FILE_CONFLICT', 409);

    const restored = await request(port, {
      method: 'POST',
      requestPath: `/api/servers/local/backups/${write.json.data.backupId}/restore`,
      headers: { cookie, origin, 'x-csrf-token': csrfToken },
      body: { confirm: true },
    });
    assert.equal(restored.status, 200);
    assert.equal(restored.json.data.restored, write.json.data.backupId);

    const finalRead = await request(port, {
      requestPath: '/api/servers/local/file?path=nginx.conf',
      headers: { cookie },
    });
    assert.equal(finalRead.json.data.content, ORIGINAL_CONF);

    const traversal = await request(port, {
      requestPath: '/api/servers/local/file?path=../etc/passwd',
      headers: { cookie },
    });
    assert.equal(traversal.status, 400);
    assert.equal(traversal.json.error.code, 'INVALID_PATH');
  });

  await t.test('uploads certificates from an archive and rejects unsafe archives', async () => {
    const certPem = await fixture('valid/cert.pem');
    const keyPem = await fixture('valid/key.pem');
    const archiveBase64 = buildTarGz([
      { name: 'nginx/fullchain.pem', data: certPem },
      { name: 'nginx/privkey.pem', data: keyPem },
      { name: 'nginx/README.md', data: 'noise\n' },
    ]).toString('base64');

    const uploaded = await request(port, {
      method: 'POST',
      requestPath: '/api/servers/local/certs/archive',
      headers: { cookie, origin, 'x-csrf-token': csrfToken },
      body: { name: 'archive.example.com', filename: 'certs.tar.gz', archiveBase64 },
    });
    assert.equal(uploaded.status, 200);
    assert.equal(uploaded.json.data.archive.format, 'tar.gz');
    assert.equal(uploaded.json.data.archive.files.certificate, 'nginx/fullchain.pem');
    assert.equal(uploaded.json.data.files.length, 3);
    assert.ok(!uploaded.text.includes('PRIVATE KEY'));
    assert.equal(
      (await fs.stat(path.join(root, 'ssl', 'archive.example.com.key'))).isFile(),
      true,
    );

    const listed = await request(port, {
      requestPath: '/api/servers/local/certs',
      headers: { cookie },
    });
    assert.equal(listed.status, 200);
    assert.ok(listed.json.data.certificates.some((item) => item.name === 'archive.example.com.crt'));

    const unsafe = buildZip([
      { name: '../escape/fullchain.pem', data: certPem },
      { name: '../escape/privkey.pem', data: keyPem },
    ]).toString('base64');
    const rejected = await request(port, {
      method: 'POST',
      requestPath: '/api/servers/local/certs/archive',
      headers: { cookie, origin, 'x-csrf-token': csrfToken },
      body: { name: 'escape.example.com', archiveBase64: unsafe },
    });
    assert.equal(rejected.status, 400);
    assert.equal(rejected.json.error.code, 'ARCHIVE_UNSAFE_PATH');
  });

  await t.test('requires explicit confirmation for restart', async () => {
    const response = await request(port, {
      method: 'POST',
      requestPath: '/api/servers/local/restart',
      headers: { cookie, origin, 'x-csrf-token': csrfToken },
      body: {},
    });
    hasError(response, 'CONFIRM_REQUIRED', 400);
  });

  await t.test('records an audit trail and invalidates the session on logout', async () => {
    const audit = await request(port, { requestPath: '/api/audit?limit=200', headers: { cookie } });
    assert.equal(audit.status, 200);
    const actions = new Set(audit.json.data.entries.map((entry) => entry.action));
    for (const expected of [
      'auth.login',
      'server.create',
      'agent.enroll',
      'server.file.write',
      'server.backup.restore',
    ]) {
      assert.ok(actions.has(expected), `missing audit action ${expected}`);
    }
    const auditText = JSON.stringify(audit.json.data.entries);
    assert.ok(!auditText.includes('AdminPassword123!'));
    assert.ok(!auditText.includes('BEGIN PRIVATE KEY'));

    const logout = await request(port, {
      method: 'POST',
      requestPath: '/api/auth/logout',
      headers: { cookie, origin },
    });
    assert.equal(logout.status, 200);
    hasError(await request(port, { requestPath: '/api/auth/me', headers: { cookie } }), 'UNAUTHENTICATED', 401);
  });
});
