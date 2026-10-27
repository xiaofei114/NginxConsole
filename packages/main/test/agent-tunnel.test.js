import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { enrollAgent } from '@ncs/agent/enroll';
import { AgentClient } from '@ncs/agent';
import { buildTarGz } from '../../shared/test/helpers/archives.js';
import { loadConfig } from '../src/config.js';
import { createApp } from '../src/app.js';

process.env.NODE_ENV = 'test';

const fixtures = fileURLToPath(new URL('../../shared/test/fixtures/', import.meta.url));

async function fixture(relativePath) {
  return fs.readFile(path.join(fixtures, relativePath), 'utf8');
}

function request(port, { method = 'GET', requestPath = '/', headers = {}, body = null } = {}) {
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
          resolve({ status: res.statusCode, headers: res.headers, json, text });
        });
      },
    );
    req.setTimeout(15_000, () => req.destroy(new Error('request timeout')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const silentLogger = { info() {}, warn() {}, error() {} };

test('agent connects outbound and executes commands over the signed tunnel', { timeout: 60_000 }, async (t) => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'ncs-tunnel-'));
  const mainRoot = path.join(base, 'main-nginx');
  const agentRoot = path.join(base, 'agent-nginx');
  await fs.mkdir(mainRoot, { recursive: true });
  await fs.mkdir(agentRoot, { recursive: true });
  await fs.writeFile(path.join(mainRoot, 'nginx.conf'), 'worker_processes 1;\n');
  await fs.writeFile(path.join(agentRoot, 'nginx.conf'), 'worker_processes 4;\n');

  const config = await loadConfig({
    NODE_ENV: 'development',
    NCS_DATA_DIR: path.join(base, 'data'),
    NCS_ALLOWED_ROOTS: mainRoot,
    NCS_LOCAL_WORKSPACE: mainRoot,
    NCS_ADMIN_USER: 'admin',
    NCS_ADMIN_PASSWORD: 'AdminPassword123!',
    NCS_DEV_UNSAFE_SKIP_NGINX_TEST: '1',
    NCS_COOKIE_SECURE: '0',
  });
  const runtime = await createApp(config, { logger: silentLogger });
  await new Promise((resolve, reject) => {
    runtime.server.once('error', reject);
    runtime.server.listen(0, '127.0.0.1', resolve);
  });
  const port = runtime.server.address().port;

  let client = null;
  t.after(async () => {
    await client?.stop();
    await runtime.close();
    await fs.rm(base, { recursive: true, force: true });
  });

  const origin = `http://127.0.0.1:${port}`;
  const login = await request(port, {
    method: 'POST',
    requestPath: '/api/auth/login',
    headers: { origin },
    body: { username: 'admin', password: 'AdminPassword123!' },
  });
  assert.equal(login.status, 200);
  const setCookie = login.headers['set-cookie'];
  const cookie = (Array.isArray(setCookie) ? setCookie[0] : setCookie).split(';')[0];
  const csrfToken = login.json.data.csrfToken;

  const created = await request(port, {
    method: 'POST',
    requestPath: '/api/servers',
    headers: { cookie, origin, 'x-csrf-token': csrfToken },
    body: { name: 'edge-agent' },
  });
  assert.equal(created.status, 201);
  const agentId = created.json.data.agent.id;
  const token = created.json.data.enrollmentToken;

  const configPath = path.join(base, 'agent-config', 'agent.json');
  const enrollment = await enrollAgent({
    configPath,
    mainUrl: `http://127.0.0.1:${port}`,
    agentId,
    token,
    allowedRoots: [agentRoot],
    workspace: agentRoot,
    nginxBin: path.resolve(base, 'no-such-nginx'),
    allowInsecureHttp: true,
    enforceTest: false,
    certDir: 'ssl',
  });
  assert.equal(enrollment.config.agentId, agentId);
  assert.equal(path.resolve(enrollment.config.workspace), path.resolve(await fs.realpath(agentRoot)));
  assert.match(enrollment.mainFingerprint, /^SHA256:/);

  client = await AgentClient.create({ configPath, logger: silentLogger });
  client.start();
  await client.waitForReady(15_000);

  const listed = runtime.manager.list().servers.find((server) => server.id === agentId);
  assert.equal(listed.online, true);
  assert.equal(listed.status, 'active');

  const info = await runtime.manager.info(agentId, { force: true });
  assert.equal(info.label, 'edge-agent');
  assert.equal(path.resolve(info.workspace), path.resolve(await fs.realpath(agentRoot)));
  assert.equal(info.configFileExists, true);
  assert.equal(info.enforceTest, false);
  assert.equal(info.nginxAvailable, false);

  const read = await runtime.manager.execute(agentId, 'fs.read', { path: 'nginx.conf' });
  assert.equal(read.content, 'worker_processes 4;\n');

  const write = await runtime.manager.execute(agentId, 'fs.write', {
    path: 'nginx.conf',
    content: 'worker_processes 8;\n',
    baseHash: read.hash,
  });
  assert.equal(write.unchanged, false);
  assert.equal(await fs.readFile(path.join(agentRoot, 'nginx.conf'), 'utf8'), 'worker_processes 8;\n');

  await assert.rejects(
    runtime.manager.execute(agentId, 'fs.read', { path: '../secret.conf' }),
    (error) => error?.code === 'INVALID_PATH',
  );

  const certPem = await fixture('valid/cert.pem');
  const keyPem = await fixture('valid/key.pem');
  const upload = await runtime.manager.execute(agentId, 'cert.upload', {
    name: 'edge.example.com',
    certPem,
    keyPem,
  });
  assert.equal(upload.files.length, 3);
  const listedCerts = await runtime.manager.execute(agentId, 'cert.list');
  const uploadedCert = listedCerts.certificates.find((item) => item.name === 'edge.example.com.crt');
  assert.ok(uploadedCert);
  assert.equal(uploadedCert.subject, upload.certificate.subject);
  assert.equal(uploadedCert.chainCount, 0);
  assert.equal((await fs.stat(path.join(agentRoot, 'ssl', 'edge.example.com.key'))).isFile(), true);

  const archiveUpload = await runtime.manager.execute(agentId, 'cert.uploadArchive', {
    name: 'edge-archive.example.com',
    archiveBase64: buildTarGz([
      { name: 'fullchain.pem', data: certPem },
      { name: 'privkey.pem', data: keyPem },
    ]).toString('base64'),
  });
  assert.equal(archiveUpload.archive.format, 'tar.gz');
  assert.equal(archiveUpload.files.length, 3);
  assert.ok(!JSON.stringify(archiveUpload).includes('PRIVATE KEY'));
  assert.equal(
    (await fs.stat(path.join(agentRoot, 'ssl', 'edge-archive.example.com.key'))).isFile(),
    true,
  );

  const audit = await request(port, { requestPath: '/api/audit?limit=100', headers: { cookie } });
  const actions = new Set(audit.json.data.entries.map((entry) => entry.action));
  assert.ok(actions.has('agent.connect'));
  assert.ok(actions.has('agent.enroll'));

  await client.stop();
  client = null;
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal(runtime.manager.list().servers.find((server) => server.id === agentId).online, false);
});
