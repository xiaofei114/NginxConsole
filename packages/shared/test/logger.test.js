import test from 'node:test';
import assert from 'node:assert/strict';
import { NcsError } from '@ncs/shared';
import { asLogger, createLogger } from '../src/logger.js';

function fakeStream({ isTTY = false } = {}) {
  const lines = [];
  return {
    isTTY,
    lines,
    write(chunk) {
      lines.push(chunk);
      return true;
    },
  };
}

test('createLogger 输出 JSON Lines 并脱敏敏感字段', () => {
  const stream = fakeStream();
  const logger = createLogger({ app: 'main', component: 'test', stream, format: 'json' });

  logger.info('启动完成', {
    port: 8787,
    password: 'super-secret',
    enrollToken: 'abc',
    keyFingerprint: 'SHA256:xyz',
    missing: undefined,
  });

  assert.equal(stream.lines.length, 1);
  assert.ok(stream.lines[0].endsWith('\n'));
  const record = JSON.parse(stream.lines[0]);
  assert.equal(record.level, 'info');
  assert.equal(record.app, 'main');
  assert.equal(record.component, 'test');
  assert.equal(record.msg, '启动完成');
  assert.equal(record.port, 8787);
  assert.equal(record.password, '[redacted]');
  assert.equal(record.enrollToken, '[redacted]');
  assert.equal(record.keyFingerprint, 'SHA256:xyz');
  assert.equal('missing' in record, false);
  assert.match(record.ts, /^\d{4}-\d{2}-\d{2}T/);
});

test('createLogger 支持在必要时关闭脱敏', () => {
  const stream = fakeStream();
  const logger = createLogger({ stream, format: 'json' });
  logger.warn('初始口令', { initialPassword: 'One-Time-Pass-123' }, { redact: false });
  const record = JSON.parse(stream.lines[0]);
  assert.equal(record.initialPassword, 'One-Time-Pass-123');
});

test('createLogger 按级别过滤', () => {
  const stream = fakeStream();
  const logger = createLogger({ stream, format: 'json', level: 'warn' });
  logger.debug('debug');
  logger.info('info');
  logger.warn('warn');
  logger.error('error');
  const levels = stream.lines.map((line) => JSON.parse(line).level);
  assert.deepEqual(levels, ['warn', 'error']);
});

test('createLogger 序列化异常并保留错误码与堆栈', () => {
  const stream = fakeStream();
  const logger = createLogger({ stream, format: 'json' });
  logger.error('执行失败', new NcsError('NGINX_TEST_FAILED', '配置检测未通过', 422));
  const record = JSON.parse(stream.lines[0]);
  assert.equal(record.err.name, 'NcsError');
  assert.equal(record.err.code, 'NGINX_TEST_FAILED');
  assert.equal(record.err.status, 422);
  assert.ok(record.err.stack.includes('NGINX_TEST_FAILED') || record.err.stack.includes('配置检测未通过'));
});

test('createLogger 的 pretty 模式输出单行可读文本', () => {
  const stream = fakeStream({ isTTY: true });
  const logger = createLogger({ app: 'agent', component: 'client', stream });
  logger.info('正在连接主服务器', { url: 'wss://console.example.com/agent/ws', attempt: 2 });

  assert.equal(stream.lines.length, 1);
  const line = stream.lines[0];
  assert.match(line, /^\[?20\d{2}-\d{2}-\d{2}T/);
  assert.ok(line.includes('INFO'));
  assert.ok(line.includes('[agent:client]'));
  assert.ok(line.includes('正在连接主服务器'));
  assert.ok(line.includes('attempt=2'));
  assert.ok(!line.replace(/\n$/, '').includes('\n'));
});

test('child 继承配置并附加固定字段', () => {
  const stream = fakeStream();
  const logger = createLogger({ app: 'main', component: 'app', stream, format: 'json' });
  const child = logger.child('hub', { serverId: 'abc' });
  child.info('已连接');

  const record = JSON.parse(stream.lines[0]);
  assert.equal(record.component, 'hub');
  assert.equal(record.serverId, 'abc');
  assert.equal(record.msg, '已连接');
});

test('createLogger 可委托给外部日志器', () => {
  const received = [];
  const stream = fakeStream();
  const logger = createLogger({
    stream,
    format: 'json',
    delegate: { info: (line) => received.push(line) },
  });
  logger.info('委托输出');

  assert.equal(stream.lines.length, 0);
  assert.equal(received.length, 1);
  assert.equal(JSON.parse(received[0]).msg, '委托输出');
});

test('asLogger 兼容共享日志器与 console 风格对象', () => {
  const stream = fakeStream();
  const base = createLogger({ app: 'main', component: 'app', stream, format: 'json' });
  const child = asLogger(base, { component: 'hub' });
  child.info('派生');
  assert.equal(JSON.parse(stream.lines[0]).component, 'hub');

  const calls = [];
  const wrapped = asLogger({ info: (line) => calls.push(line), error() {}, warn() {} }, { component: 'x' });
  wrapped.info('包装');
  assert.equal(calls.length, 1);
  assert.equal(JSON.parse(calls[0]).component, 'x');
});

test('createLogger 不会因循环引用或特殊值抛错', () => {
  const stream = fakeStream();
  const logger = createLogger({ stream, format: 'json' });
  const circular = { name: 'loop' };
  circular.self = circular;

  assert.doesNotThrow(() => {
    logger.info('循环引用', { circular });
    logger.info('特殊值', { big: 10n, buffer: Buffer.from('abc'), date: new Date(0) });
  });

  const first = JSON.parse(stream.lines[0]);
  assert.equal(first.circular.name, 'loop');
  const second = JSON.parse(stream.lines[1]);
  assert.equal(second.big, '10');
  assert.equal(second.buffer, '[Buffer 3B]');
  assert.equal(second.date, '1970-01-01T00:00:00.000Z');
});
