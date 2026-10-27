/**
 * 结构化日志。
 *
 * 设计目标：
 * - 统一主服务器与 Agent 的输出格式，便于被 pm2 / journald / 日志采集器解析。
 * - 每行一条记录；`json` 模式为标准 JSON Lines，`pretty` 模式供终端阅读。
 * - 默认不输出到 TTY 时使用 JSON，避免在生产管道里混入人类可读文本。
 * - 任何日志异常都不允许影响主流程。
 *
 * 环境变量：
 * - NCS_LOG_LEVEL  error | warn | info | debug，默认 info
 * - NCS_LOG_FORMAT json | pretty，默认按输出流是否为 TTY 自动选择
 */

const LEVEL_ORDER = { error: 0, warn: 1, info: 2, debug: 3 };
const LEVELS = Object.keys(LEVEL_ORDER);

const REDACTED = '[redacted]';
const SECRET_KEY_RE = /(pass(word|phrase)|secret|token|authorization|cookie|privatekey|private_key|keypem|archivebase64|recoverycode)/i;
const MAX_MESSAGE_LENGTH = 2000;
const MAX_STRING_LENGTH = 4000;
const MAX_DEPTH = 5;
const MAX_ARRAY_ITEMS = 50;

function truncate(value, limit) {
  return value.length > limit ? `${value.slice(0, limit)}…` : value;
}

function serializeError(error) {
  const output = {
    name: typeof error.name === 'string' ? error.name : 'Error',
    message: truncate(String(error.message ?? ''), MAX_MESSAGE_LENGTH),
  };
  if (typeof error.code === 'string') output.code = error.code;
  if (typeof error.status === 'number') output.status = error.status;
  if (typeof error.stack === 'string') output.stack = truncate(error.stack, MAX_STRING_LENGTH);
  if (error.details !== undefined) output.details = sanitize(error.details, 1, true);
  return output;
}

/**
 * 把任意值转换成可序列化的形式，并按字段名脱敏。
 * 深度/数组长度/字符串长度都有上限，避免日志被超大对象拖垮。
 */
function sanitize(value, depth = 0, redact = true) {
  if (value === null || value === undefined) return value;
  const type = typeof value;
  if (type === 'string') return truncate(value, MAX_STRING_LENGTH);
  if (type === 'number') return Number.isFinite(value) ? value : String(value);
  if (type === 'boolean') return value;
  if (type === 'bigint') return value.toString();
  if (type === 'function' || type === 'symbol') return `[${type}]`;
  if (value instanceof Error) return serializeError(value);
  if (value instanceof Date) return value.toISOString();
  if (Buffer.isBuffer(value)) return `[Buffer ${value.length}B]`;
  if (Array.isArray(value)) {
    if (depth >= MAX_DEPTH) return '[array]';
    return value.slice(0, MAX_ARRAY_ITEMS).map((item) => sanitize(item, depth + 1, redact));
  }
  if (type === 'object') {
    if (depth >= MAX_DEPTH) return '[object]';
    const output = {};
    for (const [key, item] of Object.entries(value)) {
      if (item === undefined) continue;
      output[key] = redact && SECRET_KEY_RE.test(key) ? REDACTED : sanitize(item, depth + 1, redact);
    }
    return output;
  }
  return String(value);
}

function resolveLevel(value) {
  const normalized = String(value || '').toLowerCase();
  return Object.hasOwn(LEVEL_ORDER, normalized) ? normalized : 'info';
}

function resolveFormat(value, stream) {
  const normalized = String(value || '').toLowerCase();
  if (normalized === 'json' || normalized === 'pretty') return normalized;
  return stream?.isTTY ? 'pretty' : 'json';
}

function formatValue(value) {
  if (typeof value === 'string') {
    return /^[A-Za-z0-9_./:@+-]+$/.test(value) ? value : JSON.stringify(value);
  }
  if (value === null) return 'null';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}

function formatPretty(record) {
  const { ts, level, app, component, msg, ...rest } = record;
  const parts = [ts, level.toUpperCase().padEnd(5), `[${app}:${component}]`, msg];
  for (const [key, value] of Object.entries(rest)) parts.push(`${key}=${formatValue(value)}`);
  return parts.join(' ');
}

/**
 * 创建日志器。
 *
 * @param {object} [options]
 * @param {string} [options.app]       应用标识，通常为 main 或 agent
 * @param {string} [options.component] 模块标识，用于区分同一进程内的不同组件
 * @param {object} [options.fields]    附加到每条日志的固定字段
 * @param {string} [options.level]     日志级别，默认读 NCS_LOG_LEVEL
 * @param {string} [options.format]    输出格式，默认读 NCS_LOG_FORMAT
 * @param {object} [options.stream]    正常日志输出流（默认 stdout）
 * @param {object} [options.errorStream] warn/error 输出流（默认 stderr）
 * @param {object} [options.delegate]  转交给外部日志器（console 兼容对象），用于测试注入
 * @param {object} [options.env]       环境变量来源（默认 process.env）
 */
export function createLogger(options = {}) {
  const env = options.env || process.env;
  const app = options.app || 'ncs';
  const component = options.component || app;
  const levelName = resolveLevel(options.level ?? env.NCS_LOG_LEVEL);
  const outStream = options.stream || process.stdout;
  const errStream = options.errorStream || options.stream || process.stderr;
  const format = resolveFormat(options.format ?? env.NCS_LOG_FORMAT, outStream);
  const delegate = options.delegate;
  const baseFields = options.fields || {};

  const enabled = (level) => LEVEL_ORDER[level] <= LEVEL_ORDER[levelName];

  const emit = (level, message, context, emitOptions) => {
    if (!enabled(level)) return;
    try {
      const redact = emitOptions?.redact !== false;
      const fields = { ...(sanitize(baseFields, 0, redact) || {}) };
      let detail;
      if (context instanceof Error) {
        fields.err = serializeError(context);
      } else if (typeof context === 'string') {
        detail = truncate(context, MAX_MESSAGE_LENGTH);
      } else if (context && typeof context === 'object') {
        Object.assign(fields, sanitize(context, 0, redact));
      }
      if (emitOptions?.fields) Object.assign(fields, sanitize(emitOptions.fields, 0, redact));

      const record = {
        ts: new Date().toISOString(),
        level,
        app,
        component,
        msg: truncate(String(message ?? ''), MAX_MESSAGE_LENGTH),
        ...fields,
      };
      if (detail !== undefined) record.detail = detail;

      const line = format === 'json' ? JSON.stringify(record) : formatPretty(record);
      if (delegate) {
        const write = delegate[level] || delegate.info;
        if (typeof write === 'function') write.call(delegate, line);
        return;
      }
      const stream = level === 'error' || level === 'warn' ? errStream : outStream;
      stream.write(`${line}\n`);
    } catch {
      // 日志失败不能影响主流程。
    }
  };

  const logger = {
    app,
    component,
    level: levelName,
    format,
    error: (message, context, emitOptions) => emit('error', message, context, emitOptions),
    warn: (message, context, emitOptions) => emit('warn', message, context, emitOptions),
    info: (message, context, emitOptions) => emit('info', message, context, emitOptions),
    debug: (message, context, emitOptions) => emit('debug', message, context, emitOptions),
    child(childComponent, fields = {}) {
      return createLogger({
        app,
        component: childComponent || component,
        level: levelName,
        format,
        stream: outStream,
        errorStream: errStream,
        delegate,
        env,
        fields: { ...baseFields, ...fields },
      });
    },
  };
  return logger;
}

/**
 * 兼容外部注入的 console 风格日志器。
 * 已经是本模块创建的日志器时直接派生组件子日志器，否则包装为 delegate。
 */
export function asLogger(candidate, { app = 'ncs', component = 'app' } = {}) {
  if (candidate && typeof candidate.child === 'function' && typeof candidate.info === 'function') {
    return component ? candidate.child(component) : candidate;
  }
  return createLogger({ app, component, delegate: candidate || undefined });
}

export const LOG_LEVELS = LEVELS;
