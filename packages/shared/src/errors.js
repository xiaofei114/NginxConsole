export class NcsError extends Error {
  /**
   * @param {string} code stable machine code
   * @param {string} message safe message for clients
   * @param {number} status HTTP status
   * @param {unknown} [details] safe structured details
   */
  constructor(code, message, status = 400, details = undefined) {
    super(message);
    this.name = 'NcsError';
    this.code = code;
    this.status = status;
    this.details = details;
    this.expose = true;
  }
}

export function asNcsError(error) {
  if (error instanceof NcsError) return error;
  if (error && typeof error === 'object' && typeof error.code === 'string' && error.expose === true) {
    return new NcsError(error.code, String(error.message || '操作失败'), Number(error.status) || 400, error.details);
  }
  return new NcsError('INTERNAL_ERROR', '服务器内部错误', 500);
}

export function publicError(error, { includeDetails = true } = {}) {
  const e = asNcsError(error);
  return {
    code: e.code,
    message: e.message,
    ...(includeDetails && e.details !== undefined ? { details: e.details } : {}),
  };
}
