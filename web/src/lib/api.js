let csrfToken = null;

export class ApiError extends Error {
  constructor({ code, message, status, details, requestId }) {
    super(message || '请求失败');
    this.name = 'ApiError';
    this.code = code || 'REQUEST_FAILED';
    this.status = status || 0;
    this.details = details;
    this.requestId = requestId;
  }
}

export function setCsrfToken(value) {
  csrfToken = typeof value === 'string' ? value : null;
}

function buildQuery(params) {
  if (!params) return '';
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : '';
}

async function request(method, path, { body, params, timeoutMs = 120000 } = {}) {
  const headers = { Accept: 'application/json' };
  const unsafe = !['GET', 'HEAD', 'OPTIONS'].includes(method);
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (unsafe && csrfToken) headers['X-CSRF-Token'] = csrfToken;
  const url = `/api${path}${buildQuery(params)}`;
  let response;
  try {
    response = await fetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    const timeout = error?.name === 'TimeoutError' || error?.name === 'AbortError';
    throw new ApiError({
      code: timeout ? 'REQUEST_TIMEOUT' : 'NETWORK_ERROR',
      message: timeout ? '请求超时，请检查服务器状态' : '无法连接主服务器',
      status: 0,
    });
  }
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok || !payload?.ok) {
    const error = payload?.error || {};
    const apiError = new ApiError({
      code: error.code || `HTTP_${response.status}`,
      message: error.message || `请求失败（HTTP ${response.status}）`,
      status: response.status,
      details: error.details,
      requestId: payload?.requestId,
    });
    if (response.status === 401 && apiError.code === 'UNAUTHENTICATED') {
      window.dispatchEvent(new CustomEvent('ncs:unauthenticated'));
    }
    throw apiError;
  }
  return payload.data;
}

export const api = {
  get: (path, params, options) => request('GET', path, { params, ...options }),
  post: (path, body, options) => request('POST', path, { body, ...options }),
  put: (path, body, options) => request('PUT', path, { body, ...options }),
  delete: (path, options) => request('DELETE', path, options),
};
