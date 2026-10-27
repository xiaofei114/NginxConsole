import net from 'node:net';

export const SESSION_COOKIE = 'ncs_session';

export function normalizeIp(value) {
  if (typeof value !== 'string') return '';
  let ip = value.trim();
  if (!ip) return '';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (ip.startsWith('[') && ip.includes(']')) ip = ip.slice(1, ip.indexOf(']'));
  return net.isIP(ip) ? ip : '';
}

/**
 * Resolve the client IP for rate limiting / auditing.
 *
 * With `trustProxy`, exactly one hop (the local reverse proxy) is trusted, so
 * the trustworthy value is the *last* entry of X-Forwarded-For: the address the
 * proxy itself observed. Earlier entries are attacker-controlled (a client may
 * send its own X-Forwarded-For header), so never trust them.
 */
export function getClientIp(req, { trustProxy = false } = {}) {
  if (trustProxy) {
    const header = req.headers['x-forwarded-for'];
    if (typeof header === 'string' && header.length < 1024) {
      const parts = header.split(',');
      for (let i = parts.length - 1; i >= 0; i -= 1) {
        const ip = normalizeIp(parts[i]);
        if (ip) return ip;
      }
    }
  }
  return normalizeIp(req.socket?.remoteAddress) || req.socket?.remoteAddress || '';
}

/** True when the TCP peer itself is loopback (used for proxy-on-localhost setups). */
export function isLoopbackPeer(req) {
  const ip = normalizeIp(req.socket?.remoteAddress);
  return ip === '::1' || (typeof ip === 'string' && ip.startsWith('127.'));
}

export function isSecureRequest(req, { trustProxy = false, tls = false } = {}) {
  if (tls || req.socket?.encrypted) return true;
  if (trustProxy) {
    const proto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
    return proto === 'https';
  }
  return false;
}

export function normalizeHost(hostHeader) {
  if (typeof hostHeader !== 'string' || hostHeader.length > 512) return '';
  let host = hostHeader.trim().toLowerCase();
  if (host.startsWith('[')) {
    const end = host.indexOf(']');
    if (end < 0) return '';
    return host.slice(1, end);
  }
  if (host.includes(':')) host = host.split(':')[0];
  return host;
}

export function isHostAllowed(req, allowedHosts) {
  const host = normalizeHost(req.headers.host);
  if (!host) return false;
  return allowedHosts.includes(host);
}

export function requestOrigin(req, { tls = false, trustProxy = false } = {}) {
  const protocol = isSecureRequest(req, { trustProxy, tls }) ? 'https' : 'http';
  const host = req.headers.host;
  if (typeof host !== 'string' || !host) return null;
  return `${protocol}://${host}`;
}

export function isOriginAllowed(req, config) {
  const origin = req.headers.origin;
  if (typeof origin !== 'string' || !origin) return false;
  if (origin === 'null') return false;
  // Host is already constrained by hostGuard, so a same-origin request to the
  // current host is always acceptable in addition to configured public origins.
  const allowed = Array.isArray(config.allowedOrigins) ? config.allowedOrigins : [];
  if (allowed.includes(origin)) return true;
  if (config.publicOrigin && origin === config.publicOrigin) return true;
  const expected = requestOrigin(req, config);
  return Boolean(expected) && origin === expected;
}

export function securityHeaders(config) {
  return (req, res, next) => {
    const secure = isSecureRequest(req, config);
    res.setHeader(
      'Content-Security-Policy',
      [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "manifest-src 'self'",
      ].join('; '),
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    if (secure || config.publicOrigin?.startsWith('https://')) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    if (req.path.startsWith('/api/')) {
      res.setHeader('Cache-Control', 'no-store, max-age=0');
      res.setHeader('Pragma', 'no-cache');
    }
    next();
  };
}

export function hostGuard(config) {
  return (req, res, next) => {
    if (!isHostAllowed(req, config.allowedHosts)) {
      res.status(421).json({ ok: false, error: { code: 'INVALID_HOST', message: '请求 Host 不在允许列表中' } });
      return;
    }
    next();
  };
}

export function unsafeMethod(method) {
  return !['GET', 'HEAD', 'OPTIONS'].includes(String(method || '').toUpperCase());
}

export function originGuard(config) {
  return (req, res, next) => {
    if (!unsafeMethod(req.method)) return next();
    // Agent enrollment is a machine-to-machine call over TLS with a one-time token.
    if (req.path === '/api/agent/enroll') return next();
    if (!isOriginAllowed(req, config)) {
      res.status(403).json({ ok: false, error: { code: 'INVALID_ORIGIN', message: '请求来源校验失败' } });
      return;
    }
    next();
  };
}

export function parseCookies(header) {
  if (typeof header !== 'string' || header.length > 8192) return {};
  const cookies = {};
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index <= 0) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (!name || name in cookies) continue;
    cookies[name] = value;
  }
  return cookies;
}

export function getSessionToken(req) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies[SESSION_COOKIE];
  return typeof token === 'string' ? token : null;
}

export function serializeSessionCookie(token, config, maxAgeSeconds) {
  const parts = [
    `${SESSION_COOKIE}=${token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (config.cookieSecure) parts.push('Secure');
  return parts.join('; ');
}

export function clearSessionCookie(config) {
  const parts = [`${SESSION_COOKIE}=`, 'Path=/', 'HttpOnly', 'SameSite=Strict', 'Max-Age=0'];
  if (config.cookieSecure) parts.push('Secure');
  return parts.join('; ');
}

export class RateLimiter {
  constructor({ windowMs, max, blockMs = 0, maxEntries = 20000 }) {
    this.windowMs = windowMs;
    this.max = max;
    this.blockMs = blockMs;
    this.maxEntries = maxEntries;
    this.entries = new Map();
  }

  hit(key, cost = 1) {
    const now = Date.now();
    let entry = this.entries.get(key);
    if (!entry) {
      entry = { count: 0, resetAt: now + this.windowMs, blockedUntil: 0 };
      this.entries.set(key, entry);
    }
    if (entry.blockedUntil > now) {
      return { allowed: false, retryAfter: Math.ceil((entry.blockedUntil - now) / 1000) };
    }
    if (now >= entry.resetAt) {
      entry.count = 0;
      entry.resetAt = now + this.windowMs;
      entry.blockedUntil = 0;
    }
    entry.count += cost;
    if (entry.count > this.max) {
      if (this.blockMs > 0) entry.blockedUntil = now + this.blockMs;
      const retryAfter = Math.max(1, Math.ceil((Math.max(entry.blockedUntil, entry.resetAt) - now) / 1000));
      return { allowed: false, retryAfter };
    }
    this.cleanup(now);
    return { allowed: true, retryAfter: 0 };
  }

  cleanup(now = Date.now()) {
    if (this.entries.size < this.maxEntries) return;
    for (const [key, entry] of this.entries) {
      if (entry.blockedUntil <= now && entry.resetAt <= now) this.entries.delete(key);
    }
    if (this.entries.size >= this.maxEntries) {
      const excess = this.entries.size - Math.floor(this.maxEntries * 0.8);
      let removed = 0;
      for (const key of this.entries.keys()) {
        if (removed >= excess) break;
        this.entries.delete(key);
        removed += 1;
      }
    }
  }
}
