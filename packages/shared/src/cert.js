import crypto from 'node:crypto';
import { NcsError } from './errors.js';
import { LIMITS } from './limits.js';

const CERT_BLOCK_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const KEY_BLOCK_RE = /-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----[\s\S]*?-----END \1-----/g;

function safeDate(value, fallbackString) {
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value;
  const parsed = new Date(fallbackString);
  if (Number.isNaN(parsed.getTime())) throw new NcsError('CERT_INVALID', '证书时间字段无效', 400);
  return parsed;
}

function parseSan(raw) {
  if (!raw || typeof raw !== 'string') return [];
  return raw
    .split(/,\s*/)
    .map((item) => {
      const index = item.indexOf(':');
      if (index <= 0) return null;
      return { type: item.slice(0, index).trim(), value: item.slice(index + 1).trim() };
    })
    .filter(Boolean)
    .slice(0, 100);
}

function keyStrength(key, label) {
  const type = key.asymmetricKeyType;
  const details = key.asymmetricKeyDetails || {};
  if (type === 'rsa') {
    const bits = details.modulusLength || 0;
    if (bits < 2048) throw new NcsError('CERT_WEAK_KEY', `${label} RSA 密钥长度必须不少于 2048 位`, 400);
    return { type: 'rsa', bits };
  }
  if (type === 'ec') {
    const curve = details.namedCurve || '';
    const bits = details.namedCurveSize || 0;
    const allowedCurves = new Set(['prime256v1', 'secp384r1', 'secp521r1', 'P-256', 'P-384', 'P-521']);
    if (!allowedCurves.has(curve) && !(curve === '' && [256, 384, 521].includes(bits))) {
      throw new NcsError('CERT_WEAK_KEY', `${label} EC 曲线不在允许列表中`, 400);
    }
    return { type: 'ec', curve: curve || `bits:${bits}` };
  }
  throw new NcsError('CERT_KEY_TYPE_NOT_ALLOWED', `${label} 仅支持 RSA 或 EC 密钥`, 400);
}

function certMeta(cert, { checkValidity = false, now = Date.now() } = {}) {
  const validFrom = safeDate(cert.validFromDate, cert.validFrom);
  const validTo = safeDate(cert.validToDate, cert.validTo);
  if (checkValidity) {
    if (now < validFrom.getTime()) {
      throw new NcsError('CERT_NOT_YET_VALID', '证书尚未生效', 400, { validFrom: validFrom.toISOString() });
    }
    if (now > validTo.getTime()) {
      throw new NcsError('CERT_EXPIRED', '证书已过期', 400, { validTo: validTo.toISOString() });
    }
  }
  return {
    subject: cert.subject,
    issuer: cert.issuer,
    serialNumber: cert.serialNumber,
    fingerprint256: cert.fingerprint256,
    san: parseSan(cert.subjectAltName),
    validFrom: validFrom.toISOString(),
    validTo: validTo.toISOString(),
    expired: now > validTo.getTime(),
    daysRemaining: Math.floor((validTo.getTime() - now) / 86400000),
    isCa: cert.ca === true,
  };
}

/**
 * @param {string} certPem
 * @param {{allowMultiple?:boolean, checkValidity?:boolean, now?:number}} options
 */
export function inspectCertificatePem(certPem, { allowMultiple = false, checkValidity = false, now = Date.now() } = {}) {
  if (typeof certPem !== 'string' || certPem.length === 0) {
    throw new NcsError('CERT_INVALID', '证书内容为空', 400);
  }
  if (Buffer.byteLength(certPem, 'utf8') > LIMITS.maxCertificateBytes) {
    throw new NcsError('CERT_TOO_LARGE', '证书内容超过大小限制', 400);
  }
  const blocks = certPem.match(CERT_BLOCK_RE) || [];
  if (blocks.length === 0) throw new NcsError('CERT_INVALID', '未找到 PEM 证书块', 400);
  if (!allowMultiple && blocks.length > 1) {
    throw new NcsError('CERT_INVALID', '证书文件只能包含一张叶证书，证书链请单独上传', 400);
  }
  const leftovers = certPem.replace(CERT_BLOCK_RE, '').trim();
  if (leftovers.length > 0) throw new NcsError('CERT_INVALID', '证书文件包含无法识别的内容', 400);

  const certificates = [];
  for (const block of blocks) {
    try {
      certificates.push(new crypto.X509Certificate(block));
    } catch {
      throw new NcsError('CERT_INVALID', '证书解析失败', 400);
    }
  }
  const leaf = certificates[0];
  const key = keyStrength(leaf.publicKey, '证书');
  return {
    ...certMeta(leaf, { checkValidity, now }),
    key,
    certificateCount: certificates.length,
    next: certificates[1] ? certMeta(certificates[1], { now }) : null,
    certificates,
    normalizedPem: blocks.map((block) => `${block.trim()}\n`).join(''),
  };
}

function extractPrivateKey(keyPem) {
  if (typeof keyPem !== 'string' || keyPem.length === 0) {
    throw new NcsError('KEY_INVALID', '私钥内容为空', 400);
  }
  if (Buffer.byteLength(keyPem, 'utf8') > LIMITS.maxCertificateBytes) {
    throw new NcsError('KEY_TOO_LARGE', '私钥内容超过大小限制', 400);
  }
  if (/ENCRYPTED PRIVATE KEY/.test(keyPem) || /Proc-Type:\s*4,\s*ENCRYPTED/i.test(keyPem)) {
    throw new NcsError('KEY_ENCRYPTED', '不支持带口令的私钥，请先解密', 400);
  }
  KEY_BLOCK_RE.lastIndex = 0;
  const blocks = keyPem.match(KEY_BLOCK_RE) || [];
  if (blocks.length !== 1) throw new NcsError('KEY_INVALID', '私钥文件必须且只能包含一个 PEM 私钥', 400);
  const block = blocks[0];
  const leftovers = keyPem.replace(KEY_BLOCK_RE, '').trim();
  if (leftovers.length > 0) throw new NcsError('KEY_INVALID', '私钥文件包含无法识别的内容', 400);
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(block);
  } catch {
    throw new NcsError('KEY_INVALID', '私钥解析失败', 400);
  }
  const publicKey = crypto.createPublicKey(privateKey);
  return { privateKey, publicKey, normalizedPem: `${block.trim()}\n`, strength: keyStrength(publicKey, '私钥') };
}

export function validateChain(certPem, chainPem = '') {
  let chainBlocks = [];
  if (chainPem && String(chainPem).trim().length > 0) {
    if (Buffer.byteLength(chainPem, 'utf8') > LIMITS.maxCertificateBytes) {
      throw new NcsError('CHAIN_TOO_LARGE', '证书链超过大小限制', 400);
    }
    chainBlocks = String(chainPem).match(CERT_BLOCK_RE) || [];
    const leftovers = String(chainPem).replace(CERT_BLOCK_RE, '').trim();
    if (chainBlocks.length === 0 || leftovers.length > 0) {
      throw new NcsError('CHAIN_INVALID', '证书链必须只包含 PEM 证书', 400);
    }
    if (chainBlocks.length > LIMITS.maxChainCertificates) {
      throw new NcsError('CHAIN_TOO_LARGE', '证书链数量过多', 400);
    }
  }
  const leaf = inspectCertificatePem(certPem, { allowMultiple: false });
  const chainCerts = chainBlocks.map((block) => {
    try {
      return new crypto.X509Certificate(block);
    } catch {
      throw new NcsError('CHAIN_INVALID', '证书链解析失败', 400);
    }
  });
  let issuer = leaf.certificates[0];
  for (const chainCert of chainCerts) {
    let valid = false;
    try {
      valid = issuer.verify(chainCert.publicKey);
    } catch {
      valid = false;
    }
    if (!valid) {
      throw new NcsError('CHAIN_INVALID', '证书链顺序错误或签名不匹配，请按“叶证书 -> 中间证书”顺序上传', 400);
    }
    issuer = chainCert;
  }
  return {
    leaf,
    chainCertificates: chainCerts,
    normalizedChainPem: chainBlocks.map((block) => `${block.trim()}\n`).join(''),
  };
}

/**
 * Validate a leaf certificate, optional chain and private key, and ensure the
 * private key matches the certificate. Never returns private key material.
 */
export function validateCertificateBundle({ certPem, chainPem = '', keyPem, now = Date.now() }) {
  const chain = validateChain(certPem, chainPem);
  const key = extractPrivateKey(keyPem);
  const leaf = chain.leaf;

  let keyMatches = false;
  try {
    const certSpki = leaf.certificates[0].publicKey.export({ type: 'spki', format: 'der' });
    const keySpki = key.publicKey.export({ type: 'spki', format: 'der' });
    keyMatches = Buffer.isBuffer(certSpki) && Buffer.isBuffer(keySpki) && certSpki.equals(keySpki);
  } catch {
    keyMatches = false;
  }
  if (!keyMatches) throw new NcsError('CERT_KEY_MISMATCH', '私钥与证书不匹配', 400);

  if (now > new Date(leaf.validTo).getTime()) throw new NcsError('CERT_EXPIRED', '证书已过期', 400);
  if (now < new Date(leaf.validFrom).getTime()) throw new NcsError('CERT_NOT_YET_VALID', '证书尚未生效', 400);

  return {
    certPem: leaf.normalizedPem,
    chainPem: chain.normalizedChainPem,
    keyPem: key.normalizedPem,
    certificate: {
      subject: leaf.subject,
      issuer: leaf.issuer,
      serialNumber: leaf.serialNumber,
      fingerprint256: leaf.fingerprint256,
      san: leaf.san,
      validFrom: leaf.validFrom,
      validTo: leaf.validTo,
      daysRemaining: leaf.daysRemaining,
      key: leaf.key,
      chainCount: chain.chainCertificates.length,
    },
  };
}
