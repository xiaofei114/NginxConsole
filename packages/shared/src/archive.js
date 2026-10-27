import crypto from 'node:crypto';
import { gunzipSync, inflateRawSync } from 'node:zlib';
import { NcsError } from './errors.js';
import { LIMITS } from './limits.js';
import { normalizeRelativePath } from './paths.js';

const ZIP_LOCAL_SIG = 0x04034b50;
const ZIP_CENTRAL_SIG = 0x02014b50;
const ZIP_EOCD_SIG = 0x06054b50;
const UTF8 = new TextDecoder('utf-8', { fatal: true });
const CERT_BLOCK_RE = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const KEY_BLOCK_RE = /-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----[\s\S]*?-----END \1-----/g;

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
})();

function fail(code, message, details = undefined) {
  throw new NcsError(code, message, 400, details);
}

function crc32(buffer) {
  let value = 0xffffffff;
  for (let index = 0; index < buffer.length; index += 1) {
    value = CRC_TABLE[(value ^ buffer[index]) & 0xff] ^ (value >>> 8);
  }
  return (value ^ 0xffffffff) >>> 0;
}

function preview(raw) {
  return String(raw)
    .replace(/[\u0000-\u001f\u007f]/g, '?')
    .slice(0, 120);
}

function decodeUtf8(buffer) {
  try {
    return UTF8.decode(buffer);
  } catch {
    fail('ARCHIVE_INVALID', '压缩包包含非 UTF-8 文件名或内容');
  }
  return '';
}

function safeArchivePath(raw, { allowEmpty = false } = {}) {
  try {
    const normalized = normalizeRelativePath(raw, { allowEmpty });
    if (!normalized && !allowEmpty) throw new NcsError('INVALID_PATH', '', 400);
    return normalized;
  } catch {
    fail('ARCHIVE_UNSAFE_PATH', `压缩包内路径不安全：${preview(raw)}`);
  }
  return '';
}

function addEntry(entries, seen, path, data, total) {
  if (path === '') fail('ARCHIVE_UNSAFE_PATH', '压缩包内文件名不能为空');
  if (seen.has(path)) fail('ARCHIVE_UNSAFE_PATH', `压缩包内存在重复文件：${preview(path)}`);
  if (data.length > LIMITS.maxArchiveFileBytes) {
    fail('ARCHIVE_ENTRY_TOO_LARGE', `压缩包内单个文件超过 ${Math.floor(LIMITS.maxArchiveFileBytes / 1024)} KiB`);
  }
  if (total + data.length > LIMITS.maxArchiveTotalBytes) {
    fail('ARCHIVE_TOO_LARGE', `压缩包解压后内容超过 ${Math.floor(LIMITS.maxArchiveTotalBytes / 1024)} KiB`);
  }
  seen.add(path);
  entries.push({ path, data });
}

function isZip(buffer) {
  return buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4b;
}

function isGzip(buffer) {
  return buffer.length >= 2 && buffer[0] === 0x1f && buffer[1] === 0x8b;
}

function isTar(buffer) {
  return buffer.length >= 512 && buffer.toString('latin1', 257, 262) === 'ustar';
}

function findZipEocd(buffer) {
  const minimum = Math.max(0, buffer.length - 22 - 0xffff);
  for (let offset = buffer.length - 22; offset >= minimum; offset -= 1) {
    if (buffer.readUInt32LE(offset) !== ZIP_EOCD_SIG) continue;
    if (offset + 22 > buffer.length) continue;
    // Require the record (plus its comment) to end exactly at EOF so that an
    // EOCD-like signature inside file data or a comment cannot be mistaken
    // for the real central directory pointer.
    if (offset + 22 + buffer.readUInt16LE(offset + 20) === buffer.length) return offset;
  }
  return -1;
}

function zipEntryName(rawName) {
  if (rawName.includes(0)) fail('ARCHIVE_UNSAFE_PATH', '压缩包内文件名包含非法字符');
  const decoded = decodeUtf8(rawName);
  const isDirectory = decoded.endsWith('/');
  const name = isDirectory ? decoded.slice(0, -1) : decoded;
  return { name, isDirectory };
}

function readZipEntry(buffer, recordOffset, centralEnd) {
  if (recordOffset + 46 > centralEnd) fail('ARCHIVE_INVALID', 'ZIP 中央目录已损坏');
  if (buffer.readUInt32LE(recordOffset) !== ZIP_CENTRAL_SIG) fail('ARCHIVE_INVALID', 'ZIP 中央目录签名无效');

  const flags = buffer.readUInt16LE(recordOffset + 8);
  const method = buffer.readUInt16LE(recordOffset + 10);
  const expectedCrc = buffer.readUInt32LE(recordOffset + 16);
  const compressedSize = buffer.readUInt32LE(recordOffset + 20);
  const uncompressedSize = buffer.readUInt32LE(recordOffset + 24);
  const nameLength = buffer.readUInt16LE(recordOffset + 28);
  const extraLength = buffer.readUInt16LE(recordOffset + 30);
  const commentLength = buffer.readUInt16LE(recordOffset + 32);
  const diskStart = buffer.readUInt16LE(recordOffset + 34);
  const externalAttributes = buffer.readUInt32LE(recordOffset + 38);
  const localOffset = buffer.readUInt32LE(recordOffset + 42);
  const recordEnd = recordOffset + 46 + nameLength + extraLength + commentLength;
  if (nameLength === 0 || recordEnd > centralEnd) fail('ARCHIVE_INVALID', 'ZIP 中央目录条目已损坏');
  if (diskStart !== 0) fail('ARCHIVE_UNSUPPORTED', '不支持分卷 ZIP 压缩包');
  if ((flags & 0x0001) !== 0 || (flags & 0x0040) !== 0) {
    fail('ARCHIVE_UNSUPPORTED', '不支持加密 ZIP 压缩包，请先解压或移除口令');
  }
  if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localOffset === 0xffffffff) {
    fail('ARCHIVE_UNSUPPORTED', '不支持 ZIP64 压缩包');
  }
  if (![0, 8].includes(method)) fail('ARCHIVE_UNSUPPORTED', `不支持 ZIP 压缩方式 ${method}`);
  if (uncompressedSize > LIMITS.maxArchiveFileBytes) {
    fail('ARCHIVE_ENTRY_TOO_LARGE', `压缩包内单个文件超过 ${Math.floor(LIMITS.maxArchiveFileBytes / 1024)} KiB`);
  }
  if (compressedSize === 0 && uncompressedSize > 0) fail('ARCHIVE_INVALID', 'ZIP 条目大小无效');

  const rawName = buffer.subarray(recordOffset + 46, recordOffset + 46 + nameLength);
  const { name, isDirectory } = zipEntryName(rawName);
  const unixMode = (externalAttributes >>> 16) & 0xffff;
  if ((unixMode & 0o170000) === 0o120000) fail('ARCHIVE_UNSUPPORTED', '压缩包包含符号链接，已拒绝');
  const directory = isDirectory || (unixMode & 0o170000) === 0o040000;
  const normalized = safeArchivePath(name, { allowEmpty: directory });
  if (directory) return null;

  if (localOffset + 30 > centralEnd || buffer.readUInt32LE(localOffset) !== ZIP_LOCAL_SIG) {
    fail('ARCHIVE_INVALID', 'ZIP 本地文件头无效');
  }
  const localNameLength = buffer.readUInt16LE(localOffset + 26);
  const localExtraLength = buffer.readUInt16LE(localOffset + 28);
  const localName = buffer.subarray(localOffset + 30, localOffset + 30 + localNameLength);
  if (!localName.equals(rawName)) fail('ARCHIVE_INVALID', 'ZIP 条目的本地文件头与中央目录不一致');
  const dataStart = localOffset + 30 + localNameLength + localExtraLength;
  if (dataStart + compressedSize > centralEnd) fail('ARCHIVE_INVALID', 'ZIP 条目数据越界');

  const compressed = buffer.subarray(dataStart, dataStart + compressedSize);
  let data;
  if (method === 0) {
    if (compressed.length !== uncompressedSize) fail('ARCHIVE_INVALID', 'ZIP 条目大小不一致');
    data = Buffer.from(compressed);
  } else {
    try {
      data = inflateRawSync(compressed, {
        maxOutputLength: Math.min(uncompressedSize, LIMITS.maxArchiveFileBytes) + 1,
      });
    } catch {
      fail('ARCHIVE_INVALID', 'ZIP 压缩数据损坏或解压后超出限制');
    }
    if (data.length !== uncompressedSize) fail('ARCHIVE_INVALID', 'ZIP 条目解压后大小不一致');
  }
  if (crc32(data) !== expectedCrc) fail('ARCHIVE_INVALID', 'ZIP 条目 CRC 校验失败');

  return { path: normalized, data };
}

function parseZip(buffer) {
  const eocd = findZipEocd(buffer);
  if (eocd < 0) fail('ARCHIVE_INVALID', 'ZIP 结束记录缺失或已损坏');
  if (eocd + 22 > buffer.length) fail('ARCHIVE_INVALID', 'ZIP 结束记录越界');
  const diskNumber = buffer.readUInt16LE(eocd + 4);
  const centralDisk = buffer.readUInt16LE(eocd + 6);
  const entriesOnDisk = buffer.readUInt16LE(eocd + 8);
  const entriesTotal = buffer.readUInt16LE(eocd + 10);
  const centralSize = buffer.readUInt32LE(eocd + 12);
  const centralOffset = buffer.readUInt32LE(eocd + 16);
  const commentLength = buffer.readUInt16LE(eocd + 20);
  if (eocd + 22 + commentLength > buffer.length) fail('ARCHIVE_INVALID', 'ZIP 注释长度无效');
  if (diskNumber !== 0 || centralDisk !== 0 || entriesOnDisk !== entriesTotal) {
    fail('ARCHIVE_UNSUPPORTED', '不支持分卷 ZIP 压缩包');
  }
  if (entriesTotal === 0) fail('ARCHIVE_EMPTY', '压缩包为空');
  if (entriesTotal > LIMITS.maxArchiveEntries) {
    fail('ARCHIVE_TOO_MANY_ENTRIES', `压缩包条目超过 ${LIMITS.maxArchiveEntries} 个`);
  }
  const centralEnd = centralOffset + centralSize;
  if (centralOffset < 0 || centralEnd > eocd || centralEnd > buffer.length) {
    fail('ARCHIVE_INVALID', 'ZIP 中央目录越界');
  }

  const entries = [];
  const seen = new Set();
  let total = 0;
  let recordOffset = centralOffset;
  for (let index = 0; index < entriesTotal; index += 1) {
    const record = readZipEntry(buffer, recordOffset, centralEnd);
    const nameLength = buffer.readUInt16LE(recordOffset + 28);
    const extraLength = buffer.readUInt16LE(recordOffset + 30);
    const commentLength = buffer.readUInt16LE(recordOffset + 32);
    recordOffset += 46 + nameLength + extraLength + commentLength;
    if (record) {
      addEntry(entries, seen, record.path, record.data, total);
      total += record.data.length;
    }
  }
  if (entries.length === 0) fail('ARCHIVE_EMPTY', '压缩包内没有可用文件');
  return { format: 'zip', entries };
}

function cString(buffer, start, end) {
  const slice = buffer.subarray(start, end);
  const nul = slice.indexOf(0);
  return slice.subarray(0, nul >= 0 ? nul : slice.length).toString('latin1');
}

function parseOctal(buffer, start, end, label) {
  const text = cString(buffer, start, end).trim();
  if (!/^[0-7]+$/.test(text)) fail('ARCHIVE_INVALID', `TAR ${label}字段无效`);
  return Number.parseInt(text, 8);
}

function verifyTarChecksum(header) {
  const stored = parseOctal(header, 148, 156, '校验和');
  let sum = 0;
  for (let index = 0; index < 512; index += 1) {
    sum += index >= 148 && index < 156 ? 32 : header[index];
  }
  if (sum !== stored) fail('ARCHIVE_INVALID', 'TAR 校验和无效');
}

function parseTar(buffer, format) {
  const entries = [];
  const seen = new Set();
  let total = 0;
  let offset = 0;
  let zeroBlocks = 0;

  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512);
    let isZero = true;
    for (let index = 0; index < 512; index += 1) {
      if (header[index] !== 0) {
        isZero = false;
        break;
      }
    }
    if (isZero) {
      zeroBlocks += 1;
      offset += 512;
      if (zeroBlocks >= 2) break;
      continue;
    }
    if (zeroBlocks > 0) break;

    if (header.toString('latin1', 257, 262) !== 'ustar') {
      fail('ARCHIVE_UNSUPPORTED', '仅支持 USTAR 格式的 TAR 压缩包');
    }
    verifyTarChecksum(header);
    if ((header[124] & 0x80) !== 0) fail('ARCHIVE_UNSUPPORTED', '不支持使用扩展长度编码的 TAR 条目');

    const size = parseOctal(header, 124, 136, '大小');
    if (size > LIMITS.maxArchiveFileBytes) {
      fail('ARCHIVE_ENTRY_TOO_LARGE', `压缩包内单个文件超过 ${Math.floor(LIMITS.maxArchiveFileBytes / 1024)} KiB`);
    }
    if (offset + 512 + size > buffer.length) fail('ARCHIVE_INVALID', 'TAR 条目数据越界');

    const typeFlag = header[156] === 0 ? '0' : String.fromCharCode(header[156]);
    const name = cString(header, 0, 100);
    const prefix = cString(header, 345, 500);
    const rawName = prefix ? `${prefix}/${name}` : name;
    const isDirectory = typeFlag === '5' || rawName.endsWith('/');
    if (!['0', '5'].includes(typeFlag)) {
      if (typeFlag === '1' || typeFlag === '2') {
        fail('ARCHIVE_UNSUPPORTED', '压缩包包含符号链接或硬链接，已拒绝');
      }
      fail('ARCHIVE_UNSUPPORTED', `不支持 TAR 条目类型 ${preview(typeFlag)}`);
    }
    if (rawName.includes(0)) fail('ARCHIVE_UNSAFE_PATH', '压缩包内文件名包含非法字符');
    const normalized = safeArchivePath(isDirectory ? rawName.replace(/\/+$/, '') : rawName, {
      allowEmpty: isDirectory,
    });

    if (!isDirectory) {
      const data = Buffer.from(buffer.subarray(offset + 512, offset + 512 + size));
      addEntry(entries, seen, normalized, data, total);
      total += data.length;
      if (entries.length > LIMITS.maxArchiveEntries) {
        fail('ARCHIVE_TOO_MANY_ENTRIES', `压缩包条目超过 ${LIMITS.maxArchiveEntries} 个`);
      }
    }

    offset += 512 + Math.ceil(size / 512) * 512;
  }

  if (entries.length === 0) fail('ARCHIVE_EMPTY', '压缩包内没有可用文件');
  return { format, entries };
}

/**
 * Decode and parse an archive entirely in memory. Archive paths are never used
 * as filesystem paths; only the selected certificate material is written later
 * to fixed, validated target names.
 */
export function extractArchiveEntries(input) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input || []);
  if (buffer.length === 0) fail('ARCHIVE_EMPTY', '压缩包内容为空');
  if (buffer.length > LIMITS.maxArchiveBytes) {
    fail('ARCHIVE_TOO_LARGE', `压缩包超过 ${Math.floor(LIMITS.maxArchiveBytes / 1024)} KiB 限制`);
  }
  if (isZip(buffer)) return parseZip(buffer);
  if (isGzip(buffer)) {
    let tar;
    try {
      tar = gunzipSync(buffer, { maxOutputLength: LIMITS.maxArchiveExpandedBytes });
    } catch (error) {
      if (error?.code === 'ERR_BUFFER_TOO_LARGE' || error?.code === 'ERR_OUT_OF_RANGE') {
        fail('ARCHIVE_TOO_LARGE', '压缩包解压后超出限制');
      }
      fail('ARCHIVE_INVALID', 'GZIP 解压失败或文件已损坏');
    }
    if (!isTar(tar)) fail('ARCHIVE_UNSUPPORTED', 'GZIP 内容不是 TAR 压缩包');
    return parseTar(tar, 'tar.gz');
  }
  if (isTar(buffer)) return parseTar(buffer, 'tar');
  fail('ARCHIVE_UNSUPPORTED', '仅支持 ZIP、TAR、TAR.GZ 或 TGZ 压缩包');
  return null;
}

export function decodeArchiveBase64(value) {
  if (typeof value !== 'string' || value.length === 0) {
    fail('ARCHIVE_INVALID', '压缩包内容为空');
  }
  if (value.length > LIMITS.maxArchiveBase64Chars) {
    fail('ARCHIVE_TOO_LARGE', `压缩包超过 ${Math.floor(LIMITS.maxArchiveBytes / 1024)} KiB 限制`);
  }
  if (value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    fail('ARCHIVE_INVALID', '压缩包编码无效');
  }
  const buffer = Buffer.from(value, 'base64');
  if (buffer.length === 0 || buffer.toString('base64') !== value) {
    fail('ARCHIVE_INVALID', '压缩包编码无效');
  }
  if (buffer.length > LIMITS.maxArchiveBytes) {
    fail('ARCHIVE_TOO_LARGE', `压缩包超过 ${Math.floor(LIMITS.maxArchiveBytes / 1024)} KiB 限制`);
  }
  return buffer;
}

function pemBlocks(text, regex) {
  const blocks = [];
  for (const match of text.matchAll(regex)) {
    blocks.push(`${match[0].trim()}\n`);
  }
  return blocks;
}

function decodeArchiveText(data) {
  if (data.includes(0)) return null;
  try {
    return UTF8.decode(data);
  } catch {
    return null;
  }
}

function publicKeyDer(certificate) {
  try {
    return certificate.publicKey.export({ type: 'spki', format: 'der' });
  } catch {
    return null;
  }
}

/**
 * Select exactly one private key, the matching leaf certificate and a verified
 * chain from archive entries. Unrelated files are ignored, never written.
 */
export function parseCertificateArchive(input) {
  const { format, entries } = extractArchiveEntries(input);
  const keyCandidates = new Map();
  const certificateCandidates = new Map();
  let encryptedKey = false;

  for (const entry of entries) {
    const text = decodeArchiveText(entry.data);
    if (!text) continue;
    if (/-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(text) || /Proc-Type:\s*4,\s*ENCRYPTED/i.test(text)) {
      encryptedKey = true;
    }
    for (const pem of pemBlocks(text, KEY_BLOCK_RE)) {
      if (!keyCandidates.has(pem)) keyCandidates.set(pem, entry.path);
    }
    for (const pem of pemBlocks(text, CERT_BLOCK_RE)) {
      let certificate;
      try {
        certificate = new crypto.X509Certificate(pem);
      } catch {
        fail('CERT_INVALID', `压缩包中的证书无法解析：${preview(entry.path)}`);
      }
      if (!certificateCandidates.has(certificate.fingerprint256)) {
        certificateCandidates.set(certificate.fingerprint256, {
          path: entry.path,
          pem,
          certificate,
        });
      }
    }
  }

  if (encryptedKey) fail('KEY_ENCRYPTED', '压缩包包含带口令的私钥，请先解密后再上传');
  if (keyCandidates.size === 0 && certificateCandidates.size === 0) {
    fail('ARCHIVE_EMPTY', '压缩包内未找到 PEM 证书或私钥');
  }
  if (keyCandidates.size === 0) fail('ARCHIVE_KEY_MISSING', '压缩包内未找到 PEM 私钥文件');
  if (certificateCandidates.size === 0) {
    fail('ARCHIVE_CERT_MISSING', '压缩包内未找到 PEM 证书文件');
  }
  // The same key may appear in several files (and in different PEM encodings).
  // Deduplicate by SPKI so harmless duplicates do not block an import, while
  // genuinely different keys still require an explicit choice.
  const parsedKeys = [];
  const keySpkis = new Set();
  for (const [keyPem, keyPath] of keyCandidates) {
    let privateKey;
    try {
      privateKey = crypto.createPrivateKey(keyPem);
    } catch {
      fail('KEY_INVALID', `压缩包中的私钥无法解析：${preview(keyPath)}`);
    }
    let keySpki;
    try {
      keySpki = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
    } catch {
      fail('KEY_INVALID', '压缩包中的私钥无法解析');
    }
    const fingerprint = keySpki.toString('hex');
    if (keySpkis.has(fingerprint)) continue;
    keySpkis.add(fingerprint);
    parsedKeys.push({ pem: keyPem, path: keyPath, keySpki });
  }
  if (parsedKeys.length > 1) {
    fail('ARCHIVE_AMBIGUOUS', '压缩包内存在多个不同的私钥，请只保留需要替换的私钥', {
      files: parsedKeys.map((item) => item.path).slice(0, 10),
    });
  }
  const [{ pem: keyPem, path: keyPath, keySpki }] = parsedKeys;

  const matching = [];
  for (const candidate of certificateCandidates.values()) {
    const spki = publicKeyDer(candidate.certificate);
    if (spki && Buffer.isBuffer(spki) && spki.equals(keySpki)) matching.push(candidate);
  }
  if (matching.length === 0) {
    fail('CERT_KEY_MISMATCH', '压缩包内未找到与私钥匹配的叶证书');
  }
  if (matching.length > 1) {
    fail('ARCHIVE_AMBIGUOUS', '压缩包内存在多个与私钥匹配的证书，请只保留需要替换的叶证书和链证书', {
      files: matching.map((item) => item.path).slice(0, 10),
    });
  }

  const leaf = matching[0];
  const usedCertificates = [leaf];
  const usedFingerprints = new Set([leaf.certificate.fingerprint256]);
  let issuer = leaf.certificate;

  for (let depth = 0; depth < LIMITS.maxChainCertificates; depth += 1) {
    const candidates = [];
    for (const candidate of certificateCandidates.values()) {
      if (usedFingerprints.has(candidate.certificate.fingerprint256)) continue;
      let valid = false;
      try {
        valid = issuer.verify(candidate.certificate.publicKey);
      } catch {
        valid = false;
      }
      if (valid) candidates.push(candidate);
    }
    if (candidates.length === 0) break;
    if (candidates.length > 1) {
      fail('ARCHIVE_AMBIGUOUS', '压缩包内存在多个可选的链证书，请只保留一条完整的证书链', {
        files: candidates.map((item) => item.path).slice(0, 10),
      });
    }
    const next = candidates[0];
    usedCertificates.push(next);
    usedFingerprints.add(next.certificate.fingerprint256);
    issuer = next.certificate;
  }

  const usedPaths = new Set([keyPath, ...usedCertificates.map((item) => item.path)]);
  const ignoredEntries = [...new Set(entries.map((entry) => entry.path))]
    .filter((path) => !usedPaths.has(path))
    .slice(0, 20);

  return {
    format,
    certPem: leaf.pem,
    chainPem: usedCertificates
      .slice(1)
      .map((item) => item.pem)
      .join(''),
    keyPem,
    entriesScanned: entries.length,
    files: {
      certificate: leaf.path,
      privateKey: keyPath,
      chain: [...new Set(usedCertificates.slice(1).map((item) => item.path))],
    },
    ignoredEntries,
  };
}
