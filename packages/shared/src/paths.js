import fs from 'node:fs/promises';
import path from 'node:path';
import { NcsError } from './errors.js';
import { CERT_NAME_RE, DEFAULT_TEXT_EXTENSIONS, LIMITS } from './limits.js';

/** Normalize a client-supplied path to a safe POSIX-style relative path. */
export function normalizeRelativePath(input, { allowEmpty = true } = {}) {
  if (typeof input !== 'string') {
    throw new NcsError('INVALID_PATH', '路径格式无效', 400);
  }
  if (Buffer.byteLength(input, 'utf8') > LIMITS.maxPathBytes) {
    throw new NcsError('INVALID_PATH', '路径过长', 400);
  }
  // Reject NUL/control chars and backslashes to avoid platform ambiguity.
  if (/[\u0000-\u001f\u007f]/.test(input) || input.includes('\\')) {
    throw new NcsError('INVALID_PATH', '路径包含非法字符', 400);
  }
  if (input.startsWith('/') || /^[A-Za-z]:/.test(input)) {
    throw new NcsError('INVALID_PATH', '仅允许工作目录内的相对路径', 400);
  }
  const parts = [];
  for (const segment of input.split('/')) {
    if (!segment || segment === '.') continue;
    if (segment === '..') {
      throw new NcsError('INVALID_PATH', '路径不允许包含上级目录', 400);
    }
    if (Buffer.byteLength(segment, 'utf8') > LIMITS.maxPathSegmentBytes) {
      throw new NcsError('INVALID_PATH', '路径片段过长', 400);
    }
    parts.push(segment);
  }
  const normalized = parts.join('/');
  if (!allowEmpty && normalized === '') {
    throw new NcsError('INVALID_PATH', '路径不能为空', 400);
  }
  return normalized;
}

export function isInside(rootRealPath, candidatePath) {
  const relative = path.relative(rootRealPath, candidatePath);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

export function assertInside(rootRealPath, candidatePath) {
  if (!isInside(rootRealPath, candidatePath)) {
    throw new NcsError('PATH_ESCAPE', '路径超出允许的工作目录', 403);
  }
}

export function absoluteFromRelative(rootRealPath, relativePath) {
  const normalized = normalizeRelativePath(relativePath);
  const absolute = path.join(rootRealPath, ...normalized.split('/').filter(Boolean));
  assertInside(rootRealPath, absolute);
  return absolute;
}

export function displayRelativePath(rootRealPath, absolutePath) {
  const relative = path.relative(rootRealPath, absolutePath);
  if (relative === '') return '';
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new NcsError('PATH_ESCAPE', '路径超出允许的工作目录', 403);
  }
  return relative.split(path.sep).join('/');
}

/** Resolve an existing directory, following symlinks only when they stay inside the root. */
export async function resolveSafeDirectory(rootRealPath, relativePath) {
  const normalized = normalizeRelativePath(relativePath);
  const requested = path.join(rootRealPath, ...normalized.split('/').filter(Boolean));
  assertInside(rootRealPath, requested);

  let realPath;
  try {
    realPath = await fs.realpath(requested);
  } catch (error) {
    if (error?.code === 'ENOENT') throw new NcsError('NOT_FOUND', '目录不存在', 404);
    throw new NcsError('PATH_ERROR', '无法解析目录路径', 400);
  }
  assertInside(rootRealPath, realPath);
  const stat = await fs.stat(realPath);
  if (!stat.isDirectory()) throw new NcsError('NOT_A_DIRECTORY', '目标不是目录', 400);
  return { realPath, relativePath: normalized, stat };
}

/**
 * Resolve a file for read or write.
 * - Reads may follow symlinks that resolve inside the allowed root.
 * - Writes follow an existing symlink to its in-root target (preserving links such
 *   as sites-enabled -> sites-available) but never create or replace a symlink.
 */
export async function resolveSafeFile(rootRealPath, relativePath, { mustExist = false, forWrite = false } = {}) {
  const normalized = normalizeRelativePath(relativePath, { allowEmpty: false });
  const requested = path.join(rootRealPath, ...normalized.split('/').filter(Boolean));
  assertInside(rootRealPath, requested);

  let lstat = null;
  try {
    lstat = await fs.lstat(requested);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw new NcsError('PATH_ERROR', '无法读取文件状态', 400);
  }

  if (lstat) {
    if (lstat.isDirectory()) throw new NcsError('IS_DIRECTORY', '目标是一个目录', 400);
    let realPath;
    try {
      realPath = await fs.realpath(requested);
    } catch {
      throw new NcsError('PATH_ERROR', '无法解析文件路径', 400);
    }
    assertInside(rootRealPath, realPath);
    const stat = await fs.stat(realPath);
    if (!stat.isFile()) throw new NcsError('NOT_A_FILE', '目标不是普通文件', 400);
    return {
      absolutePath: realPath,
      requestedPath: requested,
      relativePath: normalized,
      stat,
      existed: true,
      wasSymlink: lstat.isSymbolicLink(),
    };
  }

  if (mustExist) throw new NcsError('NOT_FOUND', '文件不存在', 404);
  if (!forWrite) throw new NcsError('NOT_FOUND', '文件不存在', 404);

  const parentRequested = path.dirname(requested);
  let parentReal;
  try {
    parentReal = await fs.realpath(parentRequested);
  } catch {
    throw new NcsError('PARENT_NOT_FOUND', '目标目录不存在', 404);
  }
  assertInside(rootRealPath, parentReal);
  const parentStat = await fs.stat(parentReal);
  if (!parentStat.isDirectory()) throw new NcsError('NOT_A_DIRECTORY', '目标目录无效', 400);

  const target = path.join(parentReal, path.basename(requested));
  assertInside(rootRealPath, target);
  return {
    absolutePath: target,
    requestedPath: requested,
    relativePath: displayRelativePath(rootRealPath, target),
    stat: null,
    existed: false,
    wasSymlink: false,
  };
}

/** Resolve an admin-selected workspace against an allowlist of roots. */
export async function resolveWorkspace(allowedRoots, requestedPath) {
  if (typeof requestedPath !== 'string' || requestedPath.length === 0 || requestedPath.length > LIMITS.maxPathBytes) {
    throw new NcsError('INVALID_WORKSPACE', '工作目录路径无效', 400);
  }
  if (/[\u0000-\u001f\u007f]/.test(requestedPath)) {
    throw new NcsError('INVALID_WORKSPACE', '工作目录路径包含非法字符', 400);
  }
  if (!path.isAbsolute(requestedPath)) {
    throw new NcsError('INVALID_WORKSPACE', '工作目录必须是绝对路径', 400);
  }
  let realPath;
  try {
    realPath = await fs.realpath(requestedPath);
  } catch {
    throw new NcsError('WORKSPACE_NOT_FOUND', '工作目录不存在', 404);
  }
  const stat = await fs.stat(realPath);
  if (!stat.isDirectory()) throw new NcsError('INVALID_WORKSPACE', '工作目录不是目录', 400);

  for (const root of allowedRoots) {
    if (isInside(root, realPath)) return { path: realPath, root };
  }
  throw new NcsError('WORKSPACE_NOT_ALLOWED', '工作目录不在允许的根目录范围内', 403);
}

export function assertAllowedTextFile(fileNameOrPath, allowedExtensions = DEFAULT_TEXT_EXTENSIONS) {
  const base = path.basename(fileNameOrPath).toLowerCase();
  const ext = path.extname(base);
  if (base === 'nginx.conf') return;
  if (ext === '.key' || !allowedExtensions.includes(ext)) {
    throw new NcsError('FILE_TYPE_NOT_ALLOWED', `不允许操作该类型文件${ext || '（无扩展名）'}`, 403);
  }
}

export function isPrivateKeyContent(content) {
  if (typeof content !== 'string') return false;
  const sample = content.length > 65536 ? content.slice(0, 65536) : content;
  return /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(sample);
}

export function assertSafeCertificateName(name) {
  if (typeof name !== 'string' || !CERT_NAME_RE.test(name)) {
    throw new NcsError('INVALID_CERT_NAME', '证书名称仅允许字母、数字、点、下划线和短横线，且不能以点开头', 400);
  }
  if (name.includes('..')) throw new NcsError('INVALID_CERT_NAME', '证书名称无效', 400);
  return name;
}
