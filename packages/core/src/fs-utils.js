import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { LIMITS } from '@ncs/shared';

export function sha256Hex(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

export function sanitizeCommandOutput(output) {
  if (typeof output !== 'string') return '';
  // Strip ANSI escape sequences and control characters (keep newlines/tabs).
  const clean = output
    .replace(/\u001b\[[0-9;]*[A-Za-z]/g, '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
  const buffer = Buffer.from(clean, 'utf8');
  if (buffer.length <= LIMITS.maxCommandOutputBytes) return clean;
  return `${buffer.subarray(0, LIMITS.maxCommandOutputBytes).toString('utf8')}\n...[输出已截断]`;
}

async function fsyncDirectory(directory) {
  let handle;
  try {
    handle = await fs.open(directory, 'r');
    await handle.sync();
  } catch {
    // Directory fsync is not supported on every platform/filesystem.
  } finally {
    await handle?.close().catch(() => {});
  }
}

/**
 * Write atomically: temp file in the same directory, fsync, chmod/chown, rename.
 * The caller is responsible for resolving symlinks safely.
 */
export async function atomicWriteFile(targetPath, content, { mode = 0o644, uid, gid } = {}) {
  const directory = path.dirname(targetPath);
  const tempPath = path.join(directory, `.ncs-tmp-${crypto.randomUUID()}`);
  let handle;
  try {
    handle = await fs.open(tempPath, 'wx', mode);
    await handle.writeFile(content);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.chmod(tempPath, mode);
    if (process.platform !== 'win32' && Number.isInteger(uid) && Number.isInteger(gid)) {
      await fs.chown(tempPath, uid, gid).catch(() => {});
    }
    await fs.rename(tempPath, targetPath);
    await fsyncDirectory(directory);
  } catch (error) {
    await handle?.close().catch(() => {});
    await fs.unlink(tempPath).catch(() => {});
    throw error;
  }
}

export async function ensurePrivateDirectory(directory, mode = 0o700) {
  await fs.mkdir(directory, { recursive: true, mode });
  if (process.platform !== 'win32') {
    await fs.chmod(directory, mode).catch(() => {});
  }
}

export async function readFileLimited(filePath, maxBytes) {
  const handle = await fs.open(filePath, 'r');
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error('Not a regular file');
    if (stat.size > maxBytes) {
      const error = new Error('File too large');
      error.code = 'FILE_TOO_LARGE';
      throw error;
    }
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}
