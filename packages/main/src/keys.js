import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { NcsError } from '@ncs/shared';
import { ensurePrivateDirectory } from '@ncs/core';

const MASTER_KEY_BYTES = 32;

async function createExclusive(file, data, mode = 0o600) {
  await ensurePrivateDirectory(path.dirname(file), 0o700);
  let handle;
  try {
    handle = await fs.open(file, 'wx', mode);
    await handle.writeFile(data);
    await handle.sync();
    await handle.close();
    handle = null;
    if (process.platform !== 'win32') await fs.chmod(file, mode).catch(() => {});
    return true;
  } catch (error) {
    await handle?.close().catch(() => {});
    if (error?.code === 'EEXIST') return false;
    throw error;
  }
}

async function assertRestricted(file, label) {
  if (process.platform === 'win32') return;
  const stat = await fs.stat(file);
  const mode = stat.mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new NcsError('INSECURE_KEY_PERMISSIONS', `${label} 权限过宽（${mode.toString(8)}），必须为 0600`, 500);
  }
}

export async function loadOrCreateMasterKey(file) {
  try {
    const buffer = await fs.readFile(file);
    if (buffer.length !== MASTER_KEY_BYTES) {
      throw new NcsError('INVALID_MASTER_KEY', 'master.key 长度无效，必须为 32 字节', 500);
    }
    await assertRestricted(file, 'master.key');
    return buffer;
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  const key = crypto.randomBytes(MASTER_KEY_BYTES);
  const created = await createExclusive(file, key);
  if (!created) return loadOrCreateMasterKey(file);
  return key;
}

export async function loadOrCreateMainKey(file) {
  let pem;
  try {
    pem = await fs.readFile(file, 'utf8');
    await assertRestricted(file, '主服务器签名私钥');
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    const { privateKey } = crypto.generateKeyPairSync('ed25519');
    pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const created = await createExclusive(file, pem);
    if (!created) return loadOrCreateMainKey(file);
    await assertRestricted(file, '主服务器签名私钥');
  }
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(pem);
  } catch {
    throw new NcsError('INVALID_MAIN_KEY', '主服务器签名私钥无法解析', 500);
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw new NcsError('INVALID_MAIN_KEY', '主服务器签名私钥必须是 Ed25519', 500);
  }
  const publicKeyObject = crypto.createPublicKey(privateKey);
  return {
    privateKey,
    publicKeyObject,
    publicKeyPem: publicKeyObject.export({ type: 'spki', format: 'pem' }).toString(),
  };
}
