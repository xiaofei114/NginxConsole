#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createLogger } from '@ncs/shared';
import { loadConfig } from './config.js';
import { createApp } from './app.js';

const VERSION = '1.0.0';
const logger = createLogger({ app: 'main', component: 'boot' });

function displayUrl(config) {
  const protocol = config.tls ? 'https' : 'http';
  const host = config.host === '0.0.0.0' || config.host === '::' ? 'localhost' : config.host;
  return `${protocol}://${host}:${config.port}`;
}

async function start() {
  const config = await loadConfig();
  const runtime = await createApp(config, { logger });

  logger.info('主服务器启动', {
    version: VERSION,
    url: displayUrl(config),
    tls: Boolean(config.tls),
    publicOrigin: config.publicOrigin,
    dataDir: config.dataDir,
    allowedRoots: config.allowedRoots,
    localWorkspace: runtime.localEngine.workspace || null,
    controlMode: config.controlMode,
    useSudo: config.useSudo,
    enforceTest: config.enforceTest,
    mainKeyFingerprint: runtime.manager.mainKeyFingerprint,
  });

  if (!config.localWorkspace) logger.info('主服务器本地工作目录尚未选择，请在页面中选择 Nginx 工作目录。');
  if (runtime.localEngine.workspaceError) {
    logger.warn('本地工作目录无效', { reason: runtime.localEngine.workspaceError });
  }

  if (runtime.adminSeeded) {
    logger.warn('已创建管理员账号', { username: config.admin.username });
    if (config.admin.generated) {
      if (process.stdout.isTTY) {
        logger.warn(
          '初始口令仅显示一次，请立即登录并修改口令',
          { initialPassword: config.admin.password },
          { redact: false },
        );
      } else {
        // Under pm2/systemd stdout is a file that may outlive the session and be
        // readable by other local users. Persist the one-time password to a
        // 0600 file inside the 0700 data dir instead of writing it to logs.
        const secretFile = path.join(config.dataDir, 'initial-admin-password.txt');
        try {
          await fs.writeFile(secretFile, `${config.admin.password}\n`, { mode: 0o600, flag: 'w' });
          await fs.chmod(secretFile, 0o600).catch(() => {});
        } catch (error) {
          logger.error('无法写入初始口令文件，请删除数据目录下的 store.json 并设置 NCS_ADMIN_PASSWORD 后重新启动', {
            file: secretFile,
            reason: error?.message || String(error),
          });
          throw error;
        }
        logger.warn('初始口令已写入文件（权限 0600），登录后请立即修改口令并删除该文件', { file: secretFile });
      }
    } else {
      logger.info('管理员口令取自 NCS_ADMIN_PASSWORD');
    }
  } else if (config.admin.generated) {
    logger.info('NCS_ADMIN_PASSWORD 未设置，本次随机口令未写入已有账号；请使用现有口令登录。');
  }

  for (const warning of config.warnings) logger.warn(warning);
  if (config.publicUrl && /localhost|127\.0\.0\.1|\[::1\]/.test(config.publicUrl)) {
    logger.info('主服务器注册地址为回环地址，子服务器无法通过该地址连接。请配置 NCS_PUBLIC_ORIGIN。');
  }

  await new Promise((resolve, reject) => {
    const onError = (error) => {
      runtime.server.off('listening', onListening);
      if (error?.code === 'EADDRINUSE') {
        reject(new Error(`端口 ${config.port} 已被占用`));
      } else if (error?.code === 'EACCES') {
        reject(new Error(`没有权限监听端口 ${config.port}`));
      } else {
        reject(error);
      }
    };
    const onListening = () => {
      runtime.server.off('error', onError);
      logger.info('主服务器已就绪', { url: displayUrl(config) });
      resolve();
    };
    runtime.server.once('error', onError);
    runtime.server.once('listening', onListening);
    runtime.server.listen(config.port, config.host);
  });

  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info('收到退出信号，正在关闭', { signal });
    try {
      await runtime.close();
      logger.info('主服务器已停止');
    } catch (error) {
      logger.error('关闭过程中出现异常', error);
    } finally {
      process.exit(0);
    }
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('unhandledRejection', (error) => {
    logger.error('未处理的 Promise 异常', error);
  });
}

const isEntryPoint = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isEntryPoint) {
  const major = Number(process.versions.node.split('.')[0]);
  if (major < 20) {
    process.stderr.write('错误：需要 Node.js 20 或更高版本（推荐 22 LTS）。\n');
    process.exit(1);
  }
  start().catch((error) => {
    logger.error('启动失败', error);
    process.exit(1);
  });
}

export { start };
