#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline/promises';
import { NcsError, createLogger } from '@ncs/shared';
import {
  assertAgentId,
  defaultConfigPath,
  loadAgentConfig,
  loadIdentity,
} from './config.js';
import { enrollAgent } from './enroll.js';
import { AgentClient } from './client.js';

const VERSION = '1.0.0';

const HELP = `
Nginx Console Agent v${VERSION}

用法:
  ncs-agent setup [--config <PATH>]       一键部署：自动识别 Nginx、交互式注册并启动（推荐）
  ncs-agent enroll --main https://console.example.com --id <AGENT_ID> --token <TOKEN> [选项]
  ncs-agent run [--config <PATH>]
  ncs-agent fingerprint [--config <PATH>]

setup 说明:
  缺什么就交互式询问什么；已注册过则直接启动。
  可先用 --main / --id / --nginx-bin 预填，或设置 NCS_ENROLL_TOKEN。
  加 --force 会覆盖已有配置重新注册。

enroll 选项:
  --config <PATH>            配置文件路径（默认 ${defaultConfigPath()}）
  --allowed-root <PATH>      允许管理的 Nginx 根目录，可重复；工作目录必须位于其中
  --workspace <PATH>         Nginx 工作目录（默认第一个 allowed-root）
  --nginx-bin <PATH>         nginx 可执行文件绝对路径（默认 /usr/sbin/nginx）
  --nginx-prefix <PATH>      nginx -p 前缀（可选）
  --control-mode <MODE>      signal | systemd（默认 signal）
  --systemd-unit <UNIT>      systemd 单元名（默认 nginx）
  --use-sudo                 通过 sudo -n 执行重载/重启（需要精确 sudoers）
  --cert-dir <PATH>          工作目录内的证书目录（默认 ssl）
  --insecure-http            允许 http/wss 明文（仅本地开发）
  --force                    覆盖已有配置重新注册
  --dev-allow-untested       开发环境跳过 nginx -t（需 NCS_DEV_UNSAFE=1，禁止生产使用）

环境变量:
  NCS_AGENT_CONFIG           配置文件路径
  NCS_ENROLL_TOKEN           注册令牌（避免令牌出现在命令历史中）
`;

function parseArgs(tokens) {
  const flags = Object.create(null);
  const positional = [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!token.startsWith('--')) {
      positional.push(token);
      continue;
    }
    let name;
    let value;
    const equals = token.indexOf('=');
    if (equals > 2) {
      name = token.slice(2, equals);
      value = token.slice(equals + 1);
    } else {
      name = token.slice(2);
      const next = tokens[index + 1];
      if (next !== undefined && !next.startsWith('--')) {
        value = next;
        index += 1;
      } else {
        value = true;
      }
    }
    if (name === 'allowed-root') {
      flags.allowedRoot = flags.allowedRoot || [];
      flags.allowedRoot.push(String(value));
    } else {
      if (flags[name] !== undefined) {
        throw new NcsError('DUPLICATE_FLAG', `参数 --${name} 重复`, 400);
      }
      flags[name] = value;
    }
  }
  return { flags, positional };
}

function stringFlag(flags, name, { required = false, defaultValue = undefined } = {}) {
  const value = flags[name];
  if (value === undefined) {
    if (required) throw new NcsError('MISSING_FLAG', `缺少参数 --${name}`, 400);
    return defaultValue;
  }
  if (value === true || typeof value !== 'string' || value.length === 0) {
    throw new NcsError('INVALID_FLAG', `参数 --${name} 需要值`, 400);
  }
  return value;
}

function boolFlag(flags, name) {
  const value = flags[name];
  if (value === undefined) return false;
  if (value !== true) throw new NcsError('INVALID_FLAG', `参数 --${name} 不接受值`, 400);
  return true;
}

function log(message) {
  process.stdout.write(`${message}\n`);
}

async function commandEnroll(flags) {
  const configPath = stringFlag(flags, 'config', { defaultValue: defaultConfigPath() });
  const token = process.env.NCS_ENROLL_TOKEN || stringFlag(flags, 'token', { required: true });
  const agentId = assertAgentId(stringFlag(flags, 'id', { required: true }));
  const main = stringFlag(flags, 'main', { required: true });
  const allowUntested = boolFlag(flags, 'dev-allow-untested');
  if (allowUntested && (process.env.NCS_DEV_UNSAFE !== '1' || process.env.NODE_ENV === 'production')) {
    throw new NcsError('DEV_FLAG_DENIED', '--dev-allow-untested 仅在开发环境且 NCS_DEV_UNSAFE=1 时可用', 403);
  }

  const result = await enrollAgent({
    configPath,
    mainUrl: main,
    agentId,
    token,
    allowedRoots: flags.allowedRoot || [],
    workspace: stringFlag(flags, 'workspace'),
    nginxBin: stringFlag(flags, 'nginx-bin'),
    nginxPrefix: stringFlag(flags, 'nginx-prefix'),
    controlMode: stringFlag(flags, 'control-mode', { defaultValue: 'signal' }),
    systemdUnit: stringFlag(flags, 'systemd-unit', { defaultValue: 'nginx' }),
    useSudo: boolFlag(flags, 'use-sudo'),
    certDir: stringFlag(flags, 'cert-dir', { defaultValue: 'ssl' }),
    allowInsecureHttp: boolFlag(flags, 'insecure-http'),
    force: boolFlag(flags, 'force'),
    enforceTest: !allowUntested,
  });

  log('注册成功。');
  log(`  Agent ID       : ${result.config.agentId}`);
  log(`  Agent 名称     : ${result.config.agentName}`);
  log(`  配置文件       : ${result.configPath}`);
  log(`  私钥文件       : ${result.keyPath}`);
  log(`  主服务器       : ${result.config.mainUrl}`);
  log(`  Agent 公钥指纹 : ${result.agentFingerprint}`);
  log(`  主服务器指纹   : ${result.mainFingerprint}`);
  log(`  工作目录       : ${result.config.workspace}`);
  log(`  允许根目录     : ${result.config.allowedRoots.join(', ')}`);
  if (result.insecureHttp) log('警告：正在使用明文 HTTP 连接主服务器，仅限本地开发。');
  if (allowUntested) log('警告：已开启跳过 nginx -t 的开发模式，禁止在生产使用。');
  log('');
  log('启动 Agent:');
  log(`  NCS_AGENT_CONFIG=${result.configPath} ncs-agent run`);
}

async function commandRun(flags) {
  const configPath = stringFlag(flags, 'config', { defaultValue: defaultConfigPath() });
  await startAgent(configPath);
}

async function startAgent(configPath) {
  const logger = createLogger({ app: 'agent', component: 'run' });
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    logger.warn('Agent 以 root 运行，建议配合 systemd 沙箱并限制工作目录权限（见 README 部署章节）');
  }
  const config = await loadAgentConfig(configPath);
  const client = await AgentClient.create({ configPath, logger });
  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info('收到退出信号，正在退出', { signal });
    await client.stop();
    setTimeout(() => process.exit(0), 100);
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('unhandledRejection', (error) => {
    logger.error('未处理的 Promise 异常', error);
  });
  logger.info('Agent 已启动', {
    agentId: config.agentId,
    agentName: config.agentName,
    workspace: config.workspace,
    configPath,
  });
  client.start();
  await new Promise(() => {});
}

async function exists(target) {
  try {
    await fs.stat(target);
    return true;
  } catch {
    return false;
  }
}

async function detectNginxBin() {
  const candidates = [];
  if (process.platform === 'win32') {
    candidates.push('C:/nginx/nginx.exe');
    try {
      const entries = await fs.readdir('C:/', { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory() && /^nginx/i.test(entry.name)) {
          candidates.push(`C:/${entry.name}/nginx.exe`);
        }
      }
    } catch {
      // Drive root is not listable; fall back to the common location above.
    }
  } else {
    candidates.push('/usr/sbin/nginx', '/usr/local/nginx/sbin/nginx', '/usr/local/sbin/nginx', '/sbin/nginx');
  }
  for (const candidate of candidates) {
    if (await exists(candidate)) return candidate;
  }
  return null;
}

async function commandSetup(flags) {
  const configPath = path.resolve(stringFlag(flags, 'config', { defaultValue: defaultConfigPath() }));
  const force = boolFlag(flags, 'force');

  let enrolled = false;
  try {
    await loadAgentConfig(configPath);
    enrolled = true;
  } catch {
    enrolled = false;
  }
  if (enrolled && !force) {
    log(`已注册，直接启动：${configPath}`);
    log('（需要重新注册请加 --force）');
    await startAgent(configPath);
    return;
  }

  const interactive = Boolean(process.stdin.isTTY && process.stdout.isTTY);
  const rl = interactive ? readline.createInterface({ input: process.stdin, output: process.stdout }) : null;
  const ask = async (question, provided) => {
    if (provided) return provided;
    if (!rl) throw new NcsError('MISSING_FLAG', `缺少参数：${question.replace(/[:：]\s*$/, '')}`);
    const answer = (await rl.question(question)).trim();
    if (!answer) throw new NcsError('MISSING_FLAG', '输入不能为空');
    return answer;
  };

  try {
    const mainUrl = await ask('主服务器地址（如 https://nginx.example.com）: ', flags.main || process.env.NCS_MAIN_URL);
    const agentId = await ask('Agent ID: ', stringFlag(flags, 'id'));
    const token = await ask('一次性注册令牌: ', process.env.NCS_ENROLL_TOKEN || stringFlag(flags, 'token'));

    const nginxBin = await ask('nginx 可执行文件路径: ', stringFlag(flags, 'nginx-bin') || await detectNginxBin());
    const nginxDir = path.dirname(path.resolve(nginxBin));
    const defaultWorkspace = process.platform === 'win32'
      ? nginxDir
      : (await exists('/etc/nginx/nginx.conf') ? '/etc/nginx' : nginxDir);
    const allowedRoots = flags.allowedRoot?.length ? flags.allowedRoot.map((item) => path.resolve(String(item))) : [defaultWorkspace];
    const workspace = flags.workspace ? path.resolve(flags.workspace) : allowedRoots[0];
    const nginxPrefix = stringFlag(flags, 'nginx-prefix') || (process.platform === 'win32' ? nginxDir : undefined);
    const controlMode = stringFlag(flags, 'control-mode', {
      defaultValue: process.platform === 'linux' && await exists('/run/systemd/system') ? 'systemd' : 'signal',
    });

    rl?.close();
    log(`正在注册：${mainUrl}（工作目录 ${workspace}）`);
    const result = await enrollAgent({
      configPath,
      mainUrl,
      agentId,
      token,
      allowedRoots,
      workspace,
      nginxBin,
      nginxPrefix,
      controlMode,
      systemdUnit: stringFlag(flags, 'systemd-unit', { defaultValue: 'nginx' }),
      useSudo: boolFlag(flags, 'use-sudo'),
      certDir: stringFlag(flags, 'cert-dir', { defaultValue: 'ssl' }),
      allowInsecureHttp: boolFlag(flags, 'insecure-http'),
      force,
      enforceTest: !boolFlag(flags, 'dev-allow-untested'),
    });
    log('注册成功，正在启动 Agent（Ctrl+C 退出）…');
    log(`  配置文件: ${result.configPath}`);
    log(`  工作目录: ${result.config.workspace}`);
    log(`  nginx   : ${result.config.nginxBin}`);
  } finally {
    rl?.close();
  }
  await startAgent(configPath);
}

async function commandFingerprint(flags) {
  const configPath = stringFlag(flags, 'config', { defaultValue: defaultConfigPath() });
  const identity = await loadIdentity(configPath);
  log(`Agent 私钥：${identity.keyPath}`);
  log(`Agent 公钥指纹：${identity.fingerprint}`);
  try {
    const config = await loadAgentConfig(configPath);
    log(`已注册 Agent ID：${config.agentId}`);
    log(`主服务器：${config.mainUrl}`);
    log(`主服务器公钥指纹：${config.mainFingerprint}`);
  } catch (error) {
    log(`配置文件未加载：${error?.message || String(error)}`);
  }
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === '--help' || command === '-h' || command === 'help') {
    log(HELP.trim());
    return;
  }
  if (command === '--version' || command === '-v') {
    log(VERSION);
    return;
  }
  const { flags, positional } = parseArgs(rest);
  if (positional.length > 0) throw new NcsError('INVALID_ARGUMENT', '存在无法识别的参数', 400);
  if (command === 'enroll') return commandEnroll(flags);
  if (command === 'setup') return commandSetup(flags);
  if (command === 'run') return commandRun(flags);
  if (command === 'fingerprint') return commandFingerprint(flags);
  throw new NcsError('UNKNOWN_COMMAND', `未知命令：${command}`, 400);
}

main().catch((error) => {
  const safe = error instanceof NcsError ? error.message : '命令执行失败';
  process.stderr.write(`错误：${safe}\n`);
  if (process.env.NCS_AGENT_DEBUG === '1' && error?.stack) {
    process.stderr.write(`${error.stack}\n`);
  }
  process.exitCode = 1;
});
