/**
 * pm2 进程配置。
 *
 * 用法：
 *   pm2 start ecosystem.config.cjs --only ncs-main    # 主服务器
 *   pm2 start ecosystem.config.cjs --only ncs-agent   # 子服务器 Agent
 *   pm2 restart ecosystem.config.cjs
 *   pm2 delete ecosystem.config.cjs
 *   pm2 save
 *
 * 说明：
 * - 两个进程都用 fork 模式，单实例；不要开 cluster，本系统为单管理员、有本地状态文件。
 * - 主服务器通过 `node --env-file-if-exists=.env` 读取仓库根目录的 .env，
 *   因此 pm2 的 env 里不要再设置 NODE_ENV / NCS_* 覆盖值（Node 官方环境文件不会覆盖已存在的变量）。
 * - 日志默认写入 ~/.pm2/logs/，格式由 NCS_LOG_FORMAT 控制；非 TTY 下默认输出 JSON Lines。
 * - 本机不运行 Agent 时不要启动 ncs-agent，否则会因缺少 agent.json 反复重启。
 */

const path = require('node:path');

const root = __dirname;

module.exports = {
  apps: [
    {
      name: 'ncs-main',
      script: path.join(root, 'packages/main/src/index.js'),
      cwd: root,
      interpreter: 'node',
      node_args: '--env-file-if-exists=.env',
      exec_mode: 'fork',
      instances: 1,
      autorestart: true,
      max_restarts: 30,
      min_uptime: '15s',
      restart_delay: 3000,
      exp_backoff_restart_delay: 200,
      kill_timeout: 8000,
      max_memory_restart: '512M',
      // 时间戳由日志记录自身提供（ts 字段），避免和 pm2 前缀重复。
      time: false,
      merge_logs: true,
    },
    {
      name: 'ncs-agent',
      script: path.join(root, 'packages/agent/src/index.js'),
      args: 'run',
      cwd: root,
      interpreter: 'node',
      exec_mode: 'fork',
      instances: 1,
      autorestart: true,
      max_restarts: 15,
      min_uptime: '15s',
      restart_delay: 5000,
      exp_backoff_restart_delay: 200,
      kill_timeout: 8000,
      max_memory_restart: '384M',
      time: false,
      merge_logs: true,
      ...(process.env.NCS_AGENT_CONFIG
        ? { env: { NCS_AGENT_CONFIG: process.env.NCS_AGENT_CONFIG } }
        : {}),
    },
  ],
};
