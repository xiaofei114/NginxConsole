import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { NcsError } from '@ncs/shared';
import { sanitizeCommandOutput } from './fs-utils.js';

const VERSION_CACHE_MS = 5 * 60 * 1000;

function safeEnv() {
  if (process.platform === 'win32') {
    return {
      PATH: process.env.PATH || 'C:\\Windows\\System32',
      SYSTEMROOT: process.env.SystemRoot || 'C:\\Windows',
      WINDIR: process.env.WINDIR || 'C:\\Windows',
      TEMP: process.env.TEMP || '',
      TMP: process.env.TMP || '',
    };
  }
  return {
    PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    LANG: 'C',
    LC_ALL: 'C',
    TZ: 'UTC',
  };
}

function runProcess(binary, args, { timeoutMs = 15000 } = {}) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(binary, args, {
        shell: false,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: safeEnv(),
      });
    } catch (error) {
      reject(new NcsError('COMMAND_SPAWN_FAILED', '无法启动系统命令', 500));
      return;
    }

    let output = '';
    let killedByTimeout = false;
    let settled = false;
    const append = (chunk) => {
      if (output.length < 128 * 1024) output += chunk.toString('utf8');
    };
    child.stdout.on('data', append);
    child.stderr.on('data', append);

    const timer = setTimeout(() => {
      killedByTimeout = true;
      child.kill('SIGKILL');
    }, timeoutMs);

    child.on('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error?.code === 'ENOENT') {
        reject(new NcsError('COMMAND_NOT_FOUND', `找不到可执行文件：${binary}`, 500));
      } else {
        reject(new NcsError('COMMAND_FAILED', '系统命令执行失败', 500));
      }
    });

    child.on('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (killedByTimeout) {
        reject(new NcsError('COMMAND_TIMEOUT', '系统命令执行超时', 504, { output: sanitizeCommandOutput(output) }));
        return;
      }
      resolve({ exitCode: code, signal, output: sanitizeCommandOutput(output) });
    });
  });
}

/**
 * Start a long-running process without waiting for it to exit.
 *
 * nginx.exe on Windows keeps its console attached (and may run in the
 * foreground), so waiting for `close` would report a false timeout after a
 * successful start. On POSIX this helper is unused.
 */
function startDetached(binary, args, { settleMs = 2000 } = {}) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawn(binary, args, {
        shell: false,
        windowsHide: true,
        detached: true,
        stdio: 'ignore',
        env: safeEnv(),
      });
    } catch {
      reject(new NcsError('COMMAND_SPAWN_FAILED', '无法启动系统命令', 500));
      return;
    }

    let settled = false;
    let exitCode = null;
    child.once('error', (error) => {
      if (settled) return;
      settled = true;
      if (error?.code === 'ENOENT') {
        reject(new NcsError('COMMAND_NOT_FOUND', `找不到可执行文件：${binary}`, 500));
      } else {
        reject(new NcsError('COMMAND_FAILED', '系统命令执行失败', 500));
      }
    });
    child.once('exit', (code) => {
      exitCode = code ?? 0;
    });
    child.unref();

    setTimeout(() => {
      if (settled) return;
      settled = true;
      if (exitCode !== null && exitCode !== 0) {
        reject(new NcsError('NGINX_START_FAILED', `Nginx 启动失败（退出码 ${exitCode}）`, 500));
        return;
      }
      resolve({ exitCode: 0, signal: null, output: '', detached: true });
    }, settleMs);
  });
}

export class NginxController {
  constructor(config) {
    this.nginxBin = config.nginxBin;
    this.nginxPrefix = config.nginxPrefix || null;
    this.controlMode = config.controlMode;
    this.systemctlBin = config.systemctlBin;
    this.systemdUnit = config.systemdUnit;
    this.useSudo = Boolean(config.useSudo);
    this.sudoBin = config.sudoBin;
    this.versionCache = null;
  }

  prefixArgs() {
    return this.nginxPrefix ? ['-p', this.nginxPrefix] : [];
  }

  async runNginx(args, { timeoutMs = 15000, privileged = false } = {}) {
    if (privileged && this.useSudo) {
      return runProcess(this.sudoBin, ['-n', '--', this.nginxBin, ...args], { timeoutMs });
    }
    return runProcess(this.nginxBin, args, { timeoutMs });
  }

  async runSystemctl(action, { timeoutMs = 30000 } = {}) {
    if (this.useSudo) {
      return runProcess(this.sudoBin, ['-n', '--', this.systemctlBin, action, this.systemdUnit], { timeoutMs });
    }
    return runProcess(this.systemctlBin, [action, this.systemdUnit], { timeoutMs });
  }

  async version({ force = false } = {}) {
    const now = Date.now();
    if (!force && this.versionCache && now - this.versionCache.at < VERSION_CACHE_MS) {
      return this.versionCache.value;
    }
    let value;
    try {
      const result = await this.runNginx(['-v'], { timeoutMs: 5000 });
      const combined = result.output || '';
      if (result.exitCode !== 0) {
        value = { available: false, version: null, error: combined || `退出码 ${result.exitCode}` };
      } else {
        const match = combined.match(/nginx version:\s*nginx\/([^\s]+)/i);
        value = { available: true, version: match?.[1] || 'unknown', error: null };
      }
    } catch (error) {
      value = { available: false, version: null, error: error?.message || '无法执行 nginx' };
    }
    this.versionCache = { at: now, value };
    return value;
  }

  async test(configPath) {
    const result = await this.runNginx([...this.prefixArgs(), '-t', '-c', configPath], { timeoutMs: 15000 });
    if (result.exitCode !== 0) {
      throw new NcsError('NGINX_TEST_FAILED', 'Nginx 配置检测失败', 400, {
        output: result.output || `nginx -t 退出码 ${result.exitCode}`,
        exitCode: result.exitCode,
      });
    }
    return { output: result.output, exitCode: 0, configPath };
  }

  /**
   * Resolve the pid file used by this nginx instance.
   * Prefers the `pid` directive in nginx.conf and falls back to
   * `<prefix>/logs/nginx.pid`, which is nginx's own default.
   */
  async pidFile(configPath) {
    const base = this.nginxPrefix || path.dirname(this.nginxBin);
    let pidPath = path.join(base, 'logs', 'nginx.pid');
    try {
      const text = await fs.readFile(configPath, 'utf8');
      const source = text
        .split('\n')
        .map((line) => line.replace(/#.*$/, ''))
        .join('\n');
      const match = source.match(/(?:^|\n)\s*pid\s+([^;]+);/);
      if (match) {
        const value = match[1].trim().replace(/^["']|["']$/g, '');
        if (value) pidPath = path.isAbsolute(value) ? value : path.resolve(base, value);
      }
    } catch {
      // Keep the default location when the configuration cannot be read.
    }
    return pidPath;
  }

  /**
   * Report whether this nginx instance is running.
   * `running: null` means the state cannot be determined (e.g. pid file is
   * unreadable), so callers must not assume the process is stopped.
   */
  async status(configPath) {
    if (this.controlMode === 'systemd') {
      try {
        const result = await this.runSystemctl('is-active', { timeoutMs: 5000 });
        return {
          running: String(result.output || '').trim() === 'active',
          pid: null,
          pidFile: null,
          unit: this.systemdUnit,
        };
      } catch {
        return { running: null, pid: null, pidFile: null, unit: this.systemdUnit };
      }
    }
    if (!configPath) return { running: null, pid: null, pidFile: null };
    const pidFile = await this.pidFile(configPath);
    let raw;
    try {
      raw = await fs.readFile(pidFile, 'utf8');
    } catch (error) {
      if (error?.code === 'ENOENT') return { running: false, pid: null, pidFile };
      return { running: null, pid: null, pidFile };
    }
    const pid = Number.parseInt(String(raw).trim(), 10);
    if (!Number.isSafeInteger(pid) || pid <= 0) {
      return { running: false, pid: null, pidFile };
    }
    try {
      process.kill(pid, 0);
      return { running: true, pid, pidFile };
    } catch (error) {
      if (error?.code === 'EPERM') return { running: true, pid, pidFile };
      return { running: false, pid: null, pidFile, stalePid: pid };
    }
  }

  async waitForState(configPath, expectedRunning, timeoutMs = 10000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const state = await this.status(configPath);
      if (state.running === expectedRunning || state.running === null) return state;
      if (Date.now() >= deadline) return state;
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
  }

  async reload(configPath) {
    const test = await this.test(configPath);
    if (this.controlMode !== 'systemd') {
      const state = await this.status(configPath);
      if (state.running === false) {
        throw new NcsError('NGINX_NOT_RUNNING', 'Nginx 未运行，无法平滑重载，请使用「完全重启」启动', 409, {
          pidFile: state.pidFile,
          testOutput: test.output,
        });
      }
    }
    let result;
    if (this.controlMode === 'systemd') {
      result = await this.runSystemctl('reload', { timeoutMs: 30000 });
    } else {
      result = await this.runNginx([...this.prefixArgs(), '-s', 'reload', '-c', configPath], {
        timeoutMs: 15000,
        privileged: true,
      });
    }
    if (result.exitCode !== 0) {
      throw new NcsError('NGINX_RELOAD_FAILED', 'Nginx 重载失败', 500, {
        output: result.output || `退出码 ${result.exitCode}`,
        testOutput: test.output,
      });
    }
    return {
      output: result.output,
      testOutput: test.output,
      method: this.controlMode === 'systemd' ? `systemctl reload ${this.systemdUnit}` : 'nginx -s reload',
    };
  }

  async restart(configPath) {
    const test = await this.test(configPath);
    if (this.controlMode === 'systemd') {
      const result = await this.runSystemctl('restart', { timeoutMs: 45000 });
      if (result.exitCode !== 0) {
        throw new NcsError('NGINX_RESTART_FAILED', 'Nginx 重启失败', 500, {
          output: result.output || `退出码 ${result.exitCode}`,
          testOutput: test.output,
        });
      }
      return {
        output: result.output,
        testOutput: test.output,
        method: `systemctl restart ${this.systemdUnit}`,
      };
    }

    // Signal mode: stop the running master (if any), then start with the tested config.
    const initial = await this.status(configPath);
    let stopOutput = '';
    let stopped = false;
    if (initial.running === false) {
      stopOutput = 'Nginx 未运行，跳过停止，直接启动。';
    } else {
      const stop = await this.runNginx([...this.prefixArgs(), '-s', 'stop', '-c', configPath], {
        timeoutMs: 15000,
        privileged: true,
      });
      if (stop.exitCode !== 0) {
        throw new NcsError('NGINX_STOP_FAILED', '停止 Nginx 失败，已中止重启（未执行启动）', 500, {
          output: stop.output || `退出码 ${stop.exitCode}`,
          testOutput: test.output,
        });
      }
      stopOutput = stop.output || '';
      stopped = true;
      const afterStop = await this.waitForState(configPath, false, 10000);
      if (afterStop.running !== false) {
        throw new NcsError('NGINX_STOP_FAILED', '停止 Nginx 超时，已中止重启（未执行启动）', 500, {
          output: stopOutput,
          testOutput: test.output,
        });
      }
    }

    // On Windows nginx.exe attaches to its console, so the start must not be
    // awaited to completion; on POSIX the start invocation exits by itself.
    const start = process.platform === 'win32'
      ? await startDetached(this.nginxBin, [...this.prefixArgs(), '-c', configPath])
      : await this.runNginx([...this.prefixArgs(), '-c', configPath], {
        timeoutMs: 15000,
        privileged: true,
      });
    if (start.exitCode !== 0) {
      throw new NcsError('NGINX_START_FAILED', stopped ? 'Nginx 已停止但启动失败，请立即人工检查' : 'Nginx 启动失败', 500, {
        output: start.output || `退出码 ${start.exitCode}`,
        testOutput: test.output,
      });
    }
    const afterStart = await this.waitForState(configPath, true, process.platform === 'win32' ? 10000 : 5000);
    if (afterStart.running === false) {
      throw new NcsError('NGINX_START_FAILED', '启动命令已执行，但未检测到运行中的 nginx 进程', 500, {
        output: start.output || stopOutput,
        testOutput: test.output,
        pidFile: afterStart.pidFile,
      });
    }
    return {
      output: [stopOutput, start.output].filter(Boolean).join('\n'),
      testOutput: test.output,
      stopped,
      status: afterStart,
      method: process.platform === 'win32' ? 'nginx -s stop && nginx start (detached)' : 'nginx -s stop && nginx start',
    };
  }

  async isBinaryPresent() {
    if (!this.nginxBin) return false;
    try {
      const stat = await fs.stat(this.nginxBin);
      return stat.isFile();
    } catch {
      return false;
    }
  }
}
