import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  LIMITS,
  NcsError,
  assertAllowedTextFile,
  assertInside,
  assertSafeCertificateName,
  decodeArchiveBase64,
  displayRelativePath,
  inspectCertificatePem,
  isInside,
  isPrivateKeyContent,
  normalizeRelativePath,
  parseCertificateArchive,
  resolveSafeDirectory,
  resolveSafeFile,
  resolveWorkspace,
  validateCertificateBundle,
} from '@ncs/shared';
import { BackupManager } from './backups.js';
import { atomicWriteFile, ensurePrivateDirectory, readFileLimited, sha256Hex } from './fs-utils.js';
import { NginxController } from './nginx.js';

const CONFIG_FILE_DEFAULT = 'nginx.conf';
const HEX_HASH_RE = /^[a-f0-9]{64}$/;
const CONTROL_MODES = new Set(['signal', 'systemd']);
const CERT_LAYOUTS = new Set(['flat', 'directory']);

function requireAbsolute(value, name) {
  if (typeof value !== 'string' || !path.isAbsolute(value)) {
    throw new NcsError('INVALID_ENGINE_CONFIG', `引擎配置 ${name} 必须是绝对路径`, 500);
  }
  return path.normalize(value);
}

function normalizeCertificateDirectory(value) {
  const normalized = normalizeRelativePath(value || 'ssl', { allowEmpty: false });
  if (!normalized) throw new NcsError('INVALID_ENGINE_CONFIG', '证书目录无效', 500);
  return normalized;
}

export class NginxEngine {
  constructor(rawConfig = {}) {
    if (!rawConfig.stateDir) throw new NcsError('INVALID_ENGINE_CONFIG', '缺少 stateDir', 500);
    this.stateDir = requireAbsolute(rawConfig.stateDir, 'stateDir');
    if (!Array.isArray(rawConfig.allowedRoots) || rawConfig.allowedRoots.length === 0) {
      throw new NcsError('INVALID_ENGINE_CONFIG', '至少需要配置一个允许的 Nginx 根目录', 500);
    }
    this.rawAllowedRoots = rawConfig.allowedRoots.map((root) => requireAbsolute(root, 'allowedRoots'));
    this.initialWorkspace = rawConfig.workspace ? requireAbsolute(rawConfig.workspace, 'workspace') : null;
    this.nginxBin = requireAbsolute(rawConfig.nginxBin || '/usr/sbin/nginx', 'nginxBin');
    this.nginxPrefix = rawConfig.nginxPrefix ? requireAbsolute(rawConfig.nginxPrefix, 'nginxPrefix') : null;
    this.controlMode = rawConfig.controlMode || 'signal';
    if (!CONTROL_MODES.has(this.controlMode)) {
      throw new NcsError('INVALID_ENGINE_CONFIG', 'controlMode 必须是 signal 或 systemd', 500);
    }
    this.systemdUnit = rawConfig.systemdUnit || 'nginx';
    if (!/^[A-Za-z0-9@_.-]{1,128}$/.test(this.systemdUnit)) {
      throw new NcsError('INVALID_ENGINE_CONFIG', 'systemd unit 名称无效', 500);
    }
    this.systemctlBin = requireAbsolute(rawConfig.systemctlBin || '/usr/bin/systemctl', 'systemctlBin');
    this.useSudo = Boolean(rawConfig.useSudo);
    this.sudoBin = requireAbsolute(rawConfig.sudoBin || '/usr/bin/sudo', 'sudoBin');
    this.certDir = normalizeCertificateDirectory(rawConfig.certDir);
    this.configFileRel = normalizeRelativePath(rawConfig.configFile || CONFIG_FILE_DEFAULT, { allowEmpty: false });
    if (!this.configFileRel) throw new NcsError('INVALID_ENGINE_CONFIG', '配置文件路径无效', 500);
    this.enforceTest = rawConfig.enforceTest !== false;
    this.label = typeof rawConfig.label === 'string' ? rawConfig.label.slice(0, 64) : '';
    this.onWorkspaceChange = typeof rawConfig.onWorkspaceChange === 'function' ? rawConfig.onWorkspaceChange : null;

    this.allowedRoots = [];
    this.workspace = null;
    this.workspaceError = null;
    this.configFileExists = false;
    this.backups = new BackupManager(this.stateDir);
    this.controller = new NginxController({
      nginxBin: this.nginxBin,
      nginxPrefix: this.nginxPrefix,
      controlMode: this.controlMode,
      systemctlBin: this.systemctlBin,
      systemdUnit: this.systemdUnit,
      useSudo: this.useSudo,
      sudoBin: this.sudoBin,
    });
    this.queue = Promise.resolve();
  }

  static async create(config) {
    const engine = new NginxEngine(config);
    await engine.init();
    return engine;
  }

  async init() {
    await ensurePrivateDirectory(this.stateDir, 0o700);
    this.stateDir = await fs.realpath(this.stateDir);
    await this.backups.init();

    for (const root of this.rawAllowedRoots) {
      let real;
      try {
        real = await fs.realpath(root);
        const stat = await fs.stat(real);
        if (!stat.isDirectory()) throw new Error('not a directory');
      } catch {
        throw new NcsError('INVALID_ALLOWED_ROOT', `允许的根目录不存在或不可访问：${root}`, 500);
      }
      if (!this.allowedRoots.includes(real)) this.allowedRoots.push(real);
    }

    if (this.initialWorkspace) {
      try {
        const resolved = await resolveWorkspace(this.allowedRoots, this.initialWorkspace);
        this.workspace = resolved.path;
        await this.refreshConfigFileState();
      } catch (error) {
        this.workspace = null;
        this.workspaceError = error instanceof NcsError ? error.message : '工作目录无效';
      }
    }
  }

  async refreshConfigFileState() {
    if (!this.workspace) {
      this.configFileExists = false;
      return;
    }
    try {
      const config = await resolveSafeFile(this.workspace, this.configFileRel, { mustExist: true });
      this.configFileExists = config.stat.isFile();
    } catch {
      this.configFileExists = false;
    }
  }

  async configPath() {
    this.requireWorkspace();
    try {
      const file = await resolveSafeFile(this.workspace, this.configFileRel, { mustExist: true });
      if (!file.stat.isFile()) throw new Error('not file');
      return file.absolutePath;
    } catch (error) {
      if (error instanceof NcsError) {
        throw new NcsError('NGINX_CONFIG_NOT_FOUND', `工作目录中找不到配置文件 ${this.configFileRel}`, 400);
      }
      throw new NcsError('NGINX_CONFIG_NOT_FOUND', `无法读取配置文件 ${this.configFileRel}`, 400);
    }
  }

  requireWorkspace() {
    if (this.workspace) return;
    if (this.workspaceError) {
      throw new NcsError('WORKSPACE_INVALID', `工作目录无效：${this.workspaceError}`, 409);
    }
    throw new NcsError('WORKSPACE_NOT_SET', '请先选择 Nginx 工作目录', 409);
  }

  runExclusive(fn) {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => {});
    return run;
  }

  async execute(command, payload = {}) {
    if (typeof command !== 'string' || command.length > 64) {
      throw new NcsError('UNKNOWN_COMMAND', '未知命令', 400);
    }
    if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
      throw new NcsError('INVALID_PAYLOAD', '命令参数无效', 400);
    }
    switch (command) {
      case 'ping':
        return { time: new Date().toISOString() };
      case 'system.info':
        return this.getInfo();
      case 'workspace.options':
        return this.getWorkspaceOptions();
      case 'workspace.set':
        return this.setWorkspace(payload.path);
      case 'fs.list':
        return this.listFiles(payload.path);
      case 'fs.read':
        return this.readFile(payload.path);
      case 'fs.write':
        return this.writeFile(payload);
      case 'backup.list':
        return { backups: await this.backups.list(100) };
      case 'backup.restore':
        return this.restoreBackup(payload.backupId);
      case 'nginx.test':
        return this.testNginx();
      case 'nginx.reload':
        return this.reloadNginx();
      case 'nginx.restart':
        return this.restartNginx();
      case 'cert.list':
        return this.listCertificates();
      case 'cert.upload':
        return this.uploadCertificate(payload);
      case 'cert.uploadArchive':
        return this.uploadCertificateArchive(payload);
      default:
        throw new NcsError('UNKNOWN_COMMAND', '未知命令', 400);
    }
  }

  async getInfo() {
    const nginx = await this.controller.version();
    let configFileExists = false;
    let configFile = null;
    if (this.workspace) {
      try {
        const file = await resolveSafeFile(this.workspace, this.configFileRel, { mustExist: true });
        configFileExists = file.stat.isFile();
        configFile = displayRelativePath(this.workspace, file.absolutePath);
      } catch {
        configFileExists = false;
      }
    }
    return {
      label: this.label,
      hostname: os.hostname(),
      platform: process.platform,
      serverTime: new Date().toISOString(),
      workspace: this.workspace,
      workspaceError: this.workspaceError,
      allowedRoots: [...this.allowedRoots],
      nginxBin: this.nginxBin,
      nginxVersion: nginx.version,
      nginxAvailable: nginx.available,
      nginxError: nginx.error,
      controlMode: this.controlMode,
      systemdUnit: this.controlMode === 'systemd' ? this.systemdUnit : null,
      useSudo: this.useSudo,
      certDir: this.certDir,
      configFile,
      configFileExists,
      enforceTest: this.enforceTest,
      version: '1.0.0',
    };
  }

  async getWorkspaceOptions() {
    const roots = [];
    for (const root of this.allowedRoots) {
      const workspaces = [];
      let entries = [];
      try {
        entries = await fs.readdir(root, { withFileTypes: true });
      } catch {
        entries = [];
      }
      const candidates = [{ name: '', full: root }];
      for (const entry of entries.slice(0, 300)) {
        if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
        if (entry.name.startsWith('.ncs-')) continue;
        const full = path.join(root, entry.name);
        try {
          const real = await fs.realpath(full);
          if (!isInside(root, real)) continue;
          const stat = await fs.stat(real);
          if (!stat.isDirectory()) continue;
          candidates.push({ name: entry.name, full: real });
        } catch {
          // Ignore unreadable/broken entries.
        }
      }
      for (const candidate of candidates) {
        let hasConfig = false;
        try {
          const stat = await fs.stat(path.join(candidate.full, this.configFileRel));
          hasConfig = stat.isFile();
        } catch {
          hasConfig = false;
        }
        workspaces.push({ path: candidate.full, name: candidate.name || path.basename(candidate.full), hasConfig });
      }
      roots.push({ path: root, workspaces: workspaces.slice(0, 200) });
    }
    return { current: this.workspace, certDir: this.certDir, roots };
  }

  async setWorkspace(requestedPath) {
    return this.runExclusive(async () => {
      const resolved = await resolveWorkspace(this.allowedRoots, requestedPath);
      if (this.onWorkspaceChange) await this.onWorkspaceChange(resolved.path);
      this.workspace = resolved.path;
      this.workspaceError = null;
      await this.refreshConfigFileState();
      return {
        workspace: resolved.path,
        configFileExists: this.configFileExists,
        warning: this.configFileExists
          ? null
          : `所选目录中未找到 ${this.configFileRel}，写入配置前请先创建或选择正确目录`,
      };
    });
  }

  async listFiles(relativePath = '') {
    this.requireWorkspace();
    const directory = await resolveSafeDirectory(this.workspace, relativePath);
    const entries = await fs.readdir(directory.realPath, { withFileTypes: true });
    const sorted = entries
      .filter((entry) => !entry.name.startsWith('.ncs-tmp-'))
      .sort((a, b) => {
        const aDir = a.isDirectory() ? 0 : 1;
        const bDir = b.isDirectory() ? 0 : 1;
        return aDir - bDir || a.name.localeCompare(b.name);
      });
    const truncated = sorted.length > LIMITS.maxListEntries;
    const selected = sorted.slice(0, LIMITS.maxListEntries);
    const items = await Promise.all(
      selected.map(async (entry) => {
        const abs = path.join(directory.realPath, entry.name);
        const rel = path.posix.join(directory.relativePath, entry.name);
        const item = {
          name: entry.name,
          path: rel,
          type: 'other',
          size: 0,
          mtime: null,
          symlink: entry.isSymbolicLink(),
          linkInside: null,
          editable: false,
          privateKey: entry.name.toLowerCase().endsWith('.key'),
        };
        try {
          if (entry.isSymbolicLink()) {
            const target = await fs.realpath(abs);
            item.linkInside = isInside(this.workspace, target);
            if (!item.linkInside) {
              item.type = 'symlink';
              item.path = rel;
              return item;
            }
            const targetStat = await fs.stat(target);
            item.type = targetStat.isDirectory() ? 'dir' : targetStat.isFile() ? 'file' : 'other';
            item.size = targetStat.size;
            item.mtime = targetStat.mtime.toISOString();
            const base = path.posix.basename(rel).toLowerCase();
            item.editable = targetStat.isFile() && !base.endsWith('.key');
          } else {
            const stat = await fs.stat(abs);
            item.type = stat.isDirectory() ? 'dir' : stat.isFile() ? 'file' : 'other';
            item.size = stat.size;
            item.mtime = stat.mtime.toISOString();
            item.editable = stat.isFile() && !item.privateKey;
          }
          if (item.type === 'file' && item.editable) {
            const ext = path.posix.extname(item.name).toLowerCase();
            item.editable = ['.conf', '.inc', '.txt', '.crt', '.cer', '.pem', '.csr', '.dhparam', '.template'].includes(ext) || item.name.toLowerCase() === 'nginx.conf';
          }
        } catch {
          item.type = 'broken';
        }
        return item;
      }),
    );
    return {
      path: directory.relativePath,
      entries: items,
      truncated,
    };
  }

  async readFile(relativePath) {
    this.requireWorkspace();
    const normalized = normalizeRelativePath(relativePath, { allowEmpty: false });
    assertAllowedTextFile(normalized);
    const file = await resolveSafeFile(this.workspace, normalized, { mustExist: true });
    let buffer;
    try {
      buffer = await readFileLimited(file.absolutePath, LIMITS.maxFileBytes);
    } catch (error) {
      if (error?.code === 'FILE_TOO_LARGE') throw new NcsError('FILE_TOO_LARGE', '文件超过允许的大小', 400);
      throw new NcsError('FILE_READ_FAILED', '无法读取文件', 500);
    }
    if (buffer.includes(0)) throw new NcsError('BINARY_FILE', '不允许通过编辑器读取二进制文件', 400);
    let content;
    try {
      content = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
    } catch {
      throw new NcsError('FILE_NOT_TEXT', '文件不是有效的 UTF-8 文本', 400);
    }
    if (isPrivateKeyContent(content)) {
      throw new NcsError('PRIVATE_KEY_READ_DENIED', '出于安全考虑，禁止通过通用接口读取私钥内容', 403);
    }
    return {
      path: displayRelativePath(this.workspace, file.absolutePath),
      content,
      hash: sha256Hex(buffer),
      size: buffer.length,
      mode: (file.stat.mode & 0o777).toString(8).padStart(4, '0'),
      mtime: file.stat.mtime.toISOString(),
      symlink: file.wasSymlink,
    };
  }

  async writeFile(payload) {
    const normalized = normalizeRelativePath(payload.path, { allowEmpty: false });
    assertAllowedTextFile(normalized);
    if (typeof payload.content !== 'string') throw new NcsError('INVALID_CONTENT', '文件内容无效', 400);
    const contentBuffer = Buffer.from(payload.content, 'utf8');
    if (contentBuffer.length > LIMITS.maxFileBytes) throw new NcsError('FILE_TOO_LARGE', '文件超过允许的大小', 400);
    if (contentBuffer.includes(0)) throw new NcsError('INVALID_CONTENT', '文件内容包含空字节', 400);
    if (isPrivateKeyContent(payload.content)) {
      throw new NcsError('PRIVATE_KEY_WRITE_DENIED', '请通过 SSL 证书上传功能管理私钥', 403);
    }
    const baseHash = payload.baseHash;
    if (baseHash !== undefined && baseHash !== null && (typeof baseHash !== 'string' || !HEX_HASH_RE.test(baseHash))) {
      throw new NcsError('INVALID_BASE_HASH', 'baseHash 格式无效', 400);
    }

    return this.runExclusive(async () => {
      this.requireWorkspace();
      const target = await resolveSafeFile(this.workspace, normalized, { forWrite: true });
      let oldBuffer = null;
      let backupId = null;
      let oldMode = 0o644;
      let oldStat = null;
      if (target.existed) {
        oldBuffer = await readFileLimited(target.absolutePath, LIMITS.maxFileBytes).catch(() => {
          throw new NcsError('FILE_READ_FAILED', '无法读取当前文件以进行安全覆盖', 500);
        });
        if (isPrivateKeyContent(oldBuffer.toString('utf8'))) {
          throw new NcsError('PRIVATE_KEY_WRITE_DENIED', '禁止通过通用接口修改私钥文件', 403);
        }
        const currentHash = sha256Hex(oldBuffer);
        if (baseHash !== currentHash) {
          throw new NcsError('FILE_CONFLICT', '文件已被其他操作修改，请重新加载后再保存', 409, {
            currentHash,
          });
        }
        oldStat = target.stat;
        oldMode = oldStat.mode & 0o777;
      } else if (baseHash) {
        throw new NcsError('FILE_CONFLICT', '文件不存在或已被删除', 409);
      }

      if (oldBuffer && oldBuffer.equals(contentBuffer)) {
        return {
          path: displayRelativePath(this.workspace, target.absolutePath),
          hash: sha256Hex(contentBuffer),
          size: contentBuffer.length,
          unchanged: true,
          backupId: null,
          tested: false,
        };
      }

      if (oldBuffer) {
        backupId = (
          await this.backups.create({
            workspace: this.workspace,
            relPath: target.relativePath,
            absolutePath: target.absolutePath,
            content: oldBuffer,
            mode: oldMode,
            reason: 'write',
          })
        ).id;
      }

      try {
        await atomicWriteFile(target.absolutePath, contentBuffer, {
          mode: oldMode,
          uid: oldStat?.uid,
          gid: oldStat?.gid,
        });
      } catch {
        throw new NcsError('FILE_WRITE_FAILED', '写入文件失败', 500);
      }

      let testResult = null;
      if (this.enforceTest) {
        try {
          testResult = await this.controller.test(await this.configPath());
        } catch (error) {
          await this.rollbackFile(target, oldBuffer, oldMode, oldStat);
          throw new NcsError('NGINX_TEST_FAILED', '配置检测失败，已自动回滚', 400, {
            output: error?.details?.output || error?.message || 'nginx -t 失败',
            rolledBack: true,
            backupId,
            path: displayRelativePath(this.workspace, target.absolutePath),
          });
        }
      }

      return {
        path: displayRelativePath(this.workspace, target.absolutePath),
        hash: sha256Hex(contentBuffer),
        size: contentBuffer.length,
        unchanged: false,
        backupId,
        tested: Boolean(testResult),
        testOutput: testResult?.output || null,
      };
    });
  }

  async rollbackFile(target, oldBuffer, oldMode, oldStat) {
    try {
      if (oldBuffer) {
        await atomicWriteFile(target.absolutePath, oldBuffer, { mode: oldMode, uid: oldStat?.uid, gid: oldStat?.gid });
      } else {
        await fs.unlink(target.absolutePath);
      }
    } catch {
      // The original error is more useful; log via caller audit. A backup remains.
    }
  }

  async testNginx() {
    this.requireWorkspace();
    const configPath = await this.configPath();
    const result = await this.controller.test(configPath);
    return { ...result, configFile: displayRelativePath(this.workspace, configPath) };
  }

  async reloadNginx() {
    this.requireWorkspace();
    return this.runExclusive(async () => {
      const configPath = await this.configPath();
      const result = await this.controller.reload(configPath);
      return { ...result, configFile: displayRelativePath(this.workspace, configPath) };
    });
  }

  async restartNginx() {
    this.requireWorkspace();
    return this.runExclusive(async () => {
      const configPath = await this.configPath();
      const result = await this.controller.restart(configPath);
      return { ...result, configFile: displayRelativePath(this.workspace, configPath) };
    });
  }

  async ensureDirectoryInside(relativePath) {
    this.requireWorkspace();
    const normalized = normalizeRelativePath(relativePath, { allowEmpty: false });
    let current = this.workspace;
    for (const segment of normalized.split('/')) {
      const next = path.join(current, segment);
      assertInside(this.workspace, next);
      let lstat = null;
      try {
        lstat = await fs.lstat(next);
      } catch (error) {
        if (error?.code !== 'ENOENT') throw new NcsError('CERT_DIR_FAILED', '无法检查证书目录', 500);
      }
      if (!lstat) {
        await fs.mkdir(next, { mode: 0o755 });
        const real = await fs.realpath(next);
        assertInside(this.workspace, real);
        current = real;
        continue;
      }
      if (lstat.isSymbolicLink()) {
        let real;
        try {
          real = await fs.realpath(next);
        } catch {
          throw new NcsError('CERT_DIR_FAILED', '证书目录符号链接无效', 400);
        }
        assertInside(this.workspace, real);
        const stat = await fs.stat(real);
        if (!stat.isDirectory()) throw new NcsError('CERT_DIR_FAILED', '证书目录不是目录', 400);
        current = real;
      } else {
        if (!lstat.isDirectory()) throw new NcsError('CERT_DIR_FAILED', '证书目录路径中存在非目录文件', 400);
        const real = await fs.realpath(next);
        assertInside(this.workspace, real);
        current = real;
      }
    }
    return { realPath: current, relativePath: normalized };
  }

  async listCertificates() {
    this.requireWorkspace();
    let certDir;
    try {
      certDir = await this.ensureDirectoryInside(this.certDir);
    } catch (error) {
      if (error?.code === 'CERT_DIR_FAILED') {
        return { certDir: this.certDir, certificates: [], errors: [{ file: this.certDir, error: error.message }] };
      }
      throw error;
    }
    let entries = [];
    try {
      entries = await fs.readdir(certDir.realPath, { withFileTypes: true });
    } catch {
      return { certDir: this.certDir, certificates: [], errors: [] };
    }

    const certificates = [];
    const errors = [];

    const readCertificate = async (relativePath, name, extra) => {
      const file = await resolveSafeFile(certDir.realPath, relativePath, { mustExist: true });
      const buffer = await readFileLimited(file.absolutePath, LIMITS.maxCertificateBytes);
      if (buffer.includes(0)) throw new Error('二进制文件');
      const text = buffer.toString('utf8');
      if (text.trim().length === 0) return null;
      if (isPrivateKeyContent(text)) throw new NcsError('PRIVATE_KEY_IN_CERT', '包含私钥，已跳过', 400);
      const inspected = inspectCertificatePem(text, { allowMultiple: true });
      return {
        file: displayRelativePath(this.workspace, file.absolutePath),
        name,
        subject: inspected.subject,
        issuer: inspected.issuer,
        san: inspected.san,
        validFrom: inspected.validFrom,
        validTo: inspected.validTo,
        daysRemaining: inspected.daysRemaining,
        expired: inspected.expired,
        fingerprint256: inspected.fingerprint256,
        chainCount: inspected.certificateCount - 1,
        ...extra,
      };
    };

    const fileExists = async (relativePath) => {
      try {
        const file = await resolveSafeFile(certDir.realPath, relativePath);
        return file.existed;
      } catch {
        return false;
      }
    };

    /**
     * Panel-style layouts keep one certificate per subdirectory, e.g.
     * ssl/<domain>/fullchain.pem + ssl/<domain>/privkey.pem. Read the best
     * certificate candidate inside the directory and report whether a private
     * key lives next to it (key contents are never read).
     */
    const readDirectoryCertificate = async (dirName) => {
      let children = [];
      try {
        children = await fs.readdir(path.join(certDir.realPath, dirName), { withFileTypes: true });
      } catch {
        return;
      }
      const files = children
        .filter((child) => child.isFile() && !child.name.startsWith('.'))
        .map((child) => child.name);
      if (files.length === 0) return;

      const byLower = new Map(files.map((file) => [file.toLowerCase(), file]));
      const keyPresent = files.some((file) => {
        const lower = file.toLowerCase();
        return lower.endsWith('.key') || lower === 'privkey.pem' || lower === 'private.pem';
      });

      const candidates = [];
      for (const preferred of ['fullchain.pem', 'cert.pem', 'server.crt', 'server.pem']) {
        const actual = byLower.get(preferred);
        if (actual) candidates.push(actual);
      }
      for (const file of [...files].sort((a, b) => a.localeCompare(b))) {
        const lower = file.toLowerCase();
        if (!['.crt', '.cer', '.pem'].includes(path.extname(lower))) continue;
        if (['privkey.pem', 'private.pem', 'key.pem'].includes(lower)) continue;
        if (!candidates.includes(file)) candidates.push(file);
      }

      let lastError = null;
      for (const candidate of candidates.slice(0, 5)) {
        try {
          const certificate = await readCertificate(`${dirName}/${candidate}`, dirName, {
            directory: true,
            keyPresent,
          });
          if (certificate) {
            certificates.push(certificate);
            return;
          }
        } catch (error) {
          lastError = error;
        }
      }
      if (lastError) {
        errors.push({
          file: path.posix.join(this.certDir, dirName),
          error: lastError instanceof NcsError ? lastError.message : '证书解析失败',
        });
      }
    };

    let directoryCount = 0;
    for (const entry of entries.slice(0, 300)) {
      if (entry.name.startsWith('.')) continue;
      if (entry.isDirectory()) {
        if (directoryCount >= 100) continue;
        directoryCount += 1;
        await readDirectoryCertificate(entry.name);
        continue;
      }
      const lower = entry.name.toLowerCase();
      if (!['.crt', '.cer', '.pem'].includes(path.extname(lower))) continue;
      if (lower.endsWith('.key')) continue;
      try {
        const base = entry.name.replace(/\.(crt|cer|pem)$/i, '').replace(/\.chain$/i, '');
        const certificate = await readCertificate(entry.name, entry.name, {
          directory: false,
          keyPresent: await fileExists(`${base}.key`),
        });
        if (certificate) certificates.push(certificate);
      } catch (error) {
        errors.push({
          file: path.posix.join(certDir.relativePath, entry.name),
          error: error instanceof NcsError ? error.message : '证书解析失败',
        });
      }
    }

    certificates.sort((a, b) => String(a.validTo).localeCompare(String(b.validTo)));
    return { certDir: this.certDir, certificates, errors };
  }

  async uploadCertificate(payload) {
    const name = assertSafeCertificateName(payload.name);
    const layout = payload.layout ?? 'flat';
    if (!CERT_LAYOUTS.has(layout)) {
      throw new NcsError('INVALID_CERT_LAYOUT', '证书存放方式无效', 400);
    }
    const bundle = validateCertificateBundle({
      certPem: payload.certPem,
      chainPem: payload.chainPem || '',
      keyPem: payload.keyPem,
    });

    return this.runExclusive(async () => {
      this.requireWorkspace();
      const certDirectory = await this.ensureDirectoryInside(this.certDir);
      const targets = layout === 'directory'
        ? [
            {
              relPath: path.posix.join(this.certDir, name, 'fullchain.pem'),
              content: Buffer.from(`${bundle.certPem}${bundle.chainPem}`, 'utf8'),
              mode: 0o644,
              kind: 'certificate',
            },
            {
              relPath: path.posix.join(this.certDir, name, 'privkey.pem'),
              content: Buffer.from(bundle.keyPem, 'utf8'),
              mode: 0o600,
              kind: 'privateKey',
            },
          ]
        : [
            {
              relPath: path.posix.join(this.certDir, `${name}.crt`),
              content: Buffer.from(bundle.certPem, 'utf8'),
              mode: 0o644,
              kind: 'certificate',
            },
            {
              relPath: path.posix.join(this.certDir, `${name}.chain.pem`),
              content: Buffer.from(bundle.chainPem, 'utf8'),
              mode: 0o644,
              kind: 'chain',
            },
            {
              relPath: path.posix.join(this.certDir, `${name}.key`),
              content: Buffer.from(bundle.keyPem, 'utf8'),
              mode: 0o600,
              kind: 'privateKey',
            },
          ];

      if (layout === 'directory') {
        await this.ensureDirectoryInside(path.posix.join(this.certDir, name));
      }

      const states = [];
      for (const target of targets) {
        const file = await resolveSafeFile(this.workspace, target.relPath, { forWrite: true });
        if (!isInside(certDirectory.realPath, file.absolutePath)) {
          throw new NcsError('PATH_ESCAPE', '证书目标路径超出证书目录', 403);
        }
        const state = {
          ...target,
          absolutePath: file.absolutePath,
          existed: file.existed,
          oldBuffer: null,
          oldStat: file.stat,
          backupId: null,
          written: false,
        };
        if (file.existed) {
          state.oldBuffer = await readFileLimited(file.absolutePath, LIMITS.maxCertificateBytes);
          state.backupId = (
            await this.backups.create({
              workspace: this.workspace,
              relPath: target.relPath,
              absolutePath: file.absolutePath,
              content: state.oldBuffer,
              mode: file.stat.mode & 0o777,
              reason: 'certificate',
            })
          ).id;
        }
        states.push(state);
      }

      try {
        for (const state of states) {
          await atomicWriteFile(state.absolutePath, state.content, {
            mode: state.mode,
            uid: state.oldStat?.uid,
            gid: state.oldStat?.gid,
          });
          state.written = true;
        }
      } catch {
        await this.rollbackUpload(states);
        throw new NcsError('CERT_WRITE_FAILED', '证书写入失败，已回滚', 500);
      }

      let testResult = null;
      if (this.enforceTest) {
        try {
          testResult = await this.controller.test(await this.configPath());
        } catch (error) {
          await this.rollbackUpload(states);
          throw new NcsError('NGINX_TEST_FAILED', '证书已写入但 Nginx 配置检测失败，已回滚', 400, {
            output: error?.details?.output || error?.message || 'nginx -t 失败',
            rolledBack: true,
          });
        }
      }

      return {
        name,
        layout,
        files: states.map((state) => ({
          path: state.relPath,
          kind: state.kind,
          backupId: state.backupId,
          mode: state.mode.toString(8).padStart(4, '0'),
        })),
        certificate: bundle.certificate,
        tested: Boolean(testResult),
        testOutput: testResult?.output || null,
      };
    });
  }

  async uploadCertificateArchive(payload) {
    const name = assertSafeCertificateName(payload.name);
    const archive = parseCertificateArchive(decodeArchiveBase64(payload.archiveBase64));
    const result = await this.uploadCertificate({
      name,
      certPem: archive.certPem,
      chainPem: archive.chainPem,
      keyPem: archive.keyPem,
      layout: payload.layout,
    });
    return {
      ...result,
      archive: {
        format: archive.format,
        entriesScanned: archive.entriesScanned,
        files: archive.files,
        ignoredEntries: archive.ignoredEntries,
      },
    };
  }

  async rollbackUpload(states) {
    for (const state of states) {
      if (!state.written) continue;
      try {
        if (state.oldBuffer) {
          await atomicWriteFile(state.absolutePath, state.oldBuffer, {
            mode: state.oldStat?.mode & 0o777,
            uid: state.oldStat?.uid,
            gid: state.oldStat?.gid,
          });
        } else {
          await fs.unlink(state.absolutePath).catch(() => {});
        }
      } catch {
        // Best-effort rollback; backups remain for manual recovery.
      }
    }
  }

  async restoreBackup(backupId) {
    return this.runExclusive(async () => {
      this.requireWorkspace();
      const { meta, content } = await this.backups.get(backupId);
      if (meta.workspace !== this.workspace) {
        throw new NcsError('BACKUP_WORKSPACE_MISMATCH', '备份属于其他工作目录，拒绝恢复', 409);
      }
      const normalized = normalizeRelativePath(meta.targetRel, { allowEmpty: false });
      const target = await resolveSafeFile(this.workspace, normalized, { forWrite: true });
      const mode = target.relativePath.toLowerCase().endsWith('.key') ? 0o600 : meta.mode || 0o644;
      let current = null;
      let oldStat = null;
      let preRestoreBackupId = null;
      if (target.existed) {
        current = await readFileLimited(target.absolutePath, LIMITS.maxFileBytes);
        oldStat = target.stat;
        preRestoreBackupId = (
          await this.backups.create({
            workspace: this.workspace,
            relPath: target.relativePath,
            absolutePath: target.absolutePath,
            content: current,
            mode: oldStat.mode & 0o777,
            reason: 'restore',
          })
        ).id;
      }
      try {
        await atomicWriteFile(target.absolutePath, content, { mode, uid: oldStat?.uid, gid: oldStat?.gid });
      } catch {
        throw new NcsError('RESTORE_FAILED', '恢复备份失败', 500);
      }
      let testResult = null;
      if (this.enforceTest) {
        try {
          testResult = await this.controller.test(await this.configPath());
        } catch (error) {
          await this.rollbackFile(target, current, oldStat?.mode & 0o777, oldStat);
          throw new NcsError('NGINX_TEST_FAILED', '恢复后配置检测失败，已回滚', 400, {
            output: error?.details?.output || error?.message || 'nginx -t 失败',
            rolledBack: true,
            preRestoreBackupId,
          });
        }
      }
      return {
        restored: backupId,
        path: displayRelativePath(this.workspace, target.absolutePath),
        preRestoreBackupId,
        tested: Boolean(testResult),
        testOutput: testResult?.output || null,
      };
    });
  }
}
