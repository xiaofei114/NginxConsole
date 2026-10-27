# Nginx Console — 系统设计

> 多服务器 Nginx 配置与 TLS 证书集中管理系统。  
> 主服务器提供公网 Web 控制台，子服务器运行只主动出站的 Agent。  
> 所有操作均为**固定命令白名单**，不提供任意 Shell 执行能力。

---

## 1. 目标与非目标

### 目标

- 一个公网页面集中管理多台服务器的 Nginx。
- 支持浏览/编辑 Nginx 配置文件、执行配置检测、平滑重载、完全重启。
- 支持上传/替换证书链和私钥，写入前校验证书与私钥是否匹配，替换前自动备份。
- 主服务器自身也作为「本地节点」，与子服务器使用同一套核心引擎。
- 主服务器和每台子服务器都可以在**允许的根目录**内选择 Nginx 工作目录。
- 关键写操作具备：乐观并发控制、自动备份、配置检测失败自动回滚、审计日志。
- 优先保证安全：默认不监听公网、子服务器零入站端口、双向签名、路径沙箱、最小依赖。

### 非目标

- 不是通用的 Linux 运维平台，不执行任意命令、不做包管理、不做文件删除。
- 不替代堡垒机/VPN；主服务器被完全攻陷时，已连接的 Agent 可被控制。
- 不管理 Nginx 之外的 systemd 服务。
- 不提供多租户/细粒度 RBAC（当前为单管理员模型）。如需多人使用，应在设计上扩展角色与审批流。

> 安全没有“绝对”。本项目按纵深防御设计，但最终安全性还取决于主机加固、TLS 终止、操作系统权限与备份策略。部署清单见第 9 节。

---

## 2. 总体架构

```text
                     公网 / TLS (443)
                           │
                  ┌────────▼─────────┐
                  │  反向代理 (TLS)   │  推荐 nginx/Caddy，仅反代 127.0.0.1:8787
                  └────────┬─────────┘
                           │ HTTP (loopback)
┌──────────────────────────▼───────────────────────────────┐
│ 主服务器 (Main)                                           │
│  Vue3 SPA  ── /api ──►  Node API / Session / CSRF / Audit │
│                           │                              │
│                    Agent Hub (WSS /agent/ws)             │
│                           │ 签名命令（Ed25519）           │
│                    本地 Nginx 引擎 ◄── 本地节点            │
└───────────────────────────┬──────────────────────────────┘
                            │ 子服务器主动建立出站 WSS 连接
          ┌─────────────────┼─────────────────┐
          ▼                 ▼                 ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Agent (子服务器) │ │ Agent (子服务器) │ │ Agent (子服务器) │
│  WS Client      │ │  WS Client      │ │  WS Client      │
│  Core Engine    │ │  Core Engine    │ │  Core Engine    │
│  /etc/nginx     │ │  /opt/nginx     │ │  /data/nginx    │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

关键点：

1. **子服务器不开放任何管理端口**。Agent 仅主动出站连接主服务器，天然绕过 NAT/防火墙。
2. **主服务器默认只绑定 `127.0.0.1`**，由反向代理暴露公网并终止 TLS。
3. 主服务器与 Agent 之间的每条消息都用 Ed25519 签名并带时间戳/随机数，防重放、防中间人伪造（即使 TLS 在代理处被终止）。
4. 主服务器内置的「本地节点」和子服务器共用 `@ncs/core` 引擎，行为一致。

---

## 3. 模块划分

| 包 | 职责 |
| --- | --- |
| `packages/shared` | 协议签名/验签、标准错误、路径沙箱、证书校验、结构化日志、输入限制 |
| `packages/core` | Nginx 引擎：文件读写、备份/回滚、证书写入、`nginx -t/-s`、工作目录选择 |
| `packages/agent` | 子服务器 Agent：身份密钥、注册、出站 WSS 客户端、命令处理 |
| `packages/main` | 主服务器：API、会话/CSRF、TOTP、Agent Hub、本地引擎、审计 |
| `web` | Vue3 + Vite 控制台 |

---

## 4. 信任边界与威胁模型

| 边界 | 威胁 | 控制措施 |
| --- | --- | --- |
| 浏览器 → 主服务器 | 暴力破解、会话劫持、CSRF、XSS、DNS rebinding | scrypt、TOTP、HttpOnly/SameSite Cookie、CSRF Token + Origin 校验、严格 CSP、Host 白名单、登录限速/锁定 |
| 公网 → 主服务器 | 未授权 API 访问、DoS | 默认 loopback、全 API 鉴权、请求体/并发/速率限制、无 CORS、安全响应头 |
| 主服务器 ↔ Agent | 伪造 Agent、重放命令、代理层窃听后注入 | 每 Agent 独立 Ed25519 公钥、一次性注册令牌、双向签名、±60s 时间窗、Nonce 重放缓存 |
| 控制台 → 文件系统 | 目录穿越、符号链接逃逸、覆盖系统文件 | 允许根目录白名单 + realpath 校验 + 相对路径规范化；写临时文件后原子 rename；拒绝写入 `.key`/私钥内容 |
| 配置写入 | 写坏配置导致 Nginx 不可用 | 写前备份、`nginx -t` 失败自动回滚、重载/重启前强制检测、乐观锁防并发覆盖 |
| 证书替换 | 证书与私钥不匹配、私钥泄露、服务中断 | `crypto.X509Certificate` 校验、公私钥 DER 比对、有效期检查、私钥 0600 原子写入、备份回滚 |
| 子服务器 Agent | 被主服务器上任意命令利用 | 仅接受类型化命令白名单；无 Shell；参数数组调用；路径沙箱；命令超时 |
| 数据/日志 | 密钥、口令、Token 泄漏 | 口令 scrypt 哈希、Token 仅存哈希、TOTP 密钥 AES-GCM 加密、私钥不返回 API、日志脱敏、数据目录 0700 |

残余风险：若攻击者拿到主服务器管理员会话或主服务器私钥，即可控制所有在线 Agent；若 Agent 运行账号对工作目录有写权限，本地提权不在本系统防护范围内。

---

## 5. 安全设计细节

### 5.1 认证与会话

- 单管理员账号（可扩展），口令使用 `scrypt`（N=2^15, r=8, p=1，随机 16B salt，32B 输出）存储。
- 口令最少 12 字符；未知用户也执行一次 dummy scrypt，降低时序侧信道。
- 登录失败按「IP + 用户名」限速，并在用户记录上累计失败次数：5 次后锁定 15 分钟，指数增长，最长 24 小时。
- 可选 TOTP（SHA-1 / 6 位 / 30 秒 / ±1 窗口），启用时生成 10 个一次性恢复码（仅存 HMAC-SHA256 哈希）。TOTP 密钥用 AES-256-GCM 加密存储，主密钥为 `data/master.key`（0600）。
- 会话令牌 32B 随机值，仅存 SHA-256；Cookie `HttpOnly + SameSite=Strict + Path=/`，HTTPS 下加 `Secure`；绝对过期 + 空闲过期；登录/改密/启用 TOTP 时轮换并使旧会话失效。
- 所有非 GET API 需要 `X-CSRF-Token`（与会话绑定）且校验 `Origin`。
- Host 头必须命中白名单，防 DNS rebinding；不发送 CORS 头。
- 登录接口同时校验 Origin，限制请求体大小与速率。

### 5.2 Transmission

- 生产必须使用 HTTPS。主服务器可配置 `NCS_TLS_CERT/NCS_TLS_KEY` 直接终止 TLS，或运行在反向代理之后（默认监听 loopback）。
- 若监听非 loopback 且未启用 TLS/可信代理，生产模式拒绝启动。
- 安全响应头：HSTS（HTTPS 时）、CSP（`script-src 'self'`、`frame-ancestors 'none'` 等）、`X-Content-Type-Options`、`Referrer-Policy`、`Permissions-Policy`、`X-Frame-Options: DENY`。
- Agent 强制 `https/wss`；仅在显式 `--insecure-http` 且非生产时允许明文（本地开发）。

### 5.3 主服务器 ↔ Agent 协议

- Agent 首次注册：管理员在 UI 创建 Agent，得到一次性注册令牌（32B，仅存 SHA-256，默认 30 分钟有效）。Agent 生成 Ed25519 密钥对，把公钥提交给主服务器，主服务器返回自己的公钥；Agent 固定（pin）主服务器公钥。
- Agent 后续连接 `/agent/ws`，在 Upgrade 请求头携带 `X-NCS-Auth`（base64url JSON 信封），内容包含 `agentId/ts/nonce/sig`。主服务器查库验签，并校验时间窗与 Nonce。
- 主服务器升级成功后发送签名的 `main-hello`，Agent 用固定公钥验签。
- 主服务器 → Agent 的每条命令、Agent → 主服务器的每条响应/事件都带 `ts/nonce` 和 Ed25519 签名，双方各自维护 Nonce 重放缓存。
- WebSocket 仅用 Ping/Pong 做存活检测；控制消息必须签名。消息大小上限 2 MiB，单 Agent 并发命令数 ≤ 16，命令超时 30–60 秒。
- Agent 断线指数退避重连；同一 Agent 新连接会关闭旧连接。撤销 Agent 会立即断开。

签名格式：`Ed25519( "nginx-console-envelope-v1\n" + canonicalJSON(envelope 去掉 sig) )`。canonicalJSON 对对象键排序，确保跨语言可验证。

### 5.4 文件系统沙箱

- Agent 启动时配置 `allowedRoots`（绝对路径，经 `realpath` 规范化）。UI 只能在允许根内选择工作目录。
- 工作目录本身必须位于允许根内，且包含 `nginx.conf`（选择时提示，不强制）。
- 所有 API 只传相对路径；规范化规则：仅 `/` 分隔、拒绝 `..`、绝对路径、盘符、UNC、NUL、控制字符、超长段。
- 每次读写/list 前对父目录和目标做 `realpath`，用 `path.relative` 确认仍在根内；符号链接指向根外一律拒绝。
- 允许 Nginx 常见的 `sites-enabled -> sites-available` 符号链接：读写会解析到根内的真实目标，保持符号链接不被破坏。
- 写文件使用同目录临时文件 + `fsync` + `rename` 原子替换，尽量保留原文件权限/属主；不通过 Shell。
- 默认仅允许 `.conf/.inc/.txt/.crt/.pem/.cer/.csr/.dhparam` 等文本文件（`nginx.conf` 特例）。二进制/超大文件拒绝。
- **私钥只写不读**：`.key` 与含 `PRIVATE KEY` 的文件禁止通过通用文件 API 读取/编辑；证书上传走专用接口。
- 工作目录之外禁止任何写入；备份保存在 Agent 状态目录（0700），不污染 Nginx 目录。

### 5.5 配置变更流程

1. 客户端提交 `path + content + baseHash`；`baseHash` 与当前文件 SHA-256 不一致则 `409`，防止静默覆盖。
2. 引擎把旧文件复制到备份目录（0600，保留最近 100 份）。
3. 原子写入新内容（默认 0644，保留原权限）。
4. 执行 `nginx -t -c <工作目录>/nginx.conf`（可选 `-p prefix`，参数数组，无 Shell，15s 超时）。
5. 检测失败：立即用备份内容原子回写，返回 `NGINX_TEST_FAILED` 与脱敏后的 stderr。
6. 重载/重启前再次执行 `nginx -t`，失败直接拒绝；成功后 `nginx -s reload` 或 systemd 重载/重启。
7. 每次变更写审计（操作者、IP、服务器、路径、hash、结果），不记录文件内容/证书/私钥。

> 开发模式可通过 `NCS_DEV_UNSAFE_SKIP_NGINX_TEST=1` 跳过检测，仅在 `NODE_ENV !== production` 生效，生产环境会忽略并打印警告。

### 5.6 证书替换

- 上传内容大小上限 256 KiB；仅接受 PEM。
- 叶证书：`crypto.X509Certificate` 解析，拒绝过期/尚未生效；RSA ≥ 2048 或 EC ≥ P-256。
- 私钥：`createPrivateKey` 解析，拒绝加密私钥（避免把口令带进系统）。
- 用导出 SPKI DER 比较证书公钥与私钥公钥，不匹配直接拒绝。
- 链证书逐张解析并尝试 issuer 验签；链结构无效拒绝（不要求根证书来自系统信任库）。
- 压缩包导入（ZIP / TAR / TAR.GZ / TGZ；TAR 需 USTAR 格式）：
  - 仅内存解析，条目路径不参与落盘；拒绝 `..`/绝对路径/反斜杠/NUL、重复条目、符号链接/硬链接、加密包、分卷与 ZIP64。
  - 限制压缩包 512 KiB、条目 64 个、单文件 256 KiB、解压总量 512 KiB、gzip 解压上限 8 MiB；ZIP 校验 CRC，TAR 校验 checksum。
  - 提取 PEM 块后要求恰好一个私钥和一个与其匹配的叶证书；多候选拒绝并返回候选文件名。链证书按 issuer 验签自动排序。
  - 其余文件一律忽略，不写入工作目录。
- 写入 `<workspace>/<certDir>`（默认 `ssl`，须在工作目录内），文件名只允许 `[A-Za-z0-9._-]`，私钥文件 0600，证书 0644。
- 先备份所有被替换文件，全部写临时文件后再 rename；任一失败 / `nginx -t` 失败则回滚全部。
- API 只返回证书元数据（Subject/SAN/有效期/指纹），永不返回私钥内容。

### 5.7 Nginx 进程控制

- `nginxBin` 必须为绝对路径（或固定 PATH 中解析出的路径），以 `spawn(bin, args, {shell:false})` 调用。
- 支持两种控制模式：
  - `signal`：`nginx -t` → `nginx -s reload` / `nginx -s stop` + 启动；需要 Agent 有发信号权限。
  - `systemd`：`systemctl reload|restart <unit>`，unit 名严格校验；需要受限 sudo。
- 可选 `useSudo`，通过 `sudo -n` 执行固定参数；sudoers 需按实际路径精确授权（README 给出模板）。
- 重启为高风险操作，API 要求 `confirm: true`；signal 模式重启在停止后启动失败会明确报告，需人工介入（不做自动回滚，避免掩盖故障）。
- 所有命令设置超时、输出上限 64 KiB，错误输出回传前去除控制字符。
- 平台差异：
  - POSIX：`signal` 模式启动由 `spawn` 等待退出；`systemd` 模式调用 `systemctl reload|restart`。
  - Windows：仅支持 `signal` 模式；由于 `nginx.exe` 会附着控制台，启动采用 `detached + stdio:ignore + unref`，2 秒内以非零码退出才判定失败，避免误报超时。
  - Windows 上 `useSudo` 无意义，`systemd` 模式不可用。

### 5.8 平台兼容与混合部署

- 主服务器、Agent 均可在 Windows/Linux 运行；通信只使用 JSON 与 PEM 文本，与平台无关。
- 每个节点独立配置 `allowedRoots`、`workspace`、`nginxBin`、`controlMode`，因此同一控制台可同时管理 Windows 与 Linux 节点。
- 相对路径统一使用 POSIX 风格（拒绝反斜杠），绝对路径由各平台 `path` 解析；展示层统一转成 `/`。
- Windows 不具备 POSIX 权限位：
  - `0600/0700` 在 Windows 上跳过校验与强制，安全依赖 NTFS ACL（部署文档给出 `icacls` 示例）。
  - agent 配置/私钥、主服务器 master key 均需手工 ACL 收紧后投产。
- Windows Agent 注册必须显式提供 `--allowed-root` 与 `--nginx-bin`，不回退到 `/etc/nginx`、`/usr/sbin/nginx`。
- 跨平台混合部署要求各节点时间同步（签名窗口 ±60 秒）。

### 5.9 审计与日志

- **审计**（业务事实，不可篡改用途）：JSONL 追加写（0600），字段：时间、用户、IP、动作、服务器、目标、结果、摘要；支持 UI 查询最近记录；文件超过 10 MiB 轮转。
- **应用日志**（运行诊断）：`@ncs/shared` 的 `createLogger` 统一输出，主服务器与 Agent 格式一致。
  - 每行一条记录，`json` 模式为标准 JSON Lines：`ts / level / app / component / msg` + 上下文字段；异常放在 `err`（name/message/code/status/stack）。
  - 级别 `error|warn|info|debug`，由 `NCS_LOG_LEVEL` 控制，默认 `info`；`error/warn` 走 stderr，其余走 stdout。
  - 非 TTY 默认 JSON，终端默认可读单行；由 `NCS_LOG_FORMAT` 覆盖。
  - 按字段名自动脱敏（password/token/secret/authorization/cookie/privateKey/archiveBase64 等），并对深度、数组长度、字符串长度设上限；日志逻辑自身异常被吞掉，不影响请求。
  - 唯一例外是首次启动生成的管理员初始口令：显式关闭脱敏且只输出一次。
  - 访问日志只记录方法、路径（去除查询串）、状态、耗时、来源 IP、requestId；不记录请求体与查询串。
- 应用日志不写本地文件，统一交给 pm2 / journald / 容器日志驱动采集；审计与应用日志分开保留，审计不随日志轮转删除。

### 5.10 进程管理

- 使用 pm2 托管（仓库根 `ecosystem.config.cjs`）：`ncs-main` 与 `ncs-agent` 两个 fork 单实例应用，不使用 cluster（本系统为单管理员 + 本地状态文件）。
- 主服务器通过 `node --env-file-if-exists=.env` 读取环境配置；pm2 的 `env` 不注入业务变量，避免覆盖 `.env`。
- `SIGTERM`/`SIGINT` 触发优雅关闭：停止心跳与 Agent 连接、关闭 HTTP 服务后退出；pm2 `kill_timeout` 为 8 秒。异常退出由 pm2 指数退避重启（`max_restarts` 上限防止崩溃循环）。
- 建议 `pm2-logrotate` 保留 14 天；`pm2 startup` + `pm2 save` 实现开机自启。
- pm2 与 systemd 二选一，禁止同时托管同一进程。

### 5.11 依赖与供应链

- 运行时依赖仅 `express`、`ws`；其余使用 Node 内置 `crypto/fs/net`。
- 无原生扩展、无数据库驱动、无前端第三方 UI 组件，减少攻击面。
- 数据持久化使用原子 JSON（小型单管理员场景）；大规模/多人场景建议替换为 PostgreSQL 并增加 RBAC/审批。
- 锁定依赖版本并定期 `npm audit`；生产构建后以 `--omit=dev` 运行。

---

## 6. 数据模型

`data/store.json`（0600）：

```jsonc
{
  "version": 1,
  "users": [{
    "id": "uuid", "username": "admin",
    "passwordHash": "scrypt$...",
    "totpEnabled": false, "totpSecretEnc": null, "totpPendingEnc": null,
    "totpLastCounter": 0, "recoveryCodeHashes": [],
    "failedLogins": 0, "lockedUntil": 0,
    "createdAt": "...", "updatedAt": "..."
  }],
  "agents": [{
    "id": "uuid", "name": "web-01",
    "status": "pending|active|revoked",
    "publicKey": "-----BEGIN PUBLIC KEY-----...",
    "keyFingerprint": "sha256:...",
    "enrollTokenHash": "...", "enrollExpiresAt": 0,
    "createdAt": "...", "lastSeenAt": 0, "lastMeta": {}
  }],
  "settings": { "localWorkspace": "/etc/nginx" }
}
```

其他文件：

- `data/main-key.pem`（0600）：主服务器 Ed25519 私钥。
- `data/master.key`（0600）：AES-GCM/TOTP 主密钥。
- `data/audit.jsonl`（0600）。
- Agent 状态目录（默认 `~/.config/nginx-console` 或 systemd 指定）：
  - `agent.json`（0600）：注册信息、主服务器公钥、工作目录、允许根、Nginx 路径等。
  - `agent-key.pem`（0600）：Agent Ed25519 私钥。
  - `backups/`（0700）：配置与证书备份。

---

## 7. API 概览

全部返回 `{ ok, data }` 或 `{ ok:false, error:{ code, message, details? } }`。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/auth/login` | 登录（可选 TOTP/恢复码） |
| POST | `/api/auth/logout` | 退出 |
| GET | `/api/auth/me` | 当前用户 + CSRF Token |
| POST | `/api/auth/password` | 修改口令（旧口令 + 当前 TOTP） |
| POST | `/api/auth/totp/setup` | 生成 TOTP 密钥/URI |
| POST | `/api/auth/totp/enable` | 校验并启用，返回恢复码 |
| POST | `/api/auth/totp/disable` | 关闭 TOTP |
| GET | `/api/servers` | 节点列表 + 在线状态/概要 |
| POST | `/api/servers` | 创建子服务器 + 一次性注册令牌 |
| POST | `/api/servers/:id/enrollment-token` | 重新生成注册令牌 |
| POST | `/api/servers/:id/revoke` | 撤销并断开 |
| DELETE | `/api/servers/:id` | 删除子服务器记录 |
| GET | `/api/servers/:id/info` | Nginx/工作目录/版本/说明 |
| GET | `/api/servers/:id/workspace-options` | 允许根 + 可选目录 |
| PUT | `/api/servers/:id/workspace` | 选择工作目录 |
| GET | `/api/servers/:id/files?path=` | 列目录 |
| GET | `/api/servers/:id/file?path=` | 读文本（拒绝私钥） |
| PUT | `/api/servers/:id/file` | 写文件（baseHash 乐观锁 + 自动检测/回滚） |
| GET | `/api/servers/:id/backups` | 备份列表 |
| POST | `/api/servers/:id/backups/:backupId/restore` | 恢复备份 |
| POST | `/api/servers/:id/test` | `nginx -t` |
| POST | `/api/servers/:id/reload` | 检测后平滑重载 |
| POST | `/api/servers/:id/restart` | 检测后重启（confirm） |
| GET | `/api/servers/:id/certs` | 证书列表与有效期 |
| POST | `/api/servers/:id/certs` | 上传/替换 cert/chain/key |
| POST | `/api/servers/:id/certs/archive` | 上传 ZIP/TAR 压缩包，提取证书/链/私钥 |
| GET | `/api/audit` | 审计查询（最新在前） |
| POST | `/api/agent/enroll` | Agent 注册（一次性令牌，无会话） |

Agent 命令：`system.info`、`workspace.options/set`、`fs.list/read/write`、`backup.list/restore`、`nginx.test/reload/restart`、`cert.list/upload`、`cert.uploadArchive`。

---

## 8. 部署拓扑建议

```
Internet → 443 TLS (nginx/Caddy) → 127.0.0.1:8787 (main)
                                      ↑ WSS /agent/ws 经同一反向代理
子服务器 ──出站 443──► 主服务器域名
```

- 反向代理必须：
  - 强制 HTTPS/HSTS；
  - 由代理写入 `X-Forwarded-For`（追加 `$proxy_add_x_forwarded_for` 或覆盖为 `$remote_addr`）与 `X-Forwarded-Proto $scheme`，不要原样透传客户端同名头；应用只信任最后一跳，防止伪造来源 IP 绕过限速；
  - 支持 `/agent/ws` 的 WebSocket Upgrade，并提高读超时；
  - 限制请求体（例如 2 MiB）与速率。
- 主服务器进程使用独立系统用户，数据目录 0700。
- 进程托管二选一：pm2（`ecosystem.config.cjs`，跨平台，见 5.10）或 systemd（`deploy/*.service`）；不要同时使用。
- Agent 使用独立用户，建议以 systemd 沙箱运行；对 Nginx 目录仅有必要写权限；如果必须发信号，使用精确 sudoers 或由 root 运行但加 systemd 沙箱。
- 防火墙仅允许 443 入站（主服务器反代）与必要业务端口；Agent 不需要任何入站规则。

---

## 9. 上线安全检查清单

- [ ] 主服务器绑定 loopback，TLS 由反代终止；`NCS_PUBLIC_ORIGIN` 与 `NCS_ALLOWED_HOSTS` 已配置。
- [ ] 管理员强口令（≥16 字符）+ TOTP 已启用，恢复码离线保存。
- [ ] `data/`、`master.key`、`main-key.pem` 权限 0700/0600，已纳入加密备份。
- [ ] Agent 密钥/配置 0600；注册令牌一次性使用；Agent 公钥指纹已核对。
- [ ] Agent `allowedRoots` 只包含必要 Nginx 目录，工作目录内无无关敏感文件。
- [ ] Nginx 以 `nginx -t` 作为发布门禁；备份保留策略确认。
- [ ] 登录/接口速率限制由应用与反向代理双层配置。
- [ ] 日志与审计保留周期、告警接入。
- [ ] 依赖 `npm audit` 无高危；Node 与系统补丁更新。
- [ ] 按需启用 mTLS/WireGuard 作为额外网络层防护。

---

## 10. 已知限制

- 单管理员模型；无操作审批流。
- JSON 存储适合单主服务器中小规模；并发写入串行化，重启后会话失效。
- 证书“链有效性”只做 issuer 验签与结构校验，不校验证书是否被系统信任、不检查吊销（OCSP/CRL）。
- Agent 依赖系统时间准确（±60s），需启用 NTP。
- 若 Agent 进程以高权限运行且被攻陷，Nginx 目录内文件可被任意修改；这是 Agent 的固有权限，应通过操作系统沙箱收敛。
