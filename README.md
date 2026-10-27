# Nginx Console

集中管理多台服务器 Nginx 配置与 TLS 证书的安全控制台。

- **主服务器**：Vue 3 控制台 + Node.js API，一个页面管理多台服务器；默认只监听 `127.0.0.1`，通过反向代理暴露公网。
- **子服务器 Agent**：只主动出站建立 WSS 连接，不开放入站管理端口；执行固定的 Nginx 操作命令。
- **核心能力**：选择 Nginx 工作目录、浏览/编辑配置文件、上传并替换证书、`nginx -t` 检测、重载/重启、变更备份与回滚、审计日志。

完整的威胁模型、协议、API 与数据模型见 [`docs/DESIGN.md`](docs/DESIGN.md)。

---

## 1. 架构

```
浏览器 ──HTTPS──> 反向代理 ──> 主服务器 (Node API + Vue dist, 127.0.0.1:8787)
                                      │
                                      │  WSS 出站（Ed25519 双向签名）
                                      ▼
                             子服务器 Agent ──> 本地 Nginx 工作目录
                                      │
                                      └──> nginx -t / -s reload / systemctl
```

- 主服务器也可直接管理本机 Nginx（“本地节点”），与 Agent 使用同一套引擎。
- Agent 注册使用一次性令牌（默认 30 分钟有效，只存 SHA-256）；注册后固定主服务器公钥，后续所有请求/响应双向签名，带时间戳与 Nonce 防重放。
- 主服务器只保存 Agent 公钥，不保存 Agent 私钥；Agent 私钥只落在子服务器本地（`0600`）。

### 目录结构

```
packages/shared   协议、路径沙箱、证书校验、结构化日志、错误与限制常量
packages/core     本地 Nginx 引擎、备份、命令执行、原子写
packages/agent    出站 Agent、注册、WebSocket 客户端
packages/main     主服务器 API、认证、会话、Agent Hub、审计
web               Vue 3 控制台
deploy            systemd / sudoers / 反向代理示例
ecosystem.config.cjs  pm2 进程配置（ncs-main / ncs-agent）
docs/DESIGN.md    系统设计与安全模型
```

---

## 2. 安全设计摘要

| 边界 | 措施 |
| --- | --- |
| 网络 | 主服务器默认 `127.0.0.1`；Agent 仅出站 WSS；无 CORS |
| 身份 | scrypt 口令哈希；TOTP 二次认证；一次性恢复码；登录锁定与限速 |
| 会话 | 32 字节随机 Token 仅存哈希；HttpOnly + SameSite=Strict + Secure；空闲/绝对过期；CSRF Token 绑定会话 |
| 浏览器边界 | Host 白名单、Origin 校验、CSP、HSTS、`no-store`、禁止 framing、隐藏 `X-Powered-By` |
| Agent 通道 | 一次性注册令牌 + Ed25519 互信 + 时间戳窗口 + Nonce 重放缓存 + 主服务器 challenge 防跨连接混淆 |
| 文件系统 | `allowedRoots` + `realpath` + 相对路径校验；拒绝 `..`/绝对路径/反斜杠/NUL；符号链接不得逃逸 |
| 文件类型 | 只允许文本配置扩展名；私钥只写不读；证书名白名单 |
| 配置变更 | `baseHash` 乐观锁；写前备份；写入后 `nginx -t`；失败自动回滚；重启需显式确认 |
| 命令执行 | `spawn(shell:false)` 固定参数白名单；超时与输出截断；可选精确 sudo |
| 证书 | 解析 X.509；校验证书/私钥 SPKI 匹配；拒绝过期、弱密钥、加密私钥；链按 issuer 顺序验签 |
| 审计 | JSONL `0600`；口令/令牌/私钥/文件内容脱敏；登录、变更、操作、连接事件可查 |
| 日志 | 统一 JSON Lines；字段级脱敏；不记录请求体与查询串；错误/warn 走 stderr |

> “绝对安全”不存在。本项目的目标是**默认拒绝、最小权限、可回滚、可审计**；部署时仍需按第 7 节加固。

---

## 3. 环境要求

- Node.js **22 LTS**（最低 20；项目使用 ESM 与 `--env-file-if-exists`）。
- npm 10+。
- 被管理机器已安装 Nginx；Agent 运行用户需要读写目标配置目录、执行 `nginx -t` 与重载/重启的权限。
- 公网部署需要域名、TLS 证书与反向代理（推荐 Nginx）。

---

## 4. 快速开始（本地开发）

```bash
npm install
npm run build        # 构建 Vue 控制台到 web/dist
npm start            # 启动主服务器，默认 http://127.0.0.1:8787
```

首次启动会：

- 在 `data/` 下创建数据目录、管理员和主服务器密钥；
- 未配置 `NCS_ALLOWED_ROOTS` 时创建演示工作目录 `data/nginx-workspace`；
- 在控制台打印管理员用户名与**只显示一次**的随机口令；
- 演示工作目录自动跳过 `nginx -t`（本机可能未安装 Nginx）。

生产环境不要使用演示目录，请配置 `NCS_ALLOWED_ROOTS` 并保持配置检测开启。

### 前端开发模式

```bash
# 终端 1：主服务器（默认 8787）
npm start

# 终端 2：Vite（127.0.0.1:5173，/api 代理到 8787）
npm run dev:web
```

开发模式默认允许 `http://localhost:5173` 与 `http://127.0.0.1:5173` 的 Origin。生产环境会忽略该配置。

---

## 5. 使用流程

### 5.1 管理本机 Nginx（主服务器本地节点）

1. 登录后进入“主服务器本地 Nginx”。
2. 点击“选择工作目录”，从允许的根目录中选择（例如 `/etc/nginx`）。
3. 在配置标签页编辑 `nginx.conf` / `conf.d/*.conf`，保存时自动备份并执行 `nginx -t`。
4. 证书标签页上传证书链与私钥，系统校验通过后写入工作目录的 `ssl/`。
5. “检测”“重载”“重启”按钮执行对应 Nginx 操作；失败自动回滚或提示。

### 5.2 添加子服务器 Agent

1. 在总览页点击“添加服务器”，填写名称。
2. 页面会显示 **Agent ID**、**一次性注册令牌** 与可复制的注册命令。令牌只显示一次，默认 30 分钟有效。
3. 在子服务器上安装本项目（同一版本），执行注册（令牌建议用环境变量传入，避免出现在命令历史）：

```bash
sudo -u nginx-console-agent \
  NCS_ENROLL_TOKEN='<一次性令牌>' \
  node /opt/nginx-console/packages/agent/src/index.js enroll \
    --main https://console.example.com \
    --id <AGENT_ID> \
    --allowed-root /etc/nginx \
    --workspace /etc/nginx \
    --config /etc/nginx-console/agent.json \
    --nginx-bin /usr/sbin/nginx \
    --control-mode systemd \
    --systemd-unit nginx \
    --use-sudo
```

4. 启动 Agent（或使用 systemd）：

```bash
node /opt/nginx-console/packages/agent/src/index.js run \
  --config /etc/nginx-console/agent.json
```

5. 总览页显示 Agent 在线后，即可进入其详情页管理工作目录、配置与证书。

Agent 仅主动连接主服务器的 `/agent/ws`，不需要公网入站端口。主服务器注册地址必须是 Agent 可达的公网 HTTPS 地址（`NCS_PUBLIC_ORIGIN`）。

### 5.3 证书替换

证书标签页支持三种上传方式：

1. **压缩包**（ZIP / TAR / TAR.GZ / TGZ，最大 512 KiB；TAR 需为 USTAR 格式）：自动从包内提取叶证书、可选链证书与私钥，其他文件忽略；
2. 分别上传证书文件（`fullchain.pem`，可含中间链）与私钥；
3. 手动粘贴 PEM 文本。

上传时可选择**存放方式**：

- **目录（默认）**：写入 `ssl/<name>/fullchain.pem`（叶证书 + 链）与 `ssl/<name>/privkey.pem`，兼容面板/宝塔式布局，填现有子目录名即可原地替换；
- **单文件**：写入 `ssl/<name>.crt`、`ssl/<name>.chain.pem`、`ssl/<name>.key`。

压缩包在内存中解析，条目路径不会用于落盘，只提取 PEM 证书/私钥并按上述方式写入：

- 拒绝路径穿越、重复条目、符号链接/硬链接、加密压缩包、ZIP64/分卷包；
- 限制条目数、单文件大小、解压总量与压缩包大小，并校验 CRC/校验和；
- 要求包内只有一个私钥、一个匹配私钥的叶证书；多个候选会拒绝并列出候选文件；
- 拒绝带口令私钥、过期/未生效证书、RSA < 2048；
- 按 issuer 顺序校验证书链，链证书必须能由叶证书逐级验签；
- 以 `0600` 写入私钥，生成可直接在 Nginx 中引用的路径；已有文件先备份，检测失败自动回滚。

证书文件只读可见，私钥内容永不下发到前端，也不能通过配置编辑器读取。

“已管理证书”除扫描 `ssl/` 根目录的 `.crt` / `.cer` / `.pem` 外，也识别 `ssl/<域名>/` 这类面板布局（优先读取 `fullchain.pem`、`cert.pem`），并标注同目录是否存在配套私钥；私钥内容不会被读取。

---

## 6. 配置项

主服务器使用环境变量；推荐复制 `.env.example` 为 `.env`（`0600`）。关键项：

| 变量 | 说明 |
| --- | --- |
| `NODE_ENV` | `production` 时启用严格安全检查 |
| `NCS_HOST` / `NCS_PORT` | 监听地址/端口，推荐 `127.0.0.1:8787` |
| `NCS_PUBLIC_ORIGIN` | 公网源地址（HTTPS），用于 Origin/Cookie/Agent 注册地址 |
| `NCS_TRUST_PROXY` | 反向代理后设为 `1`，信任转发头 |
| `NCS_ALLOWED_HOSTS` | Host 白名单（域名，不含端口） |
| `NCS_DATA_DIR` | 数据目录（存储、审计、备份、主密钥） |
| `NCS_ADMIN_USER` / `NCS_ADMIN_PASSWORD` | 初始管理员；口令至少 12 字符 |
| `NCS_ALLOWED_ROOTS` | 允许管理的 Nginx 根目录（逗号分隔，绝对路径） |
| `NCS_LOCAL_WORKSPACE` | 主服务器本地节点默认工作目录 |
| `NCS_NGINX_BIN` / `NCS_NGINX_PREFIX` | Nginx 可执行文件/`-p` 前缀 |
| `NCS_CONTROL_MODE` | `signal`（`nginx -s`）或 `systemd` |
| `NCS_SYSTEMD_UNIT` | systemd 单元名，默认 `nginx` |
| `NCS_USE_SUDO` | 使用 `sudo -n` 执行 Nginx 控制命令 |
| `NCS_CERT_DIR` | 工作目录内证书子目录，默认 `ssl` |
| `NCS_SESSION_IDLE_MINUTES` / `NCS_SESSION_ABSOLUTE_MINUTES` | 会话空闲/绝对过期 |
| `NCS_ENROLL_TOKEN_MINUTES` | Agent 注册令牌有效期 |
| `NCS_TLS_CERT` / `NCS_TLS_KEY` | 可选：Node 直接监听 HTTPS |
| `NCS_WEB_DIST` | 可选：前端 dist 路径，默认仓库内 `web/dist` |
| `NCS_LOG_LEVEL` | 日志级别 `error` / `warn` / `info` / `debug`，默认 `info` |
| `NCS_LOG_FORMAT` | `json`（JSON Lines，非 TTY 时默认）或 `pretty`（终端可读） |

完整注释见 [`.env.example`](.env.example)。

Agent 配置保存在 `agent.json`（`0600`），包含 Agent ID、主服务器地址、允许根目录、工作目录、Nginx 路径、控制方式与固定公钥指纹。Agent 私钥单独保存为 `agent-key.pem`（`0600`）。

---

## 7. 生产部署

### 7.1 安装

```bash
# 以 root 安装到 /opt/nginx-console
cd /opt/nginx-console
npm ci
npm run build
npm prune --omit=dev

useradd --system --home /opt/nginx-console --shell /usr/sbin/nologin nginx-console
useradd --system --home /opt/nginx-console --shell /usr/sbin/nologin nginx-console-agent
mkdir -p /var/lib/nginx-console /etc/nginx-console
chown nginx-console:nginx-console /var/lib/nginx-console
chmod 700 /var/lib/nginx-console
```

### 7.2 主服务器

1. 复制 `.env.example` 为 `/etc/nginx-console/main.env`，设置 `0600 root:root`。
2. 设置 `NODE_ENV=production`、`NCS_PUBLIC_ORIGIN=https://console.example.com`、`NCS_TRUST_PROXY=1`、`NCS_ALLOWED_HOSTS=console.example.com`、`NCS_ALLOWED_ROOTS=/etc/nginx`。
3. 安装 [`deploy/nginx-console.service`](deploy/nginx-console.service) 到 `/etc/systemd/system/`，按注释调整可写路径。
4. 安装反向代理示例 [`deploy/nginx-console.nginx.conf`](deploy/nginx-console.nginx.conf)，确保 `/agent/ws` 支持 WebSocket Upgrade。
5. `systemctl daemon-reload && systemctl enable --now nginx-console`。

> 主服务器若直接管理本机系统 Nginx，需要额外授权 `/etc/nginx` 写权限或精确 sudo；不要为此把整个服务无条件改为 root。

### 7.3 子服务器 Agent

1. 复制 [`deploy/nginx-console-agent.service`](deploy/nginx-console-agent.service) 到 `/etc/systemd/system/`。
2. 按实际路径调整 `ReadWritePaths`（Nginx 工作目录与 Agent 配置目录）。
3. 以 `nginx-console-agent` 用户执行 `enroll`（见 5.2），然后 `systemctl enable --now nginx-console-agent`。
4. 如需 sudo 控制 Nginx，使用 [`deploy/nginx-console.sudoers`](deploy/nginx-console.sudoers) 的精确规则，并用 `visudo -c` 校验。

### 7.4 上线检查清单

- [ ] 主服务器只监听 `127.0.0.1`，公网仅经 TLS 反向代理访问。
- [ ] `NCS_PUBLIC_ORIGIN` 为 HTTPS，`NCS_ALLOWED_HOSTS` 正确。
- [ ] `NCS_ALLOWED_ROOTS` 仅包含真正需要管理的目录，工作目录在其内。
- [ ] 管理员使用强口令并已启用 TOTP，恢复码离线保存。
- [ ] `.env`、`main.env`、`agent.json`、`agent-key.pem`、`master.key` 权限 `0600`，属主正确。
- [ ] Agent 以专用用户运行；`ReadWritePaths` 与 sudoers 按最小权限收紧。
- [ ] 反向代理 `/agent/ws` 支持 Upgrade，读写超时足够长。
- [ ] 已验证 `nginx -t`、重载/重启、证书替换与回滚流程。
- [ ] 审计日志已纳入日志采集与保留策略。
- [ ] 已完成数据目录备份与灾难恢复演练。

### 7.5 备份与恢复

需要备份 `NCS_DATA_DIR`：`store.json`、`audit.jsonl`、`backups/`、`master.key`、`main-key.pem`。丢失 `master.key` 将无法解密已保存的 TOTP 密钥；丢失 `store.json` 将丢失全部服务器与账号数据。恢复时保持原权限并停止服务后替换。

---

## 7A. Windows 与混合部署

### 7A.1 结论

| 场景 | 支持情况 |
| --- | --- |
| 主服务器跑在 Windows（本地开发/内网） | 支持，本项目开发环境即为 Windows，全部测试通过 |
| 主服务器 Windows + 子节点 Linux（混合） | 支持，推荐用于“Windows 办公机管理 Linux 生产机” |
| 主服务器 Linux + 子节点 Windows | 支持，但 Windows 子节点的 Nginx 控制能力受限（见 7A.3） |
| 全部生产环境 | 推荐 Linux（systemd + 专用用户 + 沙箱 + 精确 sudo） |

主服务器与 Agent 之间只传 JSON + PEM 文本，协议与平台无关；每个节点各自配置 `nginxBin`、`controlMode`、`allowedRoots`，所以混合节点可以在同一个页面统一管理。

### 7A.2 Windows 主服务器配置

`.env` 中的路径必须使用 Windows 绝对路径（可写 `C:/nginx` 或 `C:\\nginx`）：

```ini
NODE_ENV=development
NCS_HOST=127.0.0.1
NCS_PORT=8787
NCS_DATA_DIR=D:/nginx-console/data
NCS_ALLOWED_ROOTS=C:/nginx
NCS_LOCAL_WORKSPACE=C:/nginx
NCS_NGINX_BIN=C:/nginx/nginx.exe
NCS_CONTROL_MODE=signal
NCS_COOKIE_SECURE=0
```

启动方式不变：

```powershell
npm install
npm run build
npm start
```

注意：

- `NCS_NGINX_BIN` 必须指向 `nginx.exe`；默认值 `/usr/sbin/nginx` 在 Windows 上不可用。
- 不支持 `systemd` 控制模式；Windows 上只能使用 `signal`。
- `NCS_USE_SUDO` 在 Windows 上无意义，保持 `0`。
- 生产模式（`NODE_ENV=production`）仍要求 HTTPS 反向代理；Windows 可用 IIS/Caddy/Nginx for Windows 做 TLS 终止。

### 7A.3 Windows 子节点（Agent）

```powershell
$env:NCS_ENROLL_TOKEN = '<一次性令牌>'
node packages/agent/src/index.js enroll `
  --main https://console.example.com `
  --id <AGENT_ID> `
  --allowed-root C:\nginx `
  --workspace C:\nginx `
  --nginx-bin C:\nginx\nginx.exe `
  --config C:\nginx-console\agent.json

node packages/agent/src/index.js run --config C:\nginx-console\agent.json
```

Windows 上的限制：

- **必须显式指定** `--allowed-root` 与 `--nginx-bin`，不会回退到 POSIX 默认值。
- 控制模式只有 `signal`：`nginx -t`、`nginx -s reload`、`nginx -s stop` 可用；启动由系统以分离进程方式执行。
- 如需开机自启，用“任务计划程序”、NSSM 或 WinSW 把 `node packages/agent/src/index.js run` 注册为服务；本项目不提供 Windows 服务封装。
- Agent 配置默认在 `%APPDATA%\nginx-console\agent.json`。
- **权限模型不同**：Windows 不适用 `0600/0700`，代码在 Windows 上跳过 POSIX 权限校验。必须用 NTFS ACL 收紧，例如：

```powershell
icacls C:\nginx-console /inheritance:r /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F"
icacls C:\nginx-console\agent.json /inheritance:r /grant:r "Administrators:F" "SYSTEM:F"
icacls C:\nginx-console\agent-key.pem /inheritance:r /grant:r "Administrators:F" "SYSTEM:F"
```

- 文件系统大小写不敏感；符号链接需要管理员权限或开发者模式，跨出工作目录的链接同样会被拒绝。
- 若需要严格最小权限，建议改用 Linux 子节点。

### 7A.4 混合部署注意事项

- 主服务器页面上的“服务器”分为本地节点与 Agent 节点；本地节点用主服务器的 `NCS_*` 配置，Agent 节点用各自 `agent.json`，互不影响。
- 证书与配置里的路径建议用正斜杠（`C:/nginx/ssl/example.com.crt`），Nginx 在 Windows 上同时接受 `/` 和 `\\`。
- 时间戳签名窗口为 ±60 秒，混合环境请确保各节点 NTP 同步。
- 反向代理的 `/agent/ws` 必须允许 WebSocket；Windows 主服务器同样适用。
- 审计日志、备份、密钥都在主服务器数据目录，跨平台备份直接复制目录即可。

---

## 7B. 日志与进程管理（pm2）

### 7B.1 日志格式

主服务器与 Agent 共用 `@ncs/shared` 的 `createLogger`，每行一条记录：

```json
{"ts":"2026-10-27T13:49:04.404Z","level":"info","app":"main","component":"app","msg":"HTTP 请求","requestId":"55557ea9-6c7a-4e6e-b683-e87946a9ccd0","method":"GET","path":"/api/health","status":200,"durationMs":2.7,"ip":"127.0.0.1"}
```

| 字段 | 说明 |
| --- | --- |
| `ts` | ISO 8601 UTC 时间 |
| `level` | `error` / `warn` / `info` / `debug` |
| `app` | `main` 或 `agent` |
| `component` | 模块标识，如 `boot`、`app`、`hub`、`client` |
| `msg` | 事件描述 |
| `err` | 异常对象：`name` / `message` / `code` / `status` / `stack` |
| 其他 | 事件附带的上下文字段 |

约定：

- `error` / `warn` 写 stderr，`info` / `debug` 写 stdout；pm2、systemd、Docker 都会分别归档。
- 非 TTY 环境默认 `json`（JSON Lines），终端里默认 `pretty`。可用 `NCS_LOG_FORMAT` 强制。
- 访问日志只记录方法、路径、状态、耗时和来源 IP；**不记录查询串与请求体**。
- 字段名命中 `password` / `token` / `secret` / `authorization` / `cookie` / `privateKey` 等关键字时自动替换为 `[redacted]`。
- 唯一例外：首次启动生成的管理员初始口令。终端运行时只打印一次；pm2/systemd 等非 TTY 环境改为写入 `<数据目录>/initial-admin-password.txt`（权限 0600），避免明文长期留在 pm2 日志里，登录后请立即改密并删除该文件。
- 日志本身抛错会被吞掉，不会影响请求处理。

`NCS_LOG_FORMAT=pretty` 时的输出：

```text
2026-10-27T13:49:04.404Z INFO  [main:app] HTTP 请求 requestId=... method=GET path=/api/health status=200 durationMs=2.7 ip=127.0.0.1
```

### 7B.2 使用 pm2

前置条件：Node.js 22（`--env-file-if-exists` 需要 ≥ 20.6）；全局安装 pm2：`npm i -g pm2`。

仓库根目录的 [`ecosystem.config.cjs`](ecosystem.config.cjs) 定义了两个应用：

```bash
npm run pm2:start          # 只启动主服务器 ncs-main
npm run pm2:start:agent    # 仅在本机确实是子节点时启动 ncs-agent
npm run pm2:restart        # 重启
npm run pm2:status         # 状态
npm run pm2:logs           # 查看日志
npm run pm2:stop           # 停止
npm run pm2:delete         # 从 pm2 移除
npm run pm2:save           # 保存进程列表
```

要点：

- **不要开 cluster**：本系统是单管理员 + 本地状态文件，`instances` 必须为 1，使用 fork 模式。
- 主服务器仍由 `node --env-file-if-exists=.env` 读取根目录 `.env`；pm2 的 `env` 里不要再写 `NODE_ENV`/`NCS_*`，否则会覆盖 `.env`。
- 日志默认在 `~/.pm2/logs/`（`ncs-main-out.log` / `ncs-main-error.log`）。
- 建议安装轮转：`pm2 install pm2-logrotate`，然后 `pm2 set pm2-logrotate:retain 14`。
- 开机自启：`pm2 startup`（按提示执行输出的那条命令）后 `pm2 save`。
- Windows 同样可用；若要把 pm2 本身做成服务，可用 NSSM 或 pm2-installer 包装。
- 与 `deploy/*.service` 二选一，**不要同时用 systemd 和 pm2 管理同一个进程**。

---

## 8. 测试与验证

```bash
npm test             # shared + core + main（含 Agent 出站隧道端到端）
npm run build        # Vue 生产构建
```

覆盖范围：

- `packages/shared/test`：签名/篡改/过期/重放、路径穿越与符号链接逃逸、文件类型白名单、证书链/过期/弱密钥、ZIP/TAR 解包边界与证书选择、日志级别过滤与敏感字段脱敏。
- `packages/core/test`：工作目录沙箱、读写乐观锁、备份与恢复、私钥拒绝、证书上传与压缩包导入。
- `packages/main/test`：口令/TOTP/恢复码/会话/CSRF、Host/Origin 校验、登录、创建并注册 Agent、本地 Nginx 配置读写与回滚、压缩包上传接口、审计、Agent 隧道端到端（含压缩包上传）。

测试证书为静态 fixture（`packages/shared/test/fixtures`），仅用于测试，**不要用于任何真实服务**。

---

## 9. 已知限制

- 单管理员模式，不提供多租户/RBAC。
- Agent 若被完全控制，攻击者可控制该机器的 Nginx；请用专用用户、systemd 沙箱与精确 sudo 降低影响面。
- 配置编辑器只允许文本扩展名的文件；私钥不能通过编辑器读取或下载。
- “重启”是危险操作，必须显式确认；若 `nginx -t` 失败则不会重载/重启。
- 反向代理必须正确传递 `Host`、`X-Forwarded-Proto` 并支持 WebSocket，否则登录/Origin 校验或 Agent 连接会失败；同时必须**自行写入** `X-Forwarded-For`（追加 `$proxy_add_x_forwarded_for` 或覆盖为 `$remote_addr`），不能原样透传客户端提供的同名头。程序只取该头的最后一跳作为真实 IP，以保证限速与审计记录不被伪造。
- Windows 不支持 `systemd` 控制模式与 POSIX 权限位；生产环境优先使用 Linux（见 7A 节）。

---

## 10. 许可与声明

本项目为内部运维工具示例。投入使用前请结合自身环境完成安全评审、渗透测试与备份恢复演练。
