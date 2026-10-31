export function formatTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString('zh-CN', { hour12: false });
}

export function timeAgo(value) {
  if (!value) return '从未';
  const timestamp = new Date(value).getTime();
  if (Number.isNaN(timestamp)) return '—';
  const seconds = Math.round((Date.now() - timestamp) / 1000);
  if (seconds < 0) return '刚刚';
  if (seconds < 60) return `${seconds} 秒前`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`;
  return `${Math.floor(seconds / 86400)} 天前`;
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}

export function shortFingerprint(value) {
  if (!value) return '—';
  const text = String(value).replace(/^SHA256:/, '');
  return text.length > 20 ? `${text.slice(0, 10)}…${text.slice(-8)}` : text;
}

export function expiryTone(days) {
  if (!Number.isFinite(days)) return 'muted';
  if (days < 0) return 'danger';
  if (days < 14) return 'danger';
  if (days < 30) return 'warn';
  return 'ok';
}

export function daysText(days) {
  if (!Number.isFinite(days)) return '—';
  if (days < 0) return `已过期 ${Math.abs(days)} 天`;
  if (days === 0) return '今天到期';
  return `${days} 天后到期`;
}

export function actionLabel(action) {
  const labels = {
    'auth.login': '登录',
    'auth.login.failed': '登录失败',
    'auth.login.locked': '账号锁定',
    'auth.logout': '退出登录',
    'auth.password.change': '修改口令',
    'auth.totp.setup': '开始设置两步验证',
    'auth.totp.enable': '启用两步验证',
    'auth.totp.disable': '关闭两步验证',
    'agent.enroll': 'Agent 注册',
    'agent.connect': 'Agent 上线',
    'agent.disconnect': 'Agent 离线',
    'agent.auth.failed': 'Agent 认证失败',
    'agent.protocol.violation': 'Agent 协议违规',
    'server.create': '创建服务器',
    'server.delete': '删除服务器',
    'server.revoke': '撤销服务器',
    'server.enrollment_token': '重新生成注册令牌',
    'server.workspace.set': '切换工作目录',
    'server.file.write': '保存配置文件',
    'server.backup.restore': '恢复备份',
    'server.nginx.test': 'Nginx 配置检测',
    'server.nginx.reload': 'Nginx 平滑重载',
    'server.nginx.restart': 'Nginx 重启',
    'server.cert.upload': '更新 SSL 证书',
    'server.cert.delete': '删除 SSL 证书',
  };
  return labels[action] || action;
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const area = document.createElement('textarea');
      area.value = text;
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(area);
      return ok;
    } catch {
      return false;
    }
  }
}
