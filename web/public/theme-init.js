// 首屏前置脚本：在样式生效前应用用户显式选择的主题，避免刷新时闪一下另一套配色。
// CSP 为 script-src 'self'，因此必须是独立文件而不是内联脚本。
(function () {
  try {
    var mode = localStorage.getItem('ncs-theme');
    if (mode === 'light' || mode === 'dark') {
      document.documentElement.dataset.theme = mode;
    }
  } catch (error) {
    // 存储不可用时交给 prefers-color-scheme。
  }
})();
