import { computed, ref } from 'vue';

// 与 public/theme-init.js 中的常量保持一致，改一处必须同步另一处。
const STORAGE_KEY = 'ncs-theme';
const DARK_QUERY = '(prefers-color-scheme: dark)';
const MODES = ['system', 'light', 'dark'];

function readStoredMode() {
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    return MODES.includes(value) ? value : 'system';
  } catch {
    // 隐私模式或禁用存储时按跟随系统处理。
    return 'system';
  }
}

const media = typeof window !== 'undefined' && typeof window.matchMedia === 'function'
  ? window.matchMedia(DARK_QUERY)
  : null;

const systemPrefersDark = ref(media ? media.matches : true);

export const themeMode = ref(readStoredMode());

export const resolvedTheme = computed(() => (
  themeMode.value === 'system' ? (systemPrefersDark.value ? 'dark' : 'light') : themeMode.value
));

function applyTheme() {
  const root = document.documentElement;
  // 跟随系统时不写 data-theme，交给 CSS 的 prefers-color-scheme 处理。
  if (themeMode.value === 'system') root.removeAttribute('data-theme');
  else root.dataset.theme = themeMode.value;
}

export function setThemeMode(mode) {
  if (!MODES.includes(mode)) return;
  themeMode.value = mode;
  try {
    if (mode === 'system') localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, mode);
  } catch {
    // 存储不可用时仅本次会话生效。
  }
  applyTheme();
}

media?.addEventListener('change', (event) => {
  systemPrefersDark.value = event.matches;
});

applyTheme();
