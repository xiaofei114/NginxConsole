import { reactive } from 'vue';

let nextId = 1;
export const toasts = reactive([]);

export function pushToast(message, type = 'info', timeout = 5000) {
  const id = nextId;
  nextId += 1;
  toasts.push({ id, message, type });
  while (toasts.length > 5) toasts.shift();
  if (timeout > 0) {
    setTimeout(() => dismissToast(id), timeout);
  }
  return id;
}

export function dismissToast(id) {
  const index = toasts.findIndex((item) => item.id === id);
  if (index >= 0) toasts.splice(index, 1);
}

export const toast = {
  success: (message) => pushToast(message, 'success'),
  error: (message) => pushToast(message, 'error', 7000),
  warn: (message) => pushToast(message, 'warn', 6500),
  info: (message) => pushToast(message, 'info'),
};
