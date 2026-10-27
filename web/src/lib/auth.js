import { reactive } from 'vue';
import { api, setCsrfToken } from './api.js';

export const authState = reactive({
  user: null,
  session: null,
  loaded: false,
});

let pending = null;

function applySession(data) {
  setCsrfToken(data?.csrfToken || null);
  authState.user = data?.user || null;
  authState.session = data?.session || null;
  authState.loaded = true;
}

export function clearSession() {
  setCsrfToken(null);
  authState.user = null;
  authState.session = null;
  authState.loaded = true;
}

export async function ensureSession({ force = false } = {}) {
  if (authState.loaded && !force) return authState.user;
  if (pending) return pending;
  pending = (async () => {
    try {
      const data = await api.get('/auth/me');
      applySession(data);
      return authState.user;
    } catch (error) {
      if (error?.status === 401) {
        clearSession();
        return null;
      }
      authState.loaded = true;
      return authState.user;
    } finally {
      pending = null;
    }
  })();
  return pending;
}

export async function login(credentials) {
  const data = await api.post('/auth/login', credentials, { timeoutMs: 30000 });
  applySession(data);
  return data;
}

export async function logout() {
  try {
    await api.post('/auth/logout', {}, { timeoutMs: 15000 });
  } catch {
    // The local session is cleared regardless of network state.
  }
  clearSession();
}

export async function refreshSession() {
  const data = await api.get('/auth/me');
  applySession(data);
  return data;
}

export function updateUser(partial) {
  if (authState.user) authState.user = { ...authState.user, ...partial };
}
