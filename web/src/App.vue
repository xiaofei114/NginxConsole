<script setup>
import { onMounted, onBeforeUnmount } from 'vue';
import { RouterView } from 'vue-router';
import ToastHost from './components/ToastHost.vue';
import router from './router.js';
import { clearSession } from './lib/auth.js';

function handleUnauthenticated() {
  clearSession();
  if (router.currentRoute.value.name !== 'login') router.push('/login');
}

onMounted(() => window.addEventListener('ncs:unauthenticated', handleUnauthenticated));
onBeforeUnmount(() => window.removeEventListener('ncs:unauthenticated', handleUnauthenticated));
</script>

<template>
  <RouterView />
  <ToastHost />
</template>
