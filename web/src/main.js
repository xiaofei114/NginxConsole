import { createApp } from 'vue';
import App from './App.vue';
import router from './router.js';
import './lib/theme.js';
import './styles.css';

createApp(App).use(router).mount('#app');
