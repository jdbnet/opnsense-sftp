import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import './styles/theme.css'
import { applyTheme, readInitialTheme } from './stores/theme'

applyTheme(readInitialTheme())

createApp(App).use(createPinia()).use(router).mount('#app')
