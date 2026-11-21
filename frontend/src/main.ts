import { createApp } from 'vue'
import './style.css'
import App from './App.vue'
import { router } from './router'
import { applyFavicon } from './lib/brand'

applyFavicon()

createApp(App)
    .use(router)
    .mount('#app')
